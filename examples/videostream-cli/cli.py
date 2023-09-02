import argparse
import asyncio
import logging
import math
import boto3

import cv2
import numpy
from aiortc import (
    RTCIceCandidate,
    RTCPeerConnection,
    RTCSessionDescription,
    VideoStreamTrack,
)
from aiortc.contrib.media import MediaBlackhole, MediaPlayer, MediaRecorder
from aiortc.contrib.signaling import BYE, add_signaling_arguments, create_signaling
from av import VideoFrame
from aiortc.rtcconfiguration import RTCIceServer, RTCConfiguration


class FlagVideoStreamTrack(VideoStreamTrack):
    """
    A video track that returns an animated flag.
    """

    def __init__(self):
        super().__init__()  # don't forget this!
        self.counter = 0
        height, width = 480, 640

        # generate flag
        data_bgr = numpy.hstack(
            [
                self._create_rectangle(
                    width=213, height=480, color=(255, 0, 0)
                ),  # blue
                self._create_rectangle(
                    width=214, height=480, color=(255, 255, 255)
                ),  # white
                self._create_rectangle(width=213, height=480, color=(0, 0, 255)),  # red
            ]
        )

        # shrink and center it
        M = numpy.float32([[0.5, 0, width / 4], [0, 0.5, height / 4]])
        data_bgr = cv2.warpAffine(data_bgr, M, (width, height))

        # compute animation
        omega = 2 * math.pi / height
        id_x = numpy.tile(numpy.array(range(width), dtype=numpy.float32), (height, 1))
        id_y = numpy.tile(
            numpy.array(range(height), dtype=numpy.float32), (width, 1)
        ).transpose()

        self.frames = []
        for k in range(30):
            phase = 2 * k * math.pi / 30
            map_x = id_x + 10 * numpy.cos(omega * id_x + phase)
            map_y = id_y + 10 * numpy.sin(omega * id_x + phase)
            self.frames.append(
                VideoFrame.from_ndarray(
                    cv2.remap(data_bgr, map_x, map_y, cv2.INTER_LINEAR), format="bgr24"
                )
            )

    async def recv(self):
        pts, time_base = await self.next_timestamp()

        frame = self.frames[self.counter % 30]
        frame.pts = pts
        frame.time_base = time_base
        self.counter += 1
        return frame

    def _create_rectangle(self, width, height, color):
        data_bgr = numpy.zeros((height, width, 3), numpy.uint8)
        data_bgr[:, :] = color
        return data_bgr


# function to use boto3 to construct the RTCPeerConfiguration object
def getRTCPeerConfiguration():
    client = boto3.client("kinesisvideo")

    # get the channel ARN
    channelARNResponse = client.describe_signaling_channel(
        ChannelName="my_test_channel"
    )
    channelARN = channelARNResponse["ChannelInfo"]["ChannelARN"]

    # get the signalling channel endpoint
    response = client.get_signaling_channel_endpoint(
        ChannelARN=channelARN,
        SingleMasterChannelEndpointConfiguration={
            "Protocols": [
                "WSS",
                "HTTPS",
            ],  # WSS | HTTPS | WEBRTC (used for media capture which we are not doing right now)
            "Role": "MASTER",
        },
    )
    # reduce ResourceEndpointList to a dictionary with the key being the Protocol and the value being the ResourceEndpoint
    endpoints = {
        item["Protocol"]: item["ResourceEndpoint"]
        for item in response["ResourceEndpointList"]
    }

    # get the ice server configuration
    client = boto3.client("kinesis-video-signaling", endpoint_url=endpoints["HTTPS"])
    response = client.get_ice_server_config(
        ChannelARN=channelARN,
    )

    #  construct the RTCConfiguration object
    iceServerList = []
    for iceServer in response["IceServerList"]:
        iceServerList.append(
            RTCIceServer(
                urls=iceServer["Uris"],
                username=iceServer["Username"],
                credential=iceServer["Password"],
            )
        )
    # add STUN server (could disable in future but trying everything first)
    iceServerList.append(
        RTCIceServer(
            urls=["stun:stun.kinesisvideo.eu-west-2.amazonaws.com:443"],
        )
    )

    return endpoints, RTCConfiguration(iceServerList)


async def run(pc, player, recorder, signaling, role):
    def add_tracks():
        if player and player.audio:
            pc.addTrack(player.audio)

        if player and player.video:
            pc.addTrack(player.video)
        else:
            pc.addTrack(FlagVideoStreamTrack())

    @pc.on("track")
    def on_track(track):
        print("Receiving %s" % track.kind)
        recorder.addTrack(track)

    # connect signaling
    print("Connecting to signaling server")
    await signaling.connect()
    print("Connected to signaling server")

    if role == "offer":
        # send offer
        add_tracks()
        await pc.setLocalDescription(await pc.createOffer())
        print("Sending offer")
        print("XXXXXXXXXXXX")
        # print(pc.localDescription)
        print("XXXXXXXXXXXX")
        await signaling.send(pc.localDescription)
        print("Offer sent")

    # consume signaling
    while True:
        print("Waiting for event")
        obj = await signaling.receive()
        print("Received event")
        if isinstance(obj, RTCSessionDescription):
            await pc.setRemoteDescription(obj)
            await recorder.start()

            if obj.type == "offer":
                # send answer
                add_tracks()
                await pc.setLocalDescription(await pc.createAnswer())
                await signaling.send(pc.localDescription)
        elif isinstance(obj, RTCIceCandidate):
            await pc.addIceCandidate(obj)
        elif obj is BYE:
            print("Exiting")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Video stream from the command line")
    parser.add_argument("role", choices=["offer", "answer"])
    parser.add_argument("--play-from", help="Read the media from a file and sent it."),
    parser.add_argument("--record-to", help="Write received media to a file."),
    parser.add_argument("--verbose", "-v", action="count")
    add_signaling_arguments(parser)
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # get the endpoints and configuration, update args.signaling_host
    endpoints, configuration = getRTCPeerConfiguration()
    args.signaling_host = endpoints["WSS"]
    args.signaling_port = 443
    args.signaling = "websocket"

    print(endpoints)

    # create signaling and peer connection
    print("Creating signaling and peer connection")
    print(args)
    signaling = create_signaling(args)
    pc = RTCPeerConnection(configuration)

    # create media source
    if args.play_from:
        player = MediaPlayer(args.play_from)
    else:
        player = None

    # create media sink
    if args.record_to:
        recorder = MediaRecorder(args.record_to)
    else:
        recorder = MediaBlackhole()

    # run event loop
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run(
                pc=pc,
                player=player,
                recorder=recorder,
                signaling=signaling,
                role=args.role,
            )
        )
    except KeyboardInterrupt:
        pass
    finally:
        # cleanup
        loop.run_until_complete(recorder.stop())
        loop.run_until_complete(signaling.close())
        loop.run_until_complete(pc.close())

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
import os, sys, datetime, hashlib, hmac, urllib.parse


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


def getSignedURL(method, service, region, host, endpoint):
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def getSignatureKey(key, dateStamp, regionName, serviceName):
        kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, "aws4_request")
        return kSigning

    # ------------------------------------------------------------------
    # Step 2. Define the variables required for the request URL. Replace
    # values for the variables, such as region, with your own values.
    # ------------------------------------------------------------------
    method = method
    service = service
    region = region

    # Host and endpoint information.
    # host = "api.iotwireless." + region + ".amazonaws.com"
    host = host
    endpoint = endpoint

    # Create a date for headers and the credential string.
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")

    # For date stamp, the date without time is used in credential scope.
    datestamp = t.strftime("%Y%m%d")

    # -----------------------------------------------------------------------
    # Step 3. Create the canonical URI and canonical headers for the request.
    # -----------------------------------------------------------------------
    canonical_uri = "/"  # "/start-network-analyzer-stream"
    # configuration_name = "My_Network_Analyzer_Config"

    canonical_headers = "host:" + host + "\n"
    signed_headers = "host"
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = datestamp + "/" + region + "/" + service + "/" + "aws4_request"

    # -----------------------------------------------------------------------
    # Step 4. Read the  credentials that are required for the request
    # from environment variables or configuration file.
    # -----------------------------------------------------------------------

    # IMPORTANT: Best practice is NOT to embed credentials in code.

    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("AWS_SESSION_TOKEN")

    if access_key is None or secret_key is None:
        print("No access key is available.")
        sys.exit()

    if access_key.startswith("ASIA") and token is None:
        print("Detected temporary credentials. You must specify a token.")
        sys.exit()

    # ----------------------------------------------------------------------
    # Step 5. Create the canonical query string. Query string values must be
    # URI-encoded and sorted by name. Query headers must in alphabetical order.
    # ----------------------------------------------------------------------
    canonical_querystring = "X-Amz-Algorithm=" + algorithm

    canonical_querystring += "&X-Amz-ChannelARN=" + urllib.parse.quote(
        "arn:aws:kinesisvideo:eu-west-2:704753930477:channel/my_test_channel/1691592101264",
        safe="-_.~",
    )

    canonical_querystring += "&X-Amz-Credential=" + urllib.parse.quote(
        access_key + "/" + credential_scope, safe="-_.~"
    )

    canonical_querystring += "&X-Amz-Date=" + amz_date
    canonical_querystring += "&X-Amz-Expires=300"

    if access_key.startswith("ASIA"):
        # percent encode the token and double encode "="
        canonical_querystring += "&X-Amz-Security-Token=" + urllib.parse.quote(
            token, safe="-_.~"
        ).replace("=", "%253D")

    canonical_querystring += "&X-Amz-SignedHeaders=" + signed_headers
    # canonical_querystring += "&configuration-name=" + configuration_name

    # ----------------------------------------------------------------------
    # Step 6. Create a hash of the payload.
    # ----------------------------------------------------------------------
    payload_hash = hashlib.sha256(("").encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Step 7. Combine the elements, which includes the query string, the
    # headers, and the payload hash, to form the canonical request.
    # ------------------------------------------------------------------
    canonical_request = (
        method
        + "\n"
        + canonical_uri
        + "\n"
        + canonical_querystring
        + "\n"
        + canonical_headers
        + "\n"
        + signed_headers
        + "\n"
        + payload_hash
    )

    # ----------------------------------------------------------------------
    # Step 8. Create the metadata string to store the information required to
    # calculate the signature in the following step.
    # ----------------------------------------------------------------------
    string_to_sign = (
        algorithm
        + "\n"
        + amz_date
        + "\n"
        + credential_scope
        + "\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )

    # ----------------------------------------------------------------------
    # Step 9. Calculate the signature by using a signing key that"s obtained
    # from your secret key.
    # ----------------------------------------------------------------------
    # Create the signing key from your secret key.
    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing key.
    signature = hmac.new(
        signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # ----------------------------------------------------------------------
    # Step 10. Create the request URL using the calculated signature and by
    # combining it with the canonical URI and the query string.
    # ----------------------------------------------------------------------
    canonical_querystring += "&X-Amz-Signature=" + signature

    request_url = endpoint + canonical_uri + "?" + canonical_querystring
    return request_url


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
            # This property is used to determine the nature of communication over this SINGLE_MASTER signaling channel.
            # If WSS is specified, this API returns a websocket endpoint. If HTTPS is specified, this API returns an HTTPS endpoint.
            "Protocols": [
                "WSS",
                "HTTPS",
            ],  # WSS | HTTPS | WEBRTC (used for media capture which we are not doing right now)
            # This property is used to determine messaging permissions in this SINGLE_MASTER signaling channel.
            # If MASTER is specified, this API returns an endpoint that a client can use to receive offers from and
            # send answers to any of the viewers on this signaling channel. If VIEWER is specified, this API
            # returns an endpoint that a client can use only to send offers to another MASTER client on this
            # signaling channel.
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
    # aioice.stun.TransactionFailed: STUN transaction failed (403 - Forbidden IP) -> error from loading ICE config from viewer
    iceServerList.append(
        RTCIceServer(
            urls=["stun:stun.kinesisvideo.eu-west-2.amazonaws.com:443"],
        )
    )

    return endpoints, RTCConfiguration(iceServerList)


async def run(pc, player, recorder, signaling, role, remoteClientId=None):
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
    # connect signaling
    await signaling.connect()
    print("Connected to signaling server")

    # # based on
    # # https://w3c.github.io/webrtc-pc/#perfect-negotiation-example
    # # // keep track of some negotiation state to prevent races and errors
    # makingOffer = False
    # ignoreOffer = False
    # isSettingRemoteAnswerPending = False
    # # The polite peer uses rollback to avoid collision with an incoming offer.
    # # The impolite peer ignores an incoming offer when this would collide with its own.
    # polite = True

    # if we want to send an offer from the start we would need to know who to send it to...
    # this is AWS KVS specific logic
    if role == "offer":
        # send offer
        add_tracks()
        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        await signaling.send(offer, senderClientId="test")

    while True:
        # await asyncio.sleep(2)
        obj, remoteClientId = await signaling.receive()
        # print("Received %s" % obj.type)
        # print("ConnectionState %s" % pc.connectionState)
        # print("SignalingState %s" % pc.signalingState)
        # print("IceConnectionState %s" % pc.iceConnectionState)
        # print("IceGatheringState %s" % pc.iceGatheringState)

        if pc.connectionState == "failed":
            print("Connection failed")
            break
        elif isinstance(obj, RTCSessionDescription):
            print("========= offer or answer: " + obj.type)
            # // An offer may come in while we are busy processing SRD(answer).
            # // In this case, we will be in "stable" by the time the offer is processed
            # // so it is safe to chain it on our Operations Chain now.
            # readyForOffer = not makingOffer and (
            #     pc.signalingState == "stable" or isSettingRemoteAnswerPending
            # )
            # offerCollision = obj.type == "offer" and not readyForOffer

            # ignoreOffer = not polite and offerCollision
            # if ignoreOffer:
            #     continue

            # isSettingRemoteAnswerPending = obj.type == "answer"

            # print("**********************")
            # print("readyForOffer %s" % readyForOffer)
            # print("ignoreOffer %s" % ignoreOffer)
            # print("offerCollision %s" % offerCollision)
            # print("isSettingRemoteAnswerPending %s" % isSettingRemoteAnswerPending)
            # print("**********************")

            print("Setting remote description")
            # print(obj)
            await pc.setRemoteDescription(obj)
            print("Remote description set")

            # SRD rolls back as needed
            await recorder.start()
            print("Recorder started")

            # isSettingRemoteAnswerPending = False

            # if obj.type == "offer":
            # print("2")
            # print("**********************")
            # print("readyForOffer %s" % readyForOffer)
            # print("ignoreOffer %s" % ignoreOffer)
            # print("offerCollision %s" % offerCollision)
            # print("isSettingRemoteAnswerPending %s" % isSettingRemoteAnswerPending)
            # print("**********************")

            # print("icegatheringstate1: %s" % pc.iceGatheringState)
            if obj.type == "offer":
                print("========= Sending answer")
                # send answer
                print("Send answer")
                add_tracks()
                # print("icegatheringstate2: %s" % pc.iceGatheringState)
                answer = await pc.createAnswer()
                # print("icegatheringstate3: %s" % pc.iceGatheringState)
                await pc.setLocalDescription(answer)
                # print("icegatheringstate4: %s" % pc.iceGatheringState)

                print("going to send answer")
                await signaling.send(answer, recipientClientId=remoteClientId)
                # await asyncio.sleep(10)  # yield control to the event loop

        elif isinstance(obj, RTCIceCandidate):
            print("========= Adding ice candidate")
            await pc.addIceCandidate(obj)

            print("ConnectionState %s" % pc.connectionState)
            # print("SignalingState %s" % pc.signalingState)
            # print("IceConnectionState %s" % pc.iceConnectionState)
            # print("IceGatheringState %s" % pc.iceGatheringState)

            # # do we have enough candidates yet to start the stream?
            # if pc.iceGatheringState == "complete":
            #     # send the ice candidate back to the other party
            #     # await signaling.send(obj)
            #     # send offer
            #     # makingOffer = True
            #     add_tracks()
            #     await pc.setLocalDescription(await pc.createOffer())
            #     await signaling.send(pc.localDescription, senderClientId)
            # await asyncio.sleep(2)

        elif obj is BYE:
            print("========= Exiting")
            break

        # await asyncio.sleep(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Video stream from the command line")
    parser.add_argument("role", choices=["offer", "answer"])
    parser.add_argument("--remoteClientId", help="Remote client ID to connect to."),
    parser.add_argument("--play-from", help="Read the media from a file and sent it."),
    parser.add_argument("--record-to", help="Write received media to a file."),
    parser.add_argument("--verbose", "-v", action="count")
    add_signaling_arguments(parser)
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    # get the endpoints and configuration, update args.signaling_host
    endpoints, configuration = getRTCPeerConfiguration()

    # Prepare a GetCallerIdentity request.
    service = "kinesisvideo"
    region = "eu-west-2"

    url = getSignedURL(
        "GET",
        service,
        region,
        endpoints["WSS"].replace("wss://", ""),
        endpoints["WSS"],
    )
    args.signaling_host = url
    args.signaling_port = 443
    args.signaling = "websocket"

    print(endpoints)

    # create signaling and peer connection
    print("Creating signaling and peer connection")
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
                remoteClientId=args.remoteClientId,
            )
        )
    except KeyboardInterrupt:
        pass
    finally:
        # cleanup
        loop.run_until_complete(recorder.stop())
        loop.run_until_complete(signaling.close())
        loop.run_until_complete(pc.close())

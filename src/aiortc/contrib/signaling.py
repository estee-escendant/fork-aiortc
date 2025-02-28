import asyncio
import json
import logging
import os
import sys
import websockets
import base64

from aiortc import RTCIceCandidate, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp

logger = logging.getLogger(__name__)
BYE = object()

logging.basicConfig(level=logging.INFO)


def object_from_string(message_str):
    message = json.loads(message_str)
    print("message received xxx:" + message_str)
    payload = base64.b64decode(message["messagePayload"])
    senderClientId = message["senderClientId"]
    encrypted_message = json.loads(payload)
    if "type" in encrypted_message and encrypted_message["type"] in ["answer", "offer"]:
        return RTCSessionDescription(**encrypted_message), senderClientId
    elif message["messageType"] == "ICE_CANDIDATE" and encrypted_message["candidate"]:
        candidate = candidate_from_sdp(encrypted_message["candidate"].split(":", 1)[1])
        candidate.sdpMid = encrypted_message["sdpMid"]
        candidate.sdpMLineIndex = encrypted_message["sdpMLineIndex"]
        return candidate, senderClientId
    elif message["messageType"] == "BYE":
        return BYE, senderClientId


def object_to_string(obj, senderClientId=None, recipientClientId=None):
    if isinstance(obj, RTCSessionDescription) and obj.type == "offer":
        payload = {
            "sdp": obj.sdp,
            "type": obj.type,
        }
        message = {
            "messagePayload": base64.b64encode(
                json.dumps(payload).encode("utf8")
            ).decode("utf8"),
            "action": "SDP_OFFER",
            "recipientClientId": recipientClientId,
            "senderClientId": senderClientId,
        }
    elif isinstance(obj, RTCSessionDescription) and obj.type == "answer":
        payload = {
            "sdp": obj.sdp,
            "type": obj.type,
        }
        message = {
            "messagePayload": base64.b64encode(
                json.dumps(payload).encode("utf8")
            ).decode("utf8"),
            "action": "SDP_ANSWER",
            "recipientClientId": recipientClientId,
            "senderClientId": senderClientId,
        }
    elif isinstance(obj, RTCIceCandidate):
        payload = {
            "candidate": candidate_to_sdp(obj),
            "sdpMid": obj.sdpMid,
            "sdpMLineIndex": obj.sdpMLineIndex,
        }
        message = {
            "messagePayload": base64.b64encode(
                json.dumps(payload).encode("utf8")
            ).decode("utf8"),
            "action": "ICE_CANDIDATE",
            "recipientClientId": recipientClientId,
            "senderClientId": senderClientId,
        }
    else:
        assert obj is BYE or obj is None
        message = {"action": "BYE"}
    print("message sent xxx:" + json.dumps(message, sort_keys=True))
    return json.dumps(message.dict(exclude_none=True), sort_keys=True)


class CopyAndPasteSignaling:
    def __init__(self):
        self._read_pipe = sys.stdin
        self._read_transport = None
        self._reader = None
        self._write_pipe = sys.stdout

    async def connect(self):
        loop = asyncio.get_event_loop()
        self._reader = asyncio.StreamReader(loop=loop)
        self._read_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(self._reader), self._read_pipe
        )
        print("connected to signaling server via copy-and-paste")

    async def close(self):
        if self._reader is not None:
            await self.send(BYE)
            self._read_transport.close()
            self._reader = None

    async def receive(self):
        print("-- Please enter a message from remote party --")
        data = await self._reader.readline()
        print()
        return object_from_string(data.decode(self._read_pipe.encoding))

    async def send(self, descr):
        print("-- Please send this message to the remote party --")
        self._write_pipe.write(object_to_string(descr) + "\n")
        self._write_pipe.flush()
        print()


class TcpSocketSignaling:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._server = None
        self._reader = None
        self._writer = None

    async def connect(self):
        pass

    async def _connect(self, server):
        if self._writer is not None:
            return

        if server:
            connected = asyncio.Event()

            def client_connected(reader, writer):
                self._reader = reader
                self._writer = writer
                connected.set()

            self._server = await asyncio.start_server(
                client_connected, host=self._host, port=self._port
            )
            await connected.wait()
        else:
            self._reader, self._writer = await asyncio.open_connection(
                host=self._host, port=self._port
            )
        print("connected to signaling server via tcp-socket")

    async def close(self):
        if self._writer is not None:
            await self.send(BYE)
            self._writer.close()
            self._reader = None
            self._writer = None
        if self._server is not None:
            self._server.close()
            self._server = None

    async def receive(self):
        await self._connect(False)
        try:
            data = await self._reader.readuntil()
        except asyncio.IncompleteReadError:
            return
        return object_from_string(data.decode("utf8"))

    async def send(self, descr):
        await self._connect(True)
        data = object_to_string(descr).encode("utf8")
        self._writer.write(data + b"\n")


class UnixSocketSignaling:
    def __init__(self, path):
        self._path = path
        self._server = None
        self._reader = None
        self._writer = None

    async def connect(self):
        pass

    async def _connect(self, server):
        if self._writer is not None:
            return

        if server:
            connected = asyncio.Event()

            def client_connected(reader, writer):
                self._reader = reader
                self._writer = writer
                connected.set()

            self._server = await asyncio.start_unix_server(
                client_connected, path=self._path
            )
            await connected.wait()
        else:
            self._reader, self._writer = await asyncio.open_unix_connection(self._path)
        print("connected to signaling server via unix-socket")

    async def close(self):
        if self._writer is not None:
            await self.send(BYE)
            self._writer.close()
            self._reader = None
            self._writer = None
        if self._server is not None:
            self._server.close()
            self._server = None
            os.unlink(self._path)

    async def receive(self):
        await self._connect(False)
        try:
            data = await self._reader.readuntil()
        except asyncio.IncompleteReadError:
            return
        return object_from_string(data.decode("utf8"))

    async def send(self, descr):
        await self._connect(True)
        data = object_to_string(descr).encode("utf8")
        self._writer.write(data + b"\n")


class WebsocketSignaling:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._websocket = None

    async def connect(self):
        # websocket.enableTrace(True)

        self._websocket = await websockets.connect(str(self._host))
        # self._websocket = await websocket.create_connection(
        #     url=str(self._host),
        #     # header=headers,
        # )

    async def close(self):
        if self._websocket is not None and self._websocket.open is True:
            await self.send(None)
            await self._websocket.close()

    async def receive(self):
        try:
            data = await self._websocket.recv()
            while data is None or data == "" or "Endpoint request timed out" in data:
                await asyncio.sleep(0.1)
                data = await self._websocket.recv()
        except asyncio.IncompleteReadError:
            print("got no data")
            return
        ret, senderClientId = object_from_string(data)
        if ret == None:
            print("remote host says good bye!")

        return ret, senderClientId

    async def send(self, descr, senderClientId=None, recipientClientId=None):
        print("sending data")
        if descr is not None:
            print(descr)
            data = object_to_string(descr, senderClientId, recipientClientId)
            await self._websocket.send(data + "\n")


def add_signaling_arguments(parser):
    """
    Add signaling method arguments to an argparse.ArgumentParser.
    """
    parser.add_argument(
        "--signaling",
        "-s",
        choices=["copy-and-paste", "tcp-socket", "unix-socket", "websocket"],
    )
    parser.add_argument(
        "--signaling-host",
        default="127.0.0.1",
        help="Signaling host (tcp-socket and websocket only)",
    )
    parser.add_argument(
        "--signaling-port", default=443, help="Signaling port (tcp-socket only)"
    )
    parser.add_argument(
        "--signaling-path",
        default="aiortc.socket",
        help="Signaling socket path (unix-socket only)",
    )


def create_signaling(args):
    """
    Create a signaling method based on command-line arguments.
    """
    if args.signaling == "tcp-socket":
        return TcpSocketSignaling(args.signaling_host, args.signaling_port)
    elif args.signaling == "websocket":
        return WebsocketSignaling(args.signaling_host, args.signaling_port)
    elif args.signaling == "unix-socket":
        return UnixSocketSignaling(args.signaling_path)
    else:
        return CopyAndPasteSignaling()

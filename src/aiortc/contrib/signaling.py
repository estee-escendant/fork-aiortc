import asyncio
import json
import logging
import os
import sys
import websocket

from aiortc import RTCIceCandidate, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp

import base64, datetime, hashlib, hmac, urllib.parse

logger = logging.getLogger(__name__)
BYE = object()

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
    endpoint = endpoint

    # Create a date for headers and the credential string. 
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")

    # For date stamp, the date without time is used in credential scope.
    datestamp = t.strftime("%Y%m%d") 

    # -----------------------------------------------------------------------
    # Step 3. Create the canonical URI and canonical headers for the request.
    # -----------------------------------------------------------------------
    canonical_uri = "/start-network-analyzer-stream"
    configuration_name = "My_Network_Analyzer_Config"

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
        canonical_querystring  = "X-Amz-Algorithm=" + algorithm

        canonical_querystring += "&X-Amz-Credential=" + \ 
        urllib.parse.quote(access_key + "/" + credential_scope, safe="-_.~")

        canonical_querystring += "&X-Amz-Date=" + amz_date
        canonical_querystring += "&X-Amz-Expires=300"

        if access_key.startswith("ASIA"):
            # percent encode the token and double encode "="
            canonical_querystring += "&X-Amz-Security-Token=" + \ 
            urllib.parse.quote(token, safe="-_.~").replace("=", "%253D")
        
        canonical_querystring += "&X-Amz-SignedHeaders=" + signed_headers
        canonical_querystring += "&configuration-name=" + configuration_name

    # ----------------------------------------------------------------------
    # Step 6. Create a hash of the payload.
    # ----------------------------------------------------------------------
    payload_hash = hashlib.sha256(("").encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Step 7. Combine the elements, which includes the query string, the
    # headers, and the payload hash, to form the canonical request.
    # ------------------------------------------------------------------
    canonical_request = method + "\n" + canonical_uri + "\n" + canonical_querystring \ 
    + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash

    # ----------------------------------------------------------------------
    # Step 8. Create the metadata string to store the information required to
    # calculate the signature in the following step.
    # ----------------------------------------------------------------------
    string_to_sign = algorithm + "\n" + amz_date + "\n" + \ 
    credential_scope + "\n" + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------------
    # Step 9. Calculate the signature by using a signing key that"s obtained
    # from your secret key. 
    # ----------------------------------------------------------------------
    # Create the signing key from your  secret key.
    signing_key = getSignatureKey(secret_key, datestamp, region, service)
        
    # Sign the string_to_sign using the signing key.
    signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

    # ----------------------------------------------------------------------
    # Step 10. Create the request URL using the calculated signature and by
    # combining it with the canonical URI and the query string.
    # ----------------------------------------------------------------------
    canonical_querystring += "&X-Amz-Signature=" + signature
        
    request_url = endpoint + canonical_uri + "?" + canonical_querystring
    return request_url


def object_from_string(message_str):
    message = json.loads(message_str)
    if message["type"] in ["answer", "offer"]:
        return RTCSessionDescription(**message)
    elif message["type"] == "candidate" and message["candidate"]:
        candidate = candidate_from_sdp(message["candidate"].split(":", 1)[1])
        candidate.sdpMid = message["id"]
        candidate.sdpMLineIndex = message["label"]
        return candidate
    elif message["type"] == "bye":
        return BYE


def object_to_string(obj):
    if isinstance(obj, RTCSessionDescription):
        message = {"sdp": obj.sdp, "type": obj.type}
    elif isinstance(obj, RTCIceCandidate):
        message = {
            "candidate": "candidate:" + candidate_to_sdp(obj),
            "id": obj.sdpMid,
            "label": obj.sdpMLineIndex,
            "type": "candidate",
        }
    else:
        assert obj is BYE
        message = {"type": "bye"}
    return json.dumps(message, sort_keys=True)


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
        # Prepare a GetCallerIdentity request.
        service = "kinesis-video-signaling"
        region = "eu-west-2"
        url = str(self._host)
        headers = {"Content-Type": "application/x-amz-json-1.1"}

        url = getSignedURL("GET", service, region, "127.0.0.1", url)
        # headers = {
        #     "Accept-Encoding": "gzip, deflate, br",
        #     "Accept-Language": "en-US,en;q=0.9",
        #     "Cache-Control": "no-cache",
        #     "Connection": "Upgrade",
        #     "Host": "127.0.0.1",
        #     "Pragma": "no-cache",
        #     "Upgrade": "websocket",
        #     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36",
        #     "X-Amz-Date": signed_headers["X-Amz-Date"],
        #     "X-Amz-Security-Token": signed_headers["X-Amz-Security-Token"],
        #     "Authorization": signed_headers["Authorization"],
        # }

        print("trying to connect to signaling server via websocket")
        websocket.enableTrace(True)
        print("+++++++++++++++++++++++++++++++")
        print(url)
        print("+++++++++++++++++++++++++++++++")

        self._websocket = await websocket.create_connection(
            url=str(self._host),
            header=headers,
        )
        print("connected to signaling server via websocket")

    async def close(self):
        if self._websocket is not None and self._websocket.open is True:
            await self.send(None)
            await self._websocket.close()

    async def receive(self):
        try:
            data = await self._websocket.recv()
        except asyncio.IncompleteReadError:
            return
        ret = object_from_string(data)
        if ret == None:
            print("remote host says good bye!")

        return ret

    async def send(self, descr):
        data = object_to_string(descr)
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
        "--signaling-port", default=1234, help="Signaling port (tcp-socket only)"
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

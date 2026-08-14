"""
Minimal VLESS protocol implementation (proxy protocol only — no xray-core binary).

Wire format of the first client->server message (see project X / VLESS spec):
  1 byte   version
  16 bytes UUID
  1 byte   addon length (M)
  M bytes  addons (ignored)
  1 byte   command (1 = TCP)
  2 bytes  destination port (big endian)
  1 byte   address type (1=IPv4, 2=domain, 3=IPv6)
  N bytes  address
  ...      remaining bytes = first chunk of payload

Server replies with: 1 byte version + 1 byte addon length (0), then relays
raw bytes in both directions until either side closes the socket.
"""
import asyncio
import struct
import uuid as uuid_lib


class VlessHeaderError(ValueError):
    pass


def parse_vless_header(data: bytes) -> dict:
    if len(data) < 1 + 16 + 1:
        raise VlessHeaderError("truncated header (version/uuid/addonlen)")

    pos = 0
    version = data[pos]
    pos += 1

    client_uuid = uuid_lib.UUID(bytes=data[pos:pos + 16])
    pos += 16

    addon_len = data[pos]
    pos += 1
    pos += addon_len  # addons are not used by this minimal server

    if len(data) < pos + 1 + 2 + 1:
        raise VlessHeaderError("truncated header (cmd/port/atype)")

    cmd = data[pos]
    pos += 1

    port = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2

    atype = data[pos]
    pos += 1

    if atype == 1:  # IPv4
        if len(data) < pos + 4:
            raise VlessHeaderError("truncated IPv4 address")
        addr = ".".join(str(b) for b in data[pos:pos + 4])
        pos += 4
    elif atype == 2:  # domain name
        if len(data) < pos + 1:
            raise VlessHeaderError("truncated domain length")
        dlen = data[pos]
        pos += 1
        if len(data) < pos + dlen:
            raise VlessHeaderError("truncated domain")
        addr = data[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif atype == 3:  # IPv6
        if len(data) < pos + 16:
            raise VlessHeaderError("truncated IPv6 address")
        chunks = [data[pos + i:pos + i + 2] for i in range(0, 16, 2)]
        addr = ":".join(c.hex() for c in chunks)
        pos += 16
    else:
        raise VlessHeaderError(f"unknown address type {atype}")

    return {
        "version": version,
        "uuid": str(client_uuid),
        "cmd": cmd,
        "addr": addr,
        "port": port,
        "payload": data[pos:],
    }


async def relay(websocket, header: dict, on_traffic):
    """
    Opens a TCP connection to the requested destination and relays bytes
    between it and the WebSocket connection until either side closes.
    on_traffic(up_bytes, down_bytes) is called for accounting.
    """
    reader, writer = await asyncio.open_connection(header["addr"], header["port"])

    # VLESS response header: version + addon length (0)
    await websocket.send_bytes(bytes([header["version"], 0]))

    if header["payload"]:
        writer.write(header["payload"])
        await writer.drain()
        on_traffic(len(header["payload"]), 0)

    async def ws_to_remote():
        try:
            while True:
                data = await websocket.receive_bytes()
                if not data:
                    continue
                writer.write(data)
                await writer.drain()
                on_traffic(len(data), 0)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def remote_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send_bytes(data)
                on_traffic(0, len(data))
        except Exception:
            pass

    await asyncio.gather(ws_to_remote(), remote_to_ws(), return_exceptions=True)

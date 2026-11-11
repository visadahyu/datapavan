#!/usr/bin/env python3
# A SOCKS5 proxy for W6's end-to-end check, standing in for the user's circumvention tool on this
# computer (RFC 1928, with RFC 1929's username and password). It carries CONNECT and UDP ASSOCIATE and
# refuses BIND. Names are resolved from --map only, so that a test never depends on real DNS, and an
# address can be mapped too (the emulator's 10.0.2.2 to this computer's loopback). Each request is
# printed as one line, "connect NAME-OR-ADDRESS PORT" or "associate", with "refused" when it was; no
# payload is printed or kept. The emulator reaches it at 10.0.2.2.
#
#   python3 -I scripts/watch-lab/socks5.py PORT [--user USER --password PASSWORD] [--map NAME=ADDRESS ...]
import argparse
import asyncio
import ipaddress
import socket
import struct
import sys


def reply(code, address="0.0.0.0", port=0):
    ip = ipaddress.ip_address(address)
    kind = 1 if ip.version == 4 else 4
    return bytes([5, code, 0, kind]) + ip.packed + struct.pack("!H", port)


def note(line):
    print(line, flush=True)


class Proxy:
    def __init__(self, args):
        self.user = args.user.encode() if args.user else None
        self.password = args.password.encode() if args.password else None
        self.map = dict(entry.split("=", 1) for entry in args.map)

    def resolve(self, host):
        return self.map.get(host, host if not host[0].isalpha() else None)

    async def address(self, reader, kind):
        if kind == 1:
            return socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        if kind == 4:
            return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        if kind == 3:
            length = (await reader.readexactly(1))[0]
            return (await reader.readexactly(length)).decode("ascii", "replace")
        raise ValueError("address type")

    async def serve(self, reader, writer):
        try:
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            wanted = 2 if self.user else 0
            if version != 5 or wanted not in methods:
                writer.write(bytes([5, 0xFF]))
                return
            writer.write(bytes([5, wanted]))
            if self.user:
                _, length = await reader.readexactly(2)
                user = await reader.readexactly(length)
                length = (await reader.readexactly(1))[0]
                password = await reader.readexactly(length)
                right = user == self.user and password == self.password
                writer.write(bytes([1, 0 if right else 1]))
                if not right:
                    note("password refused")
                    return
            _, command, _, kind = await reader.readexactly(4)
            host = await self.address(reader, kind)
            (port,) = struct.unpack("!H", await reader.readexactly(2))
            if command == 1:
                await self.connect(reader, writer, host, port)
            elif command == 3:
                await self.associate(reader, writer)
            else:
                note("bind refused")
                writer.write(reply(7))
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            try:
                await writer.drain()
                writer.close()
            except ConnectionError:
                pass

    async def connect(self, reader, writer, host, port):
        target = self.resolve(host)
        if target is None:
            note(f"connect {host} {port} refused")
            writer.write(reply(4))
            return
        try:
            up_reader, up_writer = await asyncio.open_connection(target, port)
        except OSError:
            note(f"connect {host} {port} refused")
            writer.write(reply(5))
            return
        note(f"connect {host} {port}")
        bound = up_writer.get_extra_info("sockname")
        writer.write(reply(0, bound[0], bound[1]))
        await writer.drain()

        async def pipe(source, sink):
            try:
                while data := await source.read(65536):
                    sink.write(data)
                    await sink.drain()
            except ConnectionError:
                pass
            finally:
                try:
                    sink.write_eof()
                except (OSError, RuntimeError):
                    pass

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        up_writer.close()

    async def associate(self, reader, writer):
        loop = asyncio.get_running_loop()
        proxy = self
        client = None

        class Relay(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, sender):
                nonlocal client
                if client is None or sender == client:
                    client = sender
                    parsed = proxy.parse(data)
                    if parsed:
                        target, payload = parsed
                        self.transport.sendto(payload, target)
                else:
                    ip = ipaddress.ip_address(sender[0])
                    kind = 1 if ip.version == 4 else 4
                    header = bytes([0, 0, 0, kind]) + ip.packed + struct.pack("!H", sender[1])
                    self.transport.sendto(header + data, client)

        transport, _ = await loop.create_datagram_endpoint(Relay, local_addr=("0.0.0.0", 0))
        note("associate")
        # Unspecified, as many tools answer: the client sends to the proxy's own address.
        writer.write(reply(0, "0.0.0.0", transport.get_extra_info("sockname")[1]))
        await writer.drain()
        try:
            while await reader.read(1):
                pass
        finally:
            transport.close()

    def parse(self, data):
        if len(data) < 4 or data[:3] != b"\0\0\0":
            return None
        kind = data[3]
        if kind == 1:
            host, rest = socket.inet_ntop(socket.AF_INET, data[4:8]), data[8:]
        elif kind == 4:
            host, rest = socket.inet_ntop(socket.AF_INET6, data[4:20]), data[20:]
        elif kind == 3:
            host, rest = data[5:5 + data[4]].decode("ascii", "replace"), data[5 + data[4]:]
        else:
            return None
        target = self.resolve(host)
        if target is None or len(rest) < 2:
            return None
        return (target, struct.unpack("!H", rest[:2])[0]), rest[2:]


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--user")
    parser.add_argument("--password")
    parser.add_argument("--map", action="append", default=[])
    args = parser.parse_args()
    proxy = Proxy(args)
    server = await asyncio.start_server(proxy.serve, "0.0.0.0", args.port)
    note(f"listening {args.port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

#!/usr/bin/env python3
"""
simple_proxy.py -- 軽量なHTTP/HTTPSフォワードプロキシ（学習・自分用）
注意: 公開する場合は認証・IP制限・TLS等を必ず設定してください。
"""

import asyncio
import argparse
import base64
import logging
from typing import Optional
import aiohttp
import urllib.parse

# 設定
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8888
CONNECT_TIMEOUT = 15
RELAY_BUFFER = 65536

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("proxy")


def parse_args():
    p = argparse.ArgumentParser(description="Simple HTTP/HTTPS forward proxy")
    p.add_argument("--host", default=LISTEN_HOST)
    p.add_argument("--port", type=int, default=LISTEN_PORT)
    p.add_argument("--auth", default=None, help="Basic auth as user:pass (optional)")
    p.add_argument("--log-level", default="INFO")
    return p.parse_args()


def check_basic_auth(header_value: Optional[str], expected_userpass: Optional[str]) -> bool:
    if expected_userpass is None:
        return True
    if not header_value:
        return False
    if not header_value.lower().startswith("basic "):
        return False
    try:
        b64 = header_value.split(" ", 1)[1].strip()
        decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
        return decoded == expected_userpass
    except Exception:
        return False


async def relay_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(RELAY_BUFFER)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.debug("relay error: %s", e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, auth_userpass: Optional[str]):
    peer = client_writer.get_extra_info("peername")
    logger.info("conn from %s", peer)

    # Read request line + headers
    try:
        # Read first line
        line = await asyncio.wait_for(client_reader.readline(), timeout=CONNECT_TIMEOUT)
        if not line:
            client_writer.close()
            return
        request_line = line.decode("iso-8859-1").rstrip("\r\n")
        method, target, version = request_line.split(" ", 2)
    except Exception as e:
        logger.warning("malformed request from %s: %s", peer, e)
        client_writer.close()
        return

    # Read headers
    headers = {}
    while True:
        hline = await client_reader.readline()
        if not hline:
            client_writer.close()
            return
        s = hline.decode("iso-8859-1")
        if s in ("\r\n", "\n"):
            break
        if ":" in s:
            k, v = s.split(":", 1)
            headers[k.strip()] = v.strip()

    # Basic auth check (Proxy-Authorization)
    if not check_basic_auth(headers.get("Proxy-Authorization"), auth_userpass):
        logger.info("auth failed from %s", peer)
        resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Length: 0\r\n\r\n"
        client_writer.write(resp.encode("iso-8859-1"))
        await client_writer.drain()
        client_writer.close()
        return

    logger.info("request %s %s from %s", method, target, peer)

    if method.upper() == "CONNECT":
        # target: host:port
        hostport = target
        try:
            host, port = hostport.split(":")
            port = int(port)
        except Exception:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            return

        try:
            # connect to target
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
            )
        except Exception as e:
            logger.warning("CONNECT to %s failed: %s", hostport, e)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            return

        # Send 200 Connection Established
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # Relay both ways
        t1 = asyncio.create_task(relay_stream(client_reader, remote_writer))
        t2 = asyncio.create_task(relay_stream(remote_reader, client_writer))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        # close writers
        try:
            remote_writer.close()
            await remote_writer.wait_closed()
        except Exception:
            pass
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass
        logger.info("CONNECT closed %s", peer)
        return

    # Non-CONNECT: forward HTTP request (absolute-form or origin-form)
    # Use aiohttp client to fetch target. If target is absolute URI, parse host; otherwise use Host header.
    url = target
    if not urllib.parse.urlparse(url).scheme:
        # origin-form: build URL from Host header
        host_header = headers.get("Host")
        if not host_header:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            return
        scheme = "http"
        url = f"{scheme}://{host_header}{target}"

    # Remove hop-by-hop headers
    hop_by_hop = [
        "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
        "Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade"
    ]
    forward_headers = {k: v for k, v in headers.items() if k not in hop_by_hop}
    # Replace Proxy-Authorization (do not forward)
    forward_headers.pop("Proxy-Authorization", None)

    # Read body if Content-Length present
    body = b""
    cl = headers.get("Content-Length")
    if cl and cl.isdigit():
        n = int(cl)
        if n > 0:
            body = await client_reader.readexactly(n)

    # Use aiohttp to forward
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(method, url, headers=forward_headers, data=body, allow_redirects=False) as resp:
                # write status line
                status_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                client_writer.write(status_line.encode("iso-8859-1"))
                # forward response headers
                excluded = set(hop_by_hop)
                for k, v in resp.headers.items():
                    if k in excluded:
                        continue
                    header_line = f"{k}: {v}\r\n"
                    client_writer.write(header_line.encode("iso-8859-1"))
                client_writer.write(b"\r\n")
                await client_writer.drain()

                # stream response body
                async for chunk in resp.content.iter_chunked(RELAY_BUFFER):
                    if not chunk:
                        break
                    client_writer.write(chunk)
                    await client_writer.drain()
    except Exception as e:
        logger.warning("upstream request failed: %s", e)
        try:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
        except Exception:
            pass
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass
        logger.info("request finished %s %s", method, target)


async def main_async(listen_host: str, listen_port: int, auth_userpass: Optional[str]):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, auth_userpass),
        listen_host, listen_port
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("Proxy listening on %s", addrs)
    async with server:
        await server.serve_forever()


def main():
    args = parse_args()
    logger.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    auth = None
    if args.auth:
        if ":" not in args.auth:
            logger.error("auth must be user:pass")
            return
        auth = args.auth
        logger.info("Basic auth enabled for user=%s", args.auth.split(":",1)[0])
    try:
        asyncio.run(main_async(args.host, args.port, auth))
    except KeyboardInterrupt:
        logger.info("shutting down")


if __name__ == "__main__":
    main()

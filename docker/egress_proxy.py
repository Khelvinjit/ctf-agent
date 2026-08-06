"""A tiny HTTP(S) CONNECT proxy restricted to explicit public CTF targets."""

from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import socketserver
from http import HTTPStatus
from urllib.parse import urlsplit


def configured_targets() -> set[tuple[str, int]]:
    raw = json.loads(os.environ["EGRESS_TARGETS"])
    targets: set[tuple[str, int]] = set()
    for value in raw:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"invalid egress target: {value}")
        targets.add(
            (
                parsed.hostname.rstrip(".").lower(),
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
        )
    return targets


ALLOWED_TARGETS = configured_targets()
MAX_REQUEST_BODY_BYTES = 1_048_576


def permitted_address(host: str, port: int) -> tuple[str, int]:
    host = host.rstrip(".").lower()
    if (host, port) not in ALLOWED_TARGETS:
        raise PermissionError("host and port are not an approved challenge target")
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise PermissionError("target did not resolve")
    for family, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise PermissionError("target resolved to a non-public address")
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise PermissionError("target resolved to an unsupported address")
    # Connect to the resolved address rather than resolving a second time.
    return addresses[0][4][0], port


def parse_authority(value: str, default_port: int) -> tuple[str, int]:
    parsed = urlsplit("//" + value)
    if not parsed.hostname:
        raise ValueError("missing target host")
    return parsed.hostname, parsed.port or default_port


class EgressHandler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self) -> None:
        try:
            request = self.rfile.readline(8192).decode("iso-8859-1").strip()
            method, target, version = request.split(" ", 2)
            headers: list[str] = []
            while True:
                line = self.rfile.readline(8192).decode("iso-8859-1")
                if line in {"\r\n", "\n", ""}:
                    break
                headers.append(line.rstrip("\r\n"))
            if method.upper() == "CONNECT":
                host, port = parse_authority(target, 443)
                upstream = socket.create_connection(
                    permitted_address(host, port), timeout=self.timeout
                )
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self._relay(upstream)
                return
            url = urlsplit(target)
            if url.scheme not in {"http", "https"} or not url.hostname:
                raise PermissionError(
                    "proxy requests must contain an absolute HTTP(S) URL"
                )
            host, port = (
                url.hostname,
                url.port or (443 if url.scheme == "https" else 80),
            )
            if url.scheme != "http":
                raise PermissionError("HTTPS requests must use CONNECT")
            upstream = socket.create_connection(
                permitted_address(host, port), timeout=self.timeout
            )
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            safe_headers = [
                line
                for line in headers
                if not line.lower().startswith(
                    ("proxy-authorization:", "proxy-connection:")
                )
            ]
            upstream.sendall(
                (
                    f"{method} {path} {version}\r\n"
                    + "\r\n".join(safe_headers)
                    + "\r\n\r\n"
                ).encode("iso-8859-1")
            )
            self._forward_request_body(upstream, headers)
            self._relay(upstream)
        except (OSError, PermissionError, ValueError) as exc:
            status = (
                HTTPStatus.FORBIDDEN
                if isinstance(exc, PermissionError)
                else HTTPStatus.BAD_GATEWAY
            )
            self.wfile.write(
                f"HTTP/1.1 {status.value} {status.phrase}\r\nContent-Length: 0\r\n\r\n".encode()
            )

    def _forward_request_body(
        self, upstream: socket.socket, headers: list[str]
    ) -> None:
        """Forward a request body already buffered by ``rfile`` before relaying.

        Reading HTTP headers via ``StreamRequestHandler.rfile`` can prefetch the
        accompanying POST body.  A raw-socket relay alone then never sees that
        buffered data, leaving an upstream service waiting for Content-Length
        bytes and the client waiting for its response.
        """
        values: dict[str, str] = {}
        for line in headers:
            name, separator, value = line.partition(":")
            if separator:
                values[name.strip().lower()] = value.strip()
        if "content-length" in values:
            try:
                length = int(values["content-length"])
            except ValueError as exc:
                raise ValueError("invalid Content-Length") from exc
            if length < 0 or length > MAX_REQUEST_BODY_BYTES:
                raise PermissionError("request body exceeds proxy limit")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("incomplete request body")
            if body:
                upstream.sendall(body)
            return
        if values.get("transfer-encoding", "").lower() == "chunked":
            self._forward_chunked_body(upstream)

    def _forward_chunked_body(self, upstream: socket.socket) -> None:
        """Relay a bounded chunked body, including its framing and trailers."""
        forwarded = 0
        while True:
            size_line = self.rfile.readline(8192)
            if not size_line:
                raise ValueError("incomplete chunked request body")
            upstream.sendall(size_line)
            try:
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise ValueError("invalid chunk size") from exc
            if size < 0 or forwarded + size > MAX_REQUEST_BODY_BYTES:
                raise PermissionError("request body exceeds proxy limit")
            if size:
                chunk = self.rfile.read(size + 2)
                if len(chunk) != size + 2 or not chunk.endswith(b"\r\n"):
                    raise ValueError("incomplete chunked request body")
                upstream.sendall(chunk)
                forwarded += size
                continue
            while True:
                trailer = self.rfile.readline(8192)
                if not trailer:
                    raise ValueError("incomplete chunked request trailers")
                upstream.sendall(trailer)
                if trailer in {b"\r\n", b"\n"}:
                    return

    def _relay(self, upstream: socket.socket) -> None:
        with upstream:
            sockets = [self.connection, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], self.timeout)
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (
                        upstream if source is self.connection else self.connection
                    ).sendall(data)


class ThreadedProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with ThreadedProxy(("0.0.0.0", 3128), EgressHandler) as server:
        server.serve_forever()

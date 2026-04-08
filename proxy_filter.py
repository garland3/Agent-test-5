#!/usr/bin/env python3
"""
Simple HTTP/HTTPS filtering proxy with domain whitelist.

Used by the bwrap network demo to show selective domain access.
Supports HTTP CONNECT (for HTTPS tunneling) and plain HTTP proxying.
Whitelisted domains are allowed through; everything else gets a 403.

Usage:
    python3 proxy_filter.py --port 8888 --allow pypi.org --allow github.com

The proxy listens on 127.0.0.1 only. Agents inside bwrap connect to it
via --share-net and http_proxy/https_proxy env vars.
"""

import argparse
import http.server
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time


class FilteringProxy(http.server.BaseHTTPRequestHandler):
    """HTTP proxy that enforces a domain whitelist."""

    allowed_domains: list[str] = []
    access_log: list[dict] = []
    log_lock = threading.Lock()

    def log_message(self, format, *args):
        """Suppress default logging to stderr."""
        pass

    def _domain_allowed(self, hostname: str) -> bool:
        """Check if hostname matches any allowed domain pattern."""
        hostname = hostname.lower().strip(".")
        for domain in self.allowed_domains:
            domain = domain.lower().strip(".")
            if hostname == domain or hostname.endswith("." + domain):
                return True
        return False

    def _log_access(self, hostname: str, allowed: bool, method: str):
        with self.log_lock:
            entry = {
                "time": time.strftime("%H:%M:%S"),
                "method": method,
                "host": hostname,
                "allowed": allowed,
            }
            self.access_log.append(entry)
            status = "ALLOW" if allowed else "DENY"
            print(f"  [{status}] {method} {hostname}")

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling."""
        host_port = self.path
        hostname = host_port.split(":")[0]

        if not self._domain_allowed(hostname):
            self._log_access(hostname, False, "CONNECT")
            self.send_error(403, f"Domain not in whitelist: {hostname}")
            return

        self._log_access(hostname, True, "CONNECT")

        # Parse host:port
        parts = host_port.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {host_port}: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        # Tunnel data between client and remote
        self._tunnel(self.connection, remote)
        remote.close()

    def _tunnel(self, client_sock, remote_sock):
        """Bidirectional data relay."""
        sockets = [client_sock, remote_sock]
        timeout = 30
        while True:
            readable, _, errors = select.select(sockets, [], sockets, timeout)
            if errors:
                break
            if not readable:
                break
            for sock in readable:
                data = sock.recv(8192)
                if not data:
                    return
                other = remote_sock if sock is client_sock else client_sock
                try:
                    other.sendall(data)
                except Exception:
                    return

    def do_GET(self):
        self._proxy_request()

    def do_POST(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()

    def _proxy_request(self):
        """Handle plain HTTP proxy requests."""
        from urllib.parse import urlparse

        parsed = urlparse(self.path)
        hostname = parsed.hostname or ""

        if not self._domain_allowed(hostname):
            self._log_access(hostname, False, self.command)
            self.send_error(403, f"Domain not in whitelist: {hostname}")
            return

        self._log_access(hostname, True, self.command)

        port = parsed.port or 80
        try:
            remote = socket.create_connection((hostname, port), timeout=10)
        except Exception as e:
            self.send_error(502, f"Cannot connect: {e}")
            return

        # Forward the request
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query

        request_line = f"{self.command} {path} HTTP/1.1\r\n"
        headers = f"Host: {hostname}\r\n"
        for key, val in self.headers.items():
            if key.lower() not in ("proxy-connection", "proxy-authorization"):
                headers += f"{key}: {val}\r\n"
        headers += "\r\n"

        remote.sendall((request_line + headers).encode())

        # Read content if present
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            body = self.rfile.read(content_length)
            remote.sendall(body)

        # Relay response back
        response = b""
        while True:
            chunk = remote.recv(8192)
            if not chunk:
                break
            response += chunk

        remote.close()
        self.wfile.write(response)


class ThreadedProxy(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_proxy(port: int, allowed_domains: list[str], ready_event=None):
    """Start the filtering proxy server."""
    FilteringProxy.allowed_domains = allowed_domains
    FilteringProxy.access_log = []

    server = ThreadedProxy(("127.0.0.1", port), FilteringProxy)
    print(f"  Proxy listening on 127.0.0.1:{port}")
    print(f"  Allowed domains: {allowed_domains}")

    if ready_event:
        ready_event.set()

    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Filtering HTTP proxy")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--allow", action="append", default=[],
                        help="Domain to whitelist (can be repeated)")
    args = parser.parse_args()

    if not args.allow:
        print("WARNING: No domains whitelisted. All requests will be denied.")

    print("=" * 50)
    print("  Filtering Proxy")
    print("=" * 50)

    try:
        run_proxy(args.port, args.allow)
    except KeyboardInterrupt:
        print("\nProxy stopped.")


if __name__ == "__main__":
    main()

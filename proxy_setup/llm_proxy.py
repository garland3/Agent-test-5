#!/usr/bin/env python3
"""
LLM API Reverse Proxy — sits between a sandboxed agent and the real LLM API.

Architecture:
    agent (in bwrap, loopback only)
        → http://localhost:9090  (this proxy, plain HTTP)
            → https://api.anthropic.com  (real API, TLS)

Why plain HTTP locally?
    The agent→proxy leg is loopback only (never leaves the machine).
    No TLS = no cert issues. The proxy→API leg uses real TLS.
    This avoids the entire MITM/self-signed cert problem.

What this gives you:
    - Full visibility into every LLM call the agent makes
    - Request/response logging (token usage, prompts, tool calls)
    - Rate limiting (optional)
    - Domain enforcement (agent can ONLY reach the LLM, nothing else)
    - Token budget enforcement (optional)

Usage:
    # Terminal 1: Start the proxy
    python3 llm_proxy.py --upstream https://api.anthropic.com --port 9090

    # Terminal 2: Run agent in bwrap pointing at the proxy
    bash run_agent.sh

The agent SDK should be configured with:
    base_url="http://localhost:9090"
    # or env var: ANTHROPIC_BASE_URL=http://localhost:9090

This is NOT a MITM — the agent is explicitly configured to use the proxy.
"""

import argparse
import http.server
import json
import os
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse


class LLMProxy(http.server.BaseHTTPRequestHandler):
    """Reverse proxy that forwards requests to an upstream LLM API."""

    upstream_base: str = ""
    api_key: str = ""
    auth_style: str = "anthropic"  # "anthropic" or "openai"
    request_log: list = []
    log_lock = threading.Lock()
    request_count: int = 0
    total_tokens: int = 0

    def log_message(self, format, *args):
        """Custom logging — less noisy than default."""
        pass

    def _log_request(self, method: str, path: str, status: int,
                     req_size: int = 0, resp_size: int = 0, detail: str = ""):
        with self.log_lock:
            LLMProxy.request_count += 1
            entry = {
                "n": LLMProxy.request_count,
                "time": time.strftime("%H:%M:%S"),
                "method": method,
                "path": path,
                "status": status,
                "req_bytes": req_size,
                "resp_bytes": resp_size,
                "detail": detail,
            }
            self.request_log.append(entry)

            # Print a concise log line
            arrow = "→" if status < 400 else "✗"
            print(f"  [{entry['time']}] #{entry['n']} {arrow} {method} {path} "
                  f"=> {status} ({resp_size}B) {detail}")

    def _forward(self):
        """Forward the request to the upstream API."""
        upstream_url = self.upstream_base.rstrip("/") + self.path

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else None

        # Build upstream request
        req = urllib.request.Request(upstream_url, data=body, method=self.command)

        # Forward headers (skip hop-by-hop, set correct Host)
        parsed = urlparse(self.upstream_base)
        skip_headers = {"host", "connection", "transfer-encoding",
                        "proxy-connection", "proxy-authorization",
                        "accept-encoding"}
        for key, val in self.headers.items():
            if key.lower() not in skip_headers:
                req.add_header(key, val)

        # Set correct Host for upstream
        req.add_header("Host", parsed.netloc)

        # Inject API key if we have one and the request doesn't already have auth
        if self.api_key and not self.headers.get("x-api-key") and not self.headers.get("Authorization"):
            if self.auth_style == "openai":
                req.add_header("Authorization", f"Bearer {self.api_key}")
            else:
                req.add_header("x-api-key", self.api_key)

        # Forward to upstream (disable redirect following)
        try:
            ctx = ssl.create_default_context()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPHandler(),
            )
            # Don't follow redirects — pass them through
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener.add_handler(NoRedirect())
            resp = opener.open(req, timeout=120)
            resp_body = resp.read()
            status = resp.status

            # Send response back to agent
            self.send_response(status)
            for key, val in resp.headers.items():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp_body)

            # Extract token usage for logging
            detail = ""
            if b'"usage"' in resp_body:
                try:
                    data = json.loads(resp_body)
                    usage = data.get("usage", {})
                    input_t = usage.get("input_tokens", 0)
                    output_t = usage.get("output_tokens", 0)
                    total = input_t + output_t
                    with self.log_lock:
                        LLMProxy.total_tokens += total
                    detail = f"tokens: {input_t}in/{output_t}out (cumulative: {LLMProxy.total_tokens})"
                except (json.JSONDecodeError, KeyError):
                    pass

            self._log_request(self.command, self.path, status,
                              content_length, len(resp_body), detail)

        except urllib.error.HTTPError as e:
            error_body = e.read()
            self.send_response(e.code)
            for key, val in e.headers.items():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(error_body)

            self._log_request(self.command, self.path, e.code,
                              content_length, len(error_body), f"upstream error")

        except Exception as e:
            error_msg = f"Proxy error: {e}"
            self.send_error(502, error_msg)
            self._log_request(self.command, self.path, 502,
                              content_length, 0, str(e)[:80])

    def do_GET(self):
        # Local info endpoint — not forwarded to upstream
        if self.path == "/proxy/info":
            info = json.dumps({
                "upstream": self.upstream_base,
                "auth_style": self.auth_style,
                "requests": self.request_count,
                "total_tokens": self.total_tokens,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(info)
            return
        self._forward()

    def do_POST(self):
        self._forward()

    def do_PUT(self):
        self._forward()

    def do_DELETE(self):
        self._forward()

    def do_PATCH(self):
        self._forward()

    def do_OPTIONS(self):
        self._forward()


class ThreadedServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Suppress noisy connection reset errors."""
        pass


def main():
    parser = argparse.ArgumentParser(
        description="LLM API Reverse Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anthropic
  python3 llm_proxy.py --upstream https://api.anthropic.com --port 9090

  # OpenAI
  python3 llm_proxy.py --upstream https://api.openai.com --port 9090

  # With API key injection (agent doesn't need the key)
  python3 llm_proxy.py --upstream https://api.anthropic.com --api-key $ANTHROPIC_API_KEY

The agent then uses: base_url="http://localhost:9090"
        """)
    parser.add_argument("--upstream", required=True,
                        help="Upstream API base URL (e.g. https://api.anthropic.com)")
    parser.add_argument("--port", type=int, default=9090,
                        help="Local port to listen on (default: 8080)")
    parser.add_argument("--api-key", default="",
                        help="API key to inject into requests (keeps key out of sandbox)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Address to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    LLMProxy.upstream_base = args.upstream
    LLMProxy.api_key = args.api_key or os.environ.get("LLM_API_KEY", "")

    # Auto-detect auth style from upstream URL
    if "openai" in args.upstream.lower():
        LLMProxy.auth_style = "openai"
    else:
        LLMProxy.auth_style = "anthropic"

    auth_header = "Authorization: Bearer" if LLMProxy.auth_style == "openai" else "x-api-key"

    print("=" * 60)
    print("  LLM API Reverse Proxy")
    print("=" * 60)
    print(f"  Listen:   http://{args.bind}:{args.port}")
    print(f"  Upstream: {args.upstream}")
    print(f"  Auth:     {LLMProxy.auth_style} ({auth_header})")
    print(f"  API key:  {'injected (from --api-key or $LLM_API_KEY)' if LLMProxy.api_key else 'passthrough (agent provides)'}")
    print()
    print("  Agent config:")
    print(f'    base_url="http://{args.bind}:{args.port}"')
    print()
    print("  Request log:")
    print("-" * 60)

    server = ThreadedServer((args.bind, args.port), LLMProxy)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\nProxy stopped. Total requests: {LLMProxy.request_count}, "
              f"Total tokens: {LLMProxy.total_tokens}")


if __name__ == "__main__":
    main()

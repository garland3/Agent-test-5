#!/usr/bin/env python3
"""
Example agent that makes LLM API calls through the local proxy.

Demonstrates:
  1. Auto-detecting the upstream provider (Anthropic vs OpenAI) from the proxy
  2. Using the correct endpoint and payload format for each provider
  3. No TLS issues — plain HTTP on loopback
  4. If an API key is available, makes a real API call
  5. If not, simulates calls to show the proxy forwarding pattern

Usage (inside bwrap sandbox):
    python3 example_agent.py

    # Or with explicit proxy URL:
    python3 example_agent.py --proxy-url http://localhost:9090
"""

import argparse
import json
import os
import socket
import sys
import urllib.request
import urllib.error


def detect_provider(base_url: str) -> str:
    """Ask the proxy which upstream it's forwarding to."""
    try:
        req = urllib.request.Request(f"{base_url}/proxy/info")
        resp = urllib.request.urlopen(req, timeout=5)
        info = json.loads(resp.read())
        upstream = info.get("upstream", "")
        if "openai" in upstream.lower():
            return "openai"
        return "anthropic"
    except Exception:
        # Fallback: check env vars
        if os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_KEY"):
            return "openai"
        return "anthropic"


def make_anthropic_call(base_url: str, api_key: str, prompt: str) -> dict:
    """Call Anthropic's /v1/messages endpoint."""
    url = f"{base_url}/v1/messages"
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("anthropic-version", "2023-06-01")
    if api_key:
        req.add_header("x-api-key", api_key)
    return _do_request(req)


def make_openai_call(base_url: str, api_key: str, prompt: str) -> dict:
    """Call OpenAI's /v1/chat/completions endpoint."""
    url = f"{base_url}/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    return _do_request(req)


def _do_request(req) -> dict:
    """Execute a request and return parsed result."""
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw_response": raw.decode(errors="replace")[:500], "status": resp.status}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"error": True, "status": e.code, "body": body[:500]}
    except Exception as e:
        return {"error": True, "status": 0, "message": str(e)}


def extract_response_text(result: dict, provider: str) -> str:
    """Pull the assistant text out of a successful response."""
    if provider == "openai":
        choices = result.get("choices", [{}])
        return choices[0].get("message", {}).get("content", "") if choices else ""
    else:
        content = result.get("content", [{}])
        return content[0].get("text", "") if content else ""


def extract_usage(result: dict, provider: str) -> str:
    """Pull token usage from a successful response."""
    usage = result.get("usage", {})
    if provider == "openai":
        return f"{usage.get('prompt_tokens', '?')} in / {usage.get('completion_tokens', '?')} out"
    else:
        return f"{usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out"


def run_calls(base_url: str, api_key: str, provider: str, real: bool):
    """Run test LLM calls against the proxy."""
    make_call = make_openai_call if provider == "openai" else make_anthropic_call
    mode = "REAL" if real else "simulated"

    print(f"\n  Making {mode} {provider.upper()} API calls through proxy...")
    print(f"  Base URL: {base_url}")
    if provider == "openai":
        print(f"  Endpoint: /v1/chat/completions")
    else:
        print(f"  Endpoint: /v1/messages")
    print()

    prompts = [
        "What is 2 + 2? Reply in one word.",
        "Name one color. Reply in one word.",
    ]

    dummy_key = "test-key-for-proxy-demo" if not real else api_key

    for i, prompt in enumerate(prompts, 1):
        print(f"  Call {i}: \"{prompt}\"")
        result = make_call(base_url, dummy_key, prompt)

        if result.get("error"):
            status = result.get("status", "N/A")
            print(f"    Response: HTTP {status}")
            if status == 401:
                print(f"    (401 = proxy forwarded correctly, API key invalid — expected for simulation)")
            elif status == 404:
                print(f"    (404 = endpoint not found — wrong provider? Check proxy --upstream)")
            elif status == 502:
                print(f"    (502 = proxy couldn't reach upstream — is the proxy running?)")
            else:
                print(f"    Detail: {result.get('body', result.get('message', ''))[:200]}")
        else:
            text = extract_response_text(result, provider)
            usage = extract_usage(result, provider)
            print(f"    Response: {text[:100]}")
            print(f"    Tokens: {usage}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Example agent using LLM proxy")
    parser.add_argument("--proxy-url", default="http://localhost:9090",
                        help="Local proxy URL")
    args = parser.parse_args()

    base_url = os.environ.get("ANTHROPIC_BASE_URL",
               os.environ.get("OPENAI_BASE_URL", args.proxy_url))
    api_key = os.environ.get("ANTHROPIC_API_KEY",
              os.environ.get("OPENAI_API_KEY", ""))

    print("=" * 55)
    print("  Example Agent — LLM calls via proxy")
    print("=" * 55)
    print(f"  Proxy URL:  {base_url}")
    print(f"  API key:    {'set' if api_key else 'not set (will simulate)'}")

    # Check proxy is reachable
    parsed_host = base_url.replace("http://", "").replace("https://", "")
    host, port = parsed_host.rsplit(":", 1)
    try:
        s = socket.create_connection((host, int(port)), timeout=2)
        s.close()
        print(f"  Proxy:      reachable")
    except Exception:
        print(f"  Proxy:      NOT reachable at {base_url}")
        print(f"\n  Start the proxy first (Terminal 1):")
        print(f"    bash run_proxy.sh")
        return 1

    # Auto-detect provider
    provider = detect_provider(base_url)
    print(f"  Provider:   {provider}")

    run_calls(base_url, api_key, provider, real=bool(api_key))

    print("  Done. Check the proxy terminal for request logs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

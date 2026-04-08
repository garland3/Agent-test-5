#!/usr/bin/env python3
"""
Example agent that makes LLM API calls through the local proxy.

Demonstrates:
  1. Calling the Anthropic API via the local proxy (http://localhost:9090)
  2. No TLS issues — plain HTTP on loopback
  3. The proxy handles the real TLS connection to api.anthropic.com
  4. If ANTHROPIC_API_KEY is available, makes a real API call
  5. If not, simulates calls to show the proxy forwarding pattern

Usage (inside bwrap sandbox):
    python3 example_agent.py

    # Or with explicit proxy URL:
    python3 example_agent.py --proxy-url http://localhost:9090
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error


def make_llm_call(base_url: str, api_key: str, prompt: str) -> dict:
    """Make a Claude API call through the proxy."""
    url = f"{base_url}/v1/messages"

    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 100,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }).encode()

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-api-key", api_key)
    req.add_header("anthropic-version", "2023-06-01")

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"error": False, "status": resp.status, "raw": raw.decode(errors="replace")[:500]}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"error": True, "status": e.code, "body": body[:500]}
    except Exception as e:
        return {"error": True, "status": 0, "message": str(e)}


def simulate_llm_calls(base_url: str):
    """Simulate API calls to show proxy interaction (no real API key needed)."""
    print("\n  Simulating LLM API calls to show proxy forwarding...")
    print(f"  Base URL: {base_url}")
    print()

    # These will likely fail with 401 (no valid key) but that proves
    # the proxy is forwarding correctly
    test_prompts = [
        "What is 2 + 2?",
        "List 3 colors.",
    ]

    for i, prompt in enumerate(test_prompts, 1):
        print(f"  Call {i}: \"{prompt}\"")
        result = make_llm_call(base_url, "test-key-for-proxy-demo", prompt)

        if result.get("error"):
            status = result.get("status", "N/A")
            print(f"    Response: HTTP {status}")
            if status == 401:
                print(f"    (401 = proxy forwarded correctly, but API key is invalid — expected!)")
            elif status == 502:
                print(f"    (502 = proxy couldn't reach upstream — is the proxy running?)")
            else:
                print(f"    Detail: {result.get('body', result.get('message', ''))[:200]}")
        else:
            # Real response!
            content = result.get("content", [{}])[0].get("text", "")
            usage = result.get("usage", {})
            print(f"    Response: {content[:100]}")
            print(f"    Tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out")
        print()


def real_llm_calls(base_url: str, api_key: str):
    """Make real API calls through the proxy."""
    print("\n  Making REAL LLM API calls through proxy...")
    print(f"  Base URL: {base_url}")
    print()

    prompts = [
        "What is 2 + 2? Reply in one word.",
        "Name one color. Reply in one word.",
    ]

    for i, prompt in enumerate(prompts, 1):
        print(f"  Call {i}: \"{prompt}\"")
        result = make_llm_call(base_url, api_key, prompt)

        if result.get("error"):
            print(f"    Error: HTTP {result.get('status', 'N/A')}")
            print(f"    {result.get('body', result.get('message', ''))[:200]}")
        else:
            content = result.get("content", [{}])[0].get("text", "")
            usage = result.get("usage", {})
            print(f"    Response: {content}")
            print(f"    Tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out")
        print()


def main():
    parser = argparse.ArgumentParser(description="Example agent using LLM proxy")
    parser.add_argument("--proxy-url", default="http://localhost:9090",
                        help="Local proxy URL")
    args = parser.parse_args()

    base_url = os.environ.get("ANTHROPIC_BASE_URL", args.proxy_url)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    print("=" * 55)
    print("  Example Agent — LLM calls via proxy")
    print("=" * 55)
    print(f"  Proxy URL:  {base_url}")
    print(f"  API key:    {'set' if api_key else 'not set (will simulate)'}")

    # Check proxy is reachable
    import socket
    parsed_host = base_url.replace("http://", "").replace("https://", "")
    host, port = parsed_host.split(":")
    try:
        s = socket.create_connection((host, int(port)), timeout=2)
        s.close()
        print(f"  Proxy:      reachable")
    except Exception:
        print(f"  Proxy:      NOT reachable at {base_url}")
        print(f"\n  Start the proxy first (Terminal 1):")
        print(f"    python3 llm_proxy.py --upstream https://api.anthropic.com --port {port}")
        return 1

    if api_key:
        real_llm_calls(base_url, api_key)
    else:
        simulate_llm_calls(base_url)

    print("  Done. Check the proxy terminal for request logs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# LLM Proxy Setup for Sandboxed Agents

A practical guide to running AI agents in a bubblewrap sandbox with controlled
LLM API access. The agent runs in isolation but can still call the LLM through
a local proxy you control.

## The Problem

An AI agent needs to call an LLM API (e.g. `api.anthropic.com`), but you want
the agent sandboxed — no arbitrary network access, no data exfiltration.

Bubblewrap's `--unshare-net` gives you loopback only (no internet), and
`--share-net` gives you full internet. Neither is what you want.

## The Solution

```
agent (in bwrap)                    your proxy                     internet
┌─────────────┐     plain HTTP     ┌──────────┐       HTTPS      ┌─────────────────────┐
│  agent.py   │ ──────────────── → │ llm_proxy│ ──────────────→  │ api.anthropic.com   │
│             │   localhost:9090   │          │   real TLS cert  │                     │
│ base_url=   │                    │ logs all │                  │                     │
│ http://     │                    │ requests │                  │                     │
│ localhost:  │                    │          │                  │                     │
│ 8080       │                    └──────────┘                  └─────────────────────┘
└─────────────┘
    bwrap sandbox                      host
```

**Key insight**: The agent is *configured* to use the proxy (`base_url`), not
tricked into it. No MITM, no cert issues, no self-signed CA.

- Agent → proxy: plain HTTP on loopback (safe, never leaves machine)
- Proxy → API: real HTTPS with valid certs (no TLS problems)

## Quick Start (Two Terminals)

### Terminal 1: Start the proxy

```bash
cd proxy_setup

# Basic — agent provides its own API key:
bash run_proxy.sh

# Anthropic — inject API key (agent never sees it):
bash run_proxy.sh --api-key $ANTHROPIC_API_KEY

# OpenAI — same pattern, just change upstream + key:
bash run_proxy.sh --upstream https://api.openai.com --api-key $OPENAI_API_KEY

# Agent provides its own key (no injection):
bash run_proxy.sh
```

The proxy auto-detects the auth style from the upstream URL:
- `api.anthropic.com` → injects `x-api-key` header
- `api.openai.com` → injects `Authorization: Bearer` header

You'll see:
```
============================================================
  LLM API Reverse Proxy
============================================================
  Listen:   http://127.0.0.1:9090
  Upstream: https://api.anthropic.com
  Auth:     anthropic (x-api-key)
  API key:  injected (from --api-key or $LLM_API_KEY)

  Request log:
------------------------------------------------------------
```

### Terminal 2: Run the agent in sandbox

```bash
cd proxy_setup

# Simulated calls (no API key needed, shows proxy forwarding):
bash run_agent.sh

# Real calls (passes your API key into the sandbox):
bash run_agent.sh --with-api-key
```

You'll see the agent make calls, and **Terminal 1** will log every request:
```
  [14:23:01] #1 → POST /v1/messages => 200 (1432B) tokens: 12in/8out (cumulative: 20)
  [14:23:03] #2 → POST /v1/messages => 200 (1388B) tokens: 10in/5out (cumulative: 35)
```

## What the Proxy Gives You

### 1. Observability
Every LLM call is logged — method, path, status, token usage. You can see
exactly what the agent is doing.

### 2. Security
The agent only reaches what you allow. With `--share-net` the agent can reach
the proxy (and technically anything else). For maximum enforcement, combine with
iptables rules or `--unshare-net` + veth (see "Stronger Enforcement" below).

### 3. API Key Protection
Run the proxy with `--api-key` and the key stays on the host — the agent
never sees it. The proxy injects the correct auth header automatically:

```bash
# Anthropic — proxy injects x-api-key header
bash run_proxy.sh --api-key $ANTHROPIC_API_KEY

# OpenAI — proxy injects Authorization: Bearer header
bash run_proxy.sh --upstream https://api.openai.com --api-key $OPENAI_API_KEY

# Agent sandbox has no API key, but calls still work
bash run_agent.sh  # no --with-api-key needed
```

### 4. Rate Limiting / Token Budgets (extensible)
The proxy logs cumulative token usage. You could extend it to enforce
a token budget, rate limit, or reject certain prompts.

## Configuring Real Agent SDKs

Most LLM SDKs support a `base_url` parameter or env var:

### Anthropic Python SDK
```python
import anthropic

# If proxy injects the key, use a dummy (SDK requires something):
client = anthropic.Anthropic(
    base_url="http://localhost:9090",
    api_key="proxy-handles-this",
)

# Or if agent has the real key:
client = anthropic.Anthropic(
    base_url="http://localhost:9090",
    api_key=os.environ["ANTHROPIC_API_KEY"],
)
```

Or via env var (works with most tools that use the Anthropic SDK):
```bash
export ANTHROPIC_BASE_URL=http://localhost:9090
```

### OpenAI Python SDK
```python
from openai import OpenAI

# If proxy injects the key:
client = OpenAI(
    base_url="http://localhost:9090/v1",
    api_key="proxy-handles-this",
)

# Or if agent has the real key:
client = OpenAI(
    base_url="http://localhost:9090/v1",
    api_key=os.environ["OPENAI_API_KEY"],
)
```

Or via env var:
```bash
export OPENAI_BASE_URL=http://localhost:9090/v1
```

### curl
```bash
curl http://localhost:9090/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":100,"messages":[{"role":"user","content":"Hello"}]}'
```

## Why Not HTTPS Locally?

You might wonder — shouldn't the agent→proxy connection be HTTPS too?

**No.** The connection is loopback only (127.0.0.1). It physically cannot leave
the machine. Adding TLS here would mean:
- Self-signed certs → every SDK needs `verify=False` or custom CA
- mkcert setup → extra moving parts
- Zero actual security gain (loopback is already private)

The proxy→API leg uses real HTTPS with valid certs. That's where TLS matters.

## Stronger Enforcement

The basic setup uses `--share-net`, which means the agent *could* bypass the
proxy and connect directly to the internet. For defense-in-depth:

### Option A: iptables (moderate)
Block all outbound traffic from the sandbox except to localhost:
```bash
# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT
# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Block everything else for the agent's UID
iptables -A OUTPUT -m owner --uid-owner $AGENT_UID -j DROP
```

### Option B: Network namespace + veth (strongest)
Create a network namespace where the only route is to the proxy:
```bash
# Create isolated netns
ip netns add agent-ns
ip link add veth-host type veth peer name veth-agent
ip link set veth-agent netns agent-ns

# Configure addresses
ip addr add 10.0.0.1/24 dev veth-host
ip link set veth-host up
ip netns exec agent-ns ip addr add 10.0.0.2/24 dev veth-agent
ip netns exec agent-ns ip link set veth-agent up
ip netns exec agent-ns ip link set lo up

# Only route: proxy on host side
ip netns exec agent-ns ip route add default via 10.0.0.1

# Run proxy listening on 10.0.0.1:9090 too, then:
bwrap --unshare-pid ... \
  -- env ANTHROPIC_BASE_URL=http://10.0.0.1:9090 python3 agent.py
```

The agent literally cannot reach anything except the proxy.

## Combining with Domain Whitelist

For agents that need more than just the LLM API (e.g., pip install, git clone),
combine the LLM proxy with the domain whitelist proxy from the parent project:

```bash
# Terminal 1: LLM proxy on port 8080
python3 llm_proxy.py --upstream https://api.anthropic.com --port 9090

# Terminal 2: Domain whitelist proxy on port 8888
python3 ../proxy_filter.py --port 8888 --allow pypi.org --allow github.com

# Terminal 3: Agent with both proxies
bwrap --share-net --clearenv \
  --setenv ANTHROPIC_BASE_URL http://localhost:9090 \
  --setenv https_proxy http://localhost:8888 \
  ...
```

The agent uses the LLM proxy for API calls and the filtering proxy for
everything else. You get full observability on both channels.

## Files

| File | Purpose |
|------|---------|
| `llm_proxy.py` | Reverse proxy: forwards to LLM API, logs everything |
| `example_agent.py` | Demo agent that calls the LLM through the proxy |
| `run_proxy.sh` | Terminal 1 script: start the proxy |
| `run_agent.sh` | Terminal 2 script: run agent in bwrap sandbox |
| `README.md` | This file |

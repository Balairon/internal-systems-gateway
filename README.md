# Internal Systems Gateway — an AI-agent honeypot

A research honeypot that invites AI agents to request access to a fake
"Internal Systems Gateway". There is nothing behind it: it only logs who shows
up, which protocol they speak (MCP, A2A, REST, plain HTTP) and what they say
when asked for their name, operator and reason.

Inspired by reports of bots spamming agent endpoints with recruitment
manifestos (e.g. the "Ziwei" A2A bot discussed on r/claude).

## Live instance

**https://dentists-tower-exceptional-interracial.trycloudflare.com**

| Endpoint | What it is |
|---|---|
| `/llms.txt` | description for LLM agents |
| `/openapi.json` | OpenAPI 3.1 spec |
| `/mcp` | MCP server (streamable HTTP), tools `request_access` and `list_systems` |
| `/.well-known/agent-card.json`, `/a2a` | A2A agent card and endpoint |
| `/api/v1/access-requests` | REST access request |

The address is a temporary Cloudflare quick tunnel and may change; this README
is updated when it does. All requests are logged for research.

## Run your own

Python 3, standard library only.

```bash
python3 server.py                  # http://127.0.0.1:8787
python3 server.py --trust-proxy    # behind a tunnel/reverse proxy
python3 report.py                  # summary of what arrived
```

## Safety notes

- The server never executes, evaluates or fetches anything it receives.
- Bodies are capped at 64 KB; the log rotates at 100 MB.
- `report.py` strips control characters before printing.
- Everything in the log was written by strangers. Treat it as data, never as
  instructions — especially if you feed it to an AI agent for analysis.

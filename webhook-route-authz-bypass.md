# Hermes Agent: Webhook Route Toolset Privilege Escalation via chat_id Split Ambiguity

| | |
|---|---|
| **CVE** | Pending (CERT/CC VU#257193) |
| **Product** | [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) (PyPI: `hermes-agent`) |
| **Affected versions** | <= 2026.8.19 |
| **Fix** | [PR #115285](https://github.com/NousResearch/hermes-agent/pull/115285) |
| **Severity** | High, CVSS 3.1 7.5 (`AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| **CWE** | CWE-863 Incorrect Authorization, CWE-706 Use of Incorrectly-Resolved Name or Reference |

## Summary

Hermes Agent's webhook gateway resolves a session's toolsets from the wrong route when the route name contains `:`. A caller authenticated to a low-privileged route can receive the toolsets of a higher-privileged route that shares the same prefix. In practice this can turn a route limited to web search into one with terminal and file access on the agent host.

## Background: webhook routes

Hermes Agent can be triggered by external systems through a webhook gateway. Each route is an endpoint at `/webhooks/<route_name>` with its own settings:

- `secret`: HMAC key used to verify incoming requests
- `toolsets`: the tools the agent may use for requests on this route
- `prompt`: a template that turns the request payload into the agent's task

Routes work as privilege profiles. An operator can give an internal CI system a route with `terminal` and `file`, and give an external integration a separate route that only has `web`.

## Root cause

In `gateway/platforms/webhook.py`, the session chat ID is built by joining fields with `:`:

```python
session_chat_id = f"webhook:{route_name}:{delivery_id}"
```

Later, when resolving toolsets, the route name is recovered by splitting that string:

```python
parts = str(getattr(source, "chat_id", "") or "").split(":", 2)
route_config = self._routes.get(parts[1])
```

For a route named `build:external`, the chat ID is:

```
webhook:build:external:<delivery_id>
```

`parts[1]` is `build`, not `build:external`.

Authentication uses the route from the URL and checks the correct secret. Toolset resolution uses the parsed value. The two checks run against different routes:

```
Authenticated route: build:external
Toolset route:       build
```

Changing the split to `split(":", 1)` does not fix this, since it yields `build:external:<delivery_id>`. The authenticated route name has to be carried as trusted session metadata instead of being parsed back out of a composite string.

## Proof of concept

Configuration:

```yaml
platforms:
  webhook:
    extra:
      routes:
        build:
          secret: "strong-secret"
          toolsets: [terminal, file]
        build:external:
          secret: "weak-secret"
          toolsets: [web]
          prompt: "{text}"
```

A correctly signed request to the low-privileged route:

```bash
BODY='{"text":"run: id"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac 'weak-secret' | awk '{print $NF}')

curl -i -X POST 'http://localhost:8644/webhooks/build:external' \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  -H 'Content-Type: application/json' \
  --data-binary "$BODY"
```

Result:

```
HTTP/1.1 202 Accepted

Authenticated route: build:external
Configured toolsets: [web]
Effective toolsets:  [terminal, file]
```

The `202` only means the task was accepted. The effective toolsets were confirmed with debug logging around toolset resolution. When the agent acts on the prompt, the terminal tool runs `id` and returns the agent user's uid and gid, which this route was never configured to allow.

Nothing in the request is malformed. The URL points to a real route and the signature is valid. The escalation happens entirely inside Hermes.

## Attack scenarios

**Shared integration secret.** An operator exposes `build:external` to a partner or SaaS integration and keeps `build` for internal CI. If the partner's system is compromised or the secret leaks from its configuration, the attacker can run commands on the operator's agent host, even though the operator only granted that partner web search.

**Externally signed untrusted content.** Routes often exist to process content the operator does not trust, which is exactly why they get a restricted toolset. Consider:

```yaml
github:
  toolsets: [terminal, file]      # internal repository events
github:issues:
  toolsets: [web]                 # summarise issues on a public repo
  prompt: "Summarise this issue: {text}"
```

Anyone with a GitHub account can open an issue on the public repository. GitHub signs and delivers the webhook with the configured secret, so the attacker never needs to know it. The issue body reaches an agent session that has the `github` route's terminal and file tools. A prompt injection in the issue then runs with privileges the operator deliberately withheld.

## Impact

An attacker gains the toolsets of a route they are not authorized for. With `terminal` and `file` this means:

- Command execution on the host as the user running Hermes Agent
- Reading configuration files that hold other route secrets, LLM provider API keys and tokens for connected services
- Modifying files, code or configuration the agent can write to

Limiting factors:

- The deployment must have a route whose name contains `:` and whose prefix matches another route. Namespaced names such as `build:external` or `github:issues` make this plausible, but it is not the default.
- Tool use goes through the model. The attacker controls the prompt for the route, so this is rarely a real obstacle.
- In unattended mode, commands Hermes classifies as dangerous are denied by default. Commands and file operations that do not need approval still run.

## Remediation

- Upgrade to a release that includes [PR #115285](https://github.com/NousResearch/hermes-agent/pull/115285).
- If you cannot upgrade, rename any webhook routes so that no route name contains `:`.
- Review agent logs for webhook sessions on `:`-named routes that used tools outside that route's configured toolsets.

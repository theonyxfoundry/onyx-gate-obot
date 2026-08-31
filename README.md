# Onyx Gate for Obot

**A verifiable authorization filter for the [Obot](https://obot.ai) MCP
Gateway.** Point one of Obot's stock HTTP filters at this receiver and every
MCP `tools/call` your gateway proxies is decided by policy *before it
executes* — rejected calls never run, the caller gets the reason, and every
decision lands in a hash-chained audit trail you can re-check offline, with a
machine-checkable proof of each decision available on demand.

No changes to Obot: this uses the gateway's built-in filter mechanism exactly
as documented, and the receiver is ~200 lines of standard-library Python.

```
Obot MCP Gateway ──signed JSON-RPC──▶ onyx-gate-obot ──/gate/tool-call──▶ Onyx gateway
   (stock HTTP filter)                (this receiver)                  (policy engine + trail)
                 ◀── 200 accept / 403 reject + reason ──
```

## What it looks like

The [example](examples/obot/) gates a file-server MCP tool set with this
policy (Cedar, an allowlist — anything unmatched is denied by default):

```cedar
entity Agent::"obot" {} ;

// Searching is harmless — always permitted.
permit(principal, action == Action::"search", resource);

// File reads are permitted ONLY inside the public tree.
permit(principal, action == Action::"read_file", resource)
  when { resource.path like "/data/public/*" };
```

Real output — the dry run plays the Obot gateway byte-for-byte per the
documented filter contract (signed payloads, 200 accepts, non-200 rejects),
against a real receiver and a real Onyx gateway:

```text
[200] an agent searches — search{"query": "quarterly report template"} → accepted
[200] reads a public file — read_file{"path": "/data/public/handbook.md"} → accepted  (0.9 ms)

[403] reads a restricted file — read_file{"path": "/data/finance/q3-figures.txt"} → REJECTED (403)  (0.8 ms)
      what Obot surfaces to the caller:
      [Onyx Gate] DENIED — this tool call was blocked and did NOT execute.
        call:   read_file(path='/data/finance/q3-figures.txt')
        reason: Denied — no permit policy matches (Cedar's default deny).

[403] tries an un-permitted tool — delete_file{...} → REJECTED (403)  (0.7 ms)

[401] a tampered payload arrives
      invalid signature
```

The restricted read did not execute — not "the model chose not to": the
gateway rejected the call before the MCP server ever saw it. The reason
travels with the rejection, which is what lets an agent recover sensibly
instead of thrashing. And the mis-signed payload never reached the policy
engine at all.

## Why gate at the gateway

An MCP gateway is the right chokepoint: every agent, every client, every tool
call in one place — but the policy engine behind it is usually a rules file
you have to trust. Onyx's difference is that its decisions are *checkable*:
each one can carry a certificate that a small standalone checker re-verifies
offline, and the decision trail is hash-chained so any edit breaks loudly.

Why enforcement matters, measured: in our pilot harness, un-gated agent runs
read a policy-forbidden file in **40 of 40 runs across two models** —
capability doesn't make an agent respect a policy it can't see enforced. With
the gate enforcing: **0 of 20** forbidden reads, and every run still completed
its task from the permitted source (one task family, n=20 per arm; details at
[onyxfoundry.ai](https://onyxfoundry.ai)).

## Setup

```bash
pip install onyx-gate-obot         # standard library only, no dependencies
```

1. Run the Onyx gateway (design-partner preview — see below) with your policy:

   ```bash
   eg_gateway --policies policy.cedar --log trail.jsonl
   ```

2. Run the receiver next to it:

   ```bash
   echo -n "$(openssl rand -hex 24)" > webhook.secret
   onyx-gate-obot --secret-file webhook.secret --port 8891
   ```

3. In Obot: **Gateway → Filters → add an HTTP filter** —
   - URL: `http://<host>:8891/webhook` (from an Obot container,
     `http://host.docker.internal:8891/webhook`)
   - Secret: the contents of `webhook.secret` — the receiver verifies the
     `X-Obot-Signature-256` HMAC on every payload
   - Selectors: scope to `tools/call`

That's the whole integration. To see it work without an Obot deployment,
`python examples/obot/dry_run.py` sends the same signed payloads the gateway
would; to see it without the engine, `pip install -e '.[dev]' && pytest` runs
everything against a scripted stub.

### How calls map to policy

| MCP message part | Cedar request part |
| --- | --- |
| the receiver's `--agent` identity | `principal` = `Agent::"obot"` |
| `params.name` (the tool) | `action` = `Action::"read_file"` |
| the call itself | `resource` = `Tool::"read_file"` |
| each entry of `params.arguments` | a resource attribute — `resource.path`, … |

Every argument reaches the policy: strings/booleans/64-bit integers verbatim,
floats and oversized integers as strings, nested structures as compact JSON so
substring (`like`) policies still see their content. Nothing is silently
dropped or truncated — a policy keyed on an argument the gate can't see would
fail open.

### Failure behavior (all fail-closed)

| situation | response to Obot |
| --- | --- |
| policy allows | 200 — call proceeds |
| policy denies | 403 with the reason — call blocked |
| Onyx gateway unreachable | 503 — call blocked |
| missing / wrong signature | 401 — payload rejected before any decision |
| unparseable payload | 400 — rejected |
| non-`tools/call` messages | 200 — passed untouched (scope with selectors) |

`--observe` flips to pilot mode: nothing is rejected, would-denies are logged
and recorded in the Onyx trail — measure what enforcement *would* do on real
traffic before turning it on.

## The audit trail

The dry run above leaves this behind (`eg_verify` is the engine's offline
checker — it re-checks the hash chain and any attached certificates with the
proof kernel alone, not by trusting the gateway):

```text
$ eg_verify --audit-log trail.jsonl
  record   1  gate_tool_call
  record   2  gate_tool_call
  record   3  gate_tool_call
  record   4  gate_tool_call
chain: 4 linked, 0 unchained, 0 broken
```

Four records — the four calls that reached the policy engine; the tampered
payload is absent because it was rejected at the signature check. Edit one
byte of one record and the re-check names the broken link and fails loudly.
Pass `--certify` to the receiver and each decision additionally carries a
kernel-re-checkable certificate (measured on the example: ~2–3 ms per decision
instead of ~1 ms).

## Scope, honestly

- **This is an authorization filter, not a sandbox.** It governs MCP tool
  calls that flow through the Obot gateway; traffic that bypasses the gateway
  bypasses the filter.
- **The gate decides; it never executes.** Onyx holds no credentials for your
  MCP servers and never touches their traffic — it answers allow/deny and
  proves its answers.
- Certificates are kernel-re-checkable records of the policy reasoning — not
  digital signatures; the trail's hash chain detects edits, not deletion of
  the whole file (anchor the chain head externally for that).
- The receiver is a reference implementation (threaded stdlib server). An MCP
  filter-server variant (Obot's `accept`/`reason` tool contract, deployable
  from a catalog) is the natural next step — say the word.
- Latency figures are measured on the example, not a benchmark suite.

## Getting the gateway

This package and the filter contract are Apache-2.0 and fully documented here;
the test suite runs without the engine. The gateway binary (`eg_gateway`) and
offline checker (`eg_verify`) are part of the **Onyx engine** — a
verification-first policy engine whose decision calculus is machine-checked in
two independent proof assistants — currently in design-partner preview.

The same engine gates agent frameworks directly — see
[onyx-gate-crewai](https://github.com/theonyxfoundry/onyx-gate-crewai) (this
receiver vendors the same framework-agnostic core).

Running an MCP gateway in front of agents that touch money, records, or
customers? **contact@onyxfoundry.ai** · [onyxfoundry.ai](https://onyxfoundry.ai)

## License

[Apache-2.0](LICENSE). Obot is a trademark of its respective owner; this is an
independent integration, not affiliated with or endorsed by Obot AI.

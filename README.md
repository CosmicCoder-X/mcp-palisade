# Palisade

**A security scanner for Model Context Protocol servers.**

Palisade analyses what an MCP server *advertises* — its tools, prompts, resources and
instructions — and reports the ways that surface can be used to manipulate the agent
connected to it. It then pins what it saw, so a server that behaves during review and
changes afterwards gets caught.

```
palisade scan --stdio "npx -y @some/mcp-server"
```

---

## Why this exists

When a host application connects to an MCP server, every tool description that server
returns is inserted into the model's context. Those descriptions are attacker-controlled
text that the model treats as trusted, and the human approving the connection usually sees
a rendered summary rather than the raw bytes. That gap is the vulnerability class this tool
addresses.

Four things follow from it, and Palisade is built around them:

**A description is a prompt.** Documentation describes a tool in the third person. An
injected description addresses the model directly and issues instructions. Palisade scores
that difference structurally, so it catches phrasings no signature anticipated.

**What you approve is not what you keep.** Nothing in MCP requires a client to notice that
a server changed its tool definitions after you approved them. Palisade hashes the surface
on first use and treats later drift as a security event — the rug pull.

**Invisible is not absent.** Text encoded in Unicode tag characters or variation selectors
reaches the model in full and reaches the reviewer not at all. Palisade decodes those
channels and prints what was hidden.

**The namespace is shared.** An agent flattens every connected server into one tool list, so
a description belonging to one server is read while the model decides whether to call a tool
from another. Palisade analyses a whole workspace, not one server at a time.

---

## What it detects

| ID | Detection | Severity |
|---|---|---|
| **PAL001** | Decodable payload hidden in invisible Unicode | Critical |
| **PAL002** | Non-rendering characters in advertised text | High |
| **PAL003** | Mixed-script word (homoglyph impersonation) | High |
| **PAL004** | Text buried below a whitespace gap or excessive length | High |
| **PAL005** | Content concealed inside markup | High |
| **PAL010** | Attempt to override prior instructions | Critical |
| **PAL011** | Directive to hide behaviour from the user | Critical |
| **PAL012** | Tool claims to be a mandatory precondition for other tools | High |
| **PAL013** | Language designed to suppress user confirmation | High |
| **PAL014** | Attempt to reassign the model's role | High |
| **PAL015** | Description reads as an instruction to the agent *(heuristic)* | Medium |
| **PAL020** | Tool description directs the use of another tool | Critical |
| **PAL021** | Colliding or confusable tool names | High |
| **PAL022** | Tool description asserts scope over the whole conversation | High |
| **PAL023** | Tool name claimed by multiple servers *(cross-server)* | High |
| **PAL030** | Description solicits credentials or sensitive local files | Critical |
| **PAL031** | Parameter shaped to collect unrelated data | High |
| **PAL032** | Externally controlled endpoint referenced by the server | High |
| **PAL033** | Description asks for conversation or system-prompt content | Critical |
| **PAL040** | High-impact parameter accepts unconstrained input | Critical |
| **PAL041** | State-changing tool omits behavioural annotations | Medium |
| **PAL042** | Tool input schema is unbounded | Medium |
| **PAL050** | Approved tool definition changed *(rug pull)* | Critical |
| **PAL051** | Tool appeared after the server was approved | Medium |
| **PAL052** | Approved tool disappeared | Low |

`palisade rules` prints this table with the reasoning behind each entry.

---

## Install

```bash
pip install mcp-palisade            # static analysis
pip install "mcp-palisade[live]"    # adds live capture from running servers
```

Live capture is a separate extra on purpose. **Connecting to a stdio MCP server executes
it**, and the premise of this tool is that the target may be hostile. Everything except
capture works on a JSON surface file that can be reviewed without running anything.

---

## Use

**Scan a server you are about to install:**

```bash
palisade scan --stdio "npx -y @example/some-server"
```

**Audit everything already installed**, from your host application's config:

```bash
palisade scan --config ~/.config/Claude/claude_desktop_config.json
```

This is also where cross-server rules earn their place: PAL023 only fires when two servers
claim the same tool name, which no single-server scan can see.

**Capture now, analyse later** — useful when the machine that can reach the server is not
the machine you want to run untrusted code on:

```bash
palisade capture --stdio "npx -y @example/some-server" -o surface.json
palisade scan surface.json
```

**Pin a server you have reviewed and trust:**

```bash
palisade pin surface.json
palisade scan surface.json     # any later drift is reported as PAL050/051/052
```

**In CI:**

```bash
palisade scan surface.json --format sarif -o palisade.sarif --fail-on high
```

Exit codes are `0` clean, `1` findings at or above `--fail-on`, `2` an operational error.
SARIF output loads directly into GitHub code scanning. A ready-made workflow is in
[`.github/workflows/scan-example.yml`](.github/workflows/scan-example.yml).

Established findings you have accepted can be silenced without disabling the rule:

```bash
palisade baseline surface.json -o .palisade-baseline.json
palisade scan surface.json --baseline .palisade-baseline.json
```

---

## Try it

Two fixtures ship with the repo. One is a clean weather server, the other carries one
instance of every attack class:

```bash
palisade scan fixtures/benign.json      # no findings
palisade scan fixtures/poisoned.json    # every rule, with decoded payloads
```

The poisoned fixture is generated by [`fixtures/generate.py`](fixtures/generate.py) rather
than written by hand, because several attacks depend on exact invisible code points that do
not survive being copied out of an editor.

---

## Design notes

**Severity and confidence are separate axes.** A hidden Unicode payload is reported as
`certain` because the bytes are either there or they are not; an unusually named parameter
is `tentative` because the rule is inferring intent. Collapsing these into one number is how
security tools end up being ignored.

**Findings carry located evidence.** Every finding quotes the exact span that triggered it,
with invisible characters rendered visibly, so a reviewer can judge it without going back to
the raw JSON. Rug-pull diffs show the approved text and the current text side by side under
the same treatment.

**Rules are decoupled from transport.** Every rule consumes a normalised `TextUnit` stream
covering tool names, descriptions, nested JSON-Schema property descriptions, prompt
arguments, resource metadata and server instructions. Adding a rule means writing a `check`
method; it will automatically see text hidden three levels deep in a schema.

**False positives are treated as bugs.** `fixtures/benign.json` is a regression test that
asserts zero findings. Rules that fire on it either get a suppressing condition — as PAL040
has for parameters named `code` that mean "country code" — or get narrowed.

---

## Limitations

Worth stating plainly, because a scanner that oversells itself is worse than none:

- **Static analysis sees only what the server chose to send at capture time.** A server can
  serve a clean surface to a scanner and a poisoned one to a real client. Pinning narrows
  this but does not close it; only a client that verifies pins on every connection does.
- **PAL015 is a heuristic** and will flag some verbose but honest descriptions. It is scoped
  to `medium` for that reason.
- **Palisade does not execute tools.** It reasons about the advertised surface, not runtime
  behaviour. A tool whose description is honest and whose implementation is not will pass.
  Closing that requires a sandboxed dynamic harness, which is the next milestone.
- **Detections are heuristics, not proofs.** Treat findings as prompts for review.

---

## Roadmap

- **Dynamic canary harness** — drive a real agent loop against the server inside a sandbox
  seeded with canary secrets, with an egress proxy, and report which canaries left the box.
  This is what turns "this description looks like exfiltration" into "this server exfiltrated".
- **Continuous pin verification** as a client-side proxy, so drift is caught at connection
  time rather than at scan time.
- **Rule packs** loadable from YAML, so detections can ship without a release.

---

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
python fixtures/generate.py    # rebuild fixtures
```

## License

MIT

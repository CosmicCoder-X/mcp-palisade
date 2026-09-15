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
| **PAL030** | Credentials or sensitive local files named in a description (solicited: critical; honestly exposed: high) | Critical |
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

## Beyond patterns: the semantic layer

Every rule above matches a known shape: a phrase, a ratio, a name collision. That has a
ceiling. Nobody attacking a scanned MCP server in 2026 writes "ignore all previous
instructions" -- a competent attacker paraphrases, and a fixed pattern table has nothing to
match against.

`--semantic` sends the surface to an LLM and asks it to judge *intent* instead of
*vocabulary*, through either of two interchangeable backends -- **Claude** (`anthropic`,
default) or **Gemini** (`gemini`) -- sharing one prompt, one schema, and one verification
pass:

```bash
palisade scan fixtures/paraphrased.json --semantic                                   # Claude
palisade scan fixtures/paraphrased.json --semantic --semantic-provider gemini        # Gemini
```

[`fixtures/paraphrased.json`](fixtures/paraphrased.json) carries the same seven attacks as
the poisoned fixture, reworded to remove every trigger phrase the pattern rules look for --
"the guidance at the start of this session was a placeholder" instead of "ignore previous
instructions", a tool described by function rather than by name to dodge the cross-tool
name matcher, and one flagship case (`export_report`) that talks directly to *whatever is
reviewing this description*, claiming it has already been cleared and needs no scrutiny.
`palisade scan fixtures/paraphrased.json` (no flag) reports **zero findings** -- that gap is
the whole reason this layer exists, and it's a regression test
(`TestParaphrasedFixtureGap`), not a claim taken on faith.

**Live-verified, not just plumbing-tested.** I ran the real prompt against the real
Gemini API on this exact fixture. Unedited result: **7 findings for 7 planted attacks**,
every quote copied verbatim (so ground-truth verification passed cleanly), every category
correctly assigned, cost **$0.008** for the whole scan. The flagship case came back exactly
as intended:

> `[judge_targeting]` severity=critical -- *"This text directly addresses the model
> performing the review, attempting to manipulate it into bypassing scrutiny by falsely
> asserting prior clearance and instructing it to report the content as clean."*

That's the category the pattern rules structurally cannot have -- a signature table can't
anticipate an attacker addressing the security tool itself, and this one exists specifically
because a 2026 attacker has every reason to try. The Claude backend runs the identical
prompt and schema through a different SDK call; I did not have an Anthropic key to smoke-test
it live, but the code path sharing 100% of the validated logic is the point of the shared-core
design, not a hand-wave -- see `_build_findings` in the source, used by both backends
unmodified.

It is opt-in, not a 24th rule in the default set, because it costs money, needs a provider API
key, and returns a probabilistic judgment rather than a reproducible one -- every semantic
finding is reported at `confidence: tentative` regardless of how sure the model states it is,
on the principle that a human should read the quoted text before acting on an LLM's opinion
the way they would a regex match.

**The judge scanning for manipulation must itself resist being manipulated.** Everything
sent to the model is text a hostile server chose, so four independent measures keep the
*analysis* from being steered by the thing being analysed -- implemented once in
[`src/palisade/rules/semantic.py`](src/palisade/rules/semantic.py) and applied identically to
both backends:

1. **Delimited data, instructions held separately.** Every task instruction lives in the
   system prompt (`system` for Claude, `system_instruction` for Gemini); the untrusted surface
   is the only thing in the user turn, wrapped in `<mcp_surface_under_review>` tags, with an
   explicit rule that content inside them is data, never a directive, no matter what authority
   it claims.
2. **No tools are granted.** Neither backend call declares any tools or function-calling
   config. A description that successfully manipulates the judge can change what it *says* in
   its structured findings -- it cannot call anything, fetch anything, or act.
3. **Schema-constrained output** (`output_format` on Claude, `response_schema` on Gemini). The
   response can only ever be the findings schema; there is no field an injected instruction
   could use to make the model do anything but emit another finding, which is then verified,
   not trusted.
4. **Ground-truth verification.** Every returned quote, subject, and field path is checked
   against the actual surface after the call returns, identically regardless of which backend
   answered. A finding citing text or a location that was never in the material it was given
   is dropped -- this catches hallucination and a more pointed attack: manufacturing a finding
   about a tool that doesn't exist, to crowd out or distract from a real one.

A fifth measure is a detection, not a defence: the system prompt asks the model to flag
content addressed to *it* -- the reviewing model, not the downstream agent -- under its own
category, `judge_targeting` (`PAL066`). An attacker who assumes their server might be
scanned by an LLM judge, not just read by a human, has every reason to try talking to the
judge directly; catching that is a genuinely 2026 problem no signature table anticipates, and
it's the category that fired in the live run quoted above.

```bash
# Claude backend
pip install "mcp-palisade[semantic]"
export ANTHROPIC_API_KEY=sk-ant-...
palisade scan surface.json --semantic                                     # claude-opus-5
palisade scan surface.json --semantic --semantic-model claude-sonnet-5    # cheaper

# Gemini backend
pip install "mcp-palisade[semantic-gemini]"
export GOOGLE_API_KEY=...
palisade scan surface.json --semantic --semantic-provider gemini          # gemini-2.5-flash
```

A multi-server scan (`--config`) with the Claude backend shares one system prompt across every
call, so it's marked cacheable (`cache_control`) -- the fixed cost is paid once per process,
not once per server. Each call prints its own usage line to stderr regardless of backend
(tokens -- including Gemini's hidden reasoning tokens, which Google bills at the output rate
-- and an estimated cost from the current published rates), and a server the judge can't reach
(bad key, rate limit, network error) is skipped with a warning rather than failing the whole
scan -- the free static results for every other server still come back.

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

Three fixtures ship with the repo: a clean weather server, a server carrying one instance of
every pattern-rule attack class, and a server carrying the same attacks paraphrased past
every signature (see the semantic layer, below):

```bash
palisade scan fixtures/benign.json        # no findings
palisade scan fixtures/poisoned.json      # every pattern rule, with decoded payloads
palisade scan fixtures/paraphrased.json   # no findings -- that's the point, see below
```

The poisoned fixture is generated by [`fixtures/generate.py`](fixtures/generate.py) rather
than written by hand, because several attacks depend on exact invisible code points that do
not survive being copied out of an editor.

On a real server, the numbers should be small. Scanning the official MCP reference server
produces four findings: one `high` for a tool that returns every environment variable, and
three `medium` for state-changing tools that declare no behavioural hints. All four are
true.

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

**Wording is part of correctness.** Naming `~/.ssh/id_rsa` can mean two different things: a
tool telling the model to go and fetch it, or a tool honestly documenting what it returns.
PAL030 decides which reading applies from the verb governing the match, and reports the
second as a capability worth confirming rather than a server worth rejecting. A finding whose
remediation does not fit its cause is a finding people learn to skip.

---

## Limitations

Worth stating plainly, because a scanner that oversells itself is worse than none:

- **Static analysis sees only what the server chose to send at capture time.** A server can
  serve a clean surface to a scanner and a poisoned one to a real client. Pinning narrows
  this but does not close it; only a client that verifies pins on every connection does.
- **PAL015 is a heuristic** and will flag some verbose but honest descriptions. It is scoped
  to `medium` for that reason.
- **The semantic layer (`--semantic`) is inherently probabilistic, and its judgment can shift
  between runs of the same fixture** -- two live runs against Gemini on
  `fixtures/paraphrased.json` returned 7 and 10 findings respectively (the same 7 attacks
  every time, plus a couple of secondary observations on the reworded-away-from-`quietly`
  concealment tool on one run but not the other). Treat it as a second opinion, not ground
  truth. The Claude backend shares the identical prompt/schema/verification code but was only
  unit-tested against a mocked client, not smoke-tested live -- see the semantic layer section
  above. It is also not free and not instant: budget one API call per server scanned.
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
pip install -e ".[dev,semantic,semantic-gemini]"
pytest
ruff check src tests
python fixtures/generate.py    # rebuild fixtures
```

The test suite never calls a real LLM API -- `tests/test_semantic.py` drives `SemanticJudge`
through fake clients for both backends, so `pytest` needs no API key and costs nothing to run.

## License

MIT

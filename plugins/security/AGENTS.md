# vuln-audit — agent & design spec

A Claude Code **skill + workflow** that runs a white-box, dynamically-verified
security audit of a target repository: a
multi-phase pipeline (recon → triage → deep review → adversarial verify →
dynamic repro → report) that produces **proven, high-signal findings with
patches**, not speculative noise.

> Read this file before touching the workflow or prompts. It is the source of
> truth for the data contracts, taxonomy, severity model, and signal policy.

## Invocation

```
/security:audit /path/to/target-repo [--no-dynamic] [--classes injection,ssrf] [--out <dir>]
```

The skill (`skills/audit/SKILL.md`) is the agent-facing entry point. It parses the
target, picks a writable `outDir`, preflights host capabilities, then calls the
workflow (`workflows/vuln-audit.js`) with everything assembled in `args` —
`toolRoot` = `${CLAUDE_PLUGIN_ROOT}` (read-only, holds the prompts), `outDir` =
where the bundle is written.

## Pipeline

| Phase | What | Primitive |
|-------|------|-----------|
| 1. Recon | Detect stack, map attack surface & trust boundaries, pick run strategy, select relevant finder classes | single agent (`prompts/recon.md`) |
| 2. Triage | One finder per vuln class scans its surface, emits candidate findings | `parallel()` finders |
| 3. Dedup | Collapse same-root-cause findings across call sites | plain JS in the workflow |
| 4. Deep review | Re-examine each candidate with surrounding context (callers, sanitizers, related files); confirm a reachable source→sink path | `pipeline()` stage |
| 5. Adversarial verify | Independent skeptics, each a distinct lens, try to **refute** the finding; majority-refute kills it | `parallel()` skeptic panel |
| 6. Dynamic repro | Survivors are built & run in an isolated git **worktree** (docker-first); a real PoC is fired and impact observed | `agent(..., {isolation:'worktree'})` |
| 7. Report | Synthesize the senior-engineer report (`prompts/report-template.md`) | single agent |

## Reference evaluation (why we adopt what we adopt)

- **Anthropic security-guidance** (`code.claude.com/docs/en/security-guidance`)
  — **adopt methodology.** Validates our core moves: (a) review independence —
  the reviewer is a *fresh-context* agent, never the author, "instructed only to
  find problems"; (b) read callers/sanitizers/related files before reporting to
  keep false positives low. Our tool is the deepest layer: in-session plugin →
  `/security-review` (branch) → Code Review (PR) → **vuln-audit (on-demand,
  dynamically verified PoCs)**. We honor its extension convention: if the target
  has a `.claude/claude-security-guidance.md`, we load it as extra threat-model
  context.
- **OWASP Top 10:2025** — **adopt as primary taxonomy.** Current edition; new
  categories A03 Software Supply Chain Failures and A10 Mishandling of
  Exceptional Conditions; SSRF folded into A01. Every finder maps to a 2025 ID.
- **OWASP ASVS v5.0** (17 chapters, ~350 reqs) — **reference only, not a walked
  checklist.** Walking 350 requirements is exactly the low-signal sidetrack we
  avoid. Used two ways: (a) coverage map so the finder taxonomy has no blind
  spots; (b) cite a requirement/chapter ID in findings as a terse, authoritative
  reference for senior readers.
- **OSSF Scorecard** — **partial adopt, code-exploitable checks only.** Scorecard
  scores project *hygiene/posture* (Maintained, License, SBOM, Security-Policy,
  Contributors) — out of scope for findings. But its CI/CD checks ARE real
  exploitable issues and feed our `supply-chain` finder: Dangerous-Workflow
  (`pull_request_target` + untrusted checkout, `${{ }}` script injection),
  Token-Permissions (over-broad `GITHUB_TOKEN`), Pinned-Dependencies (unpinned
  actions/deps), Vulnerabilities (known-vuln deps via OSV). Posture/process
  checks are relegated to the Info appendix, never the high-priority body.

## Vuln-class taxonomy (finders)

Each maps to OWASP Top 10:2025 + CWE + an ASVS v5.0 chapter. One prompt file per
class under `prompts/finders/<key>.md`.

| key | title | OWASP 2025 | ASVS |
|-----|-------|-----------|------|
| access-control | Broken Access Control & IDOR | A01 | V8 |
| ssrf | Server-Side Request Forgery | A01 | V4 |
| injection | Injection (SQL/NoSQL/OS/LDAP) | A05 | V1/V2 |
| xss-ssti | XSS & Template Injection | A05 | V1/V3 |
| auth-session | Authentication & Session | A07 | V6/V7/V9/V10 |
| crypto | Cryptographic Failures | A04 | V11 |
| deserialization | Insecure Deserialization & Integrity | A08 | V2/V15 |
| path-file | Path Traversal & File Handling | A01 | V5 |
| secrets | Hardcoded Secrets & Credentials | A02 | V14 |
| misconfig | Security Misconfiguration | A02 | V13 |
| supply-chain | Software Supply Chain & CI/CD | A03 | V15 |
| logging-errors | Logging, Error & Exception Handling | A09/A10 | V16 |
| dos-redos | Denial of Service & ReDoS | A06 | V2 |
| csrf-cors | CSRF, CORS & Clickjacking | A01 | V3 |

Insecure Design (A06) is cross-cutting and handled in recon/synthesis, not a
grep-able finder.

## Data contracts

### Finding (finders + deep review)
`id` · `title` · `vuln_class` · `owasp` (A0x:2025) · `cwe` · `asvs` ·
`severity` (critical|high|medium|low|info) · `status` (confirmed|likely|triage) ·
`confidence` (low|medium|high) · `file` · `line` · `end_line` ·
`code_excerpt` · `source` (untrusted origin) · `sink` (dangerous op) ·
`data_flow` (source→sink, sanitizers noted) · `sanitizers_checked` (mitigations
verified absent/ineffective — the FP guard) · `rationale` · `exploit_sketch` ·
`dynamic_poc_plan` · `proposed_fix` (high-level direction of the change, not a
patch — implementation is left to whoever takes the issue).

After the pipeline, each finding is also stamped with `fp` (stable fingerprint =
`djb2(vuln_class | file | sink)`, the cross-scan dedup key), `display_id`
(`<slug>-<CLASS>-<fp4>`, provisional until the courier swaps in the GitHub issue
number), `status`, `kept`, `reject_reason`, `verdicts`, and `repro`.

### Verdict (adversarial verify)
`finding_id` · `lens` · `refuted` (bool) · `confidence` · `reasoning`.

### Repro (dynamic verify)
`finding_id` · `reproduced` (bool) · `method`
(live-exploit|unit-test|build-only|static-poc) · `environment` ·
`setup_commands` · `poc` · `observed` (evidence) · `impact` · `notes`.

## Severity model (exploitability × impact)

- **Critical** — remote, unauth → RCE / full data breach / auth bypass; reachable.
- **High** — low barrier (authenticated or realistic conditions); significant
  impact (priv-esc, sensitive data, injection with a real sink).
- **Medium** — unusual conditions or limited impact, or partial mitigations.
- **Low** — minor info leak, defense-in-depth gap, hard to exploit.
- **Info** — hygiene/posture, no direct exploit path.

`status` is orthogonal and drives report placement: **confirmed** (dynamically
reproduced or statically proven + survived verify), **likely** (strong proof, no
live repro), **triage** (unverified / split verdicts). Only confirmed+likely go
in the report body; triage goes to an appendix.

## Signal discipline (the anti-noise contract)

The report is for senior engineers. Stay high-signal — enforced in deep review
and verify:

- Report only issues with a **reachable** path from untrusted input to a
  dangerous sink. Check for sanitizers/validators/authz on the path first; if
  present and effective, drop it.
- No style/lint nits. No generic "defense-in-depth" without a concrete sink. No
  unreachable/dead code.
- Posture/process items (missing SECURITY.md, SBOM, license, maintainership) →
  Info appendix only, never the body.
- Dedup: one finding per root cause, list N locations.
- Prefer few proven findings over many speculative ones. Every High+ finding
  carries a PoC or an explicit source→sink trace.

## Layout

```
.claude-plugin/plugin.json           # plugin manifest (name: security)
skills/audit/SKILL.md                 # agent-facing orchestrator (/security:audit)
workflows/vuln-audit.js              # the Workflow script (the engine)
prompts/recon.md                     # phase-1 recon prompt
prompts/finders/<key>.md             # one finder prompt per vuln class
prompts/playbooks/<key>.md           # per-ecosystem build/run/exploit playbook
prompts/report-template.md           # the report format (phase 7)
docs/issue-tracking.md               # output bundle → GitHub issues + naming rules
```
(The output bundle is written to a writable `outDir`, NOT into the plugin root,
which is read-only/ephemeral.)

Schemas live inline in the workflow (the JS sandbox has no filesystem access at
runtime); prose content lives in `prompts/` so it is editable without touching
the script, and is passed into the workflow via `args`.

## Output bundle (VM → courier handoff)

The scan runs on a VM and emits a self-contained **bundle** at
`reports/<slug>/`; a separate "courier" agent SSHes in, fetches it, and files the
issues (the courier holds the only GitHub creds — the VM holds none). Bundle:

- `report.md` — the human report (findings referenced by `display_id`).
- `findings.json` — the structured findings array, verbatim; the machine
  interface the courier reconciles against, **keyed by `fp`**.
- `manifest.json` — `{ tool, schema, repo (owner/repo), target_path, ref,
  commit, slug, date, dynamic, classes_assessed, counts }`; `repo` tells the
  courier where to file.
- `evidence/` — optional captured PoC output (repro evidence also lives inline
  in `findings.json`).

**Issue tracking & the vulnerability ID/naming rules** (scan epic → finding
sub-issues, reconcile by `fp`, `display_id` = `<slug>-<CLASS>-<issue#>`, the
courier emitter, and what each host needs) live in
[`docs/issue-tracking.md`](docs/issue-tracking.md) — the portable source of truth
that travels with the repo.

## Runtime notes (gotchas)

- **`args` arrives as a JSON string.** The Workflow runtime delivers the `args`
  payload to the script as a JSON *string*, not a parsed object (verified
  empirically). `vuln-audit.js` normalizes it (`typeof args === 'string' ?
  JSON.parse(args) : args`) before reading any input — do not remove this.
- **Invoke by `scriptPath`, not `name`, mid-session.** Named-workflow discovery
  only registers files that existed at session start.
- **Subagents have full tools** (Read/Grep/Bash/Write/ast-grep, and web via
  ToolSearch) and operate on the *target*; only the orchestration JS is
  sandboxed. Dynamic repro creates its own `git worktree` of the target — the
  `isolation:'worktree'` option is about the tool repo and is not used here.
- **Host adaptivity:** pass `hostNotes` so recon picks a runnable strategy
  (docker vs native) the host can actually execute.

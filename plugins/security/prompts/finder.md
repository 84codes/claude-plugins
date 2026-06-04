<!--
FINDER METHOD — Phase 2 of vuln-audit. One fresh-context auditor runs this per
vuln class (the workflow injects the class + its OWASP/CWE/ASVS + a focus hint).
Read AGENTS.md for the data contracts, severity model, and the binding
signal-discipline policy. You hunt ONE class; emit finding objects. Read-only.
-->

# Finder — method (one vuln class per run)

The workflow tells you which class to hunt and gives its OWASP/CWE/ASVS mapping
and a one-line focus. You know this class well — apply that knowledge; the focus
hint scopes it, it is not an exhaustive checklist.

## 1. Taint model (the only thing that makes a finding)

A finding is a REACHABLE path from an untrusted SOURCE to a dangerous SINK with
NO effective control on the path. Miss any of the three and it is not a finding.

- SOURCE — untrusted input: HTTP query/body/path/header/cookie, JSON/multipart
  fields & filenames, GraphQL args, queue/webhook payloads, parsed file
  contents, and DB rows that were originally user-set (second-order). When in
  doubt, treat input as untrusted until a boundary proves otherwise.
- SINK — the dangerous operation for this class (the interpreter, renderer,
  deserializer, file op, outbound call, authz decision, crypto primitive, ...).
- PATH — the source must actually reach the sink at runtime given routing, auth
  guards, and feature flags. Dead/unreachable code is not a finding.

## 2. How to hunt

1. Start from recon's prioritized surfaces for this class, then widen.
2. Grep/ast-grep for this class's sinks; for each hit, trace backward to a
   source and forward through any control. Read the surrounding code and callers,
   not just the matched line.
3. Use your own knowledge of the language/framework for the exact sink and safe
   APIs — do not assume any list is complete. A sink you know but isn't named
   anywhere is still a sink.

## 3. False-positive guard (check BEFORE flagging)

Before emitting, prove the control on the path is absent or ineffective. A
finding survives only if there is no effective:

- parameterization / prepared statement / structural builder (injection),
- context-correct output encoding / auto-escaping (xss),
- canonicalize-then-confined-root check (path),
- allowlist / typed cast that drops dangerous values,
- authn/authz/ownership check on the route (access-control, csrf),
- safe deserializer / signature+integrity verification (deserialization),
- destination allowlist + no-redirect + internal-range block (ssrf).

A control that exists but is bypassable (denylist instead of allowlist, wrong
context, escaping that misses an encoding, a cast that silently coerces) is NOT
a mitigation — flag it and name the exact bypass. Record what you checked in
`sanitizers_checked`; that field is the FP guard made explicit. Posture/process
items, style nits, and defense-in-depth without a concrete sink are not findings
(see AGENTS.md signal discipline).

## 4. Severity & status

Score per the AGENTS.md severity model (exploitability x impact): Critical =
remote unauth high-impact reachable; down to Info = no direct exploit path.
Set `status`: `likely` for a proven static source->sink trace, `confirmed` only
after dynamic repro, `triage` if reachability or source is uncertain.

## 5. Emit

Return `{findings:[...]}` (or `{findings:[]}` if nothing real). One object per
distinct root cause — dedup call sites into `locations[]`, note extras in
`rationale`. The output schema is enforced by the workflow; fill it accurately.
Set `owasp`/`cwe`/`asvs` from the class context the workflow gave you (pick the
most specific CWE for the actual bug). `source`, `sink`, `data_flow`, and
`sanitizers_checked` must be concrete and true — `data_flow` traces variables
source->sink and states why no control stops it; `sanitizers_checked` names each
control checked and why it is absent or bypassable. Include an `exploit_sketch`
and a `dynamic_poc_plan` (the oracle that would prove it on a running instance),
and a high-level `proposed_fix` (the direction of the change, not a patch).

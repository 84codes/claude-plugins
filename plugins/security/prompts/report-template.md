<!--
AGENT GUIDANCE — read, do not emit this comment block.

You are writing the final audit report for SENIOR ENGINEERS who understand
security. Optimize for signal and brevity.

Rules:
- Lead with the worst. Sort findings by severity desc, then status.
- Body = Critical/High/Medium that are `confirmed` or `likely` ONLY.
  Low/Info and `triage` candidates go in the appendix. Never bury a Critical
  under a pile of nits.
- Per finding: 2–4 sentences of prose, max. Assume the reader knows what SSRF
  is. Explain THIS instance, not the vuln class.
- References do the heavy lifting instead of prose: cite terse linked IDs
  (CWE-89, A05:2025, ASVS V1.2.4). One line of refs, not a paragraph.
- Evidence is the point. Every confirmed finding shows the PoC command and the
  observed result. A finding without evidence or a source→sink trace does not
  belong in the body — move it to triage.
- Proposed fix = the high-level DIRECTION of the change (what must change and
  why), 1–2 sentences. NOT a diff, exact code, or step-by-step patch — the actual
  implementation is the next human/agent's job.
- If there are zero Critical/High, say so plainly in the summary — that is a
  good result, not a reason to inflate Mediums.
- NO status/tally table. The GitHub scan issue and its sub-issues are the live
  status (open/fixed); duplicating it here just goes stale. Weave the counts into
  the summary prose ("one critical and one high, both confirmed"). Verification
  status (confirmed/likely) stays as each finding's badge.
- Render the commit SHA BARE — no backticks. The report lands in GitHub issues,
  which auto-link a bare 7–40 char hex SHA to its commit page; backticks make it
  inert code and kill the link. Same for any other bare commit hash you cite.
- Omit empty sections.
-->

# Security Audit — {{target}} @ {{ref}}

**Scope:** {{paths_in_scope}} · **Out of scope:** {{paths_excluded}}
**Commit:** {{commit}} · **Date:** {{date}} · **Method:** static + dynamic (isolated worktree, live PoC) · **Tool:** vuln-audit {{version}}

## Summary

{{2–4 sentences: overall posture and the single most important thing to fix
first. Name the dominant risk theme. Weave the counts into the prose (e.g. "one
critical and one high, both confirmed; one medium") — no status table, the
GitHub scan issue is the live status.}}

## Findings

<!-- One block per confirmed/likely Critical/High/Medium. Repeat. -->

### [{{id}}] {{title}} · {{Severity}} · {{Confirmed|Likely}}

**Class:** {{vuln_class}} · **Refs:** [{{CWE}}](https://cwe.mitre.org/data/definitions/{{n}}.html) · [{{A0x:2025}}](https://owasp.org/Top10/) · [ASVS {{Vx.y.z}}](https://github.com/OWASP/ASVS)
**Location:** `{{file}}:{{line}}`{{ · +N other call sites}}

{{2–4 sentences: the specific flaw, the untrusted source, the sink, and why the
path is reachable (no effective sanitizer/authz). Senior audience — be direct.}}

**PoC**
```
{{$ command that reproduced it}}
{{observed output that proves impact}}
```

**Impact:** {{one line.}}
**Proposed fix:** {{1–2 sentences — the high-level direction of the change needed
and why (e.g. "resolve identity from a server-side session keyed by user id, not
the client cookie"). NOT a diff or line-level patch — implementation is left to
whoever picks up the issue.}}

---

## Lower severity (Medium)

<!-- Confirmed/likely Mediums as one-liners. -->
- `{{file:line}}` — {{one-line description}} — {{ref}} — **fix:** {{one-liner}}

## Appendix

### Low / Info
| Location | Note | Ref |
|----------|------|-----|
| `{{file:line}}` | {{one line}} | {{ref}} |

### Triage — not confirmed
<!-- Candidates that did not survive verification or could not be reproduced.
     Listed for transparency so reviewers can re-check; not asserted as bugs. -->
- `{{file:line}}` — {{candidate}} — **why unconfirmed:** {{refuted by verify / could not reproduce / needs prod-like data}}

### Coverage & method
- **Classes assessed:** {{list}} · **Skipped (not applicable):** {{list}}
- **ASVS chapters touched:** {{list}}
- **Dynamic verification:** {{how the target was built/run; what was and wasn't reproducible and why}}
- **Tools used:** {{semgrep/gitleaks/trivy if present, else "LLM-native"}}
- **Blind spots:** {{anything not reachable by this audit — auth-gated areas, external services, etc.}}

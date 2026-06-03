# security (vulnerability audit)

A white-box, **dynamically-verified** security-audit plugin for internal
pentests. `/security:audit` points at a repo you own, recons it, hunts
vulnerabilities across the OWASP Top 10:2025 classes, **proves them with live
PoCs in isolated git worktrees**, and writes a terse, senior-engineer report —
proven findings with a high-level proposed fix, not speculative noise.

## Install

```
/plugin marketplace add 84codes/claude-plugins
/plugin install security@84codes
```

Then run `/reload-plugins` if the command doesn't appear.

## Usage

```
/security:audit /abs/path/to/target-repo
/security:audit /abs/path/to/target-repo --no-dynamic
/security:audit /abs/path/to/target-repo --classes injection,ssrf,access-control --ref v1.2.0
/security:audit /abs/path/to/target-repo --out /abs/writable/dir
```

The output **bundle** is written to `<cwd>/vuln-audit-reports/<slug>/` (or
`--out`): `report.md` + `findings.json` + `manifest.json`.

## How it works

```
recon → triage → consolidate → deep review → adversarial verify → dynamic PoC → report
```

| Phase | Purpose |
|-------|---------|
| Recon | Detect stack, map attack surface, pick relevant vuln classes + run strategy. |
| Triage | One finder agent per relevant class emits candidates. |
| Consolidate | Dedup by root cause, assign IDs, drop low-signal noise. |
| Deep review | Confirm a reachable source→sink path with no mitigation. |
| Adversarial verify | Independent skeptics try to refute each finding; majority kills it. |
| Dynamic PoC | Build + run the target in an isolated worktree; fire a real exploit. |
| Report | Senior-engineer report: severity-first, reference-backed, PoC-evidenced. |

## Requirements

- `git` (target must be a git repo for worktree isolation + the live-PoC phase).
- `docker` for dynamic verification (works via `sudo` if the daemon needs it);
  otherwise repro falls back to unit-test/static PoCs (`--no-dynamic` skips it).
- No security scanners required — the tool is LLM-native and uses
  `semgrep`/`gitleaks`/`trivy` only opportunistically if present.

## Output & issue tracking

Findings carry a stable fingerprint (`fp`) and a `display_id`
(`<slug>-<CLASS>-<n>`). The bundle is designed to be filed to GitHub issues by a
separate courier step (scan epic + per-finding sub-issues for Critical/High/
Medium, reconciled by `fp`). See [`docs/issue-tracking.md`](docs/issue-tracking.md).

## Design

Full pipeline spec, vuln-class taxonomy (OWASP 2025 + CWE + ASVS), data
contracts, and the signal-discipline policy are in
[`AGENTS.md`](AGENTS.md).

## Safety & scope

Authorized testing only — audit repositories you own or are explicitly cleared
to test. All PoC traffic is contained to local processes/containers; the tool
never fires exploits at external hosts, uses real credentials, or exfiltrates
data.

## License

MIT

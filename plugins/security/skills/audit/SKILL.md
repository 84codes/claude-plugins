---
description: >-
  Run a white-box, dynamically-verified security audit (internal pentest) of a
  target code repository. Use when the user asks to audit/pentest a repo for
  vulnerabilities, find security bugs with proof, or runs /security:audit.
  Produces a terse, senior-engineer report of proven findings with live PoCs and
  a high-level proposed fix per finding.
---

# security:audit

Drives the bundled `vuln-audit` workflow: recon → triage → consolidate → deep
review → adversarial verify → dynamic PoC → report. Design spec and data
contracts are in `${CLAUDE_PLUGIN_ROOT}/AGENTS.md`; output handling / issue
tracking in `${CLAUDE_PLUGIN_ROOT}/docs/issue-tracking.md`. Read the spec before
changing anything.

## Input

```
/security:audit <target-path> [--no-dynamic] [--classes a,b,c] [--ref <git-ref>] [--out <dir>]
```

`$ARGUMENTS` holds the target path and any flags.

- `<target-path>` — absolute path to the repo to audit (required).
- `--no-dynamic` — skip the build/run/PoC phase (static + adversarial verify only).
- `--classes` — restrict to specific vuln-class keys (see `AGENTS.md` taxonomy).
- `--ref` — git ref to audit (default `HEAD`).
- `--out` — writable directory for the output bundle (default: `<cwd>/vuln-audit-reports`).

## Steps

1. **Parse `$ARGUMENTS`** into the target path + flags. The bundled tool root is
   `${CLAUDE_PLUGIN_ROOT}` (expands to the plugin's install dir; it holds
   `prompts/`, `workflows/`, and the docs — read-only).
2. **Pick a writable `outDir`** — the plugin root is read-only/ephemeral, so the
   bundle must go elsewhere. Use `--out` if given, else `<cwd>/vuln-audit-reports`
   (absolute path). This is also where a courier later fetches the bundle from.
3. **Validate the target** — confirm it exists and is a git repo
   (`git -C <target> rev-parse --git-dir`). Worktree isolation and the live-PoC
   phase need git. If it isn't a repo, warn and proceed with `--no-dynamic`.
   Resolve the ref to a concrete commit with
   `git -C <target> rev-parse --short <ref or HEAD>` so the run is pinned and
   reproducible; carry both the ref name and the resolved SHA.
4. **Preflight host capabilities** → assemble a `hostNotes` string: is `docker`
   usable non-interactively (note if it needs `sudo`); which native runtimes are
   present (`python3`, `node`, `ruby`, `go`, `crystal`, ...). If dynamic is on
   but neither docker nor a usable native runtime exists, fall back to
   `--no-dynamic` and say repro will be static/unit-test only.
5. **Check target threat-model** — note whether
   `<target>/.claude/claude-security-guidance.md` exists; recon folds it in.
6. **Announce the run** — before invoking, print a one-line startup summary:
   target name, the resolved commit (short SHA), and the absolute output
   directory. Name the ref only when it isn't `HEAD` (e.g. `v1.2.0 a1b2c3d`);
   for a plain `HEAD` run just show the SHA. Drop anything left at its default.
7. **Invoke the workflow** (it runs in the background and notifies on completion):
   ```
   Workflow({ scriptPath: '${CLAUDE_PLUGIN_ROOT}/workflows/vuln-audit.js', args: {
     toolRoot: '${CLAUDE_PLUGIN_ROOT}',
     outDir: '<abs writable outDir>',
     target: '<abs target-path>',
     ref: '<ref or HEAD>',
     dynamic: <true unless --no-dynamic>,
     onlyClasses: <array or omit>,
     scope: '<what is in/out of scope>',
     hostNotes: '<from step 4>'
   }})
   ```
8. **Present the result** — when it completes, read `report_path` and give a
   tight summary: severity counts and the top 1–3 confirmed findings (title +
   location + one-line impact). Point to the bundle dir; don't paste the whole
   report. Surface anything that blocked dynamic verification.

## Notes

- High-signal is the contract: the workflow drops noise, posture/process items,
  and unreachable findings on purpose. Don't reintroduce them in the summary.
- The report's remediation is a **high-level proposed fix** (direction, not a
  patch) — implementation is left to whoever takes the finding.
- This is the deepest layer of defense-in-depth, complementing the in-session
  security-guidance plugin, `/security-review`, and PR Code Review.
- Authorized testing only: target repos you own or are explicitly cleared to
  audit. All PoC traffic stays local; never fire exploits at external hosts.

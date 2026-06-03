# Output handling — findings → GitHub issues

How a scan's findings become tracked, fixable, closeable GitHub issues. This is
the source of truth for the **vulnerability ID / naming rules** and the
scan→courier→GitHub pipeline. (Design locked 2026-06-02.)

## Topology: scanner VM + courier

Scans run on a **VM**; a separate **courier** agent SSHes in, fetches the scan's
output, and files it to GitHub. The two run on different hosts on purpose:

- The **VM** runs `/security:audit`, handles untrusted code and working exploits, and
  holds **no GitHub credentials**.
- The **courier** holds the only GitHub creds, fetches the bundle read-only over
  SSH, and creates/updates issues. It is a *pure function of the bundle* — it
  needs no access to the target source or the VM's git state.

## The bundle (the scan→courier interface)

Each scan drops a self-contained bundle at `reports/<slug>/` on the VM:

| File | Purpose |
|------|---------|
| `report.md` | Human report (findings headed by `display_id`). |
| `findings.json` | Structured findings array, **verbatim**; the machine interface, **keyed by `fp`**. |
| `manifest.json` | `{ tool, schema, repo (owner/repo), target_path, ref, commit, slug, date, dynamic, classes_assessed, counts }`. `repo` tells the courier where to file. |
| `evidence/` | Optional captured PoC output (repro evidence also lives inline in `findings.json`). |

## Vulnerability ID / naming rules

- **Fingerprint** `fp = djb2(vuln_class | file | sink)` (lowercased; line number
  excluded to reduce churn). This is the **stable, cross-scan dedup key** — same
  bug → same `fp`, computed identically on the VM and the courier with no shared
  state. Stored on each issue as a `fp:<hash>` label.
- **Display ID** `<slug>-<CLASS>-<n>` — e.g. `training-tool-AC-42`. `<slug>` is the
  repo name, `<CLASS>` the short class code (AC, SSRF, INJ, XSS, AUTH, CRYPTO,
  DESER, PATH, SEC, MISC, SUPPLY, LOG, DOS, CSRF), and **`<n>` is the GitHub issue
  number**. So `training-tool-AC-42` *is* `84codes/training-tool#42` — one number,
  both meanings, permanent (GitHub never reuses issue numbers).
- **Provisional form** `<slug>-<CLASS>-<fp4>` (first 4 hex of `fp`, e.g.
  `training-tool-AC-b4a0`) — used in the VM-side `report.md` *before* an issue
  exists. The courier stamps the final `-<issue#>` ID into the issue at filing;
  `fp` is the glue linking the two forms.
- Numbers are **not contiguous per class** (GitHub shares the counter with PRs and
  other issues) — that is fine; the class prefix carries the meaning.

## Issue model

- **Scan issue** (epic), one per run: holds the report (as a comment, see
  **Report comment** below) + general comments; closes when all its finding
  sub-issues close.
- **Finding sub-issue**, one per **Critical / High / Medium** (confirmed+likely).
  **Low/Info stay in the report appendix — never issues** (same high-signal
  contract as the report).
- **Title:** `[Critical] training-tool-AC-42: <short title> (access-control)`.
- **Body:** the report's finding block (refs · location · PoC · impact ·
  proposed fix) + backlink to the scan issue + the `fp` marker.
- **Labels:** `security`, `security-scan` (epic), `sev:{critical,high,medium}`,
  `vuln:<class>`, `fp:<hash>`, `status:{confirmed,likely}` (verification outcome).
- **Two distinct "statuses":** *verification* (confirmed/likely — a scan output,
  carried as the finding's badge + the `status:` label) vs *lifecycle*
  (open/fixed — owned entirely by the GitHub issue). The **report has no status
  table**; the scan epic and its sub-issues are the live status.
- **PoC handling:** repos are private/internal, so full PoC commands go in the
  issues (the remediation is a high-level *proposed fix*, not a patch). (If a target were public, use GitHub Security Advisories for
  Critical/High instead.)
- **Report comment:** the full `report.md` is **embedded** in a comment on the
  scan epic, wrapped in a `<details><summary>…</summary>` block (collapsed by
  default) so the long report never buries the epic's sub-issue checklist. Always
  embed the report text itself — **never** reference a local bundle path
  (`reports/<slug>/…`) or any filesystem location, which is unreachable from
  GitHub. The epic body points readers to this comment, not to disk.

## Reconcile algorithm (idempotent, keyed by `fp`)

For each Critical/High/Medium finding in `findings.json`, look up existing issues
by the `fp:<hash>` label (`gh issue list --search "label:fp:<fp>" --state all`):

- **no match** → create the finding issue, link it under the scan epic.
- **open match** → comment "still present in scan `<id>`" (no duplicate).
- **closed match that still reproduces** → reopen as a regression + comment.
- **previously open, now absent / not reproduced** (dynamic re-verify) → comment +
  close.

The **report comment** on the epic is upserted the same way: tag it with a
hidden marker (`<!-- vuln-audit:report -->`), then find-and-edit that comment
on re-run instead of posting a new one — so the epic never accumulates
duplicate report blocks.

Re-running the courier on the same bundle is a no-op. The dynamic-repro phase
doubles as the fix-verifier, so "everything closed when done" is provable, not
manual.

## Close loop

Fix PRs use `Fixes #N` to auto-close the finding issue on merge; the next scan
confirms via dynamic re-verify. When all finding sub-issues are closed, the scan
epic closes.

## Build status

1. **Done (2026-06-02)** — the workflow emits the bundle and stamps `fp` +
   provisional `display_id`. See `workflows/vuln-audit.js`.
2. **Not built yet** — the `/security:track <bundle-dir>` courier skill +
   `gh` emitter. Blocked on `gh` being installed + authed on the courier host.
3. **Always gated** — creating real issues on a repo needs an explicit go-ahead.

## What each host needs

| Host | Role | Requirements |
|------|------|--------------|
| **VM (scanner)** | runs `/security:audit`, produces the bundle | Claude Code · this repo · `git` · `docker` · **no `gh`, no GitHub creds** |
| **Courier** | fetches bundle, files issues | Claude Code · this repo (for `/security:track`) · **`gh` + `gh auth login`** (token: Issues read/write) · **SSH key to the VM** (`ssh`/`rsync`) · `jq` (optional) |

Sub-issue linking uses GitHub's GraphQL API, which `gh api graphql` covers — no
extra tooling.

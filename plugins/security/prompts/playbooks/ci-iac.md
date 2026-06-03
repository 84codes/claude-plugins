# ENV Playbook — CI & Infrastructure-as-Code

Reproduce a candidate finding in a CI / Infrastructure-as-Code target: GitHub
Actions / Forgejo-Gitea / GitLab CI workflows, Terraform (`*.tf`), Kubernetes
manifests, Helm charts, and Dockerfiles. **This stack is almost never run
live** — there is no long-lived server to exploit with an HTTP request. The
repro is overwhelmingly **static**: a line-referenced trace from an untrusted
source (a fork PR title, an issue/comment body, a branch name) to a dangerous
sink (a `run:` shell step, a privileged token, attacker-controlled checkout),
backed by **actionlint / tfsec-trivy / hadolint / checkov** output and, where it
adds fidelity, a **local containerized re-enactment** of the injected command.
Keep ALL traffic and side effects inside a local container — no external hosts,
no real credentials, no data exfiltration, and **never push to or call a real
forge / cloud / registry**.

Conventions used below (substitute per finding):

- `FID` — the finding id (e.g. `f3`); use it to make names/ports unique so
  parallel repros never collide.
- `WT=/tmp/va-$FID` — isolated git worktree path.
- `CN=va-$FID` — container name. `IMG=va-$FID:repro` — image tag (only when a
  Dockerfile is the finding's subject).
- The final repro result must set `method` to one of:
  `live-exploit | unit-test | build-only | static-poc`. For this stack the
  realistic outcomes are **`static-poc`** (the default — proven injection trace
  + linter confirmation) and **`unit-test`** (re-enact the injected command in a
  local container and observe its effect). `live-exploit` and `build-only` are
  rare here and called out where they apply.

---

## 1. Detect

Confirm the stack from the target tree (read-only):

```sh
# CI/CD workflow definitions (GitHub, Forgejo/Gitea, GitLab, others):
ls -d .github/workflows .forgejo/workflows .gitea/workflows 2>/dev/null
find . -maxdepth 3 \( -path '*/.github/workflows/*.y*ml' \
  -o -path '*/.forgejo/workflows/*.y*ml' -o -path '*/.gitea/workflows/*.y*ml' \
  -o -name 'action.y*ml' -o -name '.gitlab-ci.yml' -o -name 'Jenkinsfile' \
  -o -path '*/.circleci/config.yml' -o -name 'azure-pipelines.yml' \) 2>/dev/null

# Infrastructure-as-Code:
find . -maxdepth 4 \( -name '*.tf' -o -name '*.tfvars' -o -name '*.hcl' \) 2>/dev/null | head
ls Chart.yaml values.yaml kustomization.yaml 2>/dev/null
find . -maxdepth 3 -name '*.y*ml' -exec grep -lE '^(apiVersion|kind):' {} \; 2>/dev/null | head  # k8s manifests
find . -maxdepth 3 \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name 'Containerfile' \) 2>/dev/null
```

Signals and what each means:

- **`.github/workflows/*.yml|*.yaml`** → GitHub Actions. **`.forgejo/workflows/`
  / `.gitea/workflows/`** → Forgejo/Gitea Actions: the *same* `${{ }}` expression
  model, `uses:` action references, and trigger semantics as GHA. **`action.yml`**
  at a repo root or under `actions/` → a composite/JS/Docker action (its own
  injection surface). **`.gitlab-ci.yml` / `Jenkinsfile` / `.circleci/config.yml`
  / `azure-pipelines.yml`** → other CI engines (different syntax, same root
  cause: untrusted input concatenated into a shell).
- **`*.tf` / `*.tfvars` / `*.hcl`** → Terraform / HCL. Look for provider blocks,
  `local-exec`/`remote-exec` provisioners, and `templatefile`/`external` data
  sources (command and template sinks).
- **`apiVersion:`+`kind:` YAML, `Chart.yaml`, `kustomization.yaml`** → Kubernetes
  manifests / Helm / Kustomize (RBAC, `securityContext`, `hostPath`, privileged
  pods, secrets in plain manifests).
- **`Dockerfile` / `Containerfile`** → image build (base-image pinning, `RUN
  curl | sh`, secrets in layers, `USER root`).

**The trust boundary is ground truth.** For CI-injection the only thing that
matters is *which trigger runs the workflow and what data the attacker controls
under that trigger*. Map it before anything else:

```sh
# Triggers that run with repo secrets/write token on attacker-influenced input:
grep -rnE 'pull_request_target|workflow_run|issue_comment|pull_request_review' \
  .github/workflows .forgejo/workflows .gitea/workflows 2>/dev/null

# Untrusted event fields interpolated directly (the classic GHA script-injection):
grep -rnE '\$\{\{[^}]*github\.event\.(pull_request\.(title|body|head\.(ref|label))|issue\.(title|body)|comment\.body|review\.body|head_commit\.message)' \
  .github/workflows .forgejo/workflows .gitea/workflows 2>/dev/null

# run: steps that contain a ${{ }} expression (expansion happens BEFORE the shell runs):
grep -rnzoE 'run:[^\n]*\n([^\n]*\n)*?[^\n]*\$\{\{' \
  .github/workflows 2>/dev/null

# Token scope + attacker-controlled checkout (the dangerous combination):
grep -rnE 'permissions:|write-all|contents: write|id-token: write|pull-requests: write|secrets\.' \
  .github/workflows .forgejo/workflows .gitea/workflows 2>/dev/null
grep -rnE 'actions/checkout.*|ref:\s*\$\{\{.*head' .github/workflows 2>/dev/null
```

If none of the workflow signals hold and the target is pure Terraform/k8s/Docker,
the finding is a **misconfiguration**, not an injection — drive it through the
linters (Section 3b/3c) and a static trace; there is nothing to "fire".

---

## 2. Isolate

Work in a throwaway git worktree at the target ref so the original tree is never
touched. From inside the target repo:

```sh
REF=<commit-or-branch>            # the ref under audit; default HEAD
git -C <target> worktree add --detach /tmp/va-$FID "$REF"
cd /tmp/va-$FID
```

If `<target>` is not a git repo (rare for this stack), `cp -a <target>
/tmp/va-$FID` instead and note it. All linting/build/re-enactment steps below run
from `WT=/tmp/va-$FID`.

**Do not** run the workflow against the real forge, and **never** `git push`,
`gh`/`fj` API calls, `terraform apply`, `kubectl apply`, or `docker push` from
the worktree. The worktree is for reading and for feeding files into local
linters and a local container — nothing that mutates remote state.

---

## 3. Build & run (docker-first)

There is usually nothing to "run" — the deliverables are **linter evidence** and,
for the highest-fidelity injection proof, a **local re-enactment** of the exact
command the attacker's input would produce. All tools run as throwaway
containers (host toolchain may be absent); pin a recent tag.

### 3a. CI workflow linting — actionlint (GitHub/Forgejo/Gitea Actions)

`actionlint` flags shell-injection-prone `${{ }}` interpolations in `run:` steps,
plus syntax/expression errors. It is the primary automated confirmation for a
CI-injection finding.

```sh
docker run --rm -v "$WT":/repo -w /repo rhysd/actionlint:latest \
  -color -shellcheck= .github/workflows/*.y*ml 2>&1 | tee /tmp/va-$FID.actionlint
# Forgejo/Gitea live under a different dir — point actionlint at them too:
docker run --rm -v "$WT":/repo -w /repo rhysd/actionlint:latest \
  -color .forgejo/workflows/*.y*ml .gitea/workflows/*.y*ml 2>&1 | tee -a /tmp/va-$FID.actionlint
```

The diagnostic to capture looks like:
`property "..." is potentially untrusted ... avoid using it directly in inline
scripts` — that line, with the file/line it points at, is the evidence that the
sink is real.

### 3b. Terraform / HCL — tfsec (via trivy) and validate

```sh
# Security scan (tfsec is now distributed inside trivy; both forms shown):
docker run --rm -v "$WT":/src aquasec/trivy:latest config --severity HIGH,CRITICAL /src \
  2>&1 | tee /tmp/va-$FID.tfsec
# Legacy standalone tfsec image, if trivy is unavailable:
docker run --rm -v "$WT":/src aquasec/tfsec:latest /src 2>&1 | tee -a /tmp/va-$FID.tfsec

# Syntax/structure only (no provider creds, no apply, no remote state):
docker run --rm -v "$WT":/src -w /src hashicorp/terraform:latest \
  sh -c 'terraform init -backend=false -input=false && terraform validate' \
  2>&1 | tee /tmp/va-$FID.tfvalidate
```

`-backend=false` and `validate` keep this offline — never `plan`/`apply` against
a real backend or provider.

### 3c. Dockerfile — hadolint; Kubernetes/Helm — checkov

```sh
docker run --rm -i hadolint/hadolint:latest < "$WT/Dockerfile" \
  2>&1 | tee /tmp/va-$FID.hadolint

# Broad IaC scanner covering k8s/Helm/Dockerfile/Terraform — good cross-check:
docker run --rm -v "$WT":/src bridgecrew/checkov:latest -d /src --compact \
  2>&1 | tee /tmp/va-$FID.checkov
```

### 3d. Local re-enactment of an injected command (highest-fidelity injection proof)

When the finding is a `run:`-step script injection, the most convincing proof is
to show that the attacker's input, once GHA substitutes it into the shell, runs
an arbitrary command. Reconstruct the *exact* shell the runner would execute and
run it in a disposable container — never on the host, never against the forge.

Take the vulnerable step, e.g.:

```yaml
# .github/workflows/pr.yml  (trigger: pull_request_target)
- run: echo "Title: ${{ github.event.pull_request.title }}"
```

The runner expands `${{ ... }}` *before* invoking bash, so a PR titled
`a"; touch /tmp/va-pwned; echo "` yields the literal script below. Run that
literal script in a clean container and observe the side effect:

```sh
INJECT='a"; touch /tmp/va-pwned-'$FID'; echo "'    # stands in for the PR title
docker run --rm --name $CN -e TITLE_PoC="$INJECT" ubuntu:24.04 \
  bash -c 'echo "Title: '"$INJECT"'"; ls -l /tmp/va-pwned-'"$FID"' 2>&1'
```

The reconstructed command must be derived faithfully from the workflow text
(same quoting/shell the step uses); record both the rendered script and the
observed side effect (the sentinel file, an `id`/`whoami`, an echoed marker).
Side effects are benign sentinels only — never destructive, never networked.

---

## 4. Dependencies

For this stack "dependencies" are the **actions, modules, images, and charts the
build pulls in** — pinning and provenance, not a package install.

- **Action / reusable-workflow refs** — list every `uses:` and whether it is
  pinned to a 40-hex commit SHA (safe) or a mutable tag/branch
  (`@v4`, `@main` — mutable, hijackable):

  ```sh
  grep -rnE 'uses:\s*\S+@' .github/workflows .forgejo/workflows .gitea/workflows 2>/dev/null \
    | grep -vE '@[0-9a-f]{40}\b'      # what's left is unpinned → supply-chain surface
  ```

- **Terraform modules/providers** — registry `source` + `version` constraints,
  git modules on a floating `?ref=` branch, and `.terraform.lock.hcl` (provider
  hash pinning). Restore offline only, no network mutation:

  ```sh
  docker run --rm -v "$WT":/src -w /src hashicorp/terraform:latest \
    terraform init -backend=false -input=false 2>&1 | tee /tmp/va-$FID.tfinit
  ```

- **Docker base images** — mutable tag (`:latest`, `:3`) vs digest pin
  (`@sha256:...`); `grep -nE '^FROM ' "$WT/Dockerfile"`.
- **Helm chart deps** — `Chart.yaml` `dependencies:` + `Chart.lock`.

Do **not** upgrade/bump anything — that changes the audited input set. Honor the
target's pins exactly; the *absence* of a pin is itself often the finding.

---

## 5. Run & health-check

**Usually N/A** — there is no service to start and no port to probe. Skip
straight to Fire the PoC (static trace + linter evidence). The "health check"
for this stack is that the linters parsed the files and produced diagnostics:

```sh
grep -nEi 'untrusted|injection|error|warning|CRITICAL|HIGH' \
  /tmp/va-$FID.actionlint /tmp/va-$FID.tfsec /tmp/va-$FID.hadolint \
  /tmp/va-$FID.checkov 2>/dev/null
```

Rare live cases (and their ports) — only if the finding's impact genuinely
requires a running artifact:

- A Dockerfile whose *built image* contains the vulnerability (e.g. a baked-in
  service with a flaw) — build and run it like any container target; common
  ports follow the embedded app (8080/3000/80). Confirm up with
  `curl -fsS http://127.0.0.1:$PORT/`.
- A self-hosted CI runner image — out of scope to stand up a real runner; prefer
  the Section 3d re-enactment instead.

If you do build/run an image, bind host ports to `127.0.0.1` only.

---

## 6. Seed

Minimal, synthetic, local-only. For this stack "seed" means *crafting the
untrusted input the trigger would carry* — not creating users.

- **CI script injection:** the seed is the malicious event payload string (PR
  title/body, branch name, issue comment). Keep it as a benign sentinel-producing
  payload, e.g. `x"; id > /tmp/va-$FID.out; echo "` or a branch named
  `$(touch /tmp/va-$FID.b)`. You craft it as data and feed it to the local
  re-enactment (Section 3d) — you do **not** open a real PR on a real forge.
- **Workflow that needs files at specific paths:** create the minimal files the
  step reads (e.g. an empty `dist/` or a one-line `version.txt`) inside `$WT` so
  the reconstructed step doesn't fail for an unrelated reason.
- **Terraform/k8s with required variables:** supply throwaway `*.tfvars` /
  manifest values that satisfy `validate`/lint — never real account IDs, ARNs,
  cluster endpoints, or tokens.

Never reuse real secrets from the repo or environment.

---

## 7. Fire the PoC safely

The "PoC" for CI-IaC is a **demonstrated source→sink**, not an HTTP request.
Produce the strongest of these that the finding supports, keeping everything
local:

```sh
# (A) PRIMARY — static injection proof: linter confirmation + the rendered shell.
#     actionlint pins the untrusted property; show the line and the expansion.
grep -nEi 'untrusted|injection' /tmp/va-$FID.actionlint
# Then quote the workflow step and the rendered command (what bash actually runs)
# for an attacker-chosen value of the event field — this is the static-poc body.

# (B) HIGHER FIDELITY — re-enact the injected command in a throwaway container
#     and capture the side effect (see Section 3d). Proves arbitrary execution:
INJECT='x"; id > /tmp/va-'"$FID"'.out 2>&1; echo "'
docker run --rm --name $CN ubuntu:24.04 \
  bash -c 'echo "Title: '"$INJECT"'"; cat /tmp/va-'"$FID"'.out 2>&1'
# Evidence = the `uid=0(root)` (or runner user) line: the title field executed code.

# (C) TOKEN/ checkout abuse: show the dangerous trigger + write token + attacker
#     checkout together. Evidence is the three grep'd lines that co-occur:
grep -nE 'pull_request_target|workflow_run' .github/workflows/*.y*ml
grep -nE 'contents: write|id-token: write|secrets\.|GITHUB_TOKEN' .github/workflows/*.y*ml
grep -nE 'ref:\s*\$\{\{.*head|head\.sha|head\.ref' .github/workflows/*.y*ml
# Explain the chain: untrusted code is checked out AND a privileged step runs it.

# (D) Terraform command sink: local-exec / external with interpolated input.
grep -rnE 'local-exec|remote-exec|"external"|templatefile\(' "$WT" --include='*.tf'
# Evidence = tfsec/trivy finding ID + the line where attacker-influenceable input
# reaches the provisioner command string.

# (E) Dockerfile sink: pipe-to-shell install / unpinned base / baked secret.
grep -nE 'curl .*\| *(sh|bash)|wget .*\| *(sh|bash)|^FROM .*:latest|ARG .*(TOKEN|SECRET|KEY)' \
  "$WT/Dockerfile"
# Evidence = hadolint rule (e.g. DL3008/DL4006/SC2086) + the offending line.
```

Evidence to record for the repro result:

- The exact untrusted **source** (event field / module ref / base image) and the
  **sink** (the `run:` shell, provisioner, RBAC grant), each with `file:line`
  → `poc` + `data_flow`.
- The proof artifact: the actionlint/tfsec/hadolint diagnostic line, and — when
  you did the re-enactment — the captured command output / sentinel file
  → `observed`.
- What an attacker gains (CI RCE with the write-scoped `GITHUB_TOKEN` /
  `secrets.*`, exfiltratable OIDC token, cluster privilege, etc.) → `impact`.

Set the method honestly:

- Re-enacted the injected command and observed execution → `method: unit-test`,
  `reproduced: true`.
- Linter + line-referenced source→sink trace, no live execution → `method:
  static-poc`, `reproduced: false` (the expected default for this stack).

Safety invariants: no real PR/issue/comment on any forge; no `push` / `apply` /
`kubectl` / `docker push`; all command re-enactment stays inside a disposable
local container with benign sentinels; no outbound connections to real hosts; no
real secrets or cloud/forge credentials.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN 2>/dev/null
docker image rm -f $IMG 2>/dev/null              # only if 3b/5 built one
rm -f /tmp/va-$FID.actionlint /tmp/va-$FID.tfsec /tmp/va-$FID.tfvalidate \
      /tmp/va-$FID.tfinit /tmp/va-$FID.hadolint /tmp/va-$FID.checkov \
      /tmp/va-$FID.out /tmp/va-$FID-pwned* /tmp/va-$FID.b

cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

---

## 9. Fallbacks

For CI-IaC the *expected* outcome is already a static/test proof, so "fallback"
mostly means choosing the right rung. Set `method` accordingly (enum:
`live-exploit | unit-test | build-only | static-poc`).

1. **Re-enactment ran (preferred for injection):** the reconstructed shell ran
   in a local container and the side effect was observed (sentinel file, `id`
   output, echoed marker). Set `method: unit-test`, `reproduced: true`. This is
   the highest fidelity realistically available here.

2. **Linter confirms + trace is airtight (the default):** actionlint flags the
   untrusted property / tfsec or hadolint flags the sink, and you have a complete
   `file:line` source→sink path with no effective guard (no
   `if:`-gating to trusted actors, no expression moved to an `env:` + quoted
   `"$VAR"` indirection, no minimal `permissions:`). Set `method: static-poc`,
   `reproduced: false`. Cite the diagnostic line as evidence.

3. **Linters unavailable / image can't be pulled (offline):** fall back to a
   pure static PoC — quote the workflow/Terraform/Dockerfile lines, show the
   attacker-controlled value, and render the exact command/config the sink
   produces, explaining the guard analysis by hand. Set `method: static-poc`,
   `reproduced: false`.

4. **Dockerfile-built artifact whose runtime is the real subject:** if the
   vulnerability only manifests in the *running* image, build it (Section 5) and,
   if it serves, fire a real local request → `method: live-exploit`; if it builds
   but can't start, record the build success + reachable trace → `method:
   build-only`.

Never claim `reproduced: true` without either observed runtime/command evidence
or a linter diagnostic that directly names the sink; a hand trace alone is
`static-poc` with `reproduced: false`. Prefer the highest-fidelity rung that
actually works, and remember the guard check (trusted-actor `if:`, quoted-`env:`
indirection, scoped `permissions:`) is what separates a real finding from noise.

<!--
RECON PROMPT — PHASE 1 of vuln-audit. You are a single fresh-context agent that
runs BEFORE any finder. Your job is reconnaissance only: detect the stack, map
the attack surface and trust boundaries, decide which finder classes are worth
running and which to skip, pick a dynamic-verification strategy, and emit ONE
structured recon summary the workflow forwards to every later phase. You do NOT
report vulnerabilities here — you scope the hunt. Read AGENTS.md for the data
contracts, taxonomy, and the binding signal-discipline policy. Read-only: do not
mutate the target.
-->

# Recon — Phase 1 (stack, surface, scope, run strategy)

Work the steps in order. Each step's output feeds the recon summary in step 7.
Be fast and broad first, then precise. When a step is ambiguous, prefer the
reading that EXPANDS attack surface (assume input is untrusted until proven
otherwise) but NARROWS finder selection (skip a class only when you can justify
it). Cite concrete file paths and line numbers for every claim — recon that
points later phases at real code is worth ten of generic prose.

## 1. Detect stack, frameworks, and build/run system

Identify the primary language(s), frameworks, and how the target builds and runs.
Map the result to exactly ONE env playbook key (drives Phase 6 repro):

`crystal · ruby · node · python · go · php · java-jvm · rust · generic-docker · ci-iac`

Detection signals (read-only; do not install anything):

- **Manifests / lockfiles** — the ground truth for language + package manager:
  - crystal: `shard.yml`, `shard.lock`
  - ruby: `Gemfile`, `*.gemspec`, `Gemfile.lock`
  - node: `package.json` (+ `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`), `tsconfig.json`
  - python: `pyproject.toml`, `requirements*.txt`, `Pipfile`, `setup.py`, `poetry.lock`
  - go: `go.mod`, `go.sum`
  - php: `composer.json`, `composer.lock`
  - java-jvm: `pom.xml`, `build.gradle(.kts)`, `settings.gradle`, `*.jar`
  - rust: `Cargo.toml`, `Cargo.lock`
- **Build/run tells** — `Dockerfile`, `docker-compose*.yml`, `Procfile`, `Makefile`,
  `Taskfile.yml`, `bin/`, framework CLIs, and the manifest's scripts/tasks.
- **Framework** — read deps + entry imports: web (Rails/Sinatra/Lucky/Kemal,
  Express/Nest/Next/Fastify, Django/Flask/FastAPI, Gin/Echo/chi/net-http,
  Laravel/Symfony/Slim, Spring/Quarkus/Micronaut, actix/axum/rocket), plus
  ORMs, template engines, queue/worker libs, and serializers — note each, they
  steer finder selection.

**Playbook key decision:**

- A single dominant app language → that language key.
- **Polyglot:** pick the key for the language that owns the primary attack
  surface (the network-facing app), note the others in `notes`. A thin shell of
  one language around a core of another → key on the core.
- No buildable app, just a `Dockerfile`/compose stack to run → `generic-docker`.
- The repo's PRIMARY artifact is CI/CD pipelines or IaC (GitHub Actions/GitLab
  CI/Forgejo workflows, Terraform/Pulumi/CloudFormation, k8s/Helm, Ansible) with
  no app to run → `ci-iac`. (Note: an app repo that ALSO has workflows keys on
  the app language; `ci-iac` is for infra-/pipeline-primary repos.)

Record `stack` (the key) and `frameworks` (list).

## 2. Map the attack surface and trust boundaries

Enumerate every place untrusted input crosses into the system, and the dangerous
sinks it could reach. For each, capture `file:line`, the kind, and the untrusted
source. This is the map every finder navigates — be exhaustive on surface,
precise on location.

- **HTTP routes/handlers** — every route table, controller, middleware, and
  handler. Capture method, path, auth requirement, and which params/body/headers
  flow in. Note dynamic/wildcard routes and catch-alls.
- **CLIs / entrypoints** — `main`/`bin`, argv parsing, subcommands, scripts run
  with attacker-influenced args or stdin.
- **Message/queue consumers** — AMQP/Kafka/SQS/Redis/NATS/cron/webhook handlers;
  the payload is untrusted input.
- **Deserialization points** — `JSON.parse`/`Marshal`/`pickle`/`yaml.load`/
  `ObjectInputStream`/`unserialize`/`serde`/MessagePack/protobuf over untrusted
  bytes; framework auto-binding/mass-assignment.
- **File/path operations** — reads/writes/joins/globs/zips/uploads/temp files
  where any path segment is caller-controlled (traversal, symlink, zip-slip).
- **Outbound network calls** — every server-side HTTP/DB/SMTP/DNS/socket call
  whose destination or content can be influenced by a caller (SSRF surface).
- **Auth/authz boundaries** — login, session/token issuance & validation,
  role/permission checks, tenant isolation, the line between
  unauthenticated/authenticated/admin. Mark which routes sit on which side.
- **Secrets/config loading** — env vars, config files, secret managers, key
  material, connection strings; note defaults and committed values.
- **Template/HTML rendering** — server-rendered views, string-built HTML, SSTI-
  capable engines, `dangerouslySetInnerHTML`/`html_safe`/`|safe`/`v-html`.
- **Trust boundaries** — draw the line for each: where does data go from
  trusted→untrusted or low-priv→high-priv? An input is only interesting if it
  reaches a sink ACROSS a boundary.

For each surface entry note any **sanitizer/validator/authz/parameterization**
already on the path — the FP guard. A sink fronted by an effective control is
not a lead; record it so later phases don't re-chase it.

## 3. Select relevant finder classes (and justify skips)

For each of the 14 classes, decide RELEVANT or SKIPPED based on the surface from
step 2. The 14 classes (see `prompts/finders/<key>.md`):

`access-control · ssrf · injection · xss-ssti · auth-session · crypto ·
deserialization · path-file · secrets · misconfig · supply-chain ·
logging-errors · dos-redos · csrf-cors`

Relevance heuristics (a class is RELEVANT when its source AND sink both exist):

- **access-control** — any authz boundary or multi-tenant/object-owned resource
  (IDOR). Almost always relevant if there are authenticated routes.
- **ssrf** — relevant iff an outbound network call exists with a caller-
  influenced destination (step 2 outbound list non-empty).
- **injection** — relevant iff untrusted input reaches a SQL/NoSQL/OS/LDAP/XPath
  interpreter. Skip if all DB access is ORM-parameterized AND no shell-out.
- **xss-ssti** — relevant iff server emits HTML/templates with untrusted data,
  or a template engine renders caller-controlled strings. Skip for pure JSON
  APIs with no template engine and no HTML rendering.
- **auth-session** — relevant iff the app issues/validates sessions, tokens,
  passwords, MFA, or OAuth. Skip if there is no auth at all (note that fact).
- **crypto** — relevant iff the code does its own crypto: hashing passwords,
  signing/verifying tokens, encrypting data, RNG for security, TLS config. Skip
  if no security-relevant crypto primitives are used directly.
- **deserialization** — relevant iff untrusted bytes hit a deserializer (step 2
  deserialization list non-empty), esp. native/object formats.
- **path-file** — relevant iff a caller-influenced path reaches a file op.
- **secrets** — relevant iff the repo loads/handles credentials or there is any
  chance of committed secrets (almost always run a quick pass).
- **misconfig** — relevant iff there is framework/server/cloud config: debug
  flags, CORS, cookie flags, TLS, exposed admin/actuator, default creds.
- **supply-chain** — relevant iff there are CI/CD workflows (Dangerous-Workflow,
  script injection, over-broad tokens, unpinned actions) OR dependency manifests
  with lockfiles (known-vuln deps). Code-exploitable checks ONLY (per AGENTS.md);
  posture/SBOM/maintainership is NOT a finding.
- **logging-errors** — relevant iff untrusted input is logged (log injection /
  sensitive-data leak) or error handling exposes stack traces / leaks state /
  fails open (A10).
- **dos-redos** — relevant iff a user-controlled value reaches a regex, an
  unbounded loop/allocation, a zip/decompress, or an expensive parse.
- **csrf-cors** — relevant iff there are state-changing cookie-authenticated
  routes, CORS config, or framing-sensitive UI. Skip pure token-auth APIs with
  no cookies (note why).

Output two lists. For every RELEVANT class, add a one-line **priority pointer**:
the specific surfaces/files from step 2 that finder should hit first. For every
SKIPPED class, add a one-line **justification** (why no reachable source→sink).
Default to RELEVANT when uncertain — skipping is a claim you must back.

## 4. Decide the dynamic-verification strategy

Determine how Phase 6 will reproduce findings. Docker-first.

- **Runnable?** Check for `Dockerfile`/`docker-compose*.yml` first (preferred,
  hermetic), then a native run path (manifest scripts, `Procfile`, `Makefile`
  targets, framework server command).
- **Entry command + port** — the exact command that starts the app and the port
  it binds (read it from config/compose/scripts, don't guess; note env vars and
  dependent services — DB/cache/queue — needed to boot).
- **Health check** — how to know it's up (a route, a log line, a port listen).
- **Not runnable** (library, no server, missing deps, infra-only) → repro falls
  back to a focused **unit-test** that drives the sink, or a **static PoC** /
  build-only proof. Say which and why.

Record `run_strategy` as one of:
`docker-compose | docker | native | unit-test | static-poc`,
plus the entry command, port, and any boot prerequisites in `notes`.

## 5. Fold in target threat-model guidance

Check for `<target>/.claude/claude-security-guidance.md`. If present, read it and
fold its threat model into scope: crown-jewel assets, known trust boundaries,
in/out-of-scope paths, prior findings, and any class-specific guidance. Let it
RAISE priority and tighten scope; it does NOT lower the signal bar. Summarize the
relevant points in `notes` and reflect any scope/priority changes in steps 2–4.
If absent, note that and proceed with defaults.

## 6. Signal discipline (binding — carry it into every later phase)

Recon's selections directly gate noise. Enforce the AGENTS.md contract:

- A class is RELEVANT only when there is a plausible REACHABLE path from
  untrusted input to a dangerous sink with no effective control already on it.
  No class earns a slot on defense-in-depth grounds alone.
- No posture/process items (missing SECURITY.md, SBOM, license, maintainership).
  These never gate a finder; at most they land in the report's Info appendix.
- No style/lint nits, no unreachable/dead code, no speculative surfaces.
- Prefer a tight scope that proves a few real issues over a broad scope that
  drowns them. When you skip a class, you are asserting there is no reachable
  source→sink — make that assertion only when the surface map backs it.

## 7. Emit the recon summary

Output exactly ONE structured object (this is the phase deliverable; later
phases consume it). Shape:

```json
{
  "stack": "<one playbook key>",
  "frameworks": ["<framework/orm/template/queue lib>", "..."],
  "run_strategy": "docker-compose | docker | native | unit-test | static-poc",
  "entrypoints": [
    { "kind": "http|cli|queue|cron|webhook", "ref": "file:line",
      "detail": "GET /x | subcommand | consumer", "auth": "none|user|admin" }
  ],
  "attack_surface": [
    { "kind": "route|cli|consumer|deser|file|outbound|authz|secret|template",
      "ref": "file:line", "source": "<untrusted origin>",
      "sink": "<dangerous op>", "existing_control": "<sanitizer/authz or null>",
      "classes": ["<finder keys this surface feeds>"] }
  ],
  "relevant_classes": [
    { "class": "<key>", "priority_surfaces": ["file:line", "..."] }
  ],
  "skipped_classes": [
    { "class": "<key>", "reason": "<why no reachable source->sink>" }
  ],
  "notes": "run command + port + boot prereqs; polyglot/key rationale; target security-guidance points; blind spots/auth-gated areas; anything Phase 6 needs to boot the app"
}
```

Rules for the object: `stack` is exactly one playbook key; `relevant_classes` +
`skipped_classes` together cover all 14, no overlap; every `attack_surface` entry
has a real `file:line`; `entrypoints` is the subset of surfaces where untrusted
input first enters. Keep `notes` operational — it is the bridge to Phase 6.

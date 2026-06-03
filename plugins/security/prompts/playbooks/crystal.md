<!--
ENV PLAYBOOK — crystal. You are the dynamic-verification (phase 6) agent. A
candidate finding survived deep review + adversarial verify; your job is to
BUILD, RUN, and EXPLOIT the target to reproduce it with a real PoC, then fill a
Repro object (AGENTS.md). Docker-first: the native Crystal toolchain may be
absent on the host, so prefer containerized build/run. Keep ALL traffic inside
the local container/network — no external hosts, no real creds, no exfiltration.
Emit Repro.method honestly: live-exploit > unit-test > build-only > static-poc.
Be concrete; copy the commands. Replace {{ref}}, ports, and paths as detected.
-->

# Env Playbook — Crystal (`crystal`)

**Stack key:** `crystal` · **Manifests:** `shard.yml` (+ `shard.lock`) ·
**Sources:** `*.cr` · **Common web frameworks:** Kemal, Lucky, Amber, Grip,
Athena · **Repro target:** a `Repro` object (`method`, `setup_commands`, `poc`,
`observed`, `impact`).

## 1. Detect — confirm the stack

A repo is Crystal if recon found any of:

```sh
ls shard.yml shard.lock 2>/dev/null          # the manifest + lockfile
find . -name '*.cr' -not -path './lib/*' | head   # first-party sources (skip vendored lib/)
```

Read `shard.yml` to pick the run strategy:

- `targets:` → which binaries `crystal build` produces (`name` + `main` path).
- `dependencies:` → web framework in play. Grep the keys: `kemal`, `lucky`,
  `amber`, `grip`, `athena` decide the default port and start command below.
- `crystal:` → required compiler version constraint; pin the base image to it.
- A `Dockerfile` / `docker-compose.yml` / `compose.yaml` at the root → prefer it
  (section 3). Vendored deps live in `lib/`; the cache key is `shard.lock`.

If none of these are present this playbook does not apply — stop and report the
mismatch rather than guessing.

## 2. Isolate — work in a throwaway worktree at the target ref

The verifier already runs under worktree isolation (`agent(..., {isolation:
'worktree'})`); the original tree is untouched. Do NOT build in the source tree.

If you must materialize a worktree yourself, branch from the target ref using a
LOCAL ref (never `origin/<branch>`, which silently sets upstream):

```sh
git -C /path/to/target worktree add /tmp/vuln-crystal {{ref}}
cd /tmp/vuln-crystal
git rev-parse --short HEAD            # record in Repro.environment
```

Everything below runs inside this worktree. All build artifacts (`lib/`, `bin/`,
the compiled binary) stay here and are discarded at teardown.

## 3. Build & run — docker-first

Crystal compiles to a static-ish native binary; you need the compiler image even
if the host has no toolchain. Use the official `crystallang/crystal` image,
pinned to the version from `shard.yml`'s `crystal:` key (fall back to `latest`).

### 3a. If a Dockerfile / compose file exists — use it

```sh
# Compose, only if the plugin is present (opportunistic, not required):
docker compose version >/dev/null 2>&1 && docker compose up --build -d

# Otherwise the reliable path — plain docker build/run from the repo Dockerfile:
docker build -t vuln-crystal:poc .
docker run --rm -d --name vuln-crystal \
  -p 127.0.0.1:3000:3000 vuln-crystal:poc
```

Bind to `127.0.0.1` only — never `0.0.0.0` on a shared host. Map the port the
app actually listens on (section 5).

### 3b. No Dockerfile — minimal generic image

Build inside the official image and run the binary in the same container. One
disposable container, source mounted read-write so `shards`/`crystal` can write
`lib/` and `bin/`:

```sh
docker run --rm -d --name vuln-crystal \
  -v "$PWD":/app -w /app \
  -p 127.0.0.1:3000:3000 \
  crystallang/crystal:latest \
  sh -c 'shards install && crystal run src/<main>.cr'
```

Replace `src/<main>.cr` with the `targets.<name>.main` from `shard.yml` (Kemal
apps are often `src/<app>.cr`; Lucky uses `crystal run src/start_server.cr`,
Amber `crystal run src/<app>.cr`). For a faster, repeatable run, build once then
exec:

```sh
docker run --rm -d --name vuln-crystal -v "$PWD":/app -w /app \
  -p 127.0.0.1:3000:3000 crystallang/crystal:latest \
  sh -c 'shards install && crystal build --release -o bin/app src/<main>.cr && exec bin/app'
```

Lucky/Amber may need Postgres. Stand up a private one and link it on a
throwaway network — keep it container-local:

```sh
docker network create vulnnet 2>/dev/null || true
docker run --rm -d --name vuln-db --network vulnnet \
  -e POSTGRES_PASSWORD=poc -e POSTGRES_DB=app_development postgres:16-alpine
# then add: --network vulnnet -e DATABASE_URL=postgres://postgres:poc@vuln-db/app_development
```

## 4. Dependencies — install / restore

`shards` is the package manager (ships in the Crystal image). Inside the build
container or via `docker run ... crystallang/crystal`:

```sh
shards install            # resolves & vendors into lib/ per shard.lock
shards check              # verify installed deps match shard.lock
```

If `shard.lock` is present, `shards install` honors it (reproducible). Crystal's
own stdlib needs no install. Native shards may need system libs (`libpq`,
`libsqlite3`, `libyaml`, `openssl`); the official image carries the common ones,
otherwise `apk add`/`apt-get install` the missing `-dev` package in the run cmd.

## 5. Run & health-check

Default ports by framework: **Kemal 3000**, **Lucky 5000** (`5001` boot env),
**Amber 3000**, **Grip 3000**, **Athena 3000/8080**. Confirm the real bind in
code: grep `Kemal.run`, `Kemal.config.port`, `Amber::Server`, `Lucky::Server`,
or `HTTP::Server.new ... .listen(...)`.

Confirm the app is up before firing the PoC:

```sh
docker logs vuln-crystal 2>&1 | tail -20          # look for "listening on .../3000"
# poll until healthy (no foreground sleep; loop with a timeout):
for i in $(seq 1 30); do
  curl -fsS -o /dev/null http://127.0.0.1:3000/ && { echo up; break; }
  [ "$i" = 30 ] && { echo "DOWN"; docker logs vuln-crystal | tail -40; }
done
```

If the build fails, capture `docker logs` / compiler output — a build failure is
itself a valid `build-only` outcome (section 9), not a dead end.

## 6. Seed — minimal state for auth/stateful PoCs

Only seed what the PoC strictly needs; keep it inside the container.

- **Migrations:** Lucky `crystal run tasks.cr -- db.migrate` (or
  `lucky db.create && lucky db.migrate`); Amber `amber db migrate`; raw — run
  the project's `db/migrations/*.sql` against `vuln-db`.
- **Seed/test user:** prefer the project's own seed task
  (`crystal run tasks.cr -- db.seed`, `amber db seed`). If none, insert a single
  throwaway account directly:

  ```sh
  docker exec -i vuln-db psql -U postgres -d app_development \
    -c "INSERT INTO users (email, password_digest, role) \
        VALUES ('poc@local.test', crypt('poc-pass', gen_salt('bf')), 'user');"
  ```

  Use obviously-fake, local-only credentials (`poc@local.test` / `poc-pass`).
  Never real or production-shaped secrets. Record exactly what you seeded in
  `Repro.setup_commands`.

## 7. Fire the PoC safely

Send the exploit at the local container only. Containment rules (binding):

- Target is always `http://127.0.0.1:<port>` (the mapped container) — never an
  external host or a URL pulled from the finding's real-world context.
- Use the throwaway creds from section 6; no real tokens/cookies.
- For SSRF/file-read PoCs, prove impact with a benign in-container marker (e.g.
  read `/etc/passwd` or hit `http://127.0.0.1:<port>/_internal`) — do not reach
  out to the internet or cloud metadata endpoints.
- Capture request + response verbatim for `Repro.observed` (the evidence).

Examples — adapt to the finding's `dynamic_poc_plan`:

```sh
# SQL injection (auth bypass / boolean) — observe row count or 200 vs 401:
curl -sS -i "http://127.0.0.1:3000/search?q=%27%20OR%201%3D1--%20"

# Reflected XSS — observe payload echoed unescaped in the body:
curl -sS "http://127.0.0.1:3000/greet?name=<script>alert(1)</script>" | grep -F '<script>'

# Path traversal — observe file contents leaking:
curl -sS "http://127.0.0.1:3000/files?path=../../../../etc/passwd"

# OS command injection (Process.run shell:true sink) — observe injected output:
curl -sS "http://127.0.0.1:3000/ping?host=127.0.0.1;id"

# Auth'd IDOR — login, reuse cookie, access another id (all local):
curl -sS -c /tmp/cj -d 'email=poc@local.test&password=poc-pass' \
  http://127.0.0.1:3000/login
curl -sS -b /tmp/cj "http://127.0.0.1:3000/orders/1"   # id you do not own
```

Save the transcript:

```sh
{ echo "# request"; echo "$REQ"; echo "# response"; echo "$RESP"; } > /tmp/poc-evidence.txt
```

If the observed behavior matches the predicted impact, set
`Repro.reproduced=true`, `method=live-exploit`, and paste request+response into
`observed`.

## 8. Teardown

Leave no containers, networks, volumes, or worktree behind:

```sh
docker rm -f vuln-crystal vuln-db 2>/dev/null || true
docker compose down -v 2>/dev/null || true       # if compose was used
docker network rm vulnnet 2>/dev/null || true
docker image rm vuln-crystal:poc 2>/dev/null || true

# Remove the worktree if you created it manually (skip if the harness owns it):
git -C /path/to/target worktree remove --force /tmp/vuln-crystal
```

If the harness provided the worktree (`isolation:'worktree'`), it is reclaimed
automatically — do not call `worktree remove` on it.

## 9. Fallbacks — when it cannot run live

Degrade gracefully and set `Repro.method` to match what you actually achieved:

1. **Unit/spec PoC (`method=unit-test`)** — if the app won't boot (missing
   service, broken migration) but the vulnerable function is reachable in
   isolation, write a Crystal spec under `spec/` that drives the source→sink path
   and asserts the exploit. Run it in the image:

   ```sh
   docker run --rm -v "$PWD":/app -w /app crystallang/crystal:latest \
     sh -c 'shards install && crystal spec spec/poc_spec.cr'
   ```

   A green assertion proving the unsafe behavior is the evidence.

2. **Build-only (`method=build-only`)** — if it compiles but cannot be exercised
   (no usable entry point), record the successful `crystal build` and the static
   source→sink trace; impact stays argued, not observed.

3. **Static PoC (`method=static-poc`)** — if nothing builds (toolchain/dep
   unavailable, version skew), fall back to the proven static trace: cite the
   exact `file:line` source→sink, the missing sanitizer, and a crafted payload
   that would trigger it. Set `reproduced=false`, explain the blocker in `notes`.

Always record the actual environment (image tag, Crystal version, commit SHA) in
`Repro.environment`, and the exact commands in `Repro.setup_commands`, so the
finding is replayable.

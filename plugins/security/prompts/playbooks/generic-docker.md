# ENV Playbook — Generic Docker

Build, run, and exploit a target whose ground truth is its **Docker** packaging
(a `Dockerfile` and/or `docker-compose.yml`) rather than a recognized language
toolchain — or any target where the language playbook is missing and Docker is
the reliable common denominator. This is also the universal isolation layer the
other playbooks defer to. Docker-first by definition; the host may have **no**
native toolchain for whatever lives inside the image. Use plain `docker build`/
`docker run` as the reliable path; treat `docker compose` as opportunistic (the
plugin is not guaranteed). Keep ALL traffic inside the local container — no
external hosts, no real credentials, no data exfiltration.

Conventions used below (substitute per finding):

- `FID` — the finding id (e.g. `f3`); use it to make names/ports unique so
  parallel repros never collide.
- `WT=/tmp/va-$FID` — isolated git worktree path.
- `IMG=va-$FID:repro` — image tag. `CN=va-$FID` — container name.
- `PORT` — an ephemeral host port (pick a free one, see Run & health-check).
- The final repro result must set `method` to one of:
  `live-exploit | unit-test | build-only | static-poc`.

---

## 1. Detect

Confirm the stack from the target tree (read-only). The defining signal is a
container manifest at or near the repo root:

```sh
ls Dockerfile* Containerfile docker-compose.yml docker-compose.yaml \
   compose.yml compose.yaml .dockerignore 2>/dev/null
find . -maxdepth 3 \( -iname 'Dockerfile*' -o -iname 'Containerfile' \
   -o -iname 'docker-compose*.y*ml' -o -iname 'compose.y*ml' \) | head
```

- **Manifests:**
  - `Dockerfile` / `Containerfile` — the build recipe. `FROM` reveals the real
    underlying stack (e.g. `FROM node:22`, `FROM python:3.12`, `FROM golang`).
    If a language playbook matches that base, prefer it for the inner details
    and use this one only for the container plumbing.
  - `docker-compose.yml` / `compose.yaml` — multi-service topology: which
    services exist, build contexts, exposed ports, env, volumes, and
    dependencies (`depends_on`).
  - `.dockerignore` — what the project itself excludes from the build context.
- **Read the Dockerfile** — it is the ground truth for build steps, exposed
  port, and start command:

  ```sh
  grep -nE '^(FROM|ARG|ENV|EXPOSE|WORKDIR|ENTRYPOINT|CMD|USER)' Dockerfile
  ```

  - `EXPOSE <port>` → the in-container listen port (map this).
  - `ENTRYPOINT` / `CMD` → how the app starts (this is what runs by default).
  - `FROM ... AS build` (multi-stage) → the final stage is the runtime; earlier
    stages are throwaway build tooling.
- **Read the compose file** — services, ports, and the entry service:

  ```sh
  # Prefer a real parse; fall back to grep if no compose plugin / python yaml:
  docker compose config 2>/dev/null \
    || python3 -c 'import yaml,sys;print(yaml.safe_load(open("docker-compose.yml")))' 2>/dev/null \
    || grep -nE '^( {2,4})?(services|build|image|ports|environment|depends_on|command):' docker-compose.yml
  ```

  - `ports: ["8080:80"]` → host:container; the container side is what the app
    listens on.
  - The service with the build context that holds the vulnerable code is the
    **app under test**; sidecars (db, redis, etc.) are support services.
- **No language playbook applies, no `FROM` you recognize:** treat the image as
  opaque and drive it purely through its declared port + entrypoint.

---

## 2. Isolate

Work in a throwaway git worktree at the target ref so the original tree is
never touched. From inside the target repo:

```sh
REF=<commit-or-branch>            # the ref under audit; default HEAD
git -C <target> worktree add --detach /tmp/va-$FID "$REF"
cd /tmp/va-$FID
```

If `<target>` is not a git repo (rare), `cp -a <target> /tmp/va-$FID` instead
and note it. All build/run steps below run from `WT=/tmp/va-$FID`.

Keep the build context lean and the host's git/state out of the image. Respect
the project's own `.dockerignore`; only add one if it is missing:

```sh
[ -f .dockerignore ] || printf '.git\n' > /tmp/va-$FID.dockerignore
```

Use a finding-scoped compose project name (`-p va-$FID`) and unique image/
container names so parallel repros never collide and teardown is exact.

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker (the common case here)

This is the whole point of the stack — the project's own definition wires up
the build, env, ports, dependent services, and the correct entrypoint.

```sh
# Plain docker with the repo Dockerfile (the reliable path).
# Honor an alternate filename / build context if the project uses one:
docker build -f Dockerfile -t $IMG .          # add --build-arg KEY=val if required by ARG
```

If the build context is a subdirectory (compose `build.context`), build from
there: `docker build -f path/to/Dockerfile -t $IMG path/to/context`.

```sh
# Compose — opportunistic; only when the plugin exists AND the app needs its
# sidecars (DB, cache) to boot. Brings up the whole topology:
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build
```

When compose is unavailable but the app needs a sidecar (e.g. Postgres), stand
the dependency up by hand on a shared user network and point the app at it:

```sh
docker network create va-net-$FID 2>/dev/null
docker run -d --name va-db-$FID --network va-net-$FID \
  -e POSTGRES_PASSWORD=poc -e POSTGRES_DB=app postgres:16-alpine
# then run the app on the same network with DATABASE_URL pointing at va-db-$FID
```

### 3b. No Dockerfile — minimal generic image

Reaching here means recon found a compose `image:` (no build) or only loose
files. Two sub-cases:

- **Compose references a prebuilt `image:` (no `build:`):** just pull and run it
  through compose, or `docker run` that image directly with the declared ports/
  env. There is nothing to build.
- **Loose files, unknown stack:** infer the runtime from what is present and
  wrap it in a small base. Prefer the matching language playbook if one fits;
  otherwise a generic Debian base plus the obvious install/start:

  ```sh
  cat > /tmp/Dockerfile.$FID <<'EOF'
  FROM debian:12-slim
  RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
  WORKDIR /app
  COPY . .
  # Install + start are stack-specific — set them from the files found:
  #   static site:   RUN apt-get install -y python3   (serve with python3 -m http.server)
  #   shell/binary:  RUN chmod +x ./run.sh
  EXPOSE 8080
  CMD ["sh", "-c", "echo 'set a real start command' && sleep infinity"]
  EOF

  docker build -f /tmp/Dockerfile.$FID --iidfile /tmp/va-$FID.iid -t $IMG .
  ```

The start command is whatever the Dockerfile `CMD`/`ENTRYPOINT` or compose
`command:` declares. Bind the listener to `0.0.0.0`, not `127.0.0.1`, or a `-p`
map cannot reach it (see Run & health-check for the loopback workaround).

---

## 4. Dependencies

There is no separate restore step — for a Docker target, dependency install is
**baked into the image build** (the Dockerfile's `RUN`/`COPY` layers, or the
base `image:`'s contents). Notes:

- Build deps reproducibly and from the pinned manifests the Dockerfile copies in
  (e.g. `npm ci`, `pip install -r requirements.txt`, `go mod download`,
  `bundle install`). Do **not** edit the Dockerfile to bump versions — that
  changes the audited dependency set.
- **Build-time `ARG`s:** if the build fails on a missing `ARG`, read the
  `ARG`/`ENV` lines and pass safe placeholders
  (`--build-arg NODE_ENV=development`). Never pass real secrets.
- **Private registries / base images that won't pull:** if `FROM` points at a
  private registry that needs auth, do not supply real credentials — note it and
  fall back (build-only / static-poc).
- **BuildKit secrets / SSH mounts** (`--mount=type=secret`): the build may need
  `DOCKER_BUILDKIT=1`. Provide only a dummy secret file if one is strictly
  required to get past the layer; never a real one.
- Multi-stage builds already isolate build tooling from the runtime — let them;
  do not flatten or alter the stages.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name. Map the host port to whatever the container listens on (the
`EXPOSE` / compose `ports` container side):

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
CPORT=8080            # the in-container port from EXPOSE / compose ports / the listen call

docker run -d --name $CN -p 127.0.0.1:$PORT:$CPORT $IMG
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. If the
project used compose, the published ports are already bound — find the mapped
host port instead of re-running:

```sh
docker compose -p va-$FID ps                       # see published ports
docker port "$(docker compose -p va-$FID ps -q <app-service>)" $CPORT
```

**If the app binds `127.0.0.1` inside the container,** a `-p` map can't reach it
(loopback is per-namespace). Either fire the PoC from inside the container
(`docker exec $CN ...`), or run with `--network host` on Linux so the
container's loopback is the host's:

```sh
docker run -d --name $CN --network host $IMG       # then target 127.0.0.1:<code-port>
```

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
docker ps --filter "name=$CN"      # confirm it didn't immediately exit
```

A 404 on `/` still means the server is up — any TCP/HTTP response counts as
healthy. If the container exits immediately, `docker logs` shows why (missing
env, dependent DB not ready, bad `CMD`). For a non-HTTP service, probe the port
with `docker exec $CN sh -c 'curl ... || nc -z 127.0.0.1 $CPORT'` or the
relevant client. Common exposed ports follow the inner stack (web **8080/3000/
5000/8000/80**, Postgres **5432**, MySQL **3306**, Redis **6379**) — but the
Dockerfile/compose declaration is ground truth.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **Compose stacks** usually declare the DB and may auto-run migrations on boot
  (`depends_on`, an entrypoint script, or a one-shot `migrate` service). Check
  the compose file before seeding by hand. Run the project's own migration/seed
  inside the app container:

  ```sh
  docker exec $CN sh -c '<project migrate cmd>'    # e.g. rails db:migrate, npm run migrate, ./manage.py migrate
  docker exec $CN sh -c '<project seed cmd>' 2>/dev/null || true
  ```

- **Standalone sidecar DB** (started in step 3): create the schema/user the app
  expects via the app's own migration command, or `docker exec va-db-$FID ...`
  with the DB client for a single synthetic row.

- **Auth flow:** if the PoC needs a session/token, register or log in via the
  app's own endpoint with synthetic creds and keep the cookie jar / capture the
  token:

  ```sh
  # Cookie-session apps:
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -H 'Content-Type: application/json' \
    -d '{"username":"poc","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/login"

  # Bearer/JWT apps — capture the token for the Authorization header:
  TOKEN=$(curl -s -H 'Content-Type: application/json' \
    -d '{"username":"poc","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/auth/login" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("token") or d.get("access_token",""))')
  ```

- Use only fake, local-only credentials. Never reuse real secrets from the repo
  beyond what is strictly required to boot.

---

## 7. Fire the PoC safely

Send the exploit to the **local** container only and capture concrete evidence.
Tailor to the finding's source→sink path; examples by class (stack-agnostic —
the container's declared port is the only entry point you target):

```sh
# SQL/NoSQL injection — observe error or extracted marker in the response:
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/user?id=1%20OR%201=1--" | tee /tmp/poc.$FID.out

# Path traversal / arbitrary file read — pull a file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head

# Command injection / RCE — prove exec via a benign in-container sentinel, then
# read it back (NEVER destructive commands):
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host.
# Start a canary on $CN's own network namespace, then make the app fetch it:
docker run -d --name va-canary-$FID --network "container:$CN" \
  python:3-slim python3 -c 'import http.server,socketserver;socketserver.TCPServer(("127.0.0.1",9999),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(b"CANARY"))})).serve_forever()'
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/" | grep -o CANARY

# Reflected/stored XSS — confirm the payload is reflected unescaped:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" \
  | grep -o '<script>alert(1)</script>'
```

Docker-specific findings to fire against the running container itself:

```sh
# Container hardening / privilege — confirm the image runs as root (CWE-250) or
# the container is over-privileged (misconfig). Evidence is the observed state:
docker inspect -f '{{.Config.User}}' $CN          # empty/"root"/"0" => runs as root
docker exec $CN id                                 # uid=0(root) confirms it
docker exec $CN sh -c 'cat /proc/1/status | grep -i cap'   # effective capabilities

# Hardcoded secrets baked into the image (CWE-798) — surface them from the
# layers/env WITHOUT exfiltrating; print to local evidence only:
docker exec $CN env | grep -iE 'pass|secret|token|key' | tee -a /tmp/poc.$FID.out
docker history --no-trunc $IMG | grep -iE 'pass|secret|token|key' | head

# Exposed/dangerous Docker socket mount (compose volumes: /var/run/docker.sock)
# — if mounted, prove host-control reachability from inside the container:
docker exec $CN sh -c 'test -S /var/run/docker.sock && echo DOCKER_SOCK_EXPOSED'
```

Evidence to record for the repro result:

- The exact request/command (method, path, headers, body, or `docker` invocation)
  → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, `uid=0`, leaked secret, exposed socket, 500 with
  stack) → `observed`.
- What it means for the target → `impact`. Set `reproduced: true`,
  `method: live-exploit`.

Safety invariants: traffic stays on `127.0.0.1` / inside `$CN`'s network; no
outbound connections to real hosts; no real data; side effects are benign
sentinels only.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN va-canary-$FID va-db-$FID 2>/dev/null
docker compose -p va-$FID down -v 2>/dev/null
docker network rm va-net-$FID 2>/dev/null
docker image rm -f $IMG 2>/dev/null
rm -f /tmp/jar.$FID /tmp/poc.$FID.out /tmp/Dockerfile.$FID \
      /tmp/va-$FID.dockerignore /tmp/va-$FID.iid

cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

---

## 9. Fallbacks

If a live exploit is not achievable, downgrade deliberately and set `method`
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`).

1. **Image builds but the app can't fully serve (missing sidecar, env, or the
   PoC targets a single function):** drive the vulnerable code path directly
   inside the container — exec the app's own test, or a one-off harness that
   calls the sink in whatever runtime the image provides. Set
   `method: unit-test`.

   ```sh
   # Run the project's own focused test inside the image (command is stack-specific):
   docker run --rm -v "$WT":/app -w /app $IMG sh -c '<test cmd for the matched stack>'
   ```

   For a Docker-config finding that has no running-app surface (e.g. proving the
   built image runs as root or ships a secret), the build itself plus the
   `docker inspect`/`docker history` evidence in step 7 IS the proof — record it
   here as `method: unit-test` (config assertion) or `build-only` per fidelity.

2. **Image builds but won't start at all (dependent DB/service absent, bad
   entrypoint, private base resolved but service deps missing):** record that
   `docker build` succeeds, the dependency set installs, and the vulnerable code
   /misconfiguration is present in the image, with the line-referenced
   source→sink (or Dockerfile/compose line) as evidence. Set `method: build-only`.

   ```sh
   docker build -f Dockerfile -t $IMG . && echo BUILD_OK
   ```

3. **Cannot build at all (base image won't pull, private registry, BuildKit
   secret unavailable, network blocked):** construct a static PoC — the exact
   crafted input (or the offending Dockerfile/compose lines) plus the
   line-referenced source→sink path showing why it triggers. Set
   `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

# ENV Playbook — Node / TypeScript

Build, run, and exploit a Node / TypeScript target (Express / Next / Nest /
Fastify / Koa / plain package) to reproduce a candidate finding with a real PoC.
Docker-first; the native Node / TS toolchain may be absent on the host. Keep ALL
traffic inside the local container — no external hosts, no real credentials, no
data exfiltration.

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

Confirm the stack from the target tree (read-only):

```sh
ls package.json package-lock.json pnpm-lock.yaml yarn.lock tsconfig.json 2>/dev/null
find . -maxdepth 3 \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.mjs' \) \
  -not -path '*/node_modules/*' | head
```

- **Manifests:** `package.json` (always). Lockfile picks the package manager:
  `package-lock.json` → npm, `pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn.
- **TypeScript:** `tsconfig.json` and `*.ts`/`*.tsx`. Compiled via `tsc`,
  `ts-node`/`tsx` (run TS directly), or a bundler (esbuild/swc/webpack/vite).
- **Framework tells** (`dependencies` in `package.json`, or imports):
  - Express → `express`; entry often `app.js`/`server.js`/`src/index.ts`.
  - Fastify → `fastify`. Koa → `koa`. Hapi → `@hapi/hapi`.
  - NestJS → `@nestjs/core`; entry `main.ts`, bootstraps on `3000`.
  - Next.js → `next` + a `next.config.*`; `pages/` or `app/` dir.
  - Library (no server) → no framework dep, has a `main`/`exports`/`bin` field.
- **Entry & scripts:** read `package.json` `scripts` (`start`, `dev`, `build`)
  and `main`/`module`/`exports`/`bin`. The `start`/`build` scripts are the
  ground truth for how the project runs.
- **Node version:** `.nvmrc`, `.tool-versions`, or `engines.node` in
  `package.json`. Match the image tag to it.

```sh
cat .nvmrc 2>/dev/null
node -e 'p=require("./package.json");console.log(JSON.stringify({scripts:p.scripts,main:p.main,bin:p.bin,engines:p.engines},null,2))' 2>/dev/null \
  || grep -E '"(scripts|main|bin|engines|start|build|dev)"' package.json
```

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

Never copy a host `node_modules` into the build — it may carry host-native
binaries and stale state. Let the container install fresh (the Dockerfiles below
do this; the `.dockerignore` keeps it out of the build context):

```sh
printf 'node_modules\nnpm-debug.log\n.git\n' > /tmp/va-$FID.dockerignore
```

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up DB, env, build, and
the correct start command for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the Node tag from step 1 (fall back to a recent LTS, e.g. `node:22-slim`).
The image installs deps with the detected package manager, builds if a `build`
script exists, and defers the start command to run time.

```sh
cat > /tmp/Dockerfile.$FID <<'EOF'
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy manifests first for layer caching; tolerate missing lockfiles.
COPY package.json ./
COPY package-lock.json* pnpm-lock.yaml* yarn.lock* ./
# Install with whichever lockfile is present (deterministic install per PM).
RUN if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then corepack enable && yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci; \
    else npm install; fi
COPY . .
# Build if the project defines one (TS compile / bundler); ignore if absent.
RUN npm run build --if-present
EXPOSE 3000
# overridden at run time per framework (see below)
CMD ["node", "-e", "console.log('set a start command')"]
EOF

docker build -f /tmp/Dockerfile.$FID --iidfile /tmp/va-$FID.iid \
  --build-arg DOCKER_BUILDKIT=1 -t $IMG .
```

Start command depends on how the project runs (bind to `0.0.0.0`, not
`localhost`, so the mapped port is reachable):

- **Has a `start` script:** `npm start` (or `pnpm start` / `yarn start`). This
  is the safest default — it is exactly how the project boots.
- **Express/Koa/Fastify plain entry:** `node dist/index.js` (after build) or
  `node src/index.js`. For TS without a build step: `npx tsx src/index.ts`.
- **NestJS:** `node dist/main.js` after `npm run build`; dev: `npm run start:dev`.
- **Next.js:** `npm run build && npm run start` (prod server on `3000`), or
  `npm run dev` for the dev server.
- **Library (no server):** there is nothing to serve — go to Fallbacks and drive
  the vulnerable API from a unit test (`method: unit-test`).

Most frameworks honor `PORT` (env) and/or `HOST`. Pass `-e PORT=3000 -e HOST=0.0.0.0`
when the app reads them; otherwise the in-container port is whatever the code
hardcodes — read the listen() call to confirm.

---

## 4. Dependencies

Install reproducibly from the lockfile (done in the image above; the standalone
forms, e.g. for the Fallbacks test runs):

```sh
npm ci                 # package-lock.json — clean, lockfile-exact
pnpm install --frozen-lockfile
yarn install --frozen-lockfile
npm install            # only if there is no lockfile at all
```

- Honor the lockfile exactly; do **not** `npm update` / bump versions (that
  changes the audited dependency set).
- Native addon build failures (`node-gyp`, `bcrypt`, `sharp`, `sqlite3`) → the
  image already ships `python3 make g++`; add `-dev` libs only if a specific
  module needs them.
- `postinstall` scripts run by default during install. That is intended here
  (the audited project would run them too) — but it is also why the build must
  stay in the container, never on the host.
- TypeScript that is run directly (no build script) needs `tsx`/`ts-node`
  available; `npx tsx` fetches it on demand inside the container.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:3000 \
  -e NODE_ENV=development -e PORT=3000 -e HOST=0.0.0.0 \
  $IMG npm start
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Adjust
the container port (`:3000`) and the start command per framework. If the app
hardcodes a different listen port, map that instead (`-p 127.0.0.1:$PORT:8080`).

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
```

Common in-container ports: Express/Nest/Next **3000**, Fastify **3000**
(default), but always confirm from the `listen()` call / `PORT` env. A 404 on
`/` still means the server is up — any TCP response counts as healthy; look for
the framework's boot log line (`Listening on`, `Nest application successfully
started`, `ready - started server on`).

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **DB-backed app:** run the project's own migration/seed scripts inside the
  container (read `package.json` scripts for the real names):

  ```sh
  docker exec $CN npm run migrate --if-present
  docker exec $CN sh -c 'npx prisma migrate deploy 2>/dev/null || npx sequelize-cli db:migrate 2>/dev/null || true'
  docker exec $CN npm run seed --if-present
  ```

- **Auth flow:** if the PoC needs a session/token, register or log in via the
  app's own endpoint with synthetic creds and keep the cookie jar / capture the
  token:

  ```sh
  # Cookie-session apps:
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -H 'Content-Type: application/json' \
    -d '{"email":"poc@local.test","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/login"

  # JWT/bearer apps — capture the token for the Authorization header:
  TOKEN=$(curl -s -H 'Content-Type: application/json' \
    -d '{"email":"poc@local.test","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/auth/login" | node -e 'process.stdin.on("data",d=>{try{console.log(JSON.parse(d).token||JSON.parse(d).accessToken)}catch(e){}})')
  ```

- Use only fake, local-only credentials. Never reuse real secrets from the repo
  beyond what is strictly required to boot.

---

## 7. Fire the PoC safely

Send the exploit to the **local** container only and capture concrete evidence.
Tailor to the finding's source→sink path; examples per class:

```sh
# SQL/NoSQL injection — observe error or extracted marker in the response:
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/search?q=%27%20OR%201=1--" | tee /tmp/poc.$FID.out
# NoSQL operator injection (Mongo) — JSON body that smuggles an operator:
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":null}}' "http://127.0.0.1:$PORT/login"

# Path traversal / arbitrary file read — pull a host file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head

# Prototype pollution — pollute, then observe the gadget take effect in a later request:
curl -s -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"yes"}}' "http://127.0.0.1:$PORT/<merge-sink>"
docker exec $CN node -e 'console.log(({}).polluted)'   # only meaningful in-process; prefer an app-observable gadget

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host:
docker exec -d $CN sh -c 'node -e "require(\"http\").createServer((q,s)=>s.end(\"CANARY\")).listen(9999)"'
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/"

# Command injection / RCE — prove exec via a benign in-container sentinel, then read it back
# (NEVER run destructive commands):
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# Reflected/stored XSS — confirm the payload is reflected unescaped in the response body:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o '<script>alert(1)</script>'
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, polluted property, 500 with stack) → `observed`.
- What it means for the target → `impact`. Set `reproduced: true`,
  `method: live-exploit`.

Safety invariants: traffic stays on `127.0.0.1` / inside `$CN`; no outbound
connections; no real data; side effects are benign sentinels only.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN 2>/dev/null
docker compose -p va-$FID down -v 2>/dev/null
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
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`):

1. **Won't serve but builds (library package, or web boot blocked):** drive the
   vulnerable function directly with a Node test in the container. Set
   `method: unit-test`.

   ```sh
   # Run the project's own focused test if one covers the sink:
   docker run --rm -v "$WT":/app -w /app $IMG sh -c \
     'npx jest path/to/file.test.js 2>/dev/null || npx vitest run path/to/file.test.ts 2>/dev/null || npx mocha test/<focused>.js'

   # Or a one-off harness that imports the vulnerable API and asserts impact:
   docker run --rm -v "$WT":/app -w /app $IMG node -e '
     const m = require("./dist/vulnerable.js");
     const out = m.parse("<payload>");        // call vulnerable API
     if (!/<impact-marker>/.test(String(out))) process.exit(1);
     console.log("IMPACT:", out);'
   # TypeScript source (no build): swap `node -e` for `npx tsx -e` / `npx ts-node -e`.
   ```

2. **Image builds but the app can't start (missing DB/config/env, native addon):**
   record that the dependency set installs, the build succeeds, and the
   vulnerable code is present and reachable, with the source→sink trace as
   evidence. Set `method: build-only`.

3. **Cannot build at all (toolchain/network blocked):** construct a static PoC —
   the exact crafted input plus the line-referenced source→sink path showing why
   it triggers. Set `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

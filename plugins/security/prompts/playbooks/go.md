# ENV Playbook — Go

Build, run, and exploit a Go target (net/http / gin / echo / chi / fiber /
gRPC, or a plain CLI / library) to reproduce a candidate finding with a real
PoC. Docker-first; the native Go toolchain may be absent on the host. Keep ALL
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
ls go.mod go.sum go.work vendor/modules.txt Dockerfile docker-compose.yml 2>/dev/null
find . -maxdepth 3 -name '*.go' -not -path '*/vendor/*' | head
```

- **Manifests:** `go.mod` (always for modules) declares the module path and the
  `go` directive (the language/toolchain version — match the image to it).
  `go.sum` pins dependency hashes. `go.work` means a multi-module workspace.
- **Vendoring:** a `vendor/` dir with `vendor/modules.txt` → deps are checked in;
  build offline with `-mod=vendor` (the default when `vendor/` is present).
- **Entry point:** a `package main` with a `func main()` is a runnable binary.
  Find it (and any `cmd/<name>/main.go` layout — Go's convention for multiple
  binaries):

  ```sh
  grep -rl '^package main' --include='*.go' . | grep -v /vendor/
  grep -rln 'func main' --include='*.go' . | grep -v /vendor/
  ls cmd/ 2>/dev/null
  ```

- **Framework tells** (read `go.mod` `require` block, or imports):
  - stdlib server → `net/http` (`http.ListenAndServe`, `http.HandleFunc`).
  - Gin → `github.com/gin-gonic/gin`. Echo → `github.com/labstack/echo`.
  - Chi → `github.com/go-chi/chi`. Fiber → `github.com/gofiber/fiber`
    (fasthttp-based). gorilla/mux → `github.com/gorilla/mux`.
  - gRPC → `google.golang.org/grpc`; usually a separate `*.proto` + generated
    `*.pb.go`. Default port often `50051`.
  - Library / CLI (no `ListenAndServe`, no `package main` server) → nothing to
    serve; go to Fallbacks and drive the sink from a Go test.
- **The listen address is ground truth.** Find the port and bind address — you
  must map and bind exactly what the code listens on:

  ```sh
  grep -rnE 'ListenAndServe|\.Run\(|\.Listen\(|net\.Listen' --include='*.go' . | grep -v /vendor/
  ```

  Note whether it binds `:8080` (all interfaces, mappable) vs `127.0.0.1:8080`
  (loopback only — see Run & health-check for how to still reach it).

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

Keep the build context lean and out of the host's reach (the Dockerfile below
copies the source in fresh; vendored deps come with it):

```sh
printf '.git\n*.test\n' > /tmp/va-$FID.dockerignore
```

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up the build flags, env,
DB, and the correct entry binary for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the Go tag from the `go` directive in `go.mod` (fall back to a recent
stable, e.g. `golang:1.23-bookworm`). A multi-stage build compiles in the SDK
image and runs the static binary in a tiny base — fast to start, nothing extra
in the runtime.

```sh
# Resolve the main package path (default to repo root "."):
MAINPKG=$(grep -rl '^package main' --include='*.go' "$WT" | grep -v /vendor/ | head -1)
MAINPKG=${MAINPKG:+./$(dirname "${MAINPKG#$WT/}")}; MAINPKG=${MAINPKG:-.}

cat > /tmp/Dockerfile.$FID <<EOF
FROM golang:1.23-bookworm AS build
WORKDIR /src
# Copy manifests first for layer caching; tolerate a missing go.sum.
COPY go.mod ./
COPY go.sum* ./
# Pre-fetch deps when not vendored (skipped automatically if vendor/ exists).
RUN test -d vendor || go mod download
COPY . .
# CGO off → a static binary that runs in a scratch/distroless base.
# If the project needs cgo (sqlite3, etc.), drop CGO_ENABLED and use a glibc base.
RUN CGO_ENABLED=0 go build -o /out/app $MAINPKG

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
EOF

docker build -f /tmp/Dockerfile.$FID --iidfile /tmp/va-$FID.iid -t $IMG "$WT"
```

If the runtime needs a shell or extra tooling for the PoC (e.g. command-injection
sentinels), swap the runtime stage to `debian:12-slim` or build the binary into
the `golang` image and run from there directly:

```sh
docker run -d --name $CN -p 127.0.0.1:$PORT:8080 -w /src -v "$WT":/src:ro \
  golang:1.23-bookworm sh -c "CGO_ENABLED=0 go build -o /tmp/app . && /tmp/app"
```

Start command, by how the project runs (the binary must bind `0.0.0.0` /
`:PORT`, not `127.0.0.1`, or the mapped host port can't reach it):

- **Single server binary:** the built `/app` is the entry (the `ENTRYPOINT`
  above). Pass config via flags/env at run time.
- **Multiple binaries (`cmd/<name>`):** build the specific one
  (`go build -o /out/app ./cmd/<name>`) — pick the server, not a migrator/CLI.
- **Reads `PORT`/`ADDR` from env:** pass it (`-e PORT=8080`). Many Go servers
  hardcode the listen addr — read the `ListenAndServe` arg; if it's
  `127.0.0.1:8080`, see Run & health-check for the loopback workaround.
- **Library / CLI only:** nothing to serve → Fallbacks, `method: unit-test`.

---

## 4. Dependencies

Restore reproducibly; `go.sum` makes installs hash-verified and deterministic:

```sh
go mod download        # fetch modules listed in go.mod into the build cache
go mod verify          # confirm cached modules match go.sum hashes
```

- **Vendored repos** (`vendor/` present): builds use it automatically; force it
  with `go build -mod=vendor ./...`. No network needed — preferred when offline.
- Do **not** `go get -u` / bump versions — that changes the audited dependency
  set. Honor `go.mod`/`go.sum` exactly (`-mod=readonly`, the default for
  modules, errors if a build would mutate them).
- **cgo:** if a dep imports C (e.g. `mattn/go-sqlite3`), `CGO_ENABLED=0` fails to
  build. Use `CGO_ENABLED=1` with a glibc base (`golang:1.23-bookworm` has gcc)
  and run from a `debian:12-slim` runtime, not distroless/scratch.
- **Private modules** (`GOPRIVATE`): if a require path can't resolve, it likely
  needs auth — out of scope; do not supply real credentials. Note it and fall
  back if the build blocks.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:8080 \
  -e PORT=8080 -e ADDR=0.0.0.0:8080 \
  $IMG
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Map the
container port (`:8080`) to whatever the code actually listens on (read the
`ListenAndServe` arg — common defaults: net/http/chi/gorilla **8080**, Gin
**8080**, Echo **1323**, Fiber **3000**, gRPC **50051**).

**If the app binds `127.0.0.1` inside the container,** a `-p` map can't reach it
(loopback is per-namespace). Either fire the PoC from inside the container
(`docker exec $CN ...`, but distroless has no shell — use a `debian:12-slim`
runtime), or run with `--network host` on Linux so the container's loopback is
the host's:

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
healthy. Look for the framework boot line in the logs (`Listening on`, Gin's
`[GIN-debug] Listening and serving HTTP on`, Echo's banner, `http: server
started`). For a **gRPC** target, plain `curl` won't health-check it; use
`docker exec $CN /app -test` only if it offers one, or probe with `grpcurl`
(see Fire the PoC).

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **DB-backed app:** Go projects rarely ship an ORM auto-migrate CLI — check for
  a migrations dir (`migrations/`, `db/`) and a tool (`golang-migrate`, `goose`,
  `atlas`), or a `make migrate` / project subcommand. Run it inside the
  container:

  ```sh
  docker exec $CN /app migrate 2>/dev/null \
    || docker exec $CN sh -c 'migrate -path /migrations -database "$DATABASE_URL" up 2>/dev/null' \
    || true
  ```

  If the app embeds an in-process SQLite/embedded store, it usually creates the
  schema on boot — nothing to seed beyond the auth step below.

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
# SQL injection — observe error or extracted marker (Go's database/sql with
# string-concatenated queries is the classic sink):
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/user?id=1%20OR%201=1--" | tee /tmp/poc.$FID.out

# Path traversal / arbitrary file read — http.ServeFile / os.Open on a
# user-controlled path; pull a file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head
# URL-encoded traversal that bypasses naive filepath.Clean-after-join:
curl -s "http://127.0.0.1:$PORT/static/..%2f..%2f..%2fetc%2fpasswd" | head

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host.
# Start a canary in a sidecar on $CN's network, then make the app fetch it:
docker run -d --name va-canary-$FID --network "container:$CN" \
  python:3-slim python3 -c 'import http.server,socketserver;socketserver.TCPServer(("127.0.0.1",9999),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(b"CANARY"))})).serve_forever()'
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/" | grep -o CANARY
# Also test cloud-metadata SSRF guards WITHOUT leaving the box — the request
# must stay local; 169.254.169.254 is only a payload string, not a real target.

# Command injection / RCE — os/exec with user input. Prove exec via a benign
# in-container sentinel, then read it back (NEVER destructive commands).
# Needs a shell in the runtime image (use debian:12-slim, not distroless):
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# SSTI (html/template misused as text/template, or user-controlled template
# text) — submit a template expression and observe it evaluated:
curl -s "http://127.0.0.1:$PORT/render?tpl=%7B%7B.Secret%7D%7D" | tee -a /tmp/poc.$FID.out

# Reflected/stored XSS — text/template or manual string-building bypasses Go's
# default html/template escaping; confirm the payload is reflected unescaped:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" \
  | grep -o '<script>alert(1)</script>'

# Open redirect — http.Redirect with a user-controlled Location:
curl -s -o /dev/null -D- "http://127.0.0.1:$PORT/redirect?next=https://evil.example" \
  | grep -i '^location:'   # evidence is the header value, no external request made

# gRPC sink — invoke the method with grpcurl against the local container:
docker run --rm --network "container:$CN" fullstorydev/grpcurl -plaintext \
  -d '{"id":"1 OR 1=1"}' 127.0.0.1:50051 pkg.Service/Method
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, evaluated template, redirect header, 500 with stack)
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
   vulnerable function directly with a Go test in the SDK image — the
   highest-fidelity non-server proof. Set `method: unit-test`.

   ```sh
   # Run the project's own focused test if one covers the sink (-run targets it):
   docker run --rm -v "$WT":/src -w /src golang:1.23-bookworm \
     go test -run 'TestVulnerable' ./path/to/pkg/...

   # Or drop a one-off harness into the package and run it as a test.
   # Use the module path from go.mod for the import:
   cat > "$WT/path/to/pkg/poc_test.go" <<'EOF'
   package pkg
   import "testing"
   func TestPoC(t *testing.T) {
       out := Vulnerable("<payload>")        // call the vulnerable API
       if !contains(out, "<impact-marker>") {
           t.Fatalf("no impact: %q", out)
       }
       t.Logf("IMPACT: %s", out)
   }
   EOF
   docker run --rm -v "$WT":/src -w /src golang:1.23-bookworm \
     go test -run TestPoC -v ./path/to/pkg/...
   ```

   For an HTTP handler that won't boot standalone, exercise it in-process with
   `net/http/httptest` (no real port, no network) — still `method: unit-test`:

   ```go
   req := httptest.NewRequest("GET", "/download?file=../../etc/passwd", nil)
   rr := httptest.NewRecorder(); Handler(rr, req)
   // assert rr.Body contains the leaked content
   ```

2. **Image builds but the app can't start (missing DB/config/env, cgo dep,
   private module resolved but service deps absent):** record that
   `go build` succeeds, `go mod verify` passes, and the vulnerable code is
   present and reachable, with the line-referenced source→sink trace as
   evidence. Set `method: build-only`.

   ```sh
   docker run --rm -v "$WT":/src -w /src golang:1.23-bookworm \
     sh -c 'go build ./... && go vet ./... ; true'
   ```

3. **Cannot build at all (toolchain/network blocked, unresolvable private
   deps):** construct a static PoC — the exact crafted input plus the
   line-referenced source→sink path showing why it triggers. Set
   `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

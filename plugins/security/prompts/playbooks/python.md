# ENV Playbook — Python

Build, run, and exploit a Python target (Django / Flask / FastAPI / plain
package) to reproduce a candidate finding with a real PoC. Docker-first; the
native Python toolchain may be absent on the host. Keep ALL traffic inside the
local container — no external hosts, no real credentials, no data exfiltration.

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
ls pyproject.toml requirements*.txt setup.py setup.cfg Pipfile Pipfile.lock \
   poetry.lock uv.lock manage.py 2>/dev/null
find . -maxdepth 3 -name '*.py' | head
```

- **Manifests:** `pyproject.toml` (PEP 621 / poetry / uv / hatch), one or more
  `requirements*.txt` (pip), `setup.py` / `setup.cfg` (legacy), `Pipfile(.lock)`
  (pipenv). Lockfiles: `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- **Framework tells:**
  - Django → `manage.py`, `*/settings.py`, `wsgi.py`/`asgi.py`, `INSTALLED_APPS`,
    `urls.py`; `django` in deps.
  - Flask → `from flask import Flask`, an `app = Flask(__name__)`, often
    `app.py` / `wsgi.py`; `flask` in deps.
  - FastAPI → `from fastapi import FastAPI`, `app = FastAPI()`, ASGI; `fastapi`
    + `uvicorn` in deps.
  - Plain package / CLI (no web server) → only a `pyproject.toml`/`setup.py`
    with a library or `console_scripts`, no app object.
- **Python version:** `.python-version`, `requires-python` in `pyproject.toml`,
  `python_requires` in `setup.cfg`, or a `runtime.txt`. Match the image to it.

```sh
cat .python-version 2>/dev/null
grep -E 'requires-python|python_requires' pyproject.toml setup.cfg 2>/dev/null
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

Prefer the project's own definition — it usually wires up DB, env, migrations,
and the correct start command for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the Python tag from step 1 (fall back to a recent stable, e.g.
`python:3.12-slim`). Build deps cover native wheels (`psycopg2`, `cryptography`,
`lxml`, `mysqlclient`, `Pillow`).

```sh
cat > /tmp/Dockerfile.$FID <<'EOF'
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git curl libpq-dev libssl-dev libffi-dev \
      libxml2-dev libxslt1-dev default-libmysqlclient-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy manifests first for layer caching (see Dependencies for which apply).
COPY pyproject.toml requirements*.txt setup.py setup.cfg poetry.lock uv.lock \
     Pipfile Pipfile.lock ./ 2>/dev/null || true
RUN pip install --upgrade pip
COPY . .
RUN pip install -r requirements.txt 2>/dev/null \
    || pip install . 2>/dev/null \
    || true
EXPOSE 8000
# overridden at run time per framework (see below)
CMD ["bash"]
EOF

docker build -f /tmp/Dockerfile.$FID -t $IMG .
```

> The `COPY ... 2>/dev/null` glob trick is shell-shorthand; in a real Dockerfile
> just `COPY . .` and run the dependency restore from §4. The split-copy is only
> a caching nicety — drop it if any listed manifest is absent.

Start command depends on the framework (set host `PORT`, bind to `0.0.0.0`):

- **Django:** `python manage.py runserver 0.0.0.0:8000`
  (set `DJANGO_SETTINGS_MODULE` if non-default; provide a dummy
  `SECRET_KEY=$(openssl rand -hex 32)` and `DEBUG=1` / `ALLOWED_HOSTS=*` so it
  boots in dev). Production WSGI: `gunicorn <proj>.wsgi:application -b 0.0.0.0:8000`.
- **Flask:** `flask --app app run --host 0.0.0.0 --port 8000`
  (or `gunicorn 'app:app' -b 0.0.0.0:8000` / `python app.py` if it self-serves).
- **FastAPI:** `uvicorn app.main:app --host 0.0.0.0 --port 8000`
  (substitute the real `module:app` path).
- **Library / CLI (no server):** there is nothing to serve — go to Fallbacks and
  drive the vulnerable API from a unit test (`method: unit-test`).

---

## 4. Dependencies

Restore from the project's lockfile/manifest — do **not** upgrade, that changes
the audited dependency set. Inside the container (or in the build):

```sh
# pip + requirements (most common):
pip install -r requirements.txt          # add -r requirements-dev.txt if the PoC needs it

# editable install of the package itself (for libraries / console_scripts):
pip install -e .

# poetry (lockfile present):
pip install poetry && poetry install --no-interaction --no-root

# uv (fast; lockfile present):
pip install uv && uv sync --frozen        # --frozen honors uv.lock exactly

# pipenv:
pip install pipenv && pipenv install --deploy --system   # --deploy honors Pipfile.lock
```

- Honor the lockfile exactly. Avoid `pip install -U`, `poetry update`, or
  `uv lock`.
- Native wheel build failures → install the matching `-dev` lib (see 3b:
  `libpq-dev`, `libssl-dev`, `libffi-dev`, `libxml2-dev`/`libxslt1-dev`,
  `default-libmysqlclient-dev`).
- Prefer a venv-free container install (the image is disposable). If the project
  hard-requires a venv, `python -m venv /venv && . /venv/bin/activate` first.

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:8000 \
  -e SECRET_KEY=$(openssl rand -hex 32) -e DEBUG=1 -e ALLOWED_HOSTS='*' \
  $IMG python manage.py runserver 0.0.0.0:8000
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Adjust
the container port and the start command per framework (Django/FastAPI/gunicorn
default **8000**; `flask run` defaults to **5000** unless `--port` is set).

Confirm it is up (poll, don't sleep blindly):

```sh
for i in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  sleep 1
done
docker logs --tail 50 $CN          # inspect boot errors if curl never succeeds
```

Common ports inside the container: Django/FastAPI/gunicorn **8000**, Flask dev
server **5000**. A 404 at `/` still means the server is up — health-check on any
route that returns a response, or check `docker logs` for the "listening" line.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **Django DB:** migrate, then create a throwaway user inside the container:

  ```sh
  docker exec $CN python manage.py migrate --noinput
  docker exec $CN python manage.py shell -c \
    'from django.contrib.auth import get_user_model as g; U=g(); \
     U.objects.filter(username="poc").exists() or \
     U.objects.create_user("poc","poc@local.test","Poc-Passw0rd!")'
  # superuser variant if the PoC needs admin:
  docker exec $CN sh -c 'DJANGO_SUPERUSER_PASSWORD=Poc-Passw0rd! \
     python manage.py createsuperuser --noinput --username poc --email poc@local.test' \
     2>/dev/null || true
  ```

- **Flask / FastAPI:** there is no universal ORM/seed CLI. Seed via the app's
  own DB layer in a one-off exec, e.g.:

  ```sh
  docker exec $CN python -c \
    'from app import db, User; db.create_all(); \
     db.session.add(User(email="poc@local.test", password="Poc-Passw0rd!")); \
     db.session.commit()'
  ```

  (substitute the real models/session import; if the app seeds on first boot or
  via a fixture/`flask db upgrade`, use that instead).

- **Auth flow:** if the PoC needs a session, log in via the app's own login
  endpoint with the seeded creds and keep the cookie jar:

  ```sh
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -d 'username=poc&password=Poc-Passw0rd!' \
    "http://127.0.0.1:$PORT/login"          # Django needs the CSRF token too — see §7
  ```

  Token-auth APIs (DRF/FastAPI): POST creds to the token endpoint, capture the
  returned token, send it as `Authorization: Bearer <tok>` / `Token <tok>`.

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

# SSTI (Jinja2/Django templates) — prove evaluation with arithmetic, then escalate:
curl -s "http://127.0.0.1:$PORT/render?name=%7B%7B7*7%7D%7D" | grep -o 49

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host:
docker exec -d $CN python -m http.server 9999      # canary in-container
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/"

# Insecure deserialization (pickle/yaml.load) / RCE — prove code exec by a
# benign in-container side effect (touch a sentinel), then read it back:
curl -s --data-binary @/tmp/payload.$FID "http://127.0.0.1:$PORT/<sink>"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# Django POST needs the CSRF token — fetch it from the form/cookie first:
TOKEN=$(curl -s -c /tmp/jar.$FID "http://127.0.0.1:$PORT/login" \
  | grep -oP 'csrfmiddlewaretoken" value="\K[^"]+')
curl -s -b /tmp/jar.$FID -c /tmp/jar.$FID \
  -d "csrfmiddlewaretoken=$TOKEN&username=poc&password=Poc-Passw0rd!" \
  "http://127.0.0.1:$PORT/login"
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, `49` from `7*7`, reflected script, 500 with traceback) → `observed`.
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

1. **Won't serve but builds (library/CLI, or web boot blocked):** drive the
   vulnerable function directly with a Python snippet/test in the container.
   Set `method: unit-test`.

   ```sh
   docker run --rm -v "$WT":/app -w /app $IMG \
     python -c 'from the_pkg.mod import vuln_fn; \
                out=vuln_fn("<payload>"); \
                assert "<impact marker>" in str(out), out; print("PWNED", out)'
   # or, if a suite exists: pytest tests/test_<focused>.py -x -q
   ```

2. **Image builds but the app can't start (missing DB/config/migrations, native
   wheel):** record that the dependency set installs and the vulnerable code is
   present and reachable, with the source→sink trace as evidence. Set
   `method: build-only`.

3. **Cannot build at all (toolchain/network blocked):** construct a static PoC —
   the exact crafted input plus the line-referenced source→sink path showing why
   it triggers. Set `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

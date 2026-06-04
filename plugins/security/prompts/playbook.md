<!--
REPRO PLAYBOOK — Phase 6 of vuln-audit. One agent per surviving finding builds,
runs, and exploits the target to prove it with a real PoC. Stack-agnostic: recon
gives you the stack, frameworks, run command, and port; you supply the
language-specific build/run details. Docker-first. Keep ALL traffic local — no
external hosts, no real credentials, no data exfiltration.
-->

# Repro playbook — build, run, prove (one finding)

Conventions (substitute per finding so parallel repros never collide):

- `FID` — the finding id; use it to make every name/port unique.
- `WT=/tmp/va-$FID` — isolated git worktree. `IMG=va-$FID:repro` — image tag.
  `CN=va-$FID` — container name. `PORT` — a free ephemeral host port.
- The result must set `method` to one of:
  `live-exploit | unit-test | build-only | static-poc`.

## 1. Isolate

Never touch the original tree. Create a throwaway worktree at the audited ref:

```sh
git -C <target> worktree add --detach /tmp/va-$FID "$REF"   # $REF default HEAD
cd /tmp/va-$FID
```

If `<target>` is not a git repo (rare), `cp -a <target> /tmp/va-$FID` and note
it. All build/run steps run from `WT`.

## 2. Build & run (docker-first)

Use `recon.run_strategy`, `recon.stack`, and recon's boot notes (run command,
port, prerequisite services) as your starting point — don't re-derive what recon
already found.

1. Repo ships Docker → prefer it; it usually wires up DB/env/migrations:
   `docker compose -p va-$FID up -d --build`, else `docker build -t $IMG .`.
2. No Dockerfile → write a minimal one for the detected stack: a recent stable
   base image for the language, install the build deps the native packages need,
   restore dependencies from the lockfile EXACTLY (never upgrade — that changes
   the audited dependency set), then run the app's own start command on
   `0.0.0.0`.
3. Can't containerize → run natively if the host has the runtime (see HOST
   CONSTRAINTS passed by the workflow).

Run detached, bound to loopback only, on a finding-keyed port:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
docker run -d --name $CN -p 127.0.0.1:$PORT:<app-port> $IMG <start-command>
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Poll for
health, don't sleep blindly; on failure inspect `docker logs --tail 50 $CN`.

## 3. Seed (only what the PoC needs)

Create the minimum synthetic state — a throwaway user, a row, an auth session —
using the app's own endpoints/console. Use only fake, local-only credentials;
never reuse real secrets from the repo beyond what's strictly required to boot.

## 4. Fire the PoC safely

Send the exploit to the LOCAL instance only and capture concrete evidence.
Tailor the oracle to the finding's source->sink path:

- Injection — error/boolean/time oracle (unbalanced quote, `1=1` vs `1=2`,
  `pg_sleep`/`SLEEP`), or an OS-command marker (`; sleep 5`, `| id`).
- Path traversal / file read — pull a host file the app should never serve
  (`?file=../../../../etc/passwd`).
- SSRF — point at a CONTAINER-LOCAL canary listener you start, never a real host.
- Deserialization / RCE — prove exec with a benign in-container side effect
  (touch a sentinel file), then read it back; never run destructive commands.
- XSS — confirm the payload is reflected unescaped in the response context.
- Auth/access-control — perform the action as the wrong (or no) principal and
  show it succeeds.

Record for the result: the exact request (-> `poc`), the response/log line
proving impact (leaked row, file contents, sentinel, reflected script, 500 with
stack -> `observed`), and what it means for the target (-> `impact`). Set
`reproduced: true`, `method: live-exploit`.

Safety invariants (non-negotiable): traffic stays on `127.0.0.1` / inside `$CN`;
no outbound connections; no real data; side effects are benign sentinels only.

## 5. Teardown (always, even on failure)

```sh
docker rm -f $CN 2>/dev/null
docker compose -p va-$FID down -v 2>/dev/null
docker image rm -f $IMG 2>/dev/null
cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

## 6. Fallbacks

If a live exploit isn't achievable, downgrade deliberately and set `method`;
never claim `reproduced: true` without observed runtime evidence.

1. Builds but won't serve (library, or boot blocked) → drive the vulnerable API
   directly from a focused unit test in the container. `method: unit-test`.
2. Image builds but the app can't start (missing DB/config) → record that deps
   install and the vulnerable code is present and reachable, with the
   source->sink trace as evidence. `method: build-only`.
3. Can't build at all (toolchain/network blocked) → construct a static PoC: the
   exact crafted input plus the line-referenced source->sink path showing why it
   triggers. `method: static-poc`, `reproduced: false`.

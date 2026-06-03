<!--
FINDER PROMPT — secrets. You are a fresh-context auditor hunting ONE class:
Hardcoded Secrets & Credentials. Read the target's code, config, and history;
emit finding objects. Signal discipline (AGENTS.md) is binding: a finding is a
REAL secret that grants an attacker access to a REAL resource — a key/token/
password embedded in code/config/history, or a weak default credential, where
the credential is live (or trivially reachable) and not a placeholder, test
fixture, public/non-secret value, or already-rotated artifact. No "rotate keys"
musings without a concrete live secret, no flagging env-var reads, no entropy
nags on non-secret strings, no posture items.
-->

# Finder — Hardcoded Secrets & Credentials (`secrets`)

**Class key:** `secrets` · **OWASP:** A02:2025 (Security Misconfiguration — secret
management) · **CWE:** CWE-798 (use of hard-coded credentials) / CWE-259
(hard-coded password) / CWE-321 (hard-coded cryptographic key) / CWE-547
(hard-coded sensitive constants) · **ASVS:** V14 (Configuration & Secret
Management)

## 1. Objective

Find a **real, usable secret embedded in the source, config, build artifacts, or
git history** — an API key, token, password, private key, connection string with
credentials, or a weak/default credential the app ships with — such that anyone
who can read the repo (or a fetched dependency/image) can authenticate as the
app, decrypt its data, or take over an account. The bug is the secret's presence
and liveness, not merely that "a secret exists somewhere."

## 2. Where to look

A secret is a finding when **(a) it is genuinely secret material, (b) it is live
or trivially live, and (c) an attacker can read it** (public repo, leaked source,
shipped binary/image, npm/gem package, git history). Map those three before
flagging. Surfaces:

- **Source literals:** assignments to `*_key`, `*_secret`, `*_token`,
  `*password*`, `apikey`, `client_secret`, `access_token`, `private_key`,
  `auth`, `bearer`, `signing_key`, `encryption_key`, `webhook_secret`, DSNs.
  Inline in service-client constructors (S3/Stripe/Twilio/SendGrid/OpenAI/
  Slack/GitHub/DB drivers), HTTP auth headers, and CI/deploy scripts.
- **Config & infra files:** `.env`, `.env.*` (committed!), `config/*.yml`,
  `application.properties`, `appsettings.json`, `settings.py`, `wp-config.php`,
  `docker-compose.yml`, `Dockerfile` (`ENV`/`ARG SECRET=`), `k8s` manifests &
  ConfigMaps (vs Secrets), `terraform/*.tf` + `*.tfvars`, `serverless.yml`,
  `*.plist`, mobile `strings.xml`/`Info.plist`, `.npmrc`/`.pypirc`/`.netrc`,
  `database.yml`, `secrets.yml`/`credentials.yml.enc` (unencrypted), Helm
  `values.yaml`.
- **Key material files:** committed `*.pem`/`*.key`/`id_rsa`/`*.p12`/`*.pfx`/
  `*.jks`/`*.keystore`/`*.ppk`/`serviceAccount*.json` (GCP)/`*.kubeconfig`/
  `*.crt` with private half/`*.gpg`/`*.asc` private blocks.
- **Default / fallback credentials:** `admin/admin`, `root` with empty/known
  password seeded in migrations/seeders/bootstrap, `password ||= "changeme"`,
  `ENV["X"] || "hardcoded-fallback"`, dev creds reused in prod, default JWT/
  session/encryption secret baked into the framework config when unset.
- **Git history (critical surface):** secrets removed from HEAD but **still in
  history** — `git log -p`, `git rev-list --all`, deleted `.env`, a key rotated
  in a later commit but the old value still reachable. A removed secret that was
  never rotated is still live.
- **Build/CI:** `.github/workflows/*` / `.gitlab-ci.yml` / `Jenkinsfile` /
  `.circleci/config.yml` with `echo $TOKEN` into logs, hardcoded registry/cloud
  creds, `with:` inputs holding tokens (vs `secrets.X`), base64'd kubeconfigs.
- **Frontend/client bundles:** secrets shipped to the browser/mobile/desktop —
  any "secret" key in JS/TS that reaches a webpack/vite bundle, React Native,
  Electron, Android/iOS resources. Server-side secrets in client code = leaked
  to every user.

Per-language / per-format SINK & literal signals:

- **Crystal:** `Stripe.api_key = "sk_live_..."`, `ENV["X"]? || "fallback"`,
  hardcoded `HTTP::Headers{"Authorization" => "Bearer ..."}`, `DB.open("postgres
  ://user:pass@host")`, secrets in `shard.yml`/`config/*.cr` constants.
- **Ruby:** `Stripe.api_key = "sk_live_..."`, `ENV.fetch("X", "default-secret")`,
  `secret_key_base` literal in `config/secrets.yml`/`credentials`,
  `config.secret_key_base = "..."`, `Net::HTTP` basic-auth literals, `Aws::
  Credentials.new("AKIA...", "secret")`, seeds with `password: "admin"`.
- **Node/TS:** `const API_KEY = "..."`, `process.env.X || "hardcoded"`,
  `new Stripe("sk_live_...")`, `jwt.sign(p, "supersecret")`, `axios` headers with
  literal Bearer, `mongoose.connect("mongodb://u:p@...")`, secrets in `next.
  config.js`/`vite` defines that ship to the client, `NEXT_PUBLIC_*`/`VITE_*`
  vars holding real secrets (these are bundled and public).
- **Python:** `API_KEY = "..."`, `os.getenv("X", "fallback-secret")`,
  `SECRET_KEY = "..."` (Django/Flask) literal, `boto3` `aws_access_key_id=
  "AKIA..."`, `psycopg2.connect("postgresql://u:p@...")`, `stripe.api_key=`,
  hardcoded `Authorization` in `requests` headers, `Fernet(b"hardcoded-key")`.
- **Go:** `const apiKey = "..."`, `os.Getenv("X")` with `if x == "" { x =
  "default" }`, `aws.Credentials{AccessKeyID:"AKIA...", SecretAccessKey:"..."}`,
  DSN string literals `"user:pass@tcp(...)"`, `jwt` signing with a string-literal
  key, `http.Request` with hardcoded bearer.
- **PHP:** `define('DB_PASSWORD', '...')` / `wp-config.php`, `$apiKey = "..."`,
  `getenv('X') ?: 'default'`, Laravel `config/*.php` returning literals instead of
  `env()`, `.env` committed with `APP_KEY=`, PDO DSN with creds.
- **Java/Kotlin:** `String API_KEY = "..."`, `application.properties`/`.yml`
  `spring.datasource.password=...`, `new BasicAWSCredentials("AKIA...", "...")`,
  `Jwts.builder().signWith(SignatureAlgorithm.HS256, "literal-secret")`,
  keystore passwords inline, Android `BuildConfig`/`strings.xml` with API keys.
- **Rust:** `const API_KEY: &str = "..."`, `env::var("X").unwrap_or("default")`,
  reqwest `bearer_auth("literal")`, sqlx/`DATABASE_URL` literal with creds,
  `jsonwebtoken` `EncodingKey::from_secret(b"literal")`.

High-confidence provider fingerprints (verify liveness, don't flag blindly):
`AKIA[0-9A-Z]{16}` (AWS access key), `sk_live_`/`rk_live_` (Stripe live),
`xox[baprs]-` (Slack), `ghp_`/`gho_`/`github_pat_` (GitHub PAT), `AIza[0-9A-Za-z
\-_]{35}` (Google API), `SG.` (SendGrid), `-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE
KEY-----`, `eyJ...` long-lived JWTs, `glpat-` (GitLab), `npm_` (npm token),
`xapp-`/`xoxe` (Slack app), `key-[0-9a-f]{32}` (Mailgun), `dop_v1_` (DigitalOcean).

## 3. Detection heuristics

**Taint perspective.** This class is largely *presence-driven*, not flow-driven:
the SOURCE is the attacker's read access to the repo/artifact, and the SINK is
the embedded secret that grants access to an external resource. Frame each
finding around **what the secret unlocks and who can read the secret.**

- **SOURCE** = the attacker's read path to the literal: a public/forked repo, a
  leaked or shared source tree, a published package (`npm pack`, `gem`, PyPI
  sdist), a shipped client bundle/binary/mobile APK/desktop app, the CI logs, or
  git history. Name the actual path ("repo is public", "value ships in the React
  bundle served to all users", "old `.env` still in history at commit `abc123`").
- **SINK** = the protected resource the secret authenticates to: the cloud
  account (AWS/GCP), payment processor, email/SMS sender, third-party API quota,
  the production DB, the app's own JWT/session/encryption that the secret signs,
  or admin login via a default credential. State the concrete impact of holding
  the secret.

Vulnerable patterns to confirm (each needs a real secret + a real read path):

- **Live third-party API key/token in code or config (CWE-798):** a usable
  Stripe/AWS/Slack/SendGrid/Twilio/OpenAI/GitHub key as a literal. Highest value
  when it's a *live secret* (not `test`/`pk_`/public) and the repo is reachable.
  Confirm the prefix/format implies a live secret and the surrounding code uses
  it against the real provider.
- **Hardcoded password / connection string (CWE-259):** DB/SMTP/LDAP/Redis/MQ
  credentials inline or in a committed config — `postgres://user:pass@host`,
  `spring.datasource.password=...`, `DB_PASSWORD` literal. Reachable = the host
  is network-reachable from where the attacker stands (often it is internally;
  for a public repo of an internal app, still report — the creds are the leak).
- **Hardcoded cryptographic / signing key (CWE-321):** the app's own JWT/session/
  cookie/HMAC/encryption secret as a literal or framework default (`SECRET_KEY=
  "django-insecure-..."`, `secret_key_base`, `signWith("secret")`). Holding it
  lets an attacker forge tokens/cookies for any user → auth bypass. (When the
  *crypto operation* is the bug, that's `crypto`; here the bug is the key being
  knowable. Report under whichever the path centers on; cross-link in rationale.)
- **Weak / default credential shipped (CWE-798/1392):** seeded `admin/admin`,
  empty root password, `|| "changeme"` fallback that activates when the env var
  is unset (and prod commonly leaves it unset), default framework secret used
  when config is blank. Confirm the default path is *reachable in prod* — an
  unset-env fallback that silently runs in production IS a finding.
- **Secret in git history not rotated (CWE-798):** a key/`.env`/`.pem` deleted
  from HEAD but present in history and never rotated at the provider. Removal ≠
  rotation. Confirm via `git log -p`/`git rev-list --all -- <path>` that the
  value is reachable and there's no evidence it was rotated.
- **Server secret leaked to a client (CWE-798):** a secret meant for the server
  that ends up in a browser/mobile/desktop bundle (`NEXT_PUBLIC_`/`VITE_`
  prefixed real secret, key inlined in client JS, Android `strings.xml` API key).
  Every user holds it. Distinguish from intentionally-public keys (publishable
  Stripe `pk_`, Firebase web config, Google Maps browser key with referrer
  restrictions — those are *designed* to be client-side, see §4).
- **Committed private key / keystore (CWE-321):** any `-----BEGIN ... PRIVATE
  KEY-----`, `*.p12`/`*.jks` with the password also committed, SSH host/deploy
  keys, GCP service-account JSON. The private half being in the repo defeats it.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these holds:

- **Not actually secret material:** a public/publishable key by design — Stripe
  `pk_*` publishable key, Firebase web `apiKey` (it's an identifier, not a
  secret; security is in rules), Google Maps/Analytics browser keys (restricted
  by HTTP referrer/API), Sentry public DSN, OAuth *client_id* (public),
  reCAPTCHA *site* key, public PGP/TLS *public* keys/certs. A `pk_`/`pub`/`site`/
  `client_id` is not the secret half — verify which half you're looking at.
- **Obvious placeholder / example / template:** `your-api-key-here`,
  `xxx`/`<changeme>`, `sk_test_...` test-mode keys, values in `.env.example`/
  `.env.sample`/`*.dist`/`*.template`/`README` snippets, RFC/docs example keys
  (`AKIAIOSFODNN7EXAMPLE` is the canonical AWS docs sample — never live). Match
  against known doc/example sentinels and obvious dummy patterns.
- **Test fixtures / mocks / specs:** secrets confined to `test/`/`spec/`/
  `__tests__/`/`fixtures/`/`*_test.*` that point only at a mock server or local
  test container and are never the production value. Confirm no prod wiring uses
  the same literal.
- **Sourced from real secret management at runtime:** the literal you see is a
  *variable read*, not a value — `ENV["X"]`/`os.getenv`/`process.env.X`/Vault/
  KMS/SSM/Secrets Manager/Doppler/`credentials.yml.enc` (sealed) fetch. Reading
  from a secret store is the correct pattern, not a finding. (A *fallback default*
  on the read still IS a finding — see §3.)
- **Already rotated / dead secret:** the value is demonstrably revoked (provider
  returns 401, key deleted at source, commit message/ticket confirms rotation),
  or it's a one-time-use value with no standing access. Removal from HEAD alone
  is NOT rotation — only count as dead if the *provider-side* credential is gone.
- **Low-entropy non-secret constants:** feature-flag strings, enum values, public
  URLs, version strings, salts/IVs that are *meant* to be public (a salt stored
  alongside a hash is by design not secret), cache keys — none are credentials.
- **Encrypted-at-rest secret stores:** `credentials.yml.enc`, `git-crypt`/`sops`/
  `ansible-vault`/`sealed-secrets` blobs where the *decryption key* is NOT also in
  the repo. The encrypted blob is safe; only flag if the master key is committed
  too.

If a "mitigation" is bypassable — a fallback default that runs in prod, a "test"
key that the README says to also use in staging, a sops file whose age key is
committed two dirs over, a `pk_` that's actually the `sk_` mislabeled — it is NOT
a mitigation. Flag it and name the exact bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — a **live secret granting broad/unauth, high-impact access** that
  an attacker can read now: live AWS/GCP root or broad-IAM key, live payment
  processor secret (`sk_live_`), production DB admin connection string,
  committed private key controlling prod, or the app's JWT/session signing secret
  (forge any user's auth) — when the repo/artifact is public or widely shared.
- **High** — a live secret with meaningful but scoped access, or a default/weak
  credential reachable in prod: scoped API token (single-service), SMTP/SendGrid
  send key (spoof mail), internal DB creds in a leaked repo, a `|| "changeme"`
  fallback that activates when prod leaves the env unset, server secret leaked
  into a shipped client bundle.
- **Medium** — secret with limited scope/short life or guarded reach: a key with
  tight provider-side restrictions, creds for an isolated/non-prod system that's
  still reachable, secret only in history of a private repo with limited
  audience, default cred behind an extra auth layer.
- **Low/Info** — placeholder/example/test-only value (usually drop per §4),
  rotated/dead secret, or an intentionally-public key flagged by a scanner —
  note for hygiene, do not put in the body.

## 6. Emit findings as

One JSON object per distinct secret (dedup the same value across files; list the
locations in `rationale`). Fields:

```json
{
  "id": "secrets-001",
  "title": "Live Stripe secret key hardcoded in payment service — full account access",
  "vuln_class": "secrets",
  "owasp": "A02:2025",
  "cwe": "CWE-798",
  "asvs": "V14",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": "src/services/billing.ts",
  "line": 12,
  "end_line": 12,
  "code_excerpt": "const stripe = new Stripe(\"sk_live_51H...REDACTED...\");",
  "source": "repo is public on GitHub (and the value also ships in the deployed source tree); any reader of the repo or a leaked checkout obtains the key",
  "sink": "Stripe live secret API key — full read/write to the org's Stripe account: charges, refunds, customer PII, payout config",
  "data_flow": "literal sk_live_ key -> Stripe client constructor -> used for live API calls in createCharge(). Key is the standing credential; reading the source = holding it. No env/Vault indirection on this assignment.",
  "sanitizers_checked": "prefix is sk_live_ (live, not pk_ publishable nor sk_test_); not read from process.env (it's a literal); not in a test/fixture dir; not a documented example sentinel; no evidence of provider-side rotation in history or commit messages",
  "rationale": "Genuine live secret, broadly scoped, in a reachable repo. Same key reused at src/jobs/reconcile.ts:8. Single root cause: the inlined key.",
  "exploit_sketch": "Clone the repo, extract sk_live_..., call Stripe API (e.g. GET /v1/charges, POST /v1/refunds) with it — exfiltrate customer PII and issue refunds/charges, draining the account.",
  "dynamic_poc_plan": "Against an isolated copy, issue a harmless authenticated Stripe call with the key (e.g. GET /v1/account) and show it returns 200 with the live account id — proving the key is live and usable. Do NOT mutate real data; a 200 on a read is sufficient proof.",
  "proposed_fix": "The committed live key must be treated as compromised and stop being a standing credential in the repo: rotate it at the provider and move secret material out of source into a runtime-injected secrets store. Direction only — the exact rotation/history-purge/loading mechanics are left to the engineer who picks this up."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. State *who can read the secret and how* (`source`), *what the
secret unlocks* with the concrete resource/impact (`sink`), how the literal
becomes the standing credential (`data_flow`), and which §4 guard you confirmed
absent — especially "is this actually the secret half / a live value / not a
placeholder / not an env read" (`sanitizers_checked`). A string that merely
*looks* high-entropy with no resource it unlocks and no read path is NOT a
finding. Pick `cwe` by what the secret is: 798 generic API key/token/credential,
259 a password, 321 a cryptographic/signing key, 547 a hard-coded sensitive
constant used in a security decision. Use `status:"likely"` for a strong static
trace (live-format secret + reachable path), `"confirmed"` only after a dynamic
liveness check, `"triage"` when liveness or the read path is uncertain (e.g.
unknown if the repo is public, or you can't tell test from prod value).

## 7. Dynamic PoC strategy

Goal: prove the secret is **real, live, and grants access** — not just that a
high-entropy string exists. Pick the oracle for the secret type; prefer
read-only / non-destructive probes:

1. **Third-party API key/token.** Make the provider's cheapest *authenticated
   read* call with the key. **Observed proof** = AWS `sts get-caller-identity`
   returns an account/ARN; Stripe `GET /v1/account` returns 200 + account id;
   GitHub `GET /user` (or `/rate_limit` showing an authenticated quota) returns
   the token's identity/scopes; SendGrid `GET /v3/scopes` lists send perms. A
   200 with the account/identity proves the key is live and what it unlocks.
   Never run destructive/mutating calls against real accounts.
2. **DB / service connection string.** From an isolated network position that
   matches the documented deployment, attempt a connect with the credentials
   (read-only query like `SELECT 1`). **Observed proof** = the connection
   succeeds / auth passes — proving the creds are valid. If the host isn't
   reachable from the harness, fall back to confirming the format and that the
   app itself uses these exact creds to connect at boot.
3. **App's own signing/encryption secret.** Use the committed secret to forge an
   artifact the running app must reject if the secret were unknown: sign a JWT /
   session cookie / HMAC for a victim/admin identity with it, then send it to the
   live app. **Observed proof** = the app accepts the forged token and returns
   the victim's data / an authenticated session — auth bypass. (Overlaps `crypto`
   §7 #5/#6; cite there if the operation is the bug.)
4. **Default / weak credential.** Drive the live login/admin endpoint with the
   default pair (`admin/admin`, seeded password, or the fallback that activates
   when the env var is unset). **Observed proof** = authentication succeeds and
   you reach a privileged area.
5. **Secret in git history / client bundle.** Extract the value from history
   (`git show <commit>:<path>`) or from the built client bundle, then run the
   matching oracle above (1–4) to prove it's still live. **Observed proof** = the
   recovered-from-history/bundle value passes the provider/app liveness check.

Record the exact command and observed evidence in the `Repro` object
(`reproduced`, `method:"live-exploit"`, `poc`, `observed`, `impact`). A
read-only provider call returning the account/identity, or the live app
accepting a forged token / default login, proves the class — set
`method:"live-exploit"`. If the provider/app can't be reached, fall back to
proving the value is a live-format secret and is wired into prod use (not a
test/placeholder) and set `method:"static-poc"`. NEVER perform destructive,
data-mutating, or billable actions against real third-party accounts to prove a
finding — a read-only liveness check is sufficient and required.

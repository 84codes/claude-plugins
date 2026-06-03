<!--
FINDER PROMPT — auth-session. You are a fresh-context auditor hunting ONE class:
Authentication & Session Management. Read the target's code; emit finding
objects. Signal discipline (AGENTS.md) is binding: only a REACHABLE flaw on the
identity/credential/session/token path — where an attacker can forge, bypass,
fixate, or recover identity — counts, and only after confirming the framework's
own protections are absent/disabled/misused. No defense-in-depth musings, no
dead code, no posture items (missing MFA "in general", password-policy text).
-->

# Finder — Authentication & Session (`auth-session`)

**Class key:** `auth-session` · **OWASP:** A07:2025 (Identification & Authentication
Failures) · **CWE:** CWE-287 (improper auth) / CWE-384 (session fixation) /
CWE-620 (unverified password change) / CWE-640 (weak reset mechanism) / CWE-521
(weak password reqs) · **ASVS:** V6 (Authentication) / V7 (Session) / V9 (Tokens
& JWT) / V10 (OAuth/OIDC)

## 1. Objective

Find where an attacker can **become or impersonate a user without their
credential**: forge/bypass a token or session (JWT `alg:none`/weak secret,
guessable session id, fixation), hijack the login/reset/OAuth flow (no token
check, predictable reset token, open `redirect_uri`, missing `state`), or where
credentials are stored so weakly that a DB read = mass account takeover
(plaintext, MD5/SHA1, unsalted, fast hash).

## 2. Where to look

Trace the **identity lifecycle**: login → session/token issuance → per-request
verification → privileged action → logout/reset. The bug is a step that trusts
attacker-controllable material as proof of identity.

- **Login / credential check:** `login`, `sign_in`, `authenticate`,
  `verify_password`, `check_password`, `password_verify`, controllers under
  `auth/`, `sessions/`, `accounts/`, `Devise`, `passport`, `next-auth`,
  `Spring Security`, `omniauth`. Look at the comparison and what happens on each
  branch.
- **Token mint & verify:** anything touching `jwt`, `jsonwebtoken`, `jose`,
  `pyjwt`, `golang-jwt`, `jjwt`, `ruby-jwt`, `firebase/php-jwt`; `sign`/`encode`
  and `verify`/`decode`/`decodeJwt`. The verify call and its options are the
  hot spot (algorithm allow-list, secret/key source, audience/issuer/expiry).
- **Session config & store:** `express-session`, `cookie-session`, Rails
  `config/session_store`, `flask.session`/`Flask-Login`, Django `SESSION_*`,
  `gorilla/sessions`, PHP `session_start`/`ini`, Lucky/Kemal session handlers.
  Check cookie flags, session-id regeneration on login, store integrity.
- **Password reset / email verify:** `forgot`, `reset_password`,
  `reset-token`, `confirmation_token`, `magic-link`, OTP/2FA verify. Examine
  token generation (RNG, length, lifetime, single-use, binding to the user) and
  the verify branch.
- **OAuth/OIDC:** `/callback`, `/oauth`, `redirect_uri`, `state`, `nonce`,
  `id_token` handling, provider config; PKCE for public clients; `state`
  CSRF binding; signature & `aud`/`iss` validation of `id_token`.
- **Credential storage:** user model migrations/schema, `password`/
  `password_hash`/`encrypted_password` columns, the hashing call at write time,
  API-key/token columns, "remember me" tokens.

Per-language SINK / sensitive-call signals:

- **Crystal:** `JWT.decode(token, verify: false)` or no `algorithm:` pin;
  `Crypto::Bcrypt::Password.create`/`.verify` (good) vs. `Digest::MD5`/`SHA1`
  on a password; Kemal `env.session` without `session.set` regen on login;
  `Random` (non-secure) for tokens vs. `Random::Secure`.
- **Ruby:** `JWT.decode(tok, nil, false)` (verify off) / missing `algorithm:`;
  `Digest::SHA1.hexdigest(pw)`, `Digest::MD5`; `==` on a token/HMAC instead of
  `ActiveSupport::SecurityUtils.secure_compare`; Devise `pepper`/`stretches`
  misset; `SecureRandom` (good) vs. `rand`/`Time.now` for reset tokens;
  `session_store` without `secret_key_base`; no `reset_session` after sign-in.
- **Node/TS:** `jwt.verify(tok, key, { algorithms:['none'] })` or no
  `algorithms` option (defaults can accept attacker's `alg`); `jwt.decode()`
  used as if it verifies; HS256 with a short/literal secret; `bcrypt`/`argon2`
  (good) vs. `crypto.createHash('md5'|'sha1')` or `===` on passwords;
  `express-session` `{ secret:'keyboard cat', cookie:{ secure:false,
  httpOnly:false } }`, no `req.session.regenerate()` on login; `Math.random()`
  for tokens; OAuth callback with no `state` compare.
- **Python:** `jwt.decode(tok, options={'verify_signature': False})` or
  `algorithms` omitted; `hashlib.md5/sha1(pw)`, `hashlib.sha256` unsalted vs.
  `bcrypt`/`argon2`/`pbkdf2_hmac` with enough iterations; `==` token compare vs.
  `hmac.compare_digest`; Flask `SECRET_KEY` empty/guessable, `SESSION_COOKIE_*`
  off; `random.random()`/`uuid1` for reset tokens vs. `secrets.token_urlsafe`;
  Django `check_password` good, raw compare bad.
- **Go:** `jwt.Parse` whose `Keyfunc` doesn't assert `token.Method` (accepts
  `none`/RS↔HS confusion); `ParseWithClaims` ignoring `Valid`; `md5.Sum`/
  `sha1.Sum` on passwords vs. `bcrypt.CompareHashAndPassword`/`argon2`;
  `subtle.ConstantTimeCompare` (good) vs. `==`/`bytes.Equal` on secrets;
  `math/rand` for tokens vs. `crypto/rand`; session cookie without
  `Secure`/`HttpOnly`/`SameSite`.
- **PHP:** `JWT::decode($t, $key, ['none'])` (firebase/php-jwt) or no allowed-alg
  array; `md5($pw)`/`sha1($pw)` vs. `password_hash($pw, PASSWORD_BCRYPT|ARGON2)`
  + `password_verify`; `==`/`===` on hashes vs. `hash_equals`;
  `session.cookie_secure=0`, no `session_regenerate_id(true)` after login;
  `mt_rand`/`uniqid` for reset tokens vs. `random_bytes`/`bin2hex`.
- **Java:** `Jwts.parser().parseClaimsJws` without `setSigningKey` /
  `parse(token)` accepting unsigned (`alg:none`) JWS; `MessageDigest
  .getInstance("MD5"|"SHA-1")` on passwords vs. `BCryptPasswordEncoder`/
  `Argon2`; `String.equals` on tokens vs. `MessageDigest.isEqual`; Spring
  Security `permitAll()` over a protected matcher, `csrf().disable()` paired
  with cookie sessions; `new Random()`/`Math.random()` for tokens vs.
  `SecureRandom`; `id_token` accepted without signature check.
- **Rust:** `jsonwebtoken::decode` with `Validation` whose `algorithms` allows
  attacker control or `insecure_disable_signature_validation`; `md5`/`sha1`
  crate on passwords vs. `argon2`/`bcrypt`; `==` on `&[u8]` secret vs.
  `subtle`/`constant_time_eq`; `rand::thread_rng` for tokens vs. a CSPRNG with
  enough entropy; `actix-session`/`tower-sessions` cookie without secure flags.

## 3. Detection heuristics

The pattern is always: **attacker-controllable identity material (SOURCE)
reaches a trust decision or is the credential of record (SINK) without a correct
verification** — signature/algorithm pinned, secret strong & secret, token
random+single-use+bound, session id regenerated, redirect/state validated, hash
slow+salted.

SOURCES (untrusted): the `Authorization`/`Cookie`/`X-*` headers, JWT/`id_token`
strings and their `alg`/`kid` header, session cookie value, login form
username/password, `redirect_uri`/`state`/`code` query params, reset/confirm
token from URL, OTP from body, "remember me" cookie, any header claiming a
role/user id.

SINKS (trust decisions / credential ops): JWT/`id_token` verify-decode that
yields `current_user`; password comparison branch; session creation /
`current_user =` assignment; reset-token lookup → password set; OAuth callback →
session issuance; the hashing call that persists a credential; the cookie/header
that is later trusted as identity.

- **JWT `alg:none` / unverified decode** — verification disabled or algorithm
  not pinned, so an attacker forges claims:

  ```js
  // Node — no algorithms allow-list; "alg":"none" or HS/RS confusion accepted
  const claims = jwt.verify(req.cookies.tok, PUBLIC_KEY);   // SINK
  req.user = claims.sub;                                      // trusts forged sub
  ```
  ```python
  jwt.decode(tok, key, options={"verify_signature": False})  # SINK: any token valid
  ```
  ```go
  jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) {
      return secret, nil })   // SINK: no t.Method.(*jwt.SigningMethodHMAC) check → none/RS↔HS
  ```

- **Weak/leaked JWT secret or signing key** — HS256 with a guessable literal
  secret (`"secret"`, `"changeme"`, an env default), or the public key used as
  the HMAC secret (RS→HS confusion). Attacker brute-forces or re-signs.

  ```ruby
  JWT.encode(payload, "secret", "HS256")   # SINK: brute-forceable secret
  ```

- **Session fixation** — session id NOT regenerated at privilege change (login),
  so an attacker who plants a known id rides the victim's authenticated session:

  ```python
  # Flask — login sets user in the SAME session id the attacker pre-seeded
  session["user_id"] = user.id            # SINK: no session.regenerate / new id
  ```
  ```php
  $_SESSION['uid'] = $user->id;            // SINK: no session_regenerate_id(true)
  ```

- **Insecure session cookie / store** — cookie missing `HttpOnly`/`Secure`/
  `SameSite`, predictable session id, signed-but-not-encrypted client-side
  session holding trust flags, hardcoded session secret:

  ```js
  app.use(session({ secret:'keyboard cat',
    cookie:{ secure:false, httpOnly:false } }));   // SINK: theftable, non-secure
  ```

- **Insecure password reset / magic link** — token from a weak RNG, too short,
  no expiry, reusable, or not bound to the user; or reset proceeds without
  proving possession:

  ```ruby
  token = rand(1_000_000).to_s            # SINK: 1e6 space, guessable/brute
  user.update(reset_token: token)
  ```
  ```python
  token = str(uuid.uuid1())               # SINK: time/MAC-based, predictable
  ```
  Also: reset endpoint that takes `user_id` + new password with **no token**
  (CWE-620 unverified change), or accepts the token but never checks expiry/
  single-use.

- **Plaintext / weak-hash credential storage** — password stored as-is, or with
  a fast/unsalted hash; a DB leak = instant mass ATO:

  ```python
  user.password = hashlib.md5(pw.encode()).hexdigest()   # SINK: fast, unsalted
  ```
  ```php
  $hash = sha1($password);                                // SINK
  ```
  ```sql
  INSERT INTO users(email, password) VALUES (?, ?)        -- SINK: raw plaintext pw
  ```

- **Non-constant-time secret compare** — token/HMAC/password-hash compared with
  `==`/`equals`/`bytes.Equal`, leaking via timing (lower severity, but real for
  remote-guessable tokens):

  ```go
  if token == stored { ... }              // SINK: use subtle.ConstantTimeCompare
  ```

- **OAuth/OIDC flaws** — callback issues a session without validating `state`
  (login CSRF / code injection), `redirect_uri` not allow-listed (token/code
  exfil), `id_token` accepted without signature/`aud`/`iss`/`nonce` check,
  public client without PKCE:

  ```js
  // Express — no state compare, redirect_uri reflected from request
  app.get('/callback', async (req,res)=>{
    const tok = await exchange(req.query.code);   // SINK: no state check
    req.session.user = tok.sub; });
  ```

- **Auth bypass logic** — a branch that grants identity on an attacker-set
  condition: `if (req.headers['x-user']) req.user = ...`, default/empty password
  accepted, `verify_password` returning truthy on empty input, debug/backdoor
  account, or comparison that short-circuits (`password == undefined` both).

## 4. Not-a-finding (false-positive guard)

Before flagging, confirm NONE of these neutralize the path. If an effective
control sits on the identity path, do **not** report.

- **JWT verified correctly:** `verify`/`decode` with an explicit `algorithms`
  allow-list that excludes `none` and matches the key type (HS* with a secret,
  RS*/ES* with a public key), signature validation ON, and `exp`/`aud`/`iss`
  checked. Go `Keyfunc` that asserts `token.Method.(*jwt.SigningMethodHMAC)` (or
  the expected method). A strong, env-injected, high-entropy secret/key is not a
  finding for "weak secret".
- **`decode` used only for non-trust display** (logging, UI) where the result is
  NOT used for an authorization/identity decision — re-verify reachability;
  no trust sink → not a finding.
- **Session id regenerated on privilege change:** Rails `reset_session` /
  `form_authenticity_token` rotation, `req.session.regenerate()`,
  `session_regenerate_id(true)`, Django's login cycling the key, framework that
  rotates by default on auth. Fixation is then closed.
- **Secure cookie config present:** `HttpOnly` + `Secure` + `SameSite`
  (Lax/Strict), server-side opaque session store or an encrypted+signed cookie
  with a strong secret. Missing `Secure` only matters if the app serves over
  HTTPS / is internet-facing — note the precondition.
- **Strong reset/verify token:** CSPRNG (`SecureRandom`, `secrets`,
  `crypto.randomBytes`, `random_bytes`, `crypto/rand`) ≥128 bits, single-use,
  short TTL, bound to the user, and the new password set ONLY after the token is
  validated. A signed/HMAC'd token with server-side expiry is fine.
- **Strong password hashing:** `bcrypt`/`scrypt`/`argon2`/`PBKDF2` with sane
  cost, per-user salt (these include it), verified with the library's compare.
  This is correct storage — not a finding even if the rest is imperfect.
- **Constant-time compare** for tokens/HMACs: `secure_compare`,
  `hmac.compare_digest`, `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `hash_equals`, `constant_time_eq`. Timing finding is closed.
- **OAuth done right:** `state` generated + stored + compared (CSRF bound),
  `redirect_uri` matched against a server allow-list, `id_token` signature +
  `aud`/`iss`/`exp`/`nonce` validated, PKCE on public clients.
- **Server-derived identity:** the value driving the decision is set by the
  server from an already-authenticated session (not re-read from an
  attacker-controllable header/claim) → not attacker-controlled.
- **Unreachable:** route unregistered, the insecure option behind a dev/test
  flag that is off in the audited config, handler dead, or the call returns
  before the sink.

A control counts only if it is **on the identity path and runs before the trust
decision**. "There is a login screen" is not authorization; a global
`authenticate` proving identity does not fix a forgeable token. Note any
identity-only control and keep hunting for the verification that's actually
missing.

## 5. Severity guidance

- **Critical** — unauthenticated, reachable full auth bypass / account takeover:
  JWT `alg:none` or signature-off accepted on a trust path, trivially
  brute-forceable/leaked signing secret, reset token guessable or reset without
  any token, plaintext or unsalted-MD5/SHA1 password storage (DB read → mass
  ATO), OAuth callback issuing a session with no signature/`state` check. No
  effective control on the path.
- **High** — auth/session compromise under a realistic precondition: session
  fixation (attacker must plant an id), session secret/key with limited entropy,
  reset token with a real but bounded weakness (no expiry / reusable but
  high-entropy), open `redirect_uri` enabling code/token theft, predictable
  session ids, missing `state` where same-site mitigates partially.
- **Medium** — exploitation needs unusual conditions or yields limited gain:
  non-constant-time compare of a remotely-guessable token, missing `HttpOnly`/
  `Secure` on a non-sensitive cookie or HTTP-only deployment, weak password
  policy that meaningfully enables credential stuffing, fast-but-salted hash
  (e.g. single-round SHA256 + salt).
- **Low/Info** — timing leak on a non-guessable secret, hardening gaps with a
  compensating control present, password-policy nits with no concrete bypass.

Escalate one level if the same root cause covers all auth (one verify helper, one
session config) or the credential is reused across systems.

## 6. Emit findings as

One object per root cause (list extra call sites in `data_flow`/`rationale`).
JSON object with EXACTLY these fields:

- `id` — stable slug, e.g. `as-jwt-alg-none-verify`, `as-reset-token-weak-rng`.
- `title` — one line naming the flaw + location (e.g. "JWT verified without
  algorithm pin in `auth/jwt.ts`").
- `vuln_class` — `auth-session`.
- `owasp` — `A07:2025`.
- `cwe` — most specific: `CWE-287` (improper auth / JWT bypass / OAuth),
  `CWE-384` (session fixation), `CWE-620` (unverified credential change),
  `CWE-640` (weak reset mechanism), `CWE-521` (weak password reqs); add
  `CWE-916`/`CWE-759`/`CWE-256` for weak/unsalted/plaintext storage,
  `CWE-330`/`CWE-338` for weak token RNG, `CWE-547`/`CWE-798` for hardcoded
  secrets, `CWE-208` for timing compare. List multiple if apt.
- `asvs` — the closest requirement id: V6.x (auth/passwords/storage), V7.x
  (sessions), V9.x (JWT/tokens), V10.x (OAuth/OIDC).
- `severity` — `critical|high|medium|low|info` per §5.
- `status` — `confirmed` (proven/reproduced) | `likely` (clear trace, no live
  PoC) | `triage` (needs verification).
- `confidence` — `low|medium|high`.
- `file`, `line`, `end_line` — the sink (the verify/compare/store/session call).
- `code_excerpt` — the minimal vulnerable lines (the decode/verify options, the
  hash call, the session config, the token gen).
- `source` — exact untrusted origin, e.g. `req.cookies.tok` (JWT from cookie),
  `request.args["token"]` (reset token from URL), `req.query.code` (OAuth code).
- `sink` — exact dangerous op, e.g. `jwt.verify(tok, key)` (no `algorithms`),
  `hashlib.md5(pw)`, `session["uid"]=...` (no regen), `token == stored`.
- `data_flow` — `source -> ... -> sink`, naming each hop, and **explicitly
  noting any verification/sanitizer seen and why it is insufficient** (no alg
  pin, signature off, secret guessable, no expiry, fast hash, non-const compare).
- `sanitizers_checked` — the §4 FP guard you verified: which controls you looked
  for (alg allow-list, signature on, strong secret, session regen, secure cookie
  flags, CSPRNG + single-use + expiry token, slow salted hash, constant-time
  compare, `state`/`redirect_uri`/`id_token` validation) and that each is
  **absent, disabled, or ineffective**. Mandatory; empty/hand-wavy ⇒ not credible.
- `rationale` — why reachable + exploitable; cite the exact missing check.
- `exploit_sketch` — concrete attacker steps (e.g. "craft a JWT with
  `{"alg":"none"}` and `sub:1`, strip the signature, send as cookie → server
  trusts it as admin").
- `dynamic_poc_plan` — the live request(s) and the observed result that proves it
  (see §7).
- `proposed_fix` — high-level direction, not a patch: 1-2 sentences naming WHAT
  must change and WHY, leaving the exact code to the engineer/agent who picks up
  the issue. E.g. "Pin the accepted JWT algorithm to the issuer's signing scheme
  and reject unsigned/`none` tokens so forged claims can't be trusted." No code
  diff, exact code, line-level edits, or step-by-step implementation.

Fill `source`, `sink`, `data_flow`, and `sanitizers_checked` precisely — they are
the evidence a reviewer re-checks. A finding without a clear source→sink and a
verified-absent control is `triage` at best.

## 7. Dynamic PoC strategy

Goal: prove identity can be **forged, bypassed, fixed, or recovered** against a
running instance. Capture the exact request (method, path, headers/cookie, body),
the response, and a negative control. On success set `status: confirmed`.

1. **JWT `alg:none` / unverified:** take a valid token (or mint one with the
   claimed structure), set the header to `{"alg":"none","typ":"JWT"}`, change
   `sub`/`role` to a target (admin), drop the signature (keep trailing dot), send
   it. *Proof*: an authenticated/privileged response (`200`, admin data) where a
   tampered token must yield `401`. Also try HS-signing with the server's public
   key (RS→HS confusion) and a wordlist brute of an HS secret (`jwt_tool`,
   `hashcat -m 16500`).
2. **Weak signing secret:** crack the JWT offline; re-sign a forged admin token
   with the recovered secret and replay. *Proof*: server accepts the re-signed
   token as that identity.
3. **Session fixation:** obtain a session id pre-auth (or set a chosen one),
   have the victim authenticate within that session, then reuse the SAME id.
   *Proof*: the pre-login id is now authenticated (no rotation observed in
   `Set-Cookie` after login).
4. **Insecure cookie / theft:** inspect `Set-Cookie` for missing `HttpOnly`/
   `Secure`/`SameSite`; *proof* is the flags' absence plus a reachable XSS or
   non-TLS path that would exfiltrate it (note the chain dependency).
5. **Weak/replayable reset token:** trigger a reset, capture the token; show it
   is short/predictable (enumerate the space, or derive from time/uuid1), reuse
   it twice, or use it after the stated TTL. *Proof*: a password change accepted
   with a guessed/reused/expired token. For CWE-620: hit the reset endpoint with
   only `user_id` + new password (no token) and confirm the change.
6. **Plaintext/weak hash:** if a self-registration + DB-dump or admin export is
   reachable, show the stored value equals `md5(pw)`/the plaintext. Otherwise
   prove statically from the write path and treat as `likely`.
7. **OAuth `state`/`redirect_uri`:** start a flow, drop or alter `state` on the
   callback — *proof*: a session still issued (login CSRF). Supply an attacker
   `redirect_uri` not on the server allow-list — *proof*: the code/token is sent
   to the attacker origin. Submit an unsigned/wrong-`aud` `id_token` — *proof*:
   session issued.
8. **Auth-bypass logic:** send the attacker-controlled trust input
   (`X-User: admin`, empty/null password, default account) — *proof*: a
   privileged response instead of `401`.

Negative control (a correctly-signed token, a fresh post-login session id, a
valid single-use token, a well-formed `state`) returning the EXPECTED behavior
makes the proof unambiguous. Record the request, actor, and response in
`dynamic_poc_plan`.

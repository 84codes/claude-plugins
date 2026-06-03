<!--
FINDER PROMPT — crypto. You are a fresh-context auditor hunting ONE class:
Cryptographic Failures (weak/broken algorithms, ECB, static IV/salt, weak RNG
for security, disabled TLS verification, hardcoded keys, bad key management).
Read the target's code; emit finding objects. Signal discipline (AGENTS.md) is
binding: only a REACHABLE use of broken crypto that protects something an
attacker can reach/influence, where no effective mitigation sits on the path, is
a finding. No defense-in-depth musings, no dead code, no posture items, no
"consider rotating keys" without a concrete sink.
-->

# Finder — Cryptographic Failures (`crypto`)

**Class key:** `crypto` · **OWASP:** A04:2025 · **CWE:** CWE-327 (broken/weak
algo) / CWE-328 (weak hash) / CWE-326 (inadequate strength) / CWE-330 (weak RNG)
/ CWE-331 (insufficient entropy) / CWE-916 (unsalted/fast password hash) /
CWE-295 (improper cert validation) · **ASVS:** V11

## 1. Objective

Find places where data that needs cryptographic protection is protected with a
**broken primitive, a broken mode, a predictable parameter, or no real
verification** — such that an attacker can decrypt, forge, predict, MITM, or
crack it. The bug is the crypto choice/parameterization itself, reachable on
data an attacker controls or wants. The fix is a correct primitive (AEAD, KDF,
strong hash, CSPRNG, validated TLS).

## 2. Where to look

Crypto failures cluster at a handful of surfaces. Map the data first: *what is
being protected, who can reach it, what breaks if it's forged/decrypted/cracked.*

- **Auth & credential storage:** password hashing in user/account models,
  `set_password`/`hash_password`, session-token & API-key generation,
  password-reset / email-verify / invite token mint, "remember me" cookies,
  TOTP/2FA secret handling. Weak hash or weak RNG here is the highest-value find.
- **Token / signature layers:** JWT signing & verification (`alg`, key choice),
  HMAC over webhooks/callbacks, signed URLs / signed cookies, CSRF tokens,
  license/entitlement signing, document/PDF signing.
- **At-rest encryption:** field-level encryption in ORMs/models (PII, card data,
  secrets columns), "encrypt this blob" helpers, config/secret encryptors,
  backup encryption, KMS/envelope-encryption wrappers, cookie/session
  serializers that encrypt.
- **TLS / transport clients:** every outbound HTTP/DB/SMTP/LDAP/gRPC/MQ client —
  look for verification toggles in client construction, custom `TrustManager`/
  `SSLContext`, `verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify`,
  custom hostname verifiers, pinning that's been disabled.
- **Crypto utility modules:** `crypto.rb`, `cipher.go`, `encryption.py`,
  `Crypto.cr`, `util/hash`, `security/`, anything `*encrypt*`/`*cipher*`/`*sign*`/
  `*token*`/`*nonce*`/`*salt*`/`*kdf*`.
- **Key material:** where keys/IVs/salts/secrets are *sourced* — hardcoded
  literals, committed PEM/`.key`/`.pem`/`keystore`/`.jks`, default-valued config,
  keys derived from a low-entropy/static seed, IV/salt declared as a constant or
  reused across messages.

Per-language SINK / API signals:

- **Crystal:** `Digest::MD5`/`Digest::SHA1` over secrets, `OpenSSL::Cipher.new`
  with `"des"`/`"rc4"`/`"aes-128-ecb"`, `Random` (non-secure) vs
  `Random::Secure` for tokens, `OpenSSL::SSL::Context` with
  `verify_mode = OpenSSL::SSL::VERIFY_NONE`, hardcoded `Crypto::Subtle` keys,
  `Random.rand`/`rand` for token bytes.
- **Ruby:** `Digest::MD5/SHA1.hexdigest(password)`, `OpenSSL::Cipher.new('DES'
  /'RC4'/'AES-128-ECB')`, `cipher.iv = "0"*16` / fixed IV, `rand`/`SecureRandom`
  misuse, `OpenSSL::SSL::VERIFY_NONE`, Net::HTTP `verify_mode=`, `JWT.decode(t,
  nil, false)` / `algorithm: 'none'`, `ActiveSupport::MessageEncryptor` with a
  short/static key, `Digest::SHA256` used as a password KDF (no salt/stretch).
- **Node/TS:** `crypto.createHash('md5'|'sha1')` for passwords,
  `crypto.createCipheriv('aes-256-ecb'|'des'|'rc4', ...)`, fixed/zero IV buffer,
  `Math.random()` for tokens/IDs/secrets, `crypto.randomBytes` good vs
  `Math.random` bad, `rejectUnauthorized:false` / `NODE_TLS_REJECT_UNAUTHORIZED=
  '0'`, `https.Agent({rejectUnauthorized:false})`, `jwt.verify(t, key, {
  algorithms:['none']})` / `jwt.decode` used as verify, `jsonwebtoken` with a
  weak/hardcoded secret, bcrypt rounds `< 10` / plain `pbkdf2` low iters.
- **Python:** `hashlib.md5/sha1(pw)`, `Crypto.Cipher.DES`/`ARC4`/`AES.new(key,
  AES.MODE_ECB)`, static `iv=b'\x00'*16`, `random.random()`/`random.randint`/
  `random.choice` for tokens (vs `secrets`/`os.urandom`), `ssl._create_unverified_
  context()` / `verify=False` (requests) / `cert_reqs=ssl.CERT_NONE` /
  `check_hostname=False`, `jwt.decode(t, verify=False)` / `options={'verify_
  signature':False}` / `algorithms=['none']`, `hashlib.pbkdf2_hmac` low iters,
  Django `make_password` overridden to MD5.
- **Go:** `crypto/md5`/`crypto/sha1`/`crypto/des`/`crypto/rc4` for security,
  `cipher.NewCBCEncrypter` with a static IV / ECB-style block loop, `math/rand`
  (incl. `rand.Seed(time.Now())`) for tokens/keys instead of `crypto/rand`,
  `tls.Config{InsecureSkipVerify:true}`, custom `VerifyConnection` that returns
  nil, `jwt.ParseWithClaims` accepting `none`/no key check, `x509`
  `InsecureSkipVerify`.
- **PHP:** `md5($pw)`/`sha1($pw)`/`crypt()` w/ DES, `mcrypt_*`,
  `openssl_encrypt($d,'aes-256-ecb',...)` or `'des-ede3'`/`'rc4'`, fixed `$iv`,
  `rand()`/`mt_rand()`/`uniqid()` for tokens (vs `random_bytes`/
  `random_int`), `CURLOPT_SSL_VERIFYPEER=>false` / `CURLOPT_SSL_VERIFYHOST=>0`,
  `'verify'=>false` (Guzzle), `password_hash` good vs raw hash, JWT libs with
  `'none'`/HS256 confusion.
- **Java:** `MessageDigest.getInstance("MD5"|"SHA-1")` for passwords,
  `Cipher.getInstance("DES"|"RC4"|"AES/ECB/PKCS5Padding"|"AES")` (bare "AES" =
  ECB), `new IvParameterSpec(new byte[16])` static IV, `new Random()` /
  `Math.random()` for tokens (vs `SecureRandom`), custom `X509TrustManager` with
  empty `checkServerTrusted`, `setHostnameVerifier((h,s)->true)` /
  `ALLOW_ALL_HOSTNAME_VERIFIER`, `SSLContext` w/ trust-all, JWT `none`,
  hardcoded `SecretKeySpec(literal.getBytes(), ...)`.
- **Rust:** `md5`/`sha1`/`md-5` crates for secrets, `Des`/`Rc4`/ECB block modes,
  `rand::thread_rng()` for tokens that need a CSPRNG (vs `rand::rngs::OsRng` /
  `getrandom`), `danger_accept_invalid_certs(true)` / `danger_accept_invalid_
  hostnames(true)` (reqwest), `rustls` `dangerous()` custom verifier returning
  Ok, hardcoded key bytes, static `nonce`/`iv` arrays for `aes-gcm`/`chacha20`.

## 3. Detection heuristics

**Taint perspective.** This class is partly *parameter-driven* (the SOURCE is the
crypto config/key/IV/RNG choice in the code, not always external input) and
partly *flow-driven* (untrusted ciphertext/token/MITM position reaches a sink
that fails to verify). Capture both in `source`/`sink`:

- **SOURCE** = the data being protected and *who can reach or supply it*: a
  password an attacker can offline-crack after a DB leak; a token an attacker
  receives and must not be able to forge/predict; ciphertext/cookie the attacker
  holds; a network position where the attacker can MITM the TLS client; the
  attacker-supplied `alg`/header that a verifier trusts.
- **SINK** = the weak crypto operation: the hash/cipher/mode/IV/RNG/verify call
  that is broken or unverified.

Vulnerable patterns to confirm (each needs a reachable SOURCE):

- **Broken hash for passwords (CWE-916/328):** `MD5`/`SHA1`/`SHA-256`/`SHA-512`
  used *directly* as a password store. Fast hashes (even SHA-256) are wrong for
  passwords — they must use a memory-hard/iterated KDF (bcrypt/scrypt/argon2/
  PBKDF2-high-iter). Reachable via any DB compromise → offline cracking. Confirm
  the hash output is the stored credential and no KDF wraps it.
- **Broken hash for integrity/signature (CWE-328):** MD5/SHA1 in an HMAC-less
  "signature", a hand-rolled `hash(secret + msg)` (length-extension), or MD5
  collision-relevant contexts.
- **Broken/weak cipher (CWE-327):** DES, 3DES, RC4, Blowfish for new data; RSA
  with PKCS#1 v1.5 in a padding-oracle-prone spot; export-grade params.
- **ECB mode (CWE-327):** any `*-ECB` / bare `Cipher.getInstance("AES")`
  (defaults to ECB) / manual block loop without chaining — identical plaintext
  blocks leak as identical ciphertext blocks.
- **Static / reused / predictable IV or nonce (CWE-329/330):** IV hardcoded
  (`\x00`*16), derived from a constant, or reused across messages with the same
  key. Catastrophic for CTR/GCM/ChaCha20 (nonce reuse breaks confidentiality and
  forgeability) and weakens CBC.
- **Static / missing salt, or fast unsalted hash (CWE-916/759/760):** one global
  salt, no salt, or salt = username; enables rainbow-table / cross-account
  cracking.
- **Weak RNG for security (CWE-330/338):** `Math.random`, `rand`, `mt_rand`,
  `random.random`, `math/rand`, `java.util.Random`, `time`-seeded RNG, or
  incrementing/`uniqid`/timestamp used to mint **session tokens, password-reset
  tokens, API keys, IVs, salts, OTPs, CSRF tokens, password salts, or key
  material**. Predictable → forgeable/guessable. (RNG for non-security shuffles/
  jitter is fine.)
- **Disabled TLS verification (CWE-295):** verification turned off on an outbound
  client to a security-relevant peer — `verify=False`, `rejectUnauthorized:false`,
  `InsecureSkipVerify:true`, `VERIFY_NONE`, trust-all `TrustManager`, hostname
  verifier returning true, `danger_accept_invalid_certs`. Enables MITM →
  credential/data theft, response forgery.
- **Hardcoded / committed key, IV, or secret (CWE-321/798):** symmetric key,
  HMAC/JWT secret, or private key as a string literal, default config value, or
  committed file — anyone with source/binary can decrypt/forge. (If it's purely a
  *secret leak* with no crypto-op context, that's the `secrets` finder; here the
  point is the key feeding a crypto sink that's now defeated.)
- **JWT alg/verify failures (CWE-327/347):** `alg:none` accepted, signature
  verification skipped (`decode` used where `verify` is required), HS/RS
  algorithm confusion (RSA public key used as HMAC secret), unconstrained
  `algorithms` list, or symmetric secret that is weak/guessable.
- **Bad key management (CWE-320/322):** key derived from a low-entropy
  passphrase without a KDF, no separation between signing/encryption keys, key
  reused as both IV and key, ECDH/RSA without authentication.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these holds on the path:

- **Correct password KDF in place:** `bcrypt`, `scrypt`, `argon2`/`argon2id`, or
  `PBKDF2` with a sane iteration/cost (bcrypt cost ≥ 10/12, PBKDF2 ≥ ~100k iters,
  argon2 default params) and a per-user salt. A plain SHA-256 you *thought* was
  the store but is actually wrapped by `password_hash`/`bcrypt`/Devise/
  `Argon2`/Django's `PBKDF2PasswordHasher` is safe — trace what's actually
  persisted.
- **Strong AEAD with unique nonce:** AES-GCM / ChaCha20-Poly1305 / AES-CBC+HMAC
  (encrypt-then-MAC) where the IV/nonce is freshly generated per message from a
  CSPRNG (`randomBytes`/`os.urandom`/`SecureRandom`/`crypto/rand`/`OsRng`). A
  random per-message IV is correct even if the variable name is `iv` — verify
  it's regenerated, not constant.
- **Non-security use of weak primitive:** MD5/SHA1/CRC for cache keys,
  ETags, content-addressing/dedup, checksums of non-adversarial data, file
  fingerprints, sharding, bloom filters — **not** a finding (note it only if it
  guards a trust decision). `Math.random` for UI jitter, A/B bucketing, retry
  backoff, or non-secret IDs is fine. The bar is: does breaking it grant an
  attacker anything?
- **CSPRNG actually used:** the token/IV/salt comes from `crypto.randomBytes`,
  `secrets.token_*`/`os.urandom`, `SecureRandom`, `crypto/rand`, `OsRng`,
  `Random::Secure` — even if a weak RNG exists elsewhere in the file for
  non-security purposes.
- **TLS verification is on / toggle is unreachable:** `verify=False` etc. gated
  behind a dev/test-only branch that cannot run in production (env guard you can
  confirm), or pointed only at a localhost/test fixture, or the disable is in a
  test file / mock. Confirm the branch is actually unreachable in prod before
  dropping; if the toggle keys off an attacker- or operator-misconfigurable env
  var that defaults insecure, it IS a finding.
- **Key sourced from real secret management:** key/secret read from env, a
  vault/KMS/HSM, or a runtime-injected config — not a literal. A literal that is
  obviously a *placeholder/example* in a `.example`/test fixture with no prod
  wiring is not a live finding (note it; it may be a `secrets` item).
- **JWT verified correctly:** `verify` with a pinned algorithm allowlist that
  matches the key type (RS256 with a public key, HS256 with a server secret),
  `none` rejected, `kid`/issuer/audience checked. The mere presence of `decode`
  is fine if a `verify` happens first.
- **Legacy compatibility with a real migration/guard:** a weak verifier kept only
  to *read* legacy records but rehashing/re-encrypting on next use, with no path
  that lets an attacker force the weak path. Confirm the upgrade-on-verify exists.

If a guard exists but is bypassable — bcrypt cost too low to matter, PBKDF2 with
1k iters, AEAD whose nonce is actually a counter that resets, TLS verify gated on
a header/param an attacker sets, JWT allowlist that still includes a confusable
alg, "salt" that is constant — it is NOT a mitigation. Flag it and name the
exact bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — break yields direct, unauth, high-impact compromise: predictable
  password-reset/session tokens from a weak RNG (account takeover); `alg:none`/
  skipped JWT verification or HS/RS confusion (auth bypass / forge any token);
  disabled TLS verification on a path carrying credentials or auth tokens to a
  MITM-reachable peer; hardcoded key/secret that decrypts production data or
  forges signatures for all users; nonce reuse on AES-GCM exposing plaintext or
  enabling forgery of authenticated messages.
- **High** — realistically-conditioned high impact: fast/unsalted password hash
  (MD5/SHA1/raw-SHA256) — full offline cracking after any DB leak; ECB/DES/RC4 or
  static IV protecting PII/secrets at rest that an attacker can obtain; weak RNG
  for API keys behind authn; disabled TLS verify on an internal-but-sensitive
  client.
- **Medium** — constrained: weak crypto over data with limited sensitivity or
  high attacker cost; static salt with an otherwise-strong KDF; weak RNG for a
  token with short TTL + rate limiting; padding-oracle-prone construction needing
  specific conditions; partial mitigation that raises but doesn't close the bar.
- **Low/Info** — weak primitive in a non-security context, or theoretical with no
  reachable SOURCE — usually downgrade or drop per §4. A committed example key
  with no prod wiring → Info/`secrets`.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "crypto-001",
  "title": "Unsalted SHA1 used as the password store — offline-crackable on DB leak",
  "vuln_class": "crypto",
  "owasp": "A04:2025",
  "cwe": "CWE-916",
  "asvs": "V11",
  "severity": "high",
  "status": "likely",
  "confidence": "high",
  "file": "app/models/user.py",
  "line": 41,
  "end_line": 43,
  "code_excerpt": "self.password_hash = hashlib.sha1(password.encode()).hexdigest()",
  "source": "user passwords for all accounts; attacker reaches them via any DB read/dump (SQLi, backup, insider) and cracks offline",
  "sink": "hashlib.sha1(...).hexdigest() persisted as the credential — a single-pass fast hash, no salt, no key-stretching",
  "data_flow": "password -> sha1() (one pass, no salt) -> users.password_hash column; verification recomputes the same sha1. No KDF/salt/cost between the password and the stored value.",
  "sanitizers_checked": "no bcrypt/scrypt/argon2/PBKDF2 wrapper anywhere on set or verify; no per-user salt column; not Django make_password (raw hashlib); SHA1 is ~GH/s on commodity GPUs so cost factor is effectively zero",
  "rationale": "Reachable for the entire user table the moment the DB leaks. Same pattern at admin.py:88 (admin reset). Single root cause: the hashing helper.",
  "exploit_sketch": "Obtain users.password_hash (e.g. via the SQLi at report.py:71). hashcat -m 100 against the unsalted SHA1 list cracks weak/common passwords in minutes, recovering plaintext for credential reuse.",
  "dynamic_poc_plan": "Register a user with a known password via the live signup endpoint; read the stored hash from the DB/test harness; show hashlib.sha1(known_pw) == stored value (proves no salt/KDF), then crack a second weak password with hashcat to demonstrate recovery.",
  "proposed_fix": "Move password storage onto a memory-hard, salted KDF instead of a single-pass unsalted hash, so a DB leak no longer enables practical offline cracking. (High-level direction, not a patch — the implementing engineer chooses the KDF, parameters, and legacy-migration approach.)"
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. State explicitly *what is protected and who reaches it*
(`source`), the *exact weak operation* with the real API name (`sink`), how the
data reaches that operation and why the primitive/parameter is broken
(`data_flow`), and which §4 mitigation is absent or, if present, the exact bypass
(`sanitizers_checked`). A weak primitive with **no reachable thing it protects**
is not a finding. Pick `cwe` by failure mode: 327 broken/weak algo or mode,
328 weak hash, 916 unsalted/fast password hash, 326 inadequate strength,
330/331/338 weak RNG/entropy, 329 static IV/nonce, 295/347 cert/signature
verification. Use `status:"likely"` for a proven static trace, `"confirmed"`
only after dynamic repro, `"triage"` if the protected SOURCE or reachability is
uncertain.

## 7. Dynamic PoC strategy

Goal: prove the chosen primitive/parameter is actually broken and exploitable on
the running system. Pick the oracle matching the failure mode:

1. **Weak password hash.** Register/seed a user with a known password via the
   live endpoint; extract the stored hash (DB, debug route, or test harness).
   **Observed proof** = `weak_hash(known_pw [+salt])` reproduces the stored value
   bit-for-bit (no KDF/salt), and a second weak password cracks under `hashcat`/
   `john` with the matching mode — recovering plaintext.
2. **Predictable token (weak RNG).** Trigger many token mints (signup, password
   reset, API-key create) and capture the values. **Observed proof** = tokens are
   sequential/correlated, or — given the seed source (PID/time) — you predict the
   next token and use it to claim another user's reset/session, completing an
   account takeover against the live app.
3. **ECB / static IV / nonce reuse.** Submit two plaintexts with identical
   blocks (or the same plaintext twice) through the encrypt endpoint and capture
   ciphertext. **Observed proof** = identical plaintext blocks yield identical
   ciphertext blocks (ECB), or two messages share the IV/nonce (CTR/GCM reuse) —
   then recover XOR of plaintexts / forge a GCM tag to demonstrate decryption or
   forgery.
4. **Disabled TLS verification.** Point the client at a host you control with a
   self-signed/mismatched cert (DNS override, `/etc/hosts`, or a proxy like
   mitmproxy). **Observed proof** = the client completes the request against the
   bad cert (no error), and you capture/alter the plaintext payload (e.g. the
   credentials/token it sent) — proving MITM.
5. **JWT alg/verify failure.** Take a valid token, set header `alg:none` and
   strip the signature, or sign with the public key as an HMAC secret (HS/RS
   confusion), or forge with the hardcoded/guessed secret. **Observed proof** =
   the live app accepts the forged token (returns the victim's data / an
   authenticated session) — impossible if verification were correct.
6. **Hardcoded key.** Use the literal key from source to decrypt a captured
   ciphertext/cookie or forge a valid signed token, then replay it. **Observed
   proof** = the app accepts the forged/decrypted artifact as authentic.

Record the exact payload/command and observed evidence in the `Repro` object
(`reproduced`, `method:"live-exploit"`, `poc`, `observed`, `impact`). A
reproduced forgery/decryption/MITM or a bit-for-bit weak-hash match proves the
class — set `method:"live-exploit"`. If the app can't be run, fall back to a
focused unit test that drives the crypto helper and asserts the broken property
(ECB block equality, static IV, hash without salt, `verify` accepting a forged
token) — `method:"unit-test"`.

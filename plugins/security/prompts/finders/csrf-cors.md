<!--
FINDER PROMPT — csrf-cors. You are a fresh-context auditor hunting ONE class:
CSRF, CORS & Clickjacking. Read the target's code & config; emit finding objects.
Signal discipline (AGENTS.md) is binding: only a REACHABLE cross-origin attack
path — a state-changing request a foreign site can forge, a credentialed CORS
response a foreign origin can read, or a sensitive view a foreign page can frame
— with no effective guard on the path is a finding. No generic header-hardening
checklists, no defense-in-depth musings without a concrete sink, no dead code,
no posture/process items.
-->

# Finder — CSRF, CORS & Clickjacking (csrf-cors)

**Class key:** `csrf-cors` · **OWASP:** A01:2025 · **CWE:** CWE-352, CWE-1021, CWE-942 · **ASVS:** V3

## 1. Objective

Find state-changing endpoints that a foreign web origin can drive on a
logged-in victim's behalf — via a forged cross-site request (no anti-CSRF
token / no SameSite cookie), a permissive CORS policy that lets an attacker
origin read credentialed responses, or a missing framing defense that allows
clickjacking of a sensitive action.

## 2. Where to look

The attack target is the **ambient-credential boundary**: any endpoint
authenticated by a cookie/session, HTTP Basic, or a client TLS cert that the
browser attaches automatically on cross-site requests. Bearer tokens read from
JS-controlled storage (`Authorization: Bearer`) are NOT auto-attached, so they
are generally CSRF-immune — confirm the auth mechanism before flagging.

Entry points / surfaces:

- **State-changing routes:** `POST`/`PUT`/`PATCH`/`DELETE` handlers, but also
  `GET` handlers that mutate (logout, "delete via link", `/transfer?to=...`,
  toggle/enable/disable, admin actions). GET-that-mutates is forgeable with a
  bare `<img>`/`<link>`.
- **Global CSRF config:** the framework's CSRF middleware enable/disable site,
  and per-route/per-controller `skip`/`exempt` annotations. The bug is usually
  the *exemption*, not the absence.
- **Cookie/session setup:** where the session cookie is issued — its
  `SameSite`, `Secure`, `HttpOnly` attributes drive cross-site
  exploitability.
- **CORS config:** middleware/handlers that set `Access-Control-Allow-Origin`
  (ACAO), `-Allow-Credentials` (ACAC), `-Allow-Methods`, `-Allow-Headers`,
  `-Expose-Headers`; reflected-origin logic; preflight (`OPTIONS`) handlers.
- **Framing/headers:** where `X-Frame-Options` / CSP `frame-ancestors` are
  set (or globally not set) for sensitive pages (login, OAuth consent, fund
  transfer, account settings, admin).
- **Cross-origin message channels:** browser `window.postMessage` handlers
  (`message` event listeners) that act on data without checking
  `event.origin` — a CSRF-adjacent cross-origin sink.

Route/handler & config signals to grep:

- **Crystal:** Lucky `protect_from_forgery`, Amber `CSRF` pipe / `csrf_token`,
  Kemal — *no built-in CSRF*, so cookie-auth Kemal apps are bare unless they
  roll their own; `Access-Control-Allow-Origin` header writes via
  `context.response.headers`.
- **Ruby/Rails:** `protect_from_forgery`, `skip_before_action
  :verify_authenticity_token`, `skip_forgery_protection`,
  `protect_from_forgery with: :null_session`, `config.action_controller
  .forgery_protection_origin_check`, `Rack::Cors` `allow do origins ...`,
  Sinatra `Rack::Protection` (and `Rack::Protection` *disabled*).
- **Node/TS:** `csurf`/`csrf-csrf`/`@fastify/csrf-protection` (presence &
  exemptions); `cors` package `origin: true`/`origin: '*'` with
  `credentials: true`; manual `res.setHeader('Access-Control-Allow-Origin',
  req.headers.origin)`; `helmet` framing config; Express session cookie
  `sameSite`.
- **Python:** Django `@csrf_exempt`, `CsrfViewMiddleware` removed from
  `MIDDLEWARE`, `CSRF_TRUSTED_ORIGINS`, `CORS_ALLOW_ALL_ORIGINS`/
  `CORS_ORIGIN_ALLOW_ALL`, `CORS_ALLOWED_ORIGIN_REGEXES`,
  `CORS_ALLOW_CREDENTIALS`, `django-cors-headers`; Flask `flask-wtf`
  `CSRFProtect` (presence) / `WTF_CSRF_ENABLED=False` / `@csrf.exempt`,
  `flask-cors` `CORS(app, ...)`; `SESSION_COOKIE_SAMESITE`,
  `X_FRAME_OPTIONS`/`SecurityMiddleware`, FastAPI `CORSMiddleware
  allow_origins=["*"], allow_credentials=True`.
- **Go:** `rs/cors` `AllowedOrigins: []string{"*"}` + `AllowCredentials: true`
  or `AllowOriginFunc: func(o string){ return true }`; gin
  `cors.Config{AllowAllOrigins:true}`; manual
  `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`;
  most Go routers have *no* CSRF by default — look for `gorilla/csrf`,
  `nosurf`; `http.SetCookie` SameSite field.
- **PHP:** Laravel `VerifyCsrfToken` `$except` array / `csrf_field()`;
  Symfony `csrf_protection: false` / `is_csrf_token_valid`; raw apps with no
  token at all; `header("Access-Control-Allow-Origin: " . $_SERVER
  ['HTTP_ORIGIN'])`, `header("Access-Control-Allow-Credentials: true")`.
- **Java:** Spring Security `.csrf().disable()` /
  `csrf(AbstractHttpConfigurer::disable)` / `.ignoringRequestMatchers(...)`;
  `CorsConfiguration.setAllowedOrigins(List.of("*"))` /
  `addAllowedOriginPattern("*")` + `setAllowCredentials(true)`;
  `@CrossOrigin(origins="*", allowCredentials="true")`;
  `setAllowedOriginPatterns` with `*`; framing via
  `headers().frameOptions().disable()`.
- **Rust:** `actix-cors` `Cors::permissive()` / `allow_any_origin()` +
  `supports_credentials()`; `tower-http` `CorsLayer::permissive()` /
  `AllowOrigin::any()` / `AllowOrigin::mirror_request()` +
  `allow_credentials(true)`; most Rust frameworks have *no* CSRF
  middleware — cookie-auth handlers are bare unless a token scheme is rolled.

## 3. Detection heuristics

**Taint SOURCES** (untrusted / attacker-controlled): the *cross-site request*
itself (forced by attacker HTML/JS from another origin while the victim is
logged in) and, for CORS, the attacker-chosen `Origin` request header
reflected into a response header. For postMessage, the cross-origin message
`event.data`. The "input" here is the request's *provenance*, not a parameter
value — the question is whether a foreign origin can issue/read it.

**Taint SINKS** (dangerous op):
- **CSRF:** a state-changing handler (DB write, money/permission/account
  mutation, OS/admin action) reachable with **ambient credentials** and **no
  unguessable token tied to the session** required.
- **CORS:** writing `Access-Control-Allow-Origin` to a value derived from /
  equal to the request `Origin`, **together with** `Access-Control-Allow-
  Credentials: true` — letting the attacker origin's JS read the credentialed
  response body.
- **Clickjacking:** rendering a sensitive, state-changing UI with **no**
  `X-Frame-Options: DENY/SAMEORIGIN` and **no** CSP `frame-ancestors`.
- **postMessage:** acting on `event.data` (navigation, token relay, state
  change) without validating `event.origin` against an allowlist.

Vulnerable patterns to confirm:

- **CSRF protection disabled / exempted on a mutating, cookie-auth route:**
  - Rails: `skip_before_action :verify_authenticity_token` (or
    `protect_from_forgery with: :null_session`) on a controller that writes.
  - Django: `@csrf_exempt` on a `POST` view that mutates; or
    `CsrfViewMiddleware` absent from `MIDDLEWARE`.
  - Flask: app uses session cookies but no `CSRFProtect`/`flask-wtf`, or
    `@csrf.exempt` / `WTF_CSRF_ENABLED=False`.
  - Spring: `http.csrf(csrf -> csrf.disable())` while `formLogin`/session
    cookies are in use.
  - Laravel: route/path listed in `VerifyCsrfToken::$except`.
  - Go/Rust/Kemal: cookie-session app with **no token scheme present at all**
    on mutating handlers.
- **GET that mutates:** `get "/account/delete"`, `app.get('/logout', ...)` that
  ends a session or writes — forgeable with a plain `<img src>` regardless of
  token middleware (which typically only guards unsafe methods).
- **Reflected-origin CORS with credentials:** ACAO set to the request Origin
  (or `*` paired — illegally but some stacks coerce — with credentials) and
  ACAC `true`:
  - Node: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials','true')`.
  - Express `cors`: `cors({ origin: true, credentials: true })` (reflects any
    origin).
  - Go: `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`
    + `...Allow-Credentials","true"`.
  - PHP: `header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header("Access-Control-Allow-Credentials: true");`.
  - Spring: `@CrossOrigin(origins = "*", allowCredentials = "true")` or
    `config.setAllowedOriginPatterns(List.of("*"))` +
    `setAllowCredentials(true)`.
  - FastAPI/Starlette: `allow_origins=["*"], allow_credentials=True`
    (Starlette silently mirrors the origin in this combo).
  - Rust: `Cors::permissive().supports_credentials()` /
    `CorsLayer::permissive()` then `.allow_credentials(true)`.
- **Sloppy origin allowlist (bypassable):** origin check by substring/prefix/
  suffix or unanchored regex:
  - `origin.endsWith("trusted.com")` → `trusted.com.evil.com` or
    `nottrusted.com`.
  - `origin.startsWith("https://trusted.com")` →
    `https://trusted.com.evil.com`.
  - `origin.includes("trusted.com")` → `https://evil.com?trusted.com`.
  - regex `/trusted\.com/` (no anchors / unescaped `.`) → matches
    `trustedxcom.evil.com`, `eviltrusted.com`.
  - reflecting `null` origin (`Allow-Origin: null`) — reachable from sandboxed
    iframes / `data:` documents the attacker controls.
- **Missing framing defense on sensitive pages:** no `X-Frame-Options` and no
  `frame-ancestors` on login / OAuth-consent / transfer / settings / admin
  pages, where a framed UI + a transparent overlay tricks the victim into
  clicking a real button (clickjacking). Pair with a state-changing action to
  be a finding, not a bare missing header.
- **postMessage without origin check:**
  `window.addEventListener('message', e => { /* uses e.data, no e.origin
  check */ })` — a foreign frame can drive the handler.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **No ambient credentials on the route.** If the endpoint authenticates only
  via a `Authorization: Bearer`/JWT/API-key header read from JS (not a cookie,
  not Basic, not client cert), a cross-site page cannot attach it → no CSRF.
  Likewise an endpoint that requires no auth and exposes no per-user state is
  not a CSRF target. Confirm the actual auth mechanism in code.
- **Effective anti-CSRF token** present and verified on every unsafe method:
  framework default (Rails `protect_from_forgery` active, Django
  `CsrfViewMiddleware` enabled + `{% csrf_token %}`, Spring `csrf()` default,
  Laravel `VerifyCsrfToken` not exempting the route, flask-wtf `CSRFProtect`
  active) — a synchronizer/double-submit token bound to the session and
  unguessable. A double-submit cookie counts only if the token cookie is
  `__Host-`/`SameSite` and the server compares header-vs-cookie.
- **`SameSite=Lax` or `Strict` session cookie** (and the route is *not* a
  top-level GET navigation for `Lax`). Lax is the modern browser default and
  blocks cross-site POST cookie attachment; with Lax, the remaining CSRF
  surface is top-level `GET` navigations only — so a Lax cookie largely
  neutralizes cross-site POST CSRF. Note: state-changing GETs are still
  exploitable under Lax via top-level navigation; Strict blocks those too.
- **Origin/Referer validation done correctly** on unsafe methods: parse the
  `Origin` (or `Referer`) header and **exact-match** against a closed allowlist
  of full origins (scheme+host+port) — Rails `forgery_protection_origin_check`,
  a hand-rolled `Origin == "https://app.example.com"` check. Anchored,
  fully-escaped regex matching a closed set also counts.
- **CORS that is safe by construction:**
  - ACAO is a **static, closed allowlist** of exact origins (not the reflected
    request origin, not `*`), each compared by equality; OR
  - ACAO is `*` **with credentials NOT enabled** (`Access-Control-Allow-
    Credentials` absent/false) — browsers refuse to send cookies, and `*`
    cannot be combined with credentials, so no credentialed read; the response
    is treated as public anyway. Only a finding if the data behind it is meant
    to be private and is in fact served (then it is an access-control issue,
    flag under that class); OR
  - the response carries **no credentials and no sensitive data** (truly public
    API). CORS only governs *reading* the response — it never bypasses CSRF
    protections for *writing*, so a permissive CORS policy on a token-protected,
    non-credentialed endpoint is not exploitable here.
- **Framing defense present:** `X-Frame-Options: DENY`/`SAMEORIGIN` **or** CSP
  `frame-ancestors 'none'`/`'self'`/closed allowlist covering the sensitive
  page. Either one suffices; do not flag a missing `X-Frame-Options` if
  `frame-ancestors` is set (and vice-versa). Non-sensitive, non-state-changing
  pages (marketing, docs) being frameable is not a finding.
- **postMessage handler validates `event.origin`** against an allowlist before
  acting (and ideally checks `event.source`).
- **Method genuinely safe & side-effect-free:** a `GET`/`HEAD` that only reads
  is not a CSRF sink (reading via forged request yields nothing the attacker
  can see cross-origin unless CORS leaks it — which is the CORS finding, not
  CSRF).

If a guard exists but is bypassable (token not actually verified, exemption on
a mutating route, substring/unanchored-regex origin check, reflected origin with
credentials, `SameSite=None` without a token, `X-Frame-Options` set but
duplicated/invalid value browsers ignore, `frame-ancestors` with a wildcard) it
is NOT a mitigation — flag it and name the exact bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — forgeable/cross-origin-readable path to a full account or
  privilege takeover with realistic preconditions: CSRF on
  change-password/change-email/add-admin/disable-2FA/create-API-key with no
  token and no SameSite, OR reflected-origin-with-credentials CORS exposing
  session/admin data or a CSRF-token-bearing response (which then unlocks
  further CSRF). Unauthenticated-to-admin or one-click account takeover.
- **High** — CSRF on a significant but not total-takeover action (fund
  transfer, data deletion, permission change, settings mutation) on a
  cookie-auth route with a bypassable/absent token; or credentialed CORS with a
  bypassable origin allowlist (substring/regex) exposing per-user data; or
  clickjacking of a single-click sensitive state change (delete account,
  authorize OAuth, transfer).
- **Medium** — CSRF/CORS where exploitation needs unusual conditions or yields
  limited impact: SameSite=Lax present so only a state-changing top-level GET
  is forgeable; CORS leaks non-critical per-user data; clickjacking requiring
  multi-step drag/social engineering; `null`-origin-only CORS reflection.
- **Low/Info** — missing framing header on a sensitive-but-not-mutating page,
  `*` CORS without credentials on a non-sensitive endpoint, or a
  defense-in-depth gap with no demonstrable cross-origin action. Usually an
  Info-appendix note, not a body finding.

Note in `rationale` whether the action is one-click vs. multi-step and whether
auth is required, since that drives the severity.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites / shared config;
list extras in `rationale`). Fields:

```json
{
  "id": "csrf-cors-001",
  "title": "Reflected-origin CORS with credentials exposes authenticated /api/account to any origin",
  "vuln_class": "csrf-cors",
  "owasp": "A01:2025",
  "cwe": "CWE-942",
  "asvs": "V3",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": "src/middleware/cors.ts",
  "line": 11,
  "end_line": 14,
  "code_excerpt": "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
  "source": "attacker-chosen Origin request header (req.headers.origin) reflected verbatim; victim has a session cookie auto-attached cross-site",
  "sink": "Access-Control-Allow-Origin set to the request Origin + Access-Control-Allow-Credentials:true — lets attacker-origin JS read the credentialed response",
  "data_flow": "req.headers.origin -> res ACAO header (no allowlist/equality check) ; ACAC=true ; applied globally including /api/account which returns the session user's PII and CSRF token",
  "sanitizers_checked": "no origin allowlist (any origin reflected); credentials explicitly enabled; not gated to safe public endpoints; SameSite irrelevant — CORS read bypasses it; evil.com fetch('/api/account',{credentials:'include'}) succeeds and reads body",
  "rationale": "Any malicious site visited by a logged-in user can read /api/account (PII + the anti-CSRF token), enabling account-data theft and downstream CSRF against token-protected writes. Same middleware also fronts /api/admin (admin.ts:9).",
  "exploit_sketch": "On evil.com: fetch('https://app.example.com/api/account',{credentials:'include'}).then(r=>r.json()).then(d=>exfil(d)). ACAO echoes https://evil.com, ACAC:true -> browser exposes the response.",
  "dynamic_poc_plan": "Authenticate to get a session cookie; replay GET /api/account with header 'Origin: https://evil.com' and observe the response carries 'Access-Control-Allow-Origin: https://evil.com' + 'Access-Control-Allow-Credentials: true' alongside the user's private body — proving cross-origin credentialed read.",
  "proposed_fix": "Stop trusting the attacker-controlled Origin: the credentialed CORS policy must only echo origins from a closed, trusted allowlist so a foreign site can no longer read authenticated responses. (High-level direction; the exact mechanism is left to the implementing engineer.)"
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. For this class, `source` names the cross-origin provenance
(forged request / reflected Origin / cross-origin message) and the auth
mechanism that makes it exploitable (cookie/Basic — auto-attached). `sink` is
the precise unguarded mutating handler or the exact ACAO/ACAC/framing config.
`data_flow` traces how a foreign origin issues/reads the request and names every
guard encountered and why it fails (token absent/exempt, SameSite=None,
substring origin match, ACAC+reflection). `sanitizers_checked` is the §4 FP
guard made explicit — list each control (token, SameSite, Origin check, CORS
allowlist, framing header, postMessage origin check) and state it is absent or
name the exact bypass. A route with no ambient credentials, an effective token,
a SameSite-Lax/Strict cookie on a non-GET sink, or a closed-allowlist CORS
policy is NOT a finding. Use `status:"likely"` for a proven static trace,
`"confirmed"` only after dynamic repro, `"triage"` if the auth mechanism /
reachability is uncertain.

## 7. Dynamic PoC strategy

Goal: prove a foreign origin can drive or read a credentialed action. Establish
a real authenticated session first (the cookie is the ammunition), then attack
from a *different* origin.

1. **CSRF (cross-site write):** with a valid session cookie held by the
   browser/agent, replay the state-changing request **without** the anti-CSRF
   token and **with** a foreign/absent `Origin`/`Referer`
   (`Origin: https://evil.example`). **Observed proof:** the server performs the
   mutation (200 + the side effect verified out-of-band — record changed,
   password reset, role granted). If it 403s on the missing token / bad Origin,
   the guard holds → not a finding. For the realistic browser PoC, stand up an
   attacker page that auto-submits a form / fires `fetch(..,
   {credentials:'include', mode:'no-cors'})` to the target and confirm the
   side effect lands while only the cookie (no token) traveled.
2. **CORS (cross-origin read):** replay a credentialed request to the sensitive
   endpoint with `Origin: https://evil.example`. **Observed proof:** the
   response includes `Access-Control-Allow-Origin: https://evil.example` (echoed
   or wildcard) **and** `Access-Control-Allow-Credentials: true`, and the body
   contains private/session data — meaning attacker JS would be allowed to read
   it. Run the bypass probes when an allowlist exists: `Origin:
   https://trusted.com.evil.example` (suffix), `https://eviltrusted.com`
   (unanchored regex), `Origin: null` — and check which the server reflects.
3. **Clickjacking:** request the sensitive page and inspect response headers for
   `X-Frame-Options` and CSP `frame-ancestors`. **Observed proof:** both absent
   (or a permissive `frame-ancestors *`); confirm by loading the page in an
   `<iframe src=...>` from a different origin and verifying it renders and its
   buttons are clickable (a transparent-overlay PoC clinches it).
4. **postMessage:** from an attacker-controlled framing page, `postMessage` a
   crafted payload to the target frame and observe the handler acting on it
   (navigation/state change) despite the foreign origin.

Record the exact request/headers/payload and the observed evidence in the
`Repro` object (`reproduced`, `method:"live-exploit"`, `poc`, `observed`,
`impact`). A header-only confirmation (CORS reflection observed, framing headers
absent) is sufficient proof for those sub-classes — set `method:"live-exploit"`
and note that browser-side reachability was inferred from the headers.

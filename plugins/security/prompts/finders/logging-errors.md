<!--
FINDER PROMPT — logging-errors. You are a fresh-context auditor hunting ONE
class: Logging, Error & Exception Handling. Read the target's code; emit finding
objects. Signal discipline (AGENTS.md) is binding. This class has TWO finding
shapes, both needing a concrete sink: (A) DISCLOSURE — a tainted/sensitive value
reaches a SINK that an attacker or unauthorized party reads (an HTTP error
response shown to the client, a log/telemetry stream a lower-trust party can
read); (B) MISSING/FAIL-OPEN HANDLING — a catch/rescue or an unhandled
exceptional condition that swallows or fails OPEN on a security decision, or an
absent audit record for a security-significant event whose absence is itself the
weakness. No "add more logging" musings without a security event, no flagging
ordinary debug logs that carry no secret/PII, no dead code, no posture items
(no log-retention/SIEM-integration process gaps).
-->

# Finder — Logging, Error & Exception Handling (`logging-errors`)

**Class key:** `logging-errors` · **OWASP:** A09:2025 (Security Logging &
Monitoring Failures) / A10:2025 (Mishandling of Exceptional Conditions) ·
**CWE:** CWE-532 (sensitive info in log) / CWE-209 (sensitive info in error
message/response) / CWE-755 (improper handling of exceptional conditions) /
CWE-703 (improper check/handling of exceptional conditions) / CWE-396 (catch of
overly-broad exception) · **ASVS:** V16 (Security Logging & Error Handling)

## 1. Objective

Find places where (A) a secret, credential, token, or PII reaches a log/telemetry
sink or a client-facing error response a lower-trust party can read; or (B) a
security-relevant exceptional condition is mishandled — swallowed, caught too
broadly, or failed OPEN so a security check is skipped — or a security-
significant event has no audit record. The bug is information crossing a trust
boundary via logs/errors, or a control silently not running because an exception
took a permissive path.

## 2. Where to look

Three surfaces: the **logging layer**, the **error/exception path**, and the
**security-event audit trail**.

- **Logging layer:** central logger config & formatters, request/response
  middleware that logs bodies/headers, structured-log field builders, "log the
  whole object" calls (`log.info(user)`, `log.debug(req)`, `inspect`/`to_json`
  of a model/params), audit helpers, HTTP client wrappers that log full
  requests (with `Authorization`/`Cookie`), DB query loggers echoing bound
  params, exception reporters/Sentry/Bugsnag breadcrumbs, webhook/payment
  callback handlers logging raw payloads, third-party SDK debug modes.
- **Error/exception path:** global error handlers / exception middleware,
  `rescue`/`catch`/`except`/`recover`/`?`-unwrap sites, framework debug pages
  (Rails `show_exceptions`, Flask `DEBUG=True`, Django `DEBUG=True`, Symfony
  `APP_DEBUG`, Express default error handler, Spring whitelabel/`server.error.
  include-stacktrace`), 500-handlers that render `e.message`/`e.backtrace`/
  `str(e)` to the client, `try/except: pass`, `catch (e) {}`, `rescue => e;
  nil`, `if err != nil { /* ignored */ }`, `.unwrap()`/`panic` on attacker
  input.
- **Security-event audit trail (absence is the bug):** authn (login success/
  fail, logout), authz denials, password/MFA/email changes, privilege grants,
  token issuance/revocation, admin actions, payment/refund, data export, account
  lockout, key rotation — code paths that make these decisions but write NO audit
  record (and there is a logging facility in the project, so it's an omission,
  not "no logging exists"). Only flag where the missing record defeats detection
  of a real attack the codebase is otherwise exposed to.

Route/handler signals to grep: error middleware names (`errorHandler`,
`ExceptionFilter`, `rescue_from`, `@app.errorhandler`, `Recover`), logger calls
near auth/payment/token code, `DEBUG`/`development`/`verbose` flags reachable in
prod config, and security decision points (`authorize`, `verify`, `authenticate`,
`require_role`, signature/HMAC checks) wrapped in broad try/catch.

Per-language SINK & pattern signals:

- **Crystal:** `Log.info { user.inspect }`, `Log.error(exception: ex) { ... }`
  logging full params; rendering `ex.message`/`ex.inspect_with_backtrace` to the
  response; `rescue ex; nil` / bare `rescue` swallowing; Kemal/Lucky error
  handler echoing `ex.message`; `Log.debug { request.headers.to_s }` (carries
  `Authorization`).
- **Ruby:** `Rails.logger.info(params.inspect)` / `logger.debug(user.attributes)`,
  `logger.info "token=#{token}"`, full `request.headers`/`request.body.read`
  logged; `rescue => e; render plain: e.message` / `e.backtrace`; `rescue
  StandardError; nil` / `rescue Exception` swallow; `config.consider_all_requests
  _local = true` in prod; `config.filter_parameters` NOT covering a sensitive
  field; Sidekiq/ActiveJob logging args containing secrets.
- **Node/TS:** `console.log(req.body)` / `logger.info({ headers: req.headers })`
  / `logger.debug(user)`, `pino`/`winston` without redaction of `password`/
  `authorization`; `res.status(500).send(err.stack)` / `res.json({ error: err
  .message })`; Express default error handler in prod (`NODE_ENV` not
  `production` → stack to client); `catch (e) {}` empty, `.catch(() => {})`
  swallow, `try {...} catch { return true }` fail-open on an auth check.
- **Python:** `logging.info("user=%s", user.__dict__)` / `logger.debug(request
  .headers)` / `print(token)`, logging `request.POST`/`request.json`;
  `return str(e)` / `traceback.format_exc()` in an HTTP response, Flask/Django
  `DEBUG=True` reachable in prod; `except Exception: pass`, `except:
  return True` fail-open, bare `except:` around a `check_permission`.
- **Go:** `log.Printf("req: %+v", r)` / `log.Println(token)`, logging
  `r.Header` (Authorization/Cookie); `http.Error(w, err.Error(), 500)` leaking
  internal errors / `fmt.Fprintf(w, "%v", err)`; `if err != nil { return true }`
  / `_ = doAuthCheck()` ignored error fail-open; `recover()` that resumes a
  request after a security panic; verbose `gin`/`echo` error rendering in
  release mode.
- **PHP:** `error_log(print_r($_POST, true))` / `Log::info($request->all())`,
  logging `$request->headers`; `display_errors=On` in prod, `echo $e->getMessage
  ()` / `var_dump($e)` to output, Laravel `APP_DEBUG=true` (Ignition page leaks
  env + stack); `try {...} catch (\Exception $e) {}` empty, `@`-suppressed calls
  hiding failures on a security op.
- **Java:** `log.info("user={}", user)` / `log.debug(request.getHeader("Authoriza
  tion"))`, logging full request/`Map` of params; `e.printStackTrace()` to a
  response, `@ExceptionHandler` returning `e.getMessage()`/stack, Spring
  `server.error.include-stacktrace=always` / `include-message=always`, whitelabel
  in prod; `catch (Exception e) {}` empty, `catch (SecurityException e) { return
  true; }` fail-open, swallowing `InterruptedException`/auth exceptions.
- **Rust:** `tracing::info!(?req)` / `debug!("token = {}", token)` logging a
  struct with secrets via `Debug`; returning `format!("{:?}", e)` /
  `e.to_string()` in an HTTP body; `actix`/`axum` default error response leaking
  internals; `let _ = verify(...);` ignoring a `Result`, `.unwrap_or(true)` /
  `if check().is_err() { return Ok(authorized) }` fail-open, `.unwrap()`/`panic!`
  on attacker-controlled input as an availability/exceptional-condition issue.

## 3. Detection heuristics

This class has two flow shapes. Frame every finding around a concrete SINK and a
real reader/consequence.

**Shape A — disclosure (CWE-532 / CWE-209).**
- **SOURCES (sensitive value):** credentials/tokens/secrets — `password`,
  `passwd`, `secret`, `token`, `authorization`/`Bearer`, session id, API key,
  `set-cookie`/`cookie`, JWT, private key, OTP/MFA code, reset token, signing
  key, card PAN/CVV; **and PII** — SSN/national id, full name+DOB, email at scale,
  phone, address, health/financial records. Also: an *internal detail* that aids
  attack — SQL text + bound values, file paths, stack traces, internal hostnames/
  IPs, library versions, raw exception of a downstream system.
- **SINKS (where it lands + who reads it):**
  (1) a **log/telemetry stream** a lower-trust party can read — app logs shipped
  to a broadly-readable store, container stdout, a third-party log/APM/error-
  reporter, browser `console` in client code, a log file in the web root; or
  (2) a **client-facing error/response** — an HTTP error body/header rendered to
  the requester containing `e.message`/`e.backtrace`/stack/SQL/env. Name the
  concrete reader: "shown in the 500 response to any client", "written to a log
  forwarded to $third_party", "echoed to browser console of every visitor".
- Vulnerable patterns: logging a whole request/headers/params/model
  (`inspect`/`%+v`/`__dict__`/`to_json`/`{...req}`) that *contains* a source;
  string-building a log line with a token/password var; an error handler that
  serializes the exception (message/stack/cause-chain) into the client response;
  debug/verbose mode reachable in prod that turns every 500 into a stack-trace
  page; SQL/driver errors surfaced verbatim (overlaps `injection` recon — note,
  don't double-report the injection itself here).

**Shape B — mishandled exceptional condition (CWE-755 / CWE-703 / CWE-396).**
- **SOURCE:** an operation on a security-relevant path that can throw/error —
  an authn/authz check, signature/HMAC/JWT verification, decryption, a license/
  quota/limit check, a payment/fraud check, input parsing of attacker data.
- **SINK (the mishandling):** a `catch`/`rescue`/`except`/`if err != nil`/
  `Result` site that (i) **fails OPEN** — on error returns `true`/authorized/the
  default-allow, skips the check, or proceeds as if it passed; (ii) **swallows
  silently** a security-significant failure so it neither blocks nor is recorded
  (`except: pass`, empty `catch`, `rescue; nil`, ignored error return); (iii)
  **catches too broadly** (`catch (Exception)`/`rescue Exception`/bare `except`)
  around a security op so a control-flow exception meant to deny is absorbed into
  the allow path; or (iv) is an **unhandled exceptional condition** on attacker
  input that an attacker triggers for impact (panic/`.unwrap()` → crash/DoS, or a
  thrown error that bypasses cleanup/leaves an inconsistent privileged state).
- Vulnerable patterns to confirm: `try { return verify(t) } catch { return true }`;
  `rescue => e; user.admin = true` style permissive fallback; signature check
  whose exception path continues to the protected action; `_ = authorize(...)`
  return value discarded; `recover()` that swallows then continues serving the
  request as authenticated; a deny decision that throws and is caught by a
  generic handler that returns 200.

**Shape B' — missing audit (CWE-778, under A09).** A security-significant event
(login success/fail, lockout, authz denial, privilege change, password/MFA reset,
token issue/revoke, admin/data-export/payment action) executes with **no audit
record**, in a codebase that *does* log elsewhere (so the gap is real, not "no
logging at all"). Only flag where the absence concretely defeats detection of an
attack the app is exposed to (e.g. credential stuffing with no failed-login log,
admin takeover with no actor trail). This is the one shape allowed without a
"dangerous sink" — the sink is the absent record on an attack-relevant path.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these holds and is effective on the path:

- **Redaction / filtering applied on the path (Shape A):** the framework's
  parameter/field filter covers the sensitive key and runs before the sink —
  Rails `config.filter_parameters` including the field, `pino` `redact:
  ['req.headers.authorization','*.password']`, `winston` redact format, Python
  `logging.Filter`/structlog processor that masks, Go zap/zerolog hooks that
  drop sensitive fields, a `to_log`/`as_json(except:)`/`__repr__` that omits
  secrets, an explicit `mask()/redact()/[FILTERED]` on the value. Confirm the
  filter actually covers *this* field/path — a filter list that misses the exact
  key is NOT effective (name the gap).
- **Value is not actually sensitive:** a user id (not a token), a public slug,
  a non-secret config value, a request path/method/status (ordinary access log),
  a duration/count metric, a correlation id. Logging these is normal — only flag
  when a real secret/PII/internal-leak source is in the payload.
- **Sink is not lower-trust-readable (Shape A):** the log goes only to a store no
  lower-trust party can read AND is not forwarded to a third party, and the value
  never reaches a client response. If the audit equally can't show a reader, it's
  defense-in-depth, not a finding. (Container stdout, broadly-shared log
  platforms, and third-party error reporters DO count as readable — don't dismiss
  those.)
- **Generic / safe error response (Shape A):** the client gets a generic message
  + an opaque correlation/incident id, while the detail is logged server-side
  only. Custom error pages, `production` mode with stack traces suppressed
  (`NODE_ENV=production`, `DEBUG=False`, `APP_DEBUG=false`, `include-stacktrace=
  never`) — verify the prod config actually disables verbose output; a debug flag
  defaulting on, or driven by an attacker-settable header/param, is NOT safe.
- **Fail-CLOSED handling (Shape B):** the catch/rescue/error branch DENIES —
  returns 401/403/false, re-raises, aborts the request, logs and blocks. Catching
  a *specific* expected exception (e.g. `RecordNotFound -> 404`) and handling it
  correctly is fine. A broad catch is fine if its body denies/re-raises (it
  doesn't fail open). Only a permissive/swallowing/ignored path is a finding.
- **Exception can't reach a security decision / attacker can't trigger it
  (Shape B):** the `.unwrap()`/`catch` is on a path attacker input never reaches,
  or the swallowed error is on a non-security operation with no skipped control
  and no inconsistent privileged state. No reachable trigger or no security
  consequence → not a finding.
- **Audit record exists elsewhere on the path (Shape B'):** the event IS logged
  by a wrapper/middleware/decorator/aspect/DB trigger you missed — trace the full
  path before claiming absence. A "missing logging" claim with no concrete
  attack it would have caught is defense-in-depth, not a finding.

If a guard exists but is bypassable — a redaction list missing the exact key, a
filter applied to one logger but the secret logged via another, prod-mode
detection keyed off an attacker-controlled header, a "fail-closed" branch that
only runs for one of several exception types while a sibling type falls through
to allow — it is NOT a mitigation. Flag it and name the exact bypass in
`sanitizers_checked`.

## 5. Severity guidance

- **Critical** — a live credential/session/signing-secret or bulk PII written to
  a sink a remote/lower-trust attacker reads (token in a client-readable log,
  password in an error returned to the client), enabling account/data takeover;
  OR a fail-open exception handler on a primary authn/authz/signature check that
  an unauthenticated attacker triggers to bypass the control entirely.
- **High** — sensitive value (single user's token/PII, full stack trace + SQL +
  internal paths) disclosed in a client-facing error or a broadly-readable log
  enabling targeted follow-on; OR a fail-open/swallowed exception on a security
  check behind an authn wall; OR `panic`/`.unwrap()` on unauthenticated attacker
  input giving reliable remote DoS of a critical service.
- **Medium** — internal info leak with limited attack value (versions, generic
  internal error text, partial stack) in an error response; a debug/verbose flag
  that is on but only behind auth or hard to reach; PII to a log of moderate
  reach; a swallowed exception that degrades a non-primary control; missing audit
  on a security event where partial signal exists elsewhere.
- **Low/Info** — minor over-logging with weak sensitivity, theoretical fail-open
  on an unreachable path, or a missing-audit gap with no concrete attack it would
  catch — usually downgrade or drop per §4.

For Shape B', severity tracks the *attack the missing record blinds you to*
(e.g. no failed-login log on a credential-stuffing-exposed endpoint = High), not
the act of not-logging itself.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "logging-errors-001",
  "title": "Production error handler returns exception message + stack trace to client",
  "vuln_class": "logging-errors",
  "owasp": "A10:2025",
  "cwe": "CWE-209",
  "asvs": "V16",
  "severity": "high",
  "status": "likely",
  "confidence": "high",
  "file": "src/middleware/error.ts",
  "line": 14,
  "end_line": 17,
  "code_excerpt": "app.use((err, req, res, next) => {\n  res.status(500).json({ error: err.message, stack: err.stack });\n});",
  "source": "server-side exception object (err.message/err.stack) — for DB errors it embeds the SQL, table/column names, file paths, and library versions",
  "sink": "HTTP 500 JSON body returned to the requesting client — readable by any unauthenticated caller who triggers an error",
  "data_flow": "any thrown error -> Express error middleware -> res.json({error: err.message, stack: err.stack}); the full message and stack cross the trust boundary into the response with no generic-message substitution",
  "sanitizers_checked": "no NODE_ENV gate (stack returned regardless of env); no generic-message + correlation-id pattern; no allowlist of safe error types; verbose path is the default, not opt-in; not suppressed in production config",
  "rationale": "Reachable by any client that can induce a 500 (malformed input, type errors). Stack + message reveal source paths, dependency versions, and DB schema/SQL, mapping the internals for follow-on attacks. Same leak in src/middleware/api-error.ts:22.",
  "exploit_sketch": "Send a request that throws (e.g. a body that fails a DB constraint or a type coercion). Read the 500 JSON: harvest the SQL/schema, absolute file paths, and package versions to pivot to injection/known-CVE exploitation.",
  "dynamic_poc_plan": "Against the running app, POST a malformed payload to an endpoint that hits the DB; observe the 500 response body contains err.stack with file paths and the failing SQL — proving internal detail leaks to the client. A generic message would show none of this.",
  "proposed_fix": "The error handler must stop returning the raw exception message/stack across the trust boundary and instead surface only a generic, opaque response while the detail stays server-side — so internal details no longer leak to untrusted callers. Direction only; the exact response shape and the prod-mode gating are for the engineer to design."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. For Shape A, `source` is the specific sensitive value (name
the field — `Authorization` header, `password` param, the token var) and `sink`
names *where it lands and who reads it* (the exact log stream/third party, or
"the 500 response to any client"); `data_flow` traces the value into the
log/response call and notes no redaction/generic-message sits between. For Shape
B, `source` is the security operation that throws, `sink` is the catch/ignore
site, and `data_flow` states *why the error path is permissive* (returns
true/skips the check/swallows) and what control is thereby skipped; for B'
(missing audit), `sink` is "no audit record on <event>" and `data_flow` names the
attack whose detection is defeated. `sanitizers_checked` is the §4 FP guard made
explicit — list each relevant control (redaction filter, prod-mode gate, generic-
message pattern, fail-closed branch, existing audit elsewhere) and state it is
absent or, if present, name the exact bypass. Pick `cwe` by shape: 532 sensitive
data in a **log**, 209 sensitive data in an **error message/response**, 755/703
mishandled/unchecked exceptional condition (fail-open/swallow/unhandled), 396
overly-broad catch, 778 missing audit (A09). Use `status:"likely"` for a proven
static trace, `"confirmed"` only after dynamic repro, `"triage"` when the
reader/reachability or the security consequence is uncertain.

## 7. Dynamic PoC strategy

Goal: prove a sensitive value actually crosses the boundary, or that the error
path actually fails open / a security event leaves no trace. Pick the oracle by
shape:

1. **Error-response disclosure (Shape A, CWE-209).** Induce an error on the live
   endpoint — malformed body, type mismatch, oversized/empty input, a value that
   trips a DB constraint. **Observed proof** = the HTTP response (body or headers)
   contains an exception message, stack trace, SQL text, internal file path,
   internal hostname/IP, or dependency version that a generic handler would never
   emit. Capture the exact response. If a debug flag is suspected attacker-
   settable, send it (`?debug=1`, `X-Debug: true`, `Accept` variations) and show
   it flips on verbose output.
2. **Log disclosure (Shape A, CWE-532).** Drive the endpoint with a uniquely
   marked credential/token (a nonce value in the `Authorization`/`password`/
   token field), then inspect the log sink the harness can read (container
   stdout, the configured log file, the test APM/collector). **Observed proof** =
   the nonce secret appears verbatim (or unredacted) in the log stream — proving
   the secret is logged. If the real sink isn't reachable, assert the same via a
   unit test that captures the logger output and shows the field present.
3. **Fail-open exception (Shape B, CWE-755/703/396).** Force the security
   operation to throw while sending a request that should be DENIED — feed input
   that makes the verify/decrypt/authz call raise (malformed token/signature,
   downstream dependency made to error, a value that triggers the broad catch).
   **Observed proof** = the request is nonetheless ALLOWED (200 + protected
   resource / authenticated session / privileged action performed) when a
   correct fail-closed handler would return 401/403 — demonstrating the
   exception routed into the allow path. Contrast with a well-formed denied
   request to show the difference is the thrown-and-swallowed error.
4. **Unhandled condition / DoS (Shape B, CWE-755).** Send the attacker-controlled
   input that reaches the `panic`/`.unwrap()`/uncaught throw. **Observed proof** =
   the worker/process crashes or the request hangs/aborts, and (if applicable)
   the service stops serving — a reliable single-request DoS. Note whether it's
   process-wide or request-scoped in `impact`.
5. **Missing audit (Shape B').** Perform the security-significant action on the
   live app (e.g. N failed logins, an authz-denied access, a privilege change),
   then inspect every audit/log sink. **Observed proof** = the action completed
   but NO record of it exists in any audit stream the defender would consult —
   proving the event is unobservable. Pair with the concrete attack (credential
   stuffing / silent privilege escalation) it would have surfaced.

Run the relevant bypass checks when a partial guard exists: a redaction list that
misses the exact key (send the nonce in the un-redacted field), a prod-mode gate
driven by a request header (set it), a fail-closed branch that only covers one
exception type (trigger a sibling type). Record the exact request and observed
evidence in the `Repro` object (`reproduced`, `method:"live-exploit"`, `poc`,
`observed`, `impact`). A response carrying the stack/secret, the app accepting a
denied request after a forced exception, a crash from one request, or a completed
action with no audit trace each prove the class — set `method:"live-exploit"`.
If the app can't be run, fall back to a focused unit test that drives the
sink/handler with the payload and captures the leaked output or the fail-open
return (`method:"unit-test"`).

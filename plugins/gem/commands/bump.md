---
description: Bump gem dependencies and create commits with changelog and security advisory summaries
allowed-tools: Bash(bundle outdated *), Bash(bundle update --conservative *), Bash(git add Gemfile.lock), Bash(git commit *), Bash(git diff *), Bash(curl *), Bash(bundle exec rake test), WebFetch
---

# Bump Gem

Bump one or more gem dependencies, creating a separate commit for each with
changelog and security advisory information.

## Arguments

- `$ARGUMENTS` - Required: one or more gem names to bump

## Steps

The supply-chain pre-checks in step 3 deliberately run before `bundle update` in step 4. `bundle outdated` only reads compact-index metadata, so it never fetches a `.gem` archive, runs `extconf.rb`, or executes a postinstall hook. By the time anything resembling gem code touches the system, both gates have already passed.

For each gem name in `$ARGUMENTS`, perform these steps sequentially:

1. Read OLD_VERSION from `Gemfile.lock` (a plain grep — no bundler invocation):

       awk '/^    GEM_NAME \(/{gsub(/[() ]/,""); split($0,a,"("); print a[2]; exit}' Gemfile.lock

2. Determine CANDIDATE (what bundler *would* install), metadata only — no `.gem` fetch, no code executed:

       bundle outdated --strict --no-pre --filter-strict GEM_NAME

   Parse the "Latest" column. If "Current" ≥ "Latest" (the gem isn't listed in the output), skip with "no update available" — do not proceed.
3. Supply-chain pre-checks on CANDIDATE — abort with no side effects if either gate fails. Nothing has been fetched or executed yet, so there is nothing to revert.
   - Cool-off (version age): `curl -s https://rubygems.org/api/v1/versions/GEM_NAME.json`, find CANDIDATE's `created_at`, compute its age in days. If age < 7 days, abort and tell the user the gem was published too recently. They can override per-gem with an explicit "skip cool-off for GEM_NAME" instruction in the same turn.
   - Tag-match (upstream provenance): Identify the gem's source repo via `curl -s https://rubygems.org/api/v1/gems/GEM_NAME.json` (`source_code_uri`, falling back to `homepage_uri`). Verify a release tag corresponding to CANDIDATE exists upstream and that its commit date is within ±24h of rubygems' `created_at`. Support both GitHub and GitLab repos, and dereference annotated tags before reading the commit date:
     - GitHub: `curl -s https://api.github.com/repos/OWNER/REPO/git/refs/tags/vCANDIDATE` (also try without the `v` prefix). If the returned `object.type` is `tag` (annotated), follow up with `git/tags/<sha>` to get the underlying commit sha; if `commit`, that sha is the commit directly. Then `https://api.github.com/repos/OWNER/REPO/commits/<commit_sha>` for the date.
     - GitLab: `curl -s https://gitlab.com/api/v4/projects/<URL_ENCODED_NAMESPACE>%2F<REPO>/repository/tags/vCANDIDATE` (also try without `v`).
     If no matching tag exists, abort. If the tag exists but its commit date differs from rubygems' `created_at` by more than 24h, abort and surface both dates to the user — they may explicitly approve to proceed.
4. Both gates passed. Run `bundle update --conservative <gem name>` to bump that single gem. This is the first step that actually executes gem code (native extension builds, post-install scripts).
5. Run `git diff Gemfile.lock` to see what changed
6. Identify **every** gem whose version changed in the diff, not just the requested one.
   A conservative update often pulls in transitive bumps (e.g. bumping `aws-sdk-marketplacemetering`
   forces `aws-sdk-core` to update because the new version requires `aws-sdk-core >= 3.244.0`).
   Treat the requested gem as the **primary** bump and any others as **transitive** bumps.
   Record OLD_VERSION and NEW_VERSION for each. If the primary's NEW_VERSION differs from
   CANDIDATE (rare — bundler hit an upper bound we hadn't accounted for), re-run both gates
   against the actual NEW_VERSION and abort + revert if they fail. The gates only apply to
   the primary; transitive bumps ride along with whatever bundler picked.
7. For the primary gem **and every transitive gem**, gather the same changelog information:
   - Use `curl -s https://rubygems.org/api/v1/versions/GEM_NAME.json` to fetch all versions (raw JSON, not WebFetch)
   - Parse the JSON to find all versions between OLD_VERSION and NEW_VERSION (exclusive of OLD, inclusive of NEW)
   - Find the gem's GitHub repository URL from rubygems.org
   - For each version in that range (newest first):
     - Extract release date from the `created_at` field in the JSON response
     - Build the GitHub release URL: `https://github.com/OWNER/REPO/releases/tag/TAG`
       (TAG is typically `vVERSION` or `VERSION` - check which format the repo uses)
   - Use WebFetch to fetch notable changes from the GitHub releases
   - If a transitive gem has a very large version range (e.g. 20+ releases), it's fine to
     summarise rather than enumerate every release, but still include the diffend.io link
     and rubygems.org URL so the reader can dig in.
8. For the primary gem **and every transitive gem**, check for security advisories resolved by this bump:
   - Use `curl -s "https://api.github.com/advisories?ecosystem=rubygems&affects=GEM_NAME"` to fetch advisories from the GitHub Advisory Database
   - For each advisory, inspect the `vulnerabilities` entry matching this gem and read its `vulnerable_version_range` and `first_patched_version`
   - Include the advisory if **OLD_VERSION is within `vulnerable_version_range`** AND **NEW_VERSION is at or after `first_patched_version`** (i.e., the bump resolves it)
   - Capture: GHSA id (`ghsa_id`), severity (`severity`), summary (`summary`), and advisory URL (`html_url`)
   - If any advisory affects NEW_VERSION itself (still unpatched), include it under a separate "Known unpatched advisories" section and warn the user
9. Stage and commit with the format below. A single commit covers the primary bump plus all
   transitive bumps that came with it — they belong together because reverting the primary
   bump would also revert them.
10. Run `bundle exec rake test` to verify nothing is broken
    - If tests fail, investigate and fix the issue before moving on
    - If the fix requires reverting the bump, do so and inform the user
11. Move to the next gem

## Commit Message Format

The subject line names the primary gem only. The body covers the primary gem first, then a
`Transitive bumps:` section with one block per transitive gem in the same shape (rubygems
link, diffend link, advisories, release notes, summary). Omit the `Transitive bumps:`
section entirely when there are none.

```
Bump GEM_NAME OLD_VERSION -> NEW_VERSION

https://rubygems.org/gems/GEM_NAME
https://my.diffend.io/gems/GEM_NAME/OLD_VERSION/NEW_VERSION

Supply-chain checks:
- Cool-off: PASS — NEW_VERSION released YYYY-MM-DD (Nd ago, >= 7d)
- Tag-match: PASS — OWNER/REPO@TAG, commit YYYY-MM-DD (delta 0d vs rubygems)
- ... (always include this section. Record the actual age and the upstream
  tag/commit/date that was inspected. If the user explicitly overrode a gate
  in this turn, mark that gate "OVERRIDE" and state the reason inline.)

Security advisories resolved:
- GHSA-xxxx-xxxx-xxxx (SEVERITY): SUMMARY
  ADVISORY_URL
- ... (omit this section entirely if none)

Known unpatched advisories:
- GHSA-xxxx-xxxx-xxxx (SEVERITY): SUMMARY
  ADVISORY_URL
- ... (omit this section entirely if none)

Release notes:
- VERSION (YYYY-MM-DD): GITHUB_RELEASE_URL
- ... (list all versions between OLD_VERSION and NEW_VERSION, newest first)

Summary of changes:
- Lead with security fixes if any
- Then breaking changes
- Then other notable changes
- Keep it concise

Transitive bumps:

  TRANSITIVE_GEM OLD_VERSION -> NEW_VERSION (pulled in by GEM_NAME's new dependency requirement)

  https://rubygems.org/gems/TRANSITIVE_GEM
  https://my.diffend.io/gems/TRANSITIVE_GEM/OLD_VERSION/NEW_VERSION

  Security advisories resolved:
  - ... (omit if none)

  Known unpatched advisories:
  - ... (omit if none)

  Release notes:
  - VERSION (YYYY-MM-DD): GITHUB_RELEASE_URL
  - ... (newest first; may be summarised if the range is very large)

  Summary of changes:
  - Keep it concise
```

## Notes

- Process gems one at a time to create separate commits
- If a gem has no updates available, skip it and inform the user
- If upgrading across a major version, mention key breaking changes
- Always surface security fixes prominently — they are the most important reason to bump
- Keep changelog summaries concise
- Supply-chain hygiene — the cool-off and tag-match gates in step 3 exist to give the wider ecosystem time to flag malicious releases and to spot rubygems-only versions that have no corresponding source-control tag. They run before `bundle update --conservative`, so when a gate fails no gem code has executed and there is nothing to revert. Do not silently bypass them. The `Supply-chain checks:` section in the commit message is always required so a reviewer can see at a glance that the gates were evaluated and what data backed each verdict. If the user explicitly overrides a gate in the same turn, mark that line `OVERRIDE` and state their reason inline.
- The gates apply to the primary gem only. Transitive bumps come with whatever bundler resolves; their changelogs and advisories are still gathered in steps 7 and 8, but they don't go through cool-off or tag-match. If you want a transitive gem gated, re-run `/gem:bump TRANSITIVE_GEM` so it becomes the primary in its own commit.

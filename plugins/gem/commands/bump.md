---
description: Bump gem dependencies and create commits with changelog and security advisory summaries
allowed-tools: Bash(bundle update --conservative *), Bash(git add Gemfile.lock), Bash(git commit *), Bash(git diff *), Bash(curl *), Bash(bundle exec rake test), WebFetch
---

# Bump Gem

Bump one or more gem dependencies, creating a separate commit for each with
changelog and security advisory information.

## Arguments

- `$ARGUMENTS` - Required: one or more gem names to bump

## Steps

For each gem name in `$ARGUMENTS`, perform these steps sequentially:

1. Run `bundle update --conservative <gem name>` to bump that single gem
2. Run `git diff Gemfile.lock` to see what changed
3. Identify **every** gem whose version changed in the diff, not just the requested one.
   A conservative update often pulls in transitive bumps (e.g. bumping `aws-sdk-marketplacemetering`
   forces `aws-sdk-core` to update because the new version requires `aws-sdk-core >= 3.244.0`).
   Treat the requested gem as the **primary** bump and any others as **transitive** bumps.
   Record OLD_VERSION and NEW_VERSION for each.
4. For the primary gem **and every transitive gem**, gather the same changelog information:
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
5. For the primary gem **and every transitive gem**, check for security advisories resolved by this bump:
   - Use `curl -s "https://api.github.com/advisories?ecosystem=rubygems&affects=GEM_NAME"` to fetch advisories from the GitHub Advisory Database
   - For each advisory, inspect the `vulnerabilities` entry matching this gem and read its `vulnerable_version_range` and `first_patched_version`
   - Include the advisory if **OLD_VERSION is within `vulnerable_version_range`** AND **NEW_VERSION is at or after `first_patched_version`** (i.e., the bump resolves it)
   - Capture: GHSA id (`ghsa_id`), severity (`severity`), summary (`summary`), and advisory URL (`html_url`)
   - If any advisory affects NEW_VERSION itself (still unpatched), include it under a separate "Known unpatched advisories" section and warn the user
6. Stage and commit with the format below. A single commit covers the primary bump plus all
   transitive bumps that came with it — they belong together because reverting the primary
   bump would also revert them.
7. Run `bundle exec rake test` to verify nothing is broken
   - If tests fail, investigate and fix the issue before moving on
   - If the fix requires reverting the bump, do so and inform the user
8. Move to the next gem

## Commit Message Format

The subject line names the primary gem only. The body covers the primary gem first, then a
`Transitive bumps:` section with one block per transitive gem in the same shape (rubygems
link, diffend link, advisories, release notes, summary). Omit the `Transitive bumps:`
section entirely when there are none.

```
Bump GEM_NAME OLD_VERSION -> NEW_VERSION

https://rubygems.org/gems/GEM_NAME
https://my.diffend.io/gems/GEM_NAME/OLD_VERSION/NEW_VERSION

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

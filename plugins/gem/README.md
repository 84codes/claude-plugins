# gem

Ruby gem helpers for Claude Code.

## Install

```
/plugin marketplace add 84codes/claude-plugins
/plugin install gem@84codes
```

## Commands

### `/gem:bump`

Bump one or more gem dependencies. Each gem is updated in its own commit with a
changelog-rich message linking to rubygems.org, diffend.io, and the relevant
GitHub releases.

Inside a Bundler project:

```
/gem:bump rails
/gem:bump rails sidekiq pg
```

For each gem, the command will:

1. Resolve the candidate version with `bundle outdated --strict --no-pre` —
   metadata only, no `.gem` archive fetched
2. Run supply-chain gates on the candidate before any gem code executes:
   - Cool-off: refuse versions younger than 7 days (gives the ecosystem time to
     flag malicious releases)
   - Tag-match: refuse versions with no matching upstream tag, or whose tag's
     commit date differs from the rubygems release date by more than ±24h.
     Supports GitHub and GitLab, including annotated tags.
3. Run `bundle update --conservative <gem>` only after both gates pass
4. Diff `Gemfile.lock` to find every gem whose version changed — the requested
   gem plus any transitive dependencies pulled along (e.g. bumping
   `aws-sdk-marketplacemetering` may also bump `aws-sdk-core`)
5. Fetch release notes and security advisories from rubygems.org and GitHub for
   the primary gem **and** every transitive bump
6. Commit with a summary of notable changes; transitive bumps appear in their
   own section in the same commit, and a `Supply-chain checks:` block records
   the gate verdicts that backed the bump
7. Run `bundle exec rake test` before moving on

Both gates can be overridden per-gem by telling the agent explicitly in the
same turn (e.g. "skip cool-off for foo"). Overrides are recorded in the commit
message so they remain visible in review.

## Requirements

- Bundler-managed Ruby project
- A `rake test` task (or edit the command to match your test runner)
- Network access to rubygems.org and github.com

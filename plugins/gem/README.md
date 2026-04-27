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

1. Run `bundle update --conservative <gem>`
2. Diff `Gemfile.lock` to find old/new versions
3. Fetch release notes from rubygems.org and the gem's GitHub releases
4. Commit with a summary of notable changes
5. Run `bundle exec rake test` before moving on

## Requirements

- Bundler-managed Ruby project
- A `rake test` task (or edit the command to match your test runner)
- Network access to rubygems.org and github.com

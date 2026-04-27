# 84codes Claude Code Plugins

A marketplace of [Claude Code](https://claude.com/claude-code) plugins maintained
by [84codes](https://github.com/84codes).

## Install the marketplace

```
/plugin marketplace add 84codes/claude-plugins
```

Then install any plugin from it:

```
/plugin install <plugin-name>@84codes
```

Both steps are needed: the first trusts the marketplace, the second enables a
specific plugin. A marketplace can host many plugins, so the steps are separate.

## Plugins

| Plugin | Description |
| --- | --- |
| [gem](plugins/gem) | Ruby gem helpers. Includes `/gem:bump` for changelog-rich dependency bumps. |

## Developing plugins

You can try the marketplace locally before pushing to the remote. Point
`marketplace add` at a local checkout instead of the `owner/repo` form:

```
/plugin marketplace add /path/to/claude-plugins
/plugin install <plugin-name>@84codes
```

After any change to a plugin or to `marketplace.json` (edits, renames, new
plugins), refresh the cache:

```
/plugin marketplace update 84codes
```

Without this, Claude Code keeps using the cached marketplace and you'll see
errors like `Plugin "<name>" not found in any marketplace`.

Once everything works, push to GitHub and users can install via
`/plugin marketplace add 84codes/claude-plugins`.

## License

MIT

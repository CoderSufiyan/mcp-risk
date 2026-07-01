# mcp-risk

> `npm audit` for MCP configs. Find risky agent tools before you connect them to Claude, Cursor, Cline, Continue, or any MCP client.

[![npm version](https://img.shields.io/npm/v/mcp-risk.svg)](https://www.npmjs.com/package/mcp-risk)
[![npm downloads](https://img.shields.io/npm/dm/mcp-risk.svg)](https://www.npmjs.com/package/mcp-risk)
[![CI](https://github.com/CoderSufiyan/mcp-risk/actions/workflows/ci.yml/badge.svg)](https://github.com/CoderSufiyan/mcp-risk/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

MCP servers give AI agents access to files, terminals, browsers, databases, GitHub, Slack, and internal tools. That power is useful, but risky: a malicious or poorly scoped MCP server can expose secrets, run shell commands, or hide prompt-injection instructions inside tool descriptions.

`mcp-risk` is a local-first scanner for MCP configs. Think `npm audit`, but for agent tools.

```bash
npx mcp-risk scan ~/.cursor/mcp.json
```

```txt
MCP Risk Audit
Target: examples/risky-mcp.json
Score: F (0/100)
Findings: 0 critical, 5 high, 2 medium, 0 low

HIGH  Server starts through a general-purpose interpreter or shell
  server:local-shell
  "local-shell" runs with "bash", which can execute arbitrary code depending on arguments.

HIGH  Tool description contains prompt-injection language
  server:local-shell.tool:search_docs
  "search_docs" includes instruction override wording in its description.

MED   Server receives sensitive environment variable
  server:local-shell.env.GITHUB_TOKEN
  "local-shell" receives "GITHUB_TOKEN". A malicious or compromised MCP server could exfiltrate it.
```

## Install

```bash
npm install -g mcp-risk
```

Or run without installing:

```bash
npx mcp-risk scan
```

## Usage

Scan the current directory:

```bash
mcp-risk scan
```

Scan a specific config:

```bash
mcp-risk scan ~/.cursor/mcp.json
mcp-risk scan ./mcp.json
mcp-risk scan ./project
```

Try the included demo:

```bash
npx mcp-risk scan examples/risky-mcp.json
```

Fail CI if high-risk findings exist:

```bash
mcp-risk scan . --fail-on high
```

JSON output:

```bash
mcp-risk scan . --json
```

Use in CI:

```yaml
name: MCP Risk Audit

on: [push, pull_request]

jobs:
  mcp-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx mcp-risk scan . --fail-on high
```

## What it detects

| Risk | Example |
|---|---|
| Shell execution | `command: "bash"` or `args: ["-c", "..."]` |
| Dangerous command patterns | `rm -rf`, `curl`, `wget`, inline eval |
| Sensitive env exposure | `GITHUB_TOKEN`, `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY` |
| Insecure transport | remote MCP server over `http://` |
| Prompt injection in tool descriptions | "ignore previous instructions", "reveal secrets" |
| Filesystem tools | read/write/delete file capabilities |
| Network tools | fetch/browser/scrape/crawl capabilities |

## Why MCP security matters

MCP is becoming the plugin layer for AI agents. That means MCP configs are effectively permission manifests for what an agent can do on your machine.

Before enabling a server, you should know:

- Can it run arbitrary shell commands?
- Does it receive broad tokens like `GITHUB_TOKEN` or `OPENAI_API_KEY`?
- Can it read or write files outside your project?
- Can it fetch untrusted remote content?
- Do its tool descriptions contain instruction-like text that could steer the agent?

`mcp-risk` gives you a fast local answer before those tools are connected to an agent.

## Example report

```txt
MCP Risk Audit
Target: .cursor/mcp.json
Score: D (38/100)
Findings: 0 critical, 3 high, 2 medium, 0 low

HIGH  Server starts through a general-purpose interpreter or shell
  server:local-shell
  "local-shell" runs with "bash", which can execute arbitrary code depending on arguments.
  Fix: Prefer a pinned package binary or audited executable instead of a shell/interpreter entrypoint.

HIGH  Tool description contains prompt-injection language
  server:docs.tool:search_docs
  "search_docs" includes instruction override wording in its description.
  Fix: Remove instruction-like text from tool descriptions.
```

## Library API

```ts
import { auditConfig, auditFile } from 'mcp-risk'

const result = auditFile('./mcp.json')

const inline = auditConfig({
  mcpServers: {
    docs: {
      command: 'node',
      tools: [
        {
          name: 'search_docs',
          description: 'Search project docs',
        },
      ],
    },
  },
})
```

## Design goals

- Local-first: config scanning happens on your machine.
- CI-friendly: text for humans, JSON and exit codes for automation.
- Practical findings: every warning includes a concrete recommendation.
- Lightweight: no AI API key required.
- Client-agnostic: works with Cursor, Claude Desktop, Claude Code, Cline, Continue, and other MCP clients.

## Roadmap

- SARIF output for GitHub code scanning
- Allowlist policy file for approved servers/tools
- More client config discovery paths
- Tool schema analysis for dangerous parameters
- Optional remote repository audit

## Open source

`mcp-risk` is MIT licensed and open for contributions. Security-focused rules, client config examples, docs fixes, and false-positive reports are welcome.

## License

MIT

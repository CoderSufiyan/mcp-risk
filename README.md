# mcp-risk

> Audit MCP configs for risky tools, secret exposure, and prompt-injection patterns.

[![npm version](https://img.shields.io/npm/v/mcp-risk.svg)](https://www.npmjs.com/package/mcp-risk)
[![CI](https://github.com/CoderSufiyan/mcp-risk/actions/workflows/ci.yml/badge.svg)](https://github.com/CoderSufiyan/mcp-risk/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

MCP servers give AI agents access to files, terminals, browsers, databases, GitHub, Slack, and internal tools. That power is useful, but risky: a malicious or poorly scoped MCP server can expose secrets, run shell commands, or hide prompt-injection instructions inside tool descriptions.

`mcp-risk` is a local-first scanner for MCP configs. Think `npm audit`, but for agent tools.

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

## Why this exists

AI agents are increasingly extended through MCP. That creates an agent supply-chain problem: tools are installed quickly, but their permissions and descriptions are rarely reviewed. `mcp-risk` gives developers a fast local audit before connecting a server to Cursor, Claude Desktop, Claude Code, Cline, Continue, or any MCP-compatible client.

## License

MIT

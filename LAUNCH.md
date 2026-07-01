# Launch Copy

## LinkedIn

MCP servers are becoming the plugin system for AI agents.

That means your agent can suddenly access files, shell commands, browsers, databases, GitHub tokens, Slack, and internal tools.

So I built `mcp-risk`: an npm audit-style scanner for MCP configs.

It checks for:

- shell execution
- risky command arguments
- sensitive env vars like `GITHUB_TOKEN` / `OPENAI_API_KEY`
- insecure HTTP transport
- prompt-injection language in tool descriptions
- filesystem and network-capable tools

Run it locally:

```bash
npx mcp-risk scan ~/.cursor/mcp.json
```

Or fail CI:

```bash
npx mcp-risk scan . --fail-on high
```

GitHub: https://github.com/CoderSufiyan/mcp-risk
npm: https://www.npmjs.com/package/mcp-risk

## X / Twitter

MCP servers are becoming the npm packages of AI agents.

So I built `mcp-risk`: `npm audit` for MCP configs.

It scans for shell access, leaked env tokens, risky tools, insecure transport, and prompt-injection text in tool descriptions.

```bash
npx mcp-risk scan
```

https://github.com/CoderSufiyan/mcp-risk

## Hacker News

Title:

```txt
Show HN: mcp-risk – npm audit for MCP configs
```

Post:

```txt
I built mcp-risk, a local-first CLI that audits MCP configs before you connect them to an AI agent.

MCP servers can expose files, shell commands, browsers, databases, GitHub tokens, and internal tools. mcp-risk checks configs for risky commands, sensitive env vars, insecure HTTP transport, prompt-injection language in tool descriptions, and filesystem/network-capable tools.

Usage:

npx mcp-risk scan ~/.cursor/mcp.json
npx mcp-risk scan . --fail-on high

It has text output for humans and JSON/exit codes for CI.
```

## Reddit

Title:

```txt
I built a small CLI to audit MCP configs before connecting them to AI agents
```

Post:

```txt
I’ve been experimenting with MCP servers and noticed that configs can quietly give agents access to shell commands, filesystem tools, network tools, and broad env tokens.

I built mcp-risk as a local scanner for MCP configs:

- shell/interpreter entrypoints
- risky command args
- sensitive env vars
- insecure HTTP transport
- prompt-injection text in tool descriptions
- filesystem/network/command-capable tools

Try:

npx mcp-risk scan ~/.cursor/mcp.json

Repo: https://github.com/CoderSufiyan/mcp-risk
```

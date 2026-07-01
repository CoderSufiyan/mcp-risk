# Contributing to mcp-risk

Thanks for helping improve MCP security tooling.

## Setup

```bash
git clone https://github.com/CoderSufiyan/mcp-risk.git
cd mcp-risk
npm install
npm test
npm run build
```

## Useful commands

```bash
npm test
npm run build
node dist/cli.js scan examples/risky-mcp.json
```

## Good first contributions

- Add new prompt-injection patterns with tests
- Add MCP config examples from different clients
- Improve false-positive handling
- Add SARIF output
- Add allowlist policy support
- Improve README examples

## Pull request checklist

- Tests added or updated
- `npm test` passes
- `npm run build` passes
- README updated if behavior changes

## Rule quality

Security scanners can become noisy. Prefer rules that are:

- Specific enough to avoid obvious false positives
- Easy to explain in one sentence
- Paired with a practical recommendation
- Covered by tests

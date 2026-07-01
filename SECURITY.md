# Security Policy

## Reporting a vulnerability

If you find a security issue in `mcp-risk`, please open a GitHub security advisory or contact the maintainer privately.

Do not open a public issue for vulnerabilities that could help attackers bypass detection or compromise users.

## Scope

Security reports may include:

- Scanner bypasses for dangerous MCP configs
- Prompt-injection patterns that should be detected
- Unsafe behavior in the CLI
- Supply-chain issues in dependencies or release artifacts

## Notes

`mcp-risk` is a static risk scanner. It does not prove an MCP server is safe. Treat clean scans as a baseline check, not a security guarantee.

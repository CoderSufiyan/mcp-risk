# Changelog

## 0.4.0 - 2026-07-29

- Add static verification for exact npm package versions before installation.
- Download the resolved npm tarball, calculate its SHA-256 digest, and enforce archive size and entry limits.
- Scan JavaScript, TypeScript, package manifests, and included MCP configs without executing package code or lifecycle scripts.
- Detect source-level shell execution, network access, filesystem access, hardcoded secrets, and install scripts.
- Add pinned GitHub repository verification with immutable commit resolution and private-repository token support.
- Add text, JSON, Markdown, and SARIF verification reports with configurable risk-threshold exit codes.
- Add a public safe/risky security fixture corpus for npm packages and GitHub repositories.

## 0.3.1 - 2026-07-27

- Refresh the npm package README with the `0.3.0` discovery, batch scanning, and diagnostics features.

## 0.3.0 - 2026-07-24

- Discover MCP configurations for Claude Desktop, Cursor, Claude Code, Continue, Windsurf, VS Code, and Cline.
- Add `mcp-risk scan --all` with deduplicated project and user config scanning.
- Add combined text, JSON, and SARIF reports for batch scans.
- Validate MCP config shapes and report malformed or unsupported files with diagnostics.
- Continue batch scans after invalid configs and return exit code `3` for parse or validation errors.

## 0.2.0 - 2026-07-24

- Add `--sarif` output compatible with GitHub Code Scanning.
- Add `.mcp-risk.json` allowlists for approved servers and findings.
- Analyze tool input schemas for unrestricted command, filesystem path, URL, and destructive operation parameters.
- Export SARIF and policy helpers from the library API.

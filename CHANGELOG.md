# Changelog

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

# MCP Security Fixture Corpus

This directory contains fictional, inert fixtures used to measure `mcp-risk` detections and false positives. Nothing in this directory should be installed, imported, or executed.

`manifest.json` pins every npm fixture to an exact version and every repository fixture to a commit-like reference. Each entry declares expected config findings, package install-script behavior, and static source patterns. `tests/corpus.test.ts` validates the complete corpus in CI.

## Coverage

- shell execution and install scripts
- secret exposure
- filesystem and network capabilities
- prompt injection
- dangerous and constrained tool schemas
- safe counterexamples for each category

## Contributing

Contributions must be minimal, fictional reproductions. Do not commit real credentials, malware, copied proprietary source, or code that needs to execute. Add each fixture to `manifest.json`, pin its version or reference, and state all expected findings.

Fixture contributions are provided under the repository's MIT license. Contributors must have the right to submit all included content. Third-party vulnerability samples require clear attribution and a compatible license.

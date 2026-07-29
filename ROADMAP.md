# mcp-risk roadmap

This roadmap groups open work by planned release. GitHub milestones are the source of truth for scheduling; issue dependencies determine implementation order within each release.

Track active work on the public [mcp-risk Roadmap project](https://github.com/users/CoderSufiyan/projects/1) or browse the [release milestones](https://github.com/CoderSufiyan/mcp-risk/milestones).

## Current release

`v0.4.0` provides exact npm package verification, npm tarball integrity, static JavaScript and TypeScript scanning, and pinned GitHub repository verification.

## v0.5.0 - Verification foundation

| Issue | Work |
|---|---|
| [#22](https://github.com/CoderSufiyan/mcp-risk/issues/22) | Version-pinned verification reports |
| [#25](https://github.com/CoderSufiyan/mcp-risk/issues/25) | Markdown MCP security cards |
| [#27](https://github.com/CoderSufiyan/mcp-risk/issues/27) | Static verification guarantees and limitations |
| [#29](https://github.com/CoderSufiyan/mcp-risk/issues/29) | Verification policy rules |
| [#31](https://github.com/CoderSufiyan/mcp-risk/issues/31) | Verification cache |
| [#30](https://github.com/CoderSufiyan/mcp-risk/issues/30) | Offline verification mode |

Planned order: #22, #25, #29, #31, #30. Documentation in #27 can proceed alongside the implementation work.

## v0.6.0 - Automation and sharing

| Issue | Work |
|---|---|
| [#23](https://github.com/CoderSufiyan/mcp-risk/issues/23) | Verified artifact attestations |
| [#24](https://github.com/CoderSufiyan/mcp-risk/issues/24) | Verification badges |
| [#26](https://github.com/CoderSufiyan/mcp-risk/issues/26) | GitHub Action verification mode |
| [#35](https://github.com/CoderSufiyan/mcp-risk/issues/35) | SARIF suppression reasons |

## v0.7.0 - Provenance and governance

| Issue | Work |
|---|---|
| [#32](https://github.com/CoderSufiyan/mcp-risk/issues/32) | Package provenance checks |
| [#33](https://github.com/CoderSufiyan/mcp-risk/issues/33) | Verification report diff |
| [#36](https://github.com/CoderSufiyan/mcp-risk/issues/36) | Signed MCP attestation schema |
| [#40](https://github.com/CoderSufiyan/mcp-risk/issues/40) | Organization policy presets |
| [#45](https://github.com/CoderSufiyan/mcp-risk/issues/45) | Verification baselines |
| [#48](https://github.com/CoderSufiyan/mcp-risk/issues/48) | MCP tool definition pinning |
| [#49](https://github.com/CoderSufiyan/mcp-risk/issues/49) | MCP security scoring standard |

## v0.8.0 - CI and vulnerability intelligence

| Issue | Work |
|---|---|
| [#34](https://github.com/CoderSufiyan/mcp-risk/issues/34) | GitHub Action policy and baseline inputs |
| [#37](https://github.com/CoderSufiyan/mcp-risk/issues/37) | GitHub pull request comments |
| [#38](https://github.com/CoderSufiyan/mcp-risk/issues/38) | OSV and npm vulnerability intelligence |
| [#39](https://github.com/CoderSufiyan/mcp-risk/issues/39) | Sandboxed package inspection |
| [#41](https://github.com/CoderSufiyan/mcp-risk/issues/41) | Attestation verification |
| [#46](https://github.com/CoderSufiyan/mcp-risk/issues/46) | Network egress analysis |
| [#47](https://github.com/CoderSufiyan/mcp-risk/issues/47) | Optional MCP runtime inspection |

## v0.9.0 - Registry and maintainer workflows

| Issue | Work |
|---|---|
| [#42](https://github.com/CoderSufiyan/mcp-risk/issues/42) | MCP registry security metadata |
| [#43](https://github.com/CoderSufiyan/mcp-risk/issues/43) | Runtime tool mutation detection |
| [#44](https://github.com/CoderSufiyan/mcp-risk/issues/44) | Public verification report hosting |
| [#50](https://github.com/CoderSufiyan/mcp-risk/issues/50) | Maintainer release verification workflow |

## v1.0.0 - Stable trust platform

| Issue | Work |
|---|---|
| [#51](https://github.com/CoderSufiyan/mcp-risk/issues/51) | Attestation signing key management and rotation |
| [#52](https://github.com/CoderSufiyan/mcp-risk/issues/52) | Reproducible verification mode |
| [#53](https://github.com/CoderSufiyan/mcp-risk/issues/53) | SBOM generation |
| [#54](https://github.com/CoderSufiyan/mcp-risk/issues/54) | Stable security rule plugin API |
| [#55](https://github.com/CoderSufiyan/mcp-risk/issues/55) | Security rule benchmark suite |
| [#57](https://github.com/CoderSufiyan/mcp-risk/issues/57) | Package signature verification |
| [#59](https://github.com/CoderSufiyan/mcp-risk/issues/59) | Attestation transparency log |

## v1.1.0 - Advanced analysis

| Issue | Work |
|---|---|
| [#56](https://github.com/CoderSufiyan/mcp-risk/issues/56) | Multi-language MCP source scanning |
| [#58](https://github.com/CoderSufiyan/mcp-risk/issues/58) | Source-to-tool data-flow analysis |
| [#60](https://github.com/CoderSufiyan/mcp-risk/issues/60) | Release-to-release security diff |

## Contributing to roadmap work

1. Choose an open issue in the earliest milestone that is not blocked by an unfinished dependency.
2. Comment on the issue before starting substantial work so contributors do not duplicate effort.
3. Keep verification and fixtures static-only. Runtime features must remain separate, explicit, opt-in, isolated, and documented.
4. Add focused tests and safe/risky fixtures for security behavior.
5. Open a focused pull request that links and closes the issue.

Milestones describe intent, not a guarantee of dates or scope. Security findings may cause work to move between releases.

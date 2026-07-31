# Verification guarantees and limitations

`mcp-risk verify` inspects a package or repository before you connect it to an
MCP client. Verification is static-only: target code is treated as data and is
never installed, imported, or executed.

## What verification does

For an exact npm version, verification:

1. requests package metadata from the configured npm registry;
2. downloads the tarball URL declared by that metadata;
3. calculates the tarball SHA-256 digest;
4. extracts regular files and directories into bounded temporary storage; and
5. scans JavaScript, TypeScript, package manifests, and known MCP config paths.

For a GitHub target, verification:

1. requests commit metadata from the GitHub API;
2. resolves the requested branch, tag, or commit to an exact commit SHA;
3. downloads the archive for that commit; and
4. applies the same bounded extraction and static source scan.

The scanner reports install lifecycle scripts and static patterns associated
with shell execution, network access, filesystem access, hardcoded secrets,
and risky MCP declarations. It also reports archive and source-file limits that
prevent complete inspection.

## Network requests

Verification is not an offline operation.

- npm verification requests registry metadata and the selected tarball.
- GitHub verification requests commit metadata and the exact commit archive.
- `GITHUB_TOKEN` is optional for public repositories and is used for GitHub API
  requests when supplied. It may be required for private repositories or higher
  rate limits.

No request executes code from the target. Registry metadata and downloaded
archives remain untrusted input throughout the scan.

## Temporary files and cleanup

Each archive is downloaded under the operating system temporary directory in a
new `mcp-risk-*` directory. By default, compressed archives are limited to 100
MiB, declared extracted content to 250 MiB, and archive entries to 10,000. Links
and other non-file entry types are not extracted.

The temporary directory contains the downloaded archive and its extracted
files. It is removed in a `finally` block after success or failure. A process
crash or forced termination can still interrupt cleanup, so operators with
strict storage policies should monitor their system temporary directory.

## What a clean result does not guarantee

A clean result means that the supported static checks found no reported pattern
in the files they inspected. It is not a guarantee that a package or repository
is safe. In particular, verification does not:

- run the target or observe its runtime behavior;
- prove the intent of shell, network, or filesystem operations;
- recursively download and scan dependency source;
- detect every form of generated, obfuscated, native, WebAssembly, or dynamic
  code;
- inspect private artifacts that the supplied credentials cannot access;
- verify a publisher's identity, release signature, or build provenance; or
- prove that a mutable branch or tag will resolve to the same commit later.

Review findings, the reported immutable identity and digest, dependency and
maintainer metadata, and the target's permissions before connecting it to an
agent. Treat a clean scan as one input to that review, not approval by itself.

## Examples

Verify a pinned npm release and fail when a high-severity finding is present:

```bash
mcp-risk verify npm:example-mcp@1.2.3 --fail-on high
```

Verify a GitHub tag and save a machine-readable report. The output includes the
exact commit SHA resolved at scan time:

```bash
mcp-risk verify github:owner/repository@v1.2.3 --json > verification.json
```

For the strongest repeatability, use the reported commit SHA in later runs:

```bash
mcp-risk verify github:owner/repository@0123456789abcdef0123456789abcdef01234567
```

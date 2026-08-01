# Verification report schema

`mcp-risk verify --json` emits a version-pinned verification report. The report is designed for storage, comparison, policy evaluation, attestations, and CI integrations.

The exact JSON Schema is published at [`schemas/verification-report-1.0.0.schema.json`](schemas/verification-report-1.0.0.schema.json). Versioned schema files are immutable after release; corrections and additions require a new schema version and file.

## Core identity

Every report includes:

- `schemaVersion`: version of the report contract
- `generatedAt`: ISO 8601 report generation time
- `scanner`: scanner name and package version
- `target`: the original exact verification target
- `artifact`: immutable package or repository identity and digest
- `metadata`: normalized package or repository evidence
- `policy`: policy evaluation status and violations
- `summary`: score, grade, and severity counts
- `findings`: normalized scanner findings

For npm reports, `artifact.digest` is the SHA-256 digest of the downloaded tarball selected for the exact package version.

For GitHub reports, `artifact.digest` is the resolved 40-character Git commit SHA-1. `metadata.archiveDigest` separately records the SHA-256 digest of the downloaded GitHub archive.

## Policy result

Reports currently use `not-configured` when no verification policy was evaluated. Future verification policy support may emit `passed` or `failed` with stable violation IDs and messages. Scanner findings and policy violations remain separate.

## Determinism

For equivalent raw verification results, scanner version, and policy input, `createVerificationReport` produces equivalent JSON apart from `generatedAt`.

To make this stable, the model:

- sorts findings by severity, rule ID, location, and message
- sorts maintainers, dependencies, install scripts, manifests, and policy violations
- excludes derived publish-age values that change as time passes
- normalizes timestamps to UTC ISO 8601 strings

Tests and reproducible workflows may inject `generatedAt` through `VerificationReportOptions`.

## Compatibility

The report schema follows semantic versioning independently from the `mcp-risk` package version.

- Patch schema releases clarify constraints without changing valid report structure.
- Minor schema releases may add optional fields or enum values without changing existing field meaning.
- Major schema releases may remove fields, make optional fields required, or change field meaning or type.

Strict validators should select the schema file matching `schemaVersion` exactly and reject reports for unsupported versions. Application-level consumers may choose to accept a newer minor release and ignore unknown optional fields, but must not validate that report against an older exact schema. Producers must not silently change the meaning of an existing field.

The current schema version is `1.0.0`. Raw `verifyNpmPackage` and `verifyGitHubRepository` results remain available through the library API, but persisted automation should use `createVerificationReport` or CLI JSON output.

## Library usage

```ts
import { createVerificationReport, verifyNpmPackage } from 'mcp-risk'

const result = await verifyNpmPackage('npm:example-mcp@1.2.3')
const report = createVerificationReport(result)
```

Reports describe static evidence observed for one exact artifact. They do not prove that an MCP server is safe or predict all runtime behavior.

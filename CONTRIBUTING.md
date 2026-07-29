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

Node.js 18 or newer is required. Do not commit registry credentials, GitHub tokens, private package contents, or real secrets in fixtures.

## Useful commands

```bash
npm test
npm run build
node dist/cli.js scan examples/risky-mcp.json
node dist/cli.js verify npm:mcp-risk@0.4.0
```

## Choosing work

- Start with the version plan in [ROADMAP.md](ROADMAP.md), the [public project board](https://github.com/users/CoderSufiyan/projects/1), and the repository's GitHub milestones.
- Prefer an issue labeled `good first issue` or `help wanted` if you are new to the project.
- Check the issue's `Depends on` section and choose work whose dependencies are complete.
- Comment on the issue before starting substantial work. A maintainer can confirm scope and avoid duplicate implementations.
- Keep one feature or fix per pull request unless the linked issue explicitly requires a larger change.

Useful first contributions include focused documentation fixes, safe fixture additions, false-positive reductions, and tests for existing rules.

## Static-only security boundary

Verification must never execute target package or repository code. This includes lifecycle scripts, binaries, imported modules, generated shell commands, and fixture payloads.

- Inspect registry metadata, archives, manifests, configs, and source as data.
- Extract untrusted archives only through the bounded archive utilities.
- Do not use `npm install` against a target fixture or invoke a target entrypoint.
- Do not trust `.mcp-risk.json` or other suppression files bundled inside an untrusted artifact.
- Use fictional credentials and `.example.test` hosts in fixtures.

## Fixtures and tests

Security behavior should include a focused regression test. New detection rules should normally include both a risky example and a safe counterexample.

The public corpus is in `fixtures/security-corpus`. Corpus samples must be inert, fictional, license-compatible, and described in its manifest. Tests may read or archive fixtures, but must never execute them.

Before opening a pull request, run:

```bash
npm test
npm run build
```

## Pull request checklist

- Tests added or updated
- `npm test` passes
- `npm run build` passes
- README updated if behavior changes
- `CHANGELOG.md` updated for user-visible release work when requested by a maintainer
- Static verification and fixtures do not execute target code; any runtime feature is explicit, opt-in, isolated, and documented
- New findings include a stable rule ID, severity, source location, and remediation
- Pull request links the issue with `Closes #<issue>` when it completes the work

## Rule quality

Security scanners can become noisy. Prefer rules that are:

- Specific enough to avoid obvious false positives
- Easy to explain in one sentence
- Paired with a practical recommendation
- Covered by tests

Rule IDs and report fields are public compatibility surfaces. Avoid renaming them without a migration plan and explicit maintainer agreement.

## Review and merging

Opening a pull request does not grant merge access. Maintainers merge changes after review and required CI checks. Contributors should not rewrite unrelated code, generated output, or other contributors' work.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import { describe, expect, it } from 'vitest'
import type { GitHubVerificationResult, NpmVerificationResult, VerificationReport } from '../src/types.js'
import { VERSION } from '../src/version.js'
import { createVerificationReport, VERIFICATION_REPORT_SCHEMA_VERSION } from '../src/verify/model.js'

const schema = JSON.parse(readFileSync(join(process.cwd(), 'docs', 'schemas', 'verification-report-1.0.0.schema.json'), 'utf8'))
const validate = new Ajv2020({ strict: true }).compile<VerificationReport>(schema)

describe('version-pinned verification reports', () => {
  it('normalizes npm identity, evidence, policy, and collection order', () => {
    const result = npmResult()
    const report = createVerificationReport(result, {
      generatedAt: '2026-08-01T12:34:56Z',
      policy: {
        status: 'failed',
        name: 'strict',
        violations: [
          { id: 'publisher', message: 'Publisher is not approved.' },
          { id: 'install-script', message: 'Install scripts are blocked.' },
        ],
      },
    })

    expect(report).toMatchObject({
      schemaVersion: VERIFICATION_REPORT_SCHEMA_VERSION,
      generatedAt: '2026-08-01T12:34:56.000Z',
      scanner: { name: 'mcp-risk', version: VERSION },
      artifact: {
        kind: 'npm',
        name: '@fixture/server',
        version: '1.2.3',
        digest: { algorithm: 'sha256', value: 'a'.repeat(64) },
      },
      policy: { status: 'failed', name: 'strict' },
    })
    expect(report.metadata.maintainers).toEqual(['Alpha <alpha@example.test>', 'Zulu <zulu@example.test>'])
    expect(report.metadata.dependencies.map((dependency) => dependency.name)).toEqual(['alpha', 'zulu'])
    expect(report.findings.map((finding) => finding.severity)).toEqual(['critical', 'high'])
    expect(report.policy.violations.map((violation) => violation.id)).toEqual(['install-script', 'publisher'])
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true)
  })

  it('records immutable GitHub commit and archive identities', () => {
    const commit = 'b'.repeat(40)
    const report = createVerificationReport(githubResult(commit), { generatedAt: new Date('2026-08-01T00:00:00.000Z') })

    expect(report).toMatchObject({
      artifact: {
        kind: 'github',
        owner: 'fixture',
        repository: 'server',
        requestedRef: 'v1.2.3',
        commit,
        digest: { algorithm: 'git-sha1', value: commit },
      },
      metadata: {
        archiveDigest: { algorithm: 'sha256', value: 'c'.repeat(64) },
      },
      policy: { status: 'not-configured', violations: [] },
    })
    expect(report.metadata.manifests.map((manifest) => manifest.path)).toEqual(['package.json', 'packages/worker/package.json'])
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true)
  })

  it('is deterministic apart from the generation timestamp', () => {
    const firstResult = npmResult()
    const secondResult = npmResult()
    secondResult.findings.reverse()
    secondResult.metadata.maintainers.reverse()
    secondResult.metadata.dependencies.reverse()
    secondResult.metadata.installScripts.reverse()

    const first = createVerificationReport(firstResult, { generatedAt: '2026-08-01T00:00:00Z' })
    const second = createVerificationReport(secondResult, { generatedAt: '2026-08-02T00:00:00Z' })
    const { generatedAt: firstTimestamp, ...firstStable } = first
    const { generatedAt: secondTimestamp, ...secondStable } = second

    expect(firstTimestamp).not.toBe(secondTimestamp)
    expect(JSON.stringify(firstStable)).toBe(JSON.stringify(secondStable))
  })

  it('projects only versioned schema fields from extended raw results', () => {
    const result = npmResult()
    result.findings[0] = { ...result.findings[0], futureField: 'not part of schema v1' } as typeof result.findings[number]
    result.metadata.dependencies[0] = { ...result.metadata.dependencies[0], futureField: true } as typeof result.metadata.dependencies[number]
    const report = createVerificationReport(result, { generatedAt: '2026-08-01T00:00:00Z' })

    expect(report.findings[0]).not.toHaveProperty('futureField')
    expect(report.metadata.dependencies[0]).not.toHaveProperty('futureField')
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true)
  })

  it('keeps the scanner version aligned with package metadata', () => {
    const packageJson = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as { version: string }
    expect(VERSION).toBe(packageJson.version)
  })

  it('rejects incomplete npm evidence and invalid timestamps', () => {
    const incomplete = npmResult()
    delete incomplete.metadata.tarballDigest
    expect(() => createVerificationReport(incomplete)).toThrow('missing tarball identity')
    expect(() => createVerificationReport(npmResult(), { generatedAt: 'not-a-date' })).toThrow('valid date')
  })
})

function npmResult(): NpmVerificationResult {
  return {
    target: 'npm:@fixture/server@1.2.3',
    kind: 'npm',
    package: { name: '@fixture/server', version: '1.2.3' },
    metadata: {
      publishedAt: '2026-01-02T00:00:00.000Z',
      publishAgeDays: 211,
      createdAt: '2026-01-01T00:00:00.000Z',
      maintainers: ['Zulu <zulu@example.test>', 'Alpha <alpha@example.test>'],
      dependencyCount: 2,
      dependencies: [
        { name: 'zulu', specifier: '^2.0.0', type: 'optional' },
        { name: 'alpha', specifier: '^1.0.0', type: 'dependency' },
      ],
      installScripts: ['postinstall', 'preinstall'],
      license: 'MIT',
      repository: 'https://github.com/fixture/server',
      tarball: 'https://registry.example.test/server-1.2.3.tgz',
      tarballDigest: { algorithm: 'sha256', value: 'a'.repeat(64) },
      tarballSizeBytes: 1234,
      sourceFileCount: 4,
    },
    summary: { score: 55, grade: 'C', critical: 1, high: 1, medium: 0, low: 0 },
    findings: [
      {
        id: 'network-access',
        severity: 'high',
        title: 'Source performs network access',
        message: 'Network access found.',
        location: 'package/src/server.js:2',
        recommendation: 'Restrict destinations.',
      },
      {
        id: 'hardcoded-secret',
        severity: 'critical',
        title: 'Source contains a hardcoded secret',
        message: 'Hardcoded secret found.',
        location: 'package/src/server.js:1',
        recommendation: 'Remove the secret.',
      },
    ],
  }
}

function githubResult(commit: string): GitHubVerificationResult {
  return {
    target: 'github:fixture/server@v1.2.3',
    kind: 'github',
    repository: {
      owner: 'fixture',
      name: 'server',
      url: 'https://github.com/fixture/server',
      ref: 'v1.2.3',
      commit,
    },
    metadata: {
      archiveUrl: `https://api.github.com/repos/fixture/server/tarball/${commit}`,
      archiveDigest: { algorithm: 'sha256', value: 'c'.repeat(64) },
      archiveSizeBytes: 4567,
      sourceFileCount: 6,
      manifests: [
        { path: 'packages/worker/package.json', dependencies: ['zulu', 'alpha'], installScripts: ['postinstall'] },
        { path: 'package.json', name: 'fixture-server', version: '1.2.3', dependencies: [], installScripts: [] },
      ],
    },
    summary: { score: 100, grade: 'A', critical: 0, high: 0, medium: 0, low: 0 },
    findings: [],
  }
}

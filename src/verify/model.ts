import type {
  Finding,
  GitHubVerificationReport,
  GitHubVerificationResult,
  NpmVerificationReport,
  NpmVerificationResult,
  VerificationPolicyResult,
  VerificationReport,
} from '../types.js'
import { VERSION } from '../version.js'

export const VERIFICATION_REPORT_SCHEMA_VERSION = '1.0.0' as const

export type VerificationReportOptions = {
  generatedAt?: Date | string
  policy?: VerificationPolicyResult
}

export function createVerificationReport(result: NpmVerificationResult, options?: VerificationReportOptions): NpmVerificationReport
export function createVerificationReport(result: GitHubVerificationResult, options?: VerificationReportOptions): GitHubVerificationReport
export function createVerificationReport(result: NpmVerificationResult | GitHubVerificationResult, options?: VerificationReportOptions): VerificationReport
export function createVerificationReport(result: NpmVerificationResult | GitHubVerificationResult, options: VerificationReportOptions = {}): VerificationReport {
  const base = {
    schemaVersion: VERIFICATION_REPORT_SCHEMA_VERSION,
    generatedAt: normalizeTimestamp(options.generatedAt),
    scanner: { name: 'mcp-risk' as const, version: VERSION },
    target: result.target,
    policy: normalizePolicy(options.policy),
    summary: {
      score: result.summary.score,
      grade: result.summary.grade,
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low,
    },
    findings: [...result.findings].sort(compareFindings).map(normalizeFinding),
  }

  if (result.kind === 'npm') {
    const digest = result.metadata.tarballDigest
    if (!digest || !result.metadata.tarball) throw new Error('npm verification result is missing tarball identity')
    if (result.metadata.tarballSizeBytes === undefined || result.metadata.sourceFileCount === undefined) {
      throw new Error('npm verification result is missing archive inspection metadata')
    }
    return {
      ...base,
      artifact: {
        kind: 'npm',
        name: result.package.name,
        version: result.package.version,
        tarballUrl: result.metadata.tarball,
        digest: { algorithm: 'sha256' as const, value: digest.value },
      },
      metadata: {
        ...(result.metadata.publishedAt ? { publishedAt: result.metadata.publishedAt } : {}),
        ...(result.metadata.createdAt ? { createdAt: result.metadata.createdAt } : {}),
        maintainers: [...result.metadata.maintainers].sort(compareText),
        dependencies: result.metadata.dependencies
          .map((dependency) => ({
            name: dependency.name,
            ...(dependency.specifier === undefined ? {} : { specifier: dependency.specifier }),
            type: dependency.type,
          }))
          .sort((left, right) => compareText(left.name, right.name) || compareText(left.type, right.type) || compareText(left.specifier ?? '', right.specifier ?? '')),
        installScripts: [...result.metadata.installScripts].sort(compareText),
        ...(result.metadata.license ? { license: result.metadata.license } : {}),
        ...(result.metadata.repository ? { repository: result.metadata.repository } : {}),
        tarballSizeBytes: result.metadata.tarballSizeBytes,
        sourceFileCount: result.metadata.sourceFileCount,
      },
    }
  }

  return {
    ...base,
    artifact: {
      kind: 'github',
      owner: result.repository.owner,
      repository: result.repository.name,
      repositoryUrl: result.repository.url,
      requestedRef: result.repository.ref,
      commit: result.repository.commit,
      digest: { algorithm: 'git-sha1', value: result.repository.commit },
    },
    metadata: {
      archiveUrl: result.metadata.archiveUrl,
      archiveDigest: { algorithm: 'sha256', value: result.metadata.archiveDigest.value },
      archiveSizeBytes: result.metadata.archiveSizeBytes,
      sourceFileCount: result.metadata.sourceFileCount,
      manifests: result.metadata.manifests
        .map((manifest) => ({
          path: manifest.path,
          ...(manifest.name === undefined ? {} : { name: manifest.name }),
          ...(manifest.version === undefined ? {} : { version: manifest.version }),
          dependencies: [...manifest.dependencies].sort(compareText),
          installScripts: [...manifest.installScripts].sort(compareText),
        }))
        .sort((left, right) => compareText(left.path, right.path)),
    },
  }
}

function normalizeTimestamp(value: Date | string | undefined): string {
  const date = value instanceof Date ? value : value === undefined ? new Date() : new Date(value)
  if (Number.isNaN(date.getTime())) throw new Error('Verification report timestamp must be a valid date')
  return date.toISOString()
}

function normalizePolicy(policy: VerificationPolicyResult | undefined): VerificationPolicyResult {
  if (!policy) return { status: 'not-configured', violations: [] }
  return {
    status: policy.status,
    ...(policy.name ? { name: policy.name } : {}),
    violations: policy.violations
      .map((violation) => ({ id: violation.id, message: violation.message }))
      .sort((left, right) => compareText(left.id, right.id) || compareText(left.message, right.message)),
  }
}

function compareFindings(left: Finding, right: Finding): number {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
  return severityOrder[left.severity] - severityOrder[right.severity]
    || compareText(left.id, right.id)
    || compareText(left.location, right.location)
    || compareText(left.message, right.message)
    || compareText(left.title, right.title)
    || compareText(left.recommendation, right.recommendation)
}

function normalizeFinding(finding: Finding): Finding {
  return {
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    message: finding.message,
    location: finding.location,
    recommendation: finding.recommendation,
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

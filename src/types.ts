export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type McpServerConfig = {
  command?: string
  args?: string[]
  env?: Record<string, string>
  url?: string
  transport?: string
  tools?: McpTool[]
  [key: string]: unknown
}

export type McpTool = {
  name?: string
  description?: string
  inputSchema?: unknown
  [key: string]: unknown
}

export type McpConfig = {
  mcpServers?: Record<string, McpServerConfig>
  servers?: Record<string, McpServerConfig>
  tools?: McpTool[]
  [key: string]: unknown
}

export type Finding = {
  id: string
  severity: Severity
  title: string
  message: string
  location: string
  recommendation: string
}

export type AuditSummary = {
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  critical: number
  high: number
  medium: number
  low: number
}

export type AuditResult = {
  target: string
  summary: AuditSummary
  findings: Finding[]
  suppressed: number
}

export type AuditBatchResult = {
  results: AuditResult[]
  summary: AuditSummary
  suppressed: number
  diagnostics: ConfigDiagnostic[]
}

export type ConfigDiagnostic = {
  target: string
  kind: 'parse' | 'validation'
  message: string
}

export type NpmVerificationMetadata = {
  publishedAt?: string
  publishAgeDays?: number
  createdAt?: string
  maintainers: string[]
  dependencyCount: number
  dependencies: Array<{
    name: string
    specifier?: string
    type: 'dependency' | 'optional' | 'peer' | 'bundled'
  }>
  installScripts: string[]
  license?: string
  repository?: string
  tarball?: string
  tarballDigest?: {
    algorithm: 'sha256'
    value: string
  }
  tarballSizeBytes?: number
  sourceFileCount?: number
}

export type NpmVerificationResult = {
  target: string
  kind: 'npm'
  package: {
    name: string
    version: string
  }
  metadata: NpmVerificationMetadata
  summary: AuditSummary
  findings: Finding[]
}

export type PackageManifestSummary = {
  path: string
  name?: string
  version?: string
  dependencies: string[]
  installScripts: string[]
}

export type GitHubVerificationResult = {
  target: string
  kind: 'github'
  repository: {
    owner: string
    name: string
    url: string
    ref: string
    commit: string
  }
  metadata: {
    archiveUrl: string
    archiveDigest: {
      algorithm: 'sha256'
      value: string
    }
    archiveSizeBytes: number
    sourceFileCount: number
    manifests: PackageManifestSummary[]
  }
  summary: AuditSummary
  findings: Finding[]
}

export type VerificationPolicyViolation = {
  id: string
  message: string
}

export type VerificationPolicyResult = {
  status: 'not-configured' | 'passed' | 'failed'
  name?: string
  violations: VerificationPolicyViolation[]
}

export type VerificationReportBase = {
  schemaVersion: '1.0.0'
  generatedAt: string
  scanner: {
    name: 'mcp-risk'
    version: string
  }
  target: string
  policy: VerificationPolicyResult
  summary: AuditSummary
  findings: Finding[]
}

export type VerificationReportDependency = {
  name: string
  specifier?: string
  type: 'dependency' | 'optional' | 'peer' | 'bundled'
}

export type VerificationReportManifest = {
  path: string
  name?: string
  version?: string
  dependencies: string[]
  installScripts: string[]
}

export type NpmVerificationReport = VerificationReportBase & {
  artifact: {
    kind: 'npm'
    name: string
    version: string
    tarballUrl: string
    digest: {
      algorithm: 'sha256'
      value: string
    }
  }
  metadata: {
    publishedAt?: string
    createdAt?: string
    maintainers: string[]
    dependencies: VerificationReportDependency[]
    installScripts: string[]
    license?: string
    repository?: string
    tarballSizeBytes: number
    sourceFileCount: number
  }
}

export type GitHubVerificationReport = VerificationReportBase & {
  artifact: {
    kind: 'github'
    owner: string
    repository: string
    repositoryUrl: string
    requestedRef: string
    commit: string
    digest: {
      algorithm: 'git-sha1'
      value: string
    }
  }
  metadata: {
    archiveUrl: string
    archiveDigest: {
      algorithm: 'sha256'
      value: string
    }
    archiveSizeBytes: number
    sourceFileCount: number
    manifests: VerificationReportManifest[]
  }
}

export type VerificationReport = NpmVerificationReport | GitHubVerificationReport

export type RiskPolicyAllowEntry = {
  server?: string
  finding?: string
}

export type RiskPolicy = {
  allow: RiskPolicyAllowEntry[]
}

export type AuditOptions = {
  includeLow?: boolean
  policy?: RiskPolicy
}

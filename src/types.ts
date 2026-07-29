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

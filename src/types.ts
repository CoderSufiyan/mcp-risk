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

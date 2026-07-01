import type { AuditSummary, Finding, Severity } from './types.js'

const weights: Record<Severity, number> = {
  critical: 35,
  high: 20,
  medium: 8,
  low: 3,
}

export function summarize(findings: Finding[]): AuditSummary {
  const critical = findings.filter((finding) => finding.severity === 'critical').length
  const high = findings.filter((finding) => finding.severity === 'high').length
  const medium = findings.filter((finding) => finding.severity === 'medium').length
  const low = findings.filter((finding) => finding.severity === 'low').length
  const penalty = findings.reduce((sum, finding) => sum + weights[finding.severity], 0)
  const score = Math.max(0, 100 - penalty)

  return {
    score,
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
    critical,
    high,
    medium,
    low,
  }
}

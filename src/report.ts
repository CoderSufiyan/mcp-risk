import pc from 'picocolors'
import type { AuditResult, Finding, Severity } from './types.js'

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

function colorSeverity(severity: Severity): string {
  if (severity === 'critical') return pc.bgRed(pc.white(' CRIT '))
  if (severity === 'high') return pc.red('HIGH ')
  if (severity === 'medium') return pc.yellow('MED  ')
  return pc.gray('LOW  ')
}

function colorGrade(grade: string): string {
  if (grade === 'A' || grade === 'B') return pc.green(grade)
  if (grade === 'C') return pc.yellow(grade)
  return pc.red(grade)
}

export function formatTextReport(result: AuditResult): string {
  const lines = [
    '',
    pc.bold('MCP Risk Audit'),
    `Target: ${result.target}`,
    `Score: ${colorGrade(result.summary.grade)} (${result.summary.score}/100)`,
    `Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`,
    ...(result.suppressed > 0 ? [`Suppressed: ${result.suppressed}`] : []),
    '',
  ]

  if (result.findings.length === 0) {
    lines.push(pc.green('No risky MCP patterns found.'), '')
    return lines.join('\n')
  }

  const findings = [...result.findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity])
  for (const finding of findings) {
    lines.push(formatFinding(finding), `  Fix: ${finding.recommendation}`, '')
  }

  return lines.join('\n')
}

function formatFinding(finding: Finding): string {
  return `${colorSeverity(finding.severity)} ${pc.bold(finding.title)}\n  ${pc.gray(finding.location)}\n  ${finding.message}`
}

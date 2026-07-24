import pc from 'picocolors'
import { summarize } from './scoring.js'
import type { AuditResult, ConfigDiagnostic, Finding, Severity } from './types.js'

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

export function formatTextReports(results: AuditResult[], diagnostics: ConfigDiagnostic[] = []): string {
  const findings = results.flatMap((result) => result.findings)
  const summary = summarize(findings)
  const suppressed = results.reduce((total, result) => total + result.suppressed, 0)
  const lines = [
    '',
    pc.bold('MCP Risk Audit'),
    `Targets: ${results.length}`,
    `Score: ${colorGrade(summary.grade)} (${summary.score}/100)`,
    `Findings: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`,
    ...(suppressed > 0 ? [`Suppressed: ${suppressed}`] : []),
    ...(diagnostics.length > 0 ? [`Diagnostics: ${diagnostics.length}`] : []),
    '',
  ]

  for (const result of results) {
    lines.push(pc.bold(`Target: ${result.target}`))
    if (result.findings.length === 0) {
      lines.push(pc.green('No risky MCP patterns found.'), '')
      continue
    }

    const sorted = [...result.findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity])
    for (const finding of sorted) lines.push(formatFinding(finding), `  Fix: ${finding.recommendation}`, '')
  }

  for (const diagnostic of diagnostics) {
    lines.push(pc.red(`${diagnostic.kind.toUpperCase()} ${diagnostic.message}`), '')
  }

  return lines.join('\n')
}

function formatFinding(finding: Finding): string {
  return `${colorSeverity(finding.severity)} ${pc.bold(finding.title)}\n  ${pc.gray(finding.location)}\n  ${finding.message}`
}

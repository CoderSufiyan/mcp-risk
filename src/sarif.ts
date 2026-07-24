import type { AuditResult, Finding, Severity } from './types.js'

type SarifLevel = 'error' | 'warning' | 'note'

function severityLevel(severity: Severity): SarifLevel {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'note'
}

function ruleFromFinding(finding: Finding) {
  return {
    id: finding.id,
    name: finding.id,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.message },
    help: { text: finding.recommendation },
    defaultConfiguration: { level: severityLevel(finding.severity) },
  }
}

function resultFromFinding(finding: Finding, target: string) {
  return {
    ruleId: finding.id,
    level: severityLevel(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: target },
        },
        logicalLocations: [{ name: finding.location }],
      },
    ],
    fixes: [
      {
        description: { text: finding.recommendation },
      },
    ],
  }
}

export function formatSarifReport(result: AuditResult): object {
  return formatSarifReports([result])
}

export function formatSarifReports(results: AuditResult[]): object {
  const rules = new Map<string, Finding>()
  for (const result of results) {
    for (const finding of result.findings) {
      if (!rules.has(finding.id)) rules.set(finding.id, finding)
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-risk',
            informationUri: 'https://github.com/CoderSufiyan/mcp-risk',
            rules: [...rules.values()].map(ruleFromFinding),
          },
        },
        results: results.flatMap((result) => result.findings.map((finding) => resultFromFinding(finding, result.target))),
      },
    ],
  }
}

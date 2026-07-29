import type { Finding, Severity } from './types.js'

type SarifResult = {
  target: string
  findings: Finding[]
  repository?: {
    url: string
    commit: string
  }
}

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

function targetIdentity(result: SarifResult) {
  if (!result.repository) return { target: result.target }
  return {
    target: result.target,
    repository: result.repository.url,
    commit: result.repository.commit,
  }
}

function artifactTarget(result: SarifResult): string {
  return result.repository ? `${result.repository.url}/tree/${result.repository.commit}` : result.target
}

export function formatSarifReport(result: SarifResult): object {
  return formatSarifReports([result])
}

export function formatSarifReports(results: SarifResult[]): object {
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
        properties: { targets: results.map(targetIdentity) },
        results: results.flatMap((result) => result.findings.map((finding) => resultFromFinding(finding, artifactTarget(result)))),
      },
    ],
  }
}

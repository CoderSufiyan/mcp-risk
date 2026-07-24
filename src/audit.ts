import { ConfigError, discoverAllConfigPaths, getServers, parseConfig, resolveTarget, validateConfig } from './parse.js'
import { isFindingAllowed, loadPolicyForFile } from './policy.js'
import { scanServer, scanTool } from './rules/config-rules.js'
import { summarize } from './scoring.js'
import type { AuditBatchResult, AuditOptions, AuditResult, ConfigDiagnostic, McpConfig, McpServerConfig, McpTool } from './types.js'
import type { DiscoveryOptions } from './parse.js'

export function auditConfig(config: McpConfig, target = '<inline>', options: AuditOptions = {}): AuditResult {
  const findings = []
  const validated = validateConfig(config, target)
  const servers = getServers(validated)

  for (const [name, value] of Object.entries(servers)) {
    findings.push(...scanServer(name, value as McpServerConfig))
  }

  if (Array.isArray(validated.tools)) {
    for (const tool of validated.tools) findings.push(...scanTool('root', tool as McpTool))
  }

  const included = options.includeLow ? findings : findings.filter((finding) => finding.severity !== 'low')
  const filtered = included.filter((finding) => !isFindingAllowed(finding, options.policy))

  return {
    target,
    findings: filtered,
    summary: summarize(filtered),
    suppressed: included.length - filtered.length,
  }
}

export function auditFile(target: string, options?: AuditOptions): AuditResult {
  const path = resolveTarget(target)
  return auditConfig(parseConfig(path), path, { ...options, policy: options?.policy ?? loadPolicyForFile(path) })
}

export function auditAll(target: string, options?: AuditOptions, discoveryOptions?: DiscoveryOptions): AuditBatchResult {
  const paths = discoverAllConfigPaths(target, discoveryOptions)
  if (paths.length === 0) throw new Error(`No MCP configs found in ${target} or supported user locations`)

  const results: AuditResult[] = []
  const diagnostics: ConfigDiagnostic[] = []
  for (const path of paths) {
    try {
      results.push(auditConfig(parseConfig(path), path, {
        ...options,
        policy: options?.policy ?? loadPolicyForFile(path),
      }))
    } catch (error) {
      if (!(error instanceof ConfigError)) throw error
      diagnostics.push({ target: path, kind: error.kind, message: error.message })
    }
  }

  return aggregateAuditResults(results, diagnostics)
}

export function aggregateAuditResults(results: AuditResult[], diagnostics: ConfigDiagnostic[] = []): AuditBatchResult {
  const findings = results.flatMap((result) => result.findings)
  return {
    results,
    summary: summarize(findings),
    suppressed: results.reduce((total, result) => total + result.suppressed, 0),
    diagnostics,
  }
}

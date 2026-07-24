import { getServers, parseConfig, resolveTarget } from './parse.js'
import { isFindingAllowed, loadPolicyForFile } from './policy.js'
import { scanServer, scanTool } from './rules/config-rules.js'
import { summarize } from './scoring.js'
import type { AuditOptions, AuditResult, McpConfig, McpServerConfig, McpTool } from './types.js'

export function auditConfig(config: McpConfig, target = '<inline>', options: AuditOptions = {}): AuditResult {
  const findings = []
  const servers = getServers(config)

  for (const [name, value] of Object.entries(servers)) {
    findings.push(...scanServer(name, value as McpServerConfig))
  }

  if (Array.isArray(config.tools)) {
    for (const tool of config.tools) findings.push(...scanTool('root', tool as McpTool))
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

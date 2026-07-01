import type { Finding, McpServerConfig, McpTool } from '../types.js'
import { DANGEROUS_ARG_PATTERNS, DANGEROUS_COMMANDS, INJECTION_PATTERNS, SENSITIVE_ENV_PATTERNS } from './patterns.js'

export function scanServer(name: string, server: McpServerConfig): Finding[] {
  const findings: Finding[] = []
  const location = `server:${name}`
  const command = String(server.command ?? '')
  const args = Array.isArray(server.args) ? server.args.map(String) : []
  const joinedArgs = args.join(' ')

  if (DANGEROUS_COMMANDS.includes(command)) {
    findings.push({
      id: 'dangerous-command',
      severity: 'high',
      title: 'Server starts through a general-purpose interpreter or shell',
      message: `"${name}" runs with "${command}", which can execute arbitrary code depending on arguments.`,
      location,
      recommendation: 'Prefer a pinned package binary or audited executable instead of a shell/interpreter entrypoint.',
    })
  }

  for (const check of DANGEROUS_ARG_PATTERNS) {
    if (check.pattern.test(joinedArgs)) {
      findings.push({
        id: check.id,
        severity: check.id === 'destructive-command' ? 'critical' : 'high',
        title: 'Server arguments contain risky execution pattern',
        message: `"${name}" ${check.message}: ${joinedArgs}`,
        location,
        recommendation: 'Review the command arguments manually and require explicit user confirmation before enabling this server.',
      })
    }
  }

  const env = server.env ?? {}
  for (const key of Object.keys(env)) {
    if (SENSITIVE_ENV_PATTERNS.some((pattern) => pattern.test(key))) {
      findings.push({
        id: 'sensitive-env',
        severity: 'medium',
        title: 'Server receives sensitive environment variable',
        message: `"${name}" receives "${key}". A malicious or compromised MCP server could exfiltrate it.`,
        location: `${location}.env.${key}`,
        recommendation: 'Scope tokens narrowly, avoid passing broad secrets, and use read-only credentials where possible.',
      })
    }
  }

  if (typeof server.url === 'string' && /^http:\/\//i.test(server.url)) {
    findings.push({
      id: 'insecure-transport',
      severity: 'medium',
      title: 'Server uses insecure HTTP transport',
      message: `"${name}" connects over plain HTTP: ${server.url}`,
      location: `${location}.url`,
      recommendation: 'Use HTTPS for remote MCP servers.',
    })
  }

  if (Array.isArray(server.tools)) {
    for (const tool of server.tools) findings.push(...scanTool(name, tool))
  }

  return findings
}

export function scanTool(serverName: string, tool: McpTool): Finding[] {
  const findings: Finding[] = []
  const name = String(tool.name ?? 'unknown')
  const description = String(tool.description ?? '')
  const location = `server:${serverName}.tool:${name}`

  for (const check of INJECTION_PATTERNS) {
    if (check.pattern.test(description)) {
      findings.push({
        id: `prompt-injection:${check.id}`,
        severity: 'high',
        title: 'Tool description contains prompt-injection language',
        message: `"${name}" includes ${check.label} wording in its description.`,
        location,
        recommendation: 'Remove instruction-like text from tool descriptions. Descriptions should explain capability, not tell the agent how to behave.',
      })
    }
  }

  const lower = `${name} ${description}`.toLowerCase()
  if (/\b(shell|terminal|exec|execute|command|bash|powershell)\b/.test(lower)) {
    findings.push({
      id: 'tool-shell-capability',
      severity: 'high',
      title: 'Tool appears able to execute commands',
      message: `"${name}" looks like it can run shell or terminal commands.`,
      location,
      recommendation: 'Require user confirmation and restrict allowed commands before enabling this tool.',
    })
  }

  if (/\b(read|write|delete|modify|edit)\b.*\b(file|filesystem|directory|path)\b/.test(lower)) {
    findings.push({
      id: 'tool-filesystem-capability',
      severity: 'medium',
      title: 'Tool appears able to access the filesystem',
      message: `"${name}" looks like it can read or modify files.`,
      location,
      recommendation: 'Restrict filesystem access to the project directory and block writes unless needed.',
    })
  }

  if (/\b(fetch|http|request|download|browser|scrape|crawl|network)\b/.test(lower)) {
    findings.push({
      id: 'tool-network-capability',
      severity: 'medium',
      title: 'Tool appears able to access the network',
      message: `"${name}" looks like it can make network requests or browse remote content.`,
      location,
      recommendation: 'Review allowed domains and treat remote content as untrusted instructions.',
    })
  }

  return findings
}

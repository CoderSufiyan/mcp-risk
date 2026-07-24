import { readFileSync, statSync } from 'node:fs'
import { dirname, join, parse, resolve } from 'node:path'
import type { Finding, RiskPolicy, RiskPolicyAllowEntry } from './types.js'

const POLICY_FILE = '.mcp-risk.json'

export function loadPolicyForFile(configPath: string): RiskPolicy | undefined {
  let directory = resolve(dirname(configPath))

  while (true) {
    const policyPath = join(directory, POLICY_FILE)
    try {
      if (statSync(policyPath).isFile()) return parsePolicy(readFileSync(policyPath, 'utf8'), policyPath)
    } catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error
    }

    const parent = dirname(directory)
    if (parent === directory) return undefined
    directory = parent
  }
}

export function isFindingAllowed(finding: Finding, policy: RiskPolicy | undefined): boolean {
  if (!policy) return false

  return policy.allow.some((entry) => matchesEntry(entry, finding.location, finding.id))
}

function parsePolicy(raw: string, policyPath: string): RiskPolicy {
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw new Error(`Invalid JSON in policy file ${policyPath}`)
  }

  if (!value || typeof value !== 'object' || !Array.isArray((value as { allow?: unknown }).allow)) {
    throw new Error(`Policy file ${policyPath} must contain an "allow" array`)
  }

  const allow = (value as { allow: unknown[] }).allow.map((entry, index) => parseAllowEntry(entry, policyPath, index))
  return { allow }
}

function parseAllowEntry(entry: unknown, policyPath: string, index: number): RiskPolicyAllowEntry {
  if (!entry || typeof entry !== 'object') {
    throw new Error(`Policy file ${policyPath} has an invalid allow entry at index ${index}`)
  }

  const { server, finding } = entry as { server?: unknown; finding?: unknown }
  if ((server !== undefined && typeof server !== 'string') || (finding !== undefined && typeof finding !== 'string') || (!server && !finding)) {
    throw new Error(`Policy file ${policyPath} has an invalid allow entry at index ${index}`)
  }

  return { server, finding }
}

function matchesEntry(entry: RiskPolicyAllowEntry, location: string, findingId: string): boolean {
  return (!entry.server || locationMatchesServer(location, entry.server)) && (!entry.finding || entry.finding === findingId)
}

function locationMatchesServer(location: string, server: string): boolean {
  const prefix = `server:${server}`
  return location === prefix || location.startsWith(`${prefix}.env.`) || location.startsWith(`${prefix}.tool:`)
}

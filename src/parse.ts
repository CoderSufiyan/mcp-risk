import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import YAML from 'yaml'
import type { McpConfig } from './types.js'

const CONFIG_CANDIDATES = [
  'mcp.json',
  '.mcp.json',
  'mcp.config.json',
  'mcp.yaml',
  'mcp.yml',
  '.cursor/mcp.json',
  '.claude/mcp.json',
]

export function resolveTarget(target: string): string {
  const stat = statSync(target)
  if (stat.isFile()) return target

  for (const candidate of CONFIG_CANDIDATES) {
    const fullPath = join(target, candidate)
    try {
      if (statSync(fullPath).isFile()) return fullPath
    } catch {
      // keep looking
    }
  }

  throw new Error(`No MCP config found in ${target}`)
}

export function parseConfig(path: string): McpConfig {
  const raw = readFileSync(path, 'utf8')
  if (path.endsWith('.yaml') || path.endsWith('.yml')) {
    return YAML.parse(raw) as McpConfig
  }
  return JSON.parse(raw) as McpConfig
}

export function getServers(config: McpConfig): Record<string, unknown> {
  return config.mcpServers ?? config.servers ?? {}
}

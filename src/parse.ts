import { readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import YAML from 'yaml'
import type { McpConfig } from './types.js'

const PROJECT_CONFIG_CANDIDATES = [
  'mcp.json',
  '.mcp.json',
  'mcp.config.json',
  'mcp.yaml',
  'mcp.yml',
  '.cursor/mcp.json',
  '.claude/mcp.json',
  '.vscode/mcp.json',
  '.windsurf/mcp.json',
  '.continue/config.yaml',
  '.continue/config.yml',
  '.cline/mcp.json',
]

export type DiscoveryOptions = {
  home?: string
  platform?: NodeJS.Platform
  appData?: string
}

export function resolveTarget(target: string): string {
  const stat = statSync(target)
  if (stat.isFile()) return target

  const [path] = discoverProjectConfigPaths(target)
  if (path) return path

  throw new Error(`No MCP config found in ${target}`)
}

export function discoverProjectConfigPaths(directory: string): string[] {
  return PROJECT_CONFIG_CANDIDATES
    .map((candidate) => join(directory, candidate))
    .filter(isFile)
}

export function discoverUserConfigPaths(options: DiscoveryOptions = {}): string[] {
  const home = options.home ?? homedir()
  const platform = options.platform ?? process.platform
  const appData = options.appData ?? process.env.APPDATA ?? join(home, 'AppData', 'Roaming')
  const candidates = [
    join(home, '.cursor', 'mcp.json'),
    join(home, '.claude.json'),
    join(home, '.continue', 'config.json'),
    join(home, '.continue', 'config.yaml'),
    join(home, '.continue', 'config.yml'),
    join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  ]

  if (platform === 'darwin') {
    candidates.push(
      join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'),
      join(home, 'Library', 'Application Support', 'Windsurf', 'User', 'mcp.json'),
      join(home, 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    )
  } else if (platform === 'win32') {
    candidates.push(
      join(appData, 'Claude', 'claude_desktop_config.json'),
      join(appData, 'Code', 'User', 'mcp.json'),
      join(appData, 'Windsurf', 'User', 'mcp.json'),
      join(appData, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    )
  } else {
    candidates.push(
      join(home, '.config', 'Claude', 'claude_desktop_config.json'),
      join(home, '.config', 'Code', 'User', 'mcp.json'),
      join(home, '.config', 'Windsurf', 'User', 'mcp.json'),
      join(home, '.config', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    )
  }

  return candidates.filter(isFile)
}

export function discoverAllConfigPaths(target: string, options: DiscoveryOptions = {}): string[] {
  if (statSync(target).isFile()) return [target]

  const paths = [
    ...discoverProjectConfigPaths(target),
    ...discoverUserConfigPaths(options),
  ]
  return [...new Map(paths.map((path) => [resolve(path), path])).values()]
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

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile()
  } catch {
    return false
  }
}

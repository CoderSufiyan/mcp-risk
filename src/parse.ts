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

export class ConfigError extends Error {
  constructor(
    readonly kind: 'parse' | 'validation',
    readonly path: string,
    message: string,
  ) {
    super(message)
    this.name = 'ConfigError'
  }
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
    try {
      return validateConfig(YAML.parse(raw), path)
    } catch (error) {
      if (error instanceof ConfigError) throw error
      throw new ConfigError('parse', path, `Invalid YAML in ${path}${yamlLocation(error)}: ${errorMessage(error)}`)
    }
  }

  try {
    return validateConfig(JSON.parse(raw), path)
  } catch (error) {
    if (error instanceof ConfigError) throw error
    const position = jsonPosition(raw, errorMessage(error))
    const location = position === undefined ? '' : jsonLocation(raw, position)
    throw new ConfigError('parse', path, `Invalid JSON in ${path}${location}: ${errorMessage(error)}`)
  }
}

export function validateConfig(config: unknown, path = '<inline>'): McpConfig {
  if (!isRecord(config)) throw new ConfigError('validation', path, `${path}: MCP config must be an object`)

  const hasServers = config.mcpServers !== undefined || config.servers !== undefined
  const hasTools = config.tools !== undefined
  if (!hasServers && !hasTools) {
    throw new ConfigError('validation', path, `${path}: no recognized MCP servers or tools found`)
  }

  if (config.mcpServers !== undefined) validateServers(config.mcpServers, path, 'mcpServers')
  if (config.servers !== undefined) validateServers(config.servers, path, 'servers')
  if (config.tools !== undefined) validateTools(config.tools, path, 'tools')

  const serverCount = [config.mcpServers, config.servers]
    .filter(isRecord)
    .reduce((count, servers) => count + Object.keys(servers).length, 0)
  const toolCount = Array.isArray(config.tools) ? config.tools.length : 0
  if (serverCount === 0 && toolCount === 0) {
    throw new ConfigError('validation', path, `${path}: no recognized MCP servers or tools found`)
  }

  return config as McpConfig
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

function validateServers(value: unknown, path: string, key: string): void {
  if (!isRecord(value)) throw new ConfigError('validation', path, `${path}: "${key}" must be an object keyed by server name`)
  for (const [name, server] of Object.entries(value)) {
    if (!isRecord(server)) throw new ConfigError('validation', path, `${path}: server "${name}" must be an object`)
    if (server.command !== undefined && typeof server.command !== 'string') {
      throw new ConfigError('validation', path, `${path}: server "${name}" command must be a string`)
    }
    if (server.url !== undefined && typeof server.url !== 'string') {
      throw new ConfigError('validation', path, `${path}: server "${name}" url must be a string`)
    }
    if (server.args !== undefined && !Array.isArray(server.args)) {
      throw new ConfigError('validation', path, `${path}: server "${name}" args must be an array`)
    }
    if (server.tools !== undefined) validateTools(server.tools, path, `server "${name}" tools`)
  }
}

function validateTools(value: unknown, path: string, key: string): void {
  if (!Array.isArray(value)) throw new ConfigError('validation', path, `${path}: "${key}" must be an array`)
  if (value.some((tool) => !isRecord(tool))) {
    throw new ConfigError('validation', path, `${path}: "${key}" must contain tool objects`)
  }
}

function jsonLocation(raw: string, position: number): string {
  const before = raw.slice(0, position)
  const line = before.split('\n').length
  const column = before.length - before.lastIndexOf('\n')
  return ` at line ${line}, column ${column}`
}

function yamlLocation(error: unknown): string {
  const linePos = (error as { linePos?: Array<{ line: number; col: number }> }).linePos?.[0]
  return linePos ? ` at line ${linePos.line}, column ${linePos.col}` : ''
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function jsonPosition(raw: string, message: string): number | undefined {
  const position = message.match(/position (\d+)/i)?.[1]
  if (position) return Number(position)

  const token = message.match(/Unexpected token '([^']+)'/i)?.[1]
  if (token) return raw.lastIndexOf(token)
  if (/Unexpected end/i.test(message)) return raw.length
  return undefined
}

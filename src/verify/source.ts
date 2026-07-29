import { lstat, readFile, readdir } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'
import YAML from 'yaml'
import { auditConfig } from '../audit.js'
import { ConfigError } from '../parse.js'
import type { Finding } from '../types.js'

const sourceExtensions = new Set(['.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx'])
const configPaths = [
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
  '.continue/config.json',
  '.cline/mcp.json',
  '.claude.json',
  '.codeium/windsurf/mcp_config.json',
  'claude_desktop_config.json',
  'cline_mcp_settings.json',
]
const maximumSourceBytes = 1024 * 1024

const sourceRules: Array<{
  id: string
  severity: Finding['severity']
  title: string
  pattern: RegExp
  recommendation: string
}> = [
  {
    id: 'shell-execution',
    severity: 'critical',
    title: 'Source can execute shell commands',
    pattern: /(?:node:)?child_process|\b(?:exec|execFile|execSync|spawn|spawnSync)\s*\(|\bBun\.spawn\s*\(|\bnew\s+Deno\.Command\s*\(/,
    recommendation: 'Remove shell execution or constrain commands and arguments to a strict allowlist.',
  },
  {
    id: 'network-access',
    severity: 'high',
    title: 'Source performs network access',
    pattern: /\bfetch\s*\(|\baxios(?:\.|\s*\()|(?:node:)?(?:https?|net|tls)['"]|\b(?:https?|net|tls|undici)\.(?:connect|get|request)\s*\(|\bnew\s+WebSocket\s*\(/,
    recommendation: 'Restrict outbound destinations and document why network access is required.',
  },
  {
    id: 'filesystem-write',
    severity: 'high',
    title: 'Source accesses the filesystem',
    pattern: /(?:node:)?fs(?:\/promises)?['"]|\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rm|rmSync|unlink|unlinkSync|rename|renameSync)\s*\(/,
    recommendation: 'Constrain filesystem access to explicit application-owned paths.',
  },
  {
    id: 'hardcoded-secret',
    severity: 'critical',
    title: 'Source contains a hardcoded secret',
    pattern: /(?:api[_-]?key|secret|token|password)\s*(?::\s*[A-Za-z_$][\w$<>[\]| ]*\s*)?(?:=|:)\s*['"][^'"\s]{8,}['"]|\b(?:sk[-_]|ghp_|github_pat_)[A-Za-z0-9_-]{8,}/i,
    recommendation: 'Remove embedded credentials, rotate them, and load secrets from protected runtime configuration.',
  },
]

export type SourceScanResult = {
  findings: Finding[]
  scannedFiles: number
}

export async function scanPackageDirectory(root: string): Promise<SourceScanResult> {
  const findings: Finding[] = []
  let scannedFiles = 0

  for (const path of await walkFiles(root)) {
    const packagePath = relative(root, path).replaceAll('\\', '/')
    const name = packagePath.split('/').at(-1) ?? packagePath
    if (sourceExtensions.has(extname(name).toLowerCase())) {
      const stat = await lstat(path)
      if (stat.size > maximumSourceBytes) {
        findings.push({
          id: 'source-file-too-large',
          severity: 'high',
          title: 'Source file exceeds the static scan limit',
          message: `"${packagePath}" is ${stat.size} bytes and was not scanned.`,
          location: packagePath,
          recommendation: 'Review this source file manually or reduce it below the static scan limit.',
        })
        continue
      }
      const source = await readFile(path, 'utf8')
      scannedFiles += 1
      for (const rule of sourceRules) {
        const match = rule.pattern.exec(source)
        if (!match) continue
        const line = source.slice(0, match.index).split('\n').length
        findings.push({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          message: `Static source pattern matched in "${packagePath}".`,
          location: `${packagePath}:${line}`,
          recommendation: rule.recommendation,
        })
      }
    }

    if (isConfigPath(packagePath)) {
      scannedFiles += 1
      try {
        const raw = await readFile(path, 'utf8')
        const config = extname(path).toLowerCase() === '.json' ? JSON.parse(raw) : YAML.parse(raw)
        if (!isRecord(config)) continue
        for (const key of ['mcpServers', 'servers', 'tools']) {
          if (config[key] === undefined) continue
          try {
            findings.push(...auditConfig({ [key]: config[key] }, packagePath).findings.map((finding) => ({
              ...finding,
              location: `${packagePath}:${finding.location}`,
            })))
          } catch (error) {
            if (!(error instanceof ConfigError)) throw error
          }
        }
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error
      }
    }

    if (name === 'package.json') {
      scannedFiles += 1
      try {
        const manifest = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
        for (const key of ['mcpServers', 'servers', 'tools']) {
          if (manifest[key] === undefined) continue
          try {
            findings.push(...auditConfig({ [key]: manifest[key] }, packagePath).findings.map((finding) => ({
              ...finding,
              location: `${packagePath}:${finding.location}`,
            })))
          } catch (error) {
            if (!(error instanceof ConfigError)) throw error
          }
        }
      } catch (error) {
        if (error instanceof SyntaxError) continue
        throw error
      }
    }
  }

  return { findings, scannedFiles }
}

function isConfigPath(packagePath: string): boolean {
  const normalized = packagePath.replace(/^\.\//, '').replace(/^package\//, '')
  return configPaths.some((candidate) => normalized === candidate || normalized.endsWith(`/${candidate}`))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = []
  const pending = [root]
  while (pending.length > 0) {
    const directory = pending.pop()!
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) pending.push(path)
      else if (entry.isFile()) files.push(path)
    }
  }
  return files.sort()
}

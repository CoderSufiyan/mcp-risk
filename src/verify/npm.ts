import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, mkdtemp, open, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Parser, x as extractTar } from 'tar'
import { auditConfig } from '../audit.js'
import { ConfigError } from '../parse.js'
import { summarize } from '../scoring.js'
import type { Finding, McpConfig, NpmVerificationResult } from '../types.js'
import { scanPackageDirectory } from './source.js'

const installScriptNames = ['preinstall', 'install', 'postinstall']

export type NpmVerifyOptions = {
  registry?: string
  fetch?: FetchLike
  now?: Date
  timeoutMs?: number
  temporaryDirectory?: string
  maxTarballBytes?: number
  maxExtractedBytes?: number
  maxExtractedFiles?: number
}

type FetchLike = (url: string, init?: { signal?: AbortSignal }) => Promise<{
  ok: boolean
  status: number
  json?(): Promise<unknown>
  body?: ReadableStream<Uint8Array> | null
}>

export async function verifyNpmPackage(target: string, options: NpmVerifyOptions = {}): Promise<NpmVerificationResult> {
  const { name, version } = parseNpmTarget(target)
  const registry = (options.registry ?? 'https://registry.npmjs.org').replace(/\/$/, '')
  const fetcher: FetchLike = options.fetch ?? ((url, init) => fetch(url, init))
  const response = await fetcher(`${registry}/${encodeURIComponent(name)}`, {
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
  })
  if (!response.ok) throw new Error(`npm registry returned ${response.status} for ${name}`)
  if (!response.json) throw new Error(`npm registry returned invalid metadata for ${name}`)

  const document = await response.json()
  if (!isRecord(document) || !isRecord(document.versions)) throw new Error(`npm registry returned invalid metadata for ${name}`)
  const packageVersion = document.versions[version]
  if (!isRecord(packageVersion)) throw new Error(`npm package ${name}@${version} was not found`)

  const maintainers = normalizeMaintainers(packageVersion.maintainers ?? document.maintainers)
  const dependencies = normalizeDependencies(packageVersion)
  const tarball = isRecord(packageVersion.dist) ? stringValue(packageVersion.dist.tarball) : undefined
  if (!tarball) throw new Error(`npm package ${name}@${version} does not declare a tarball URL`)
  const integrity = await inspectTarball(tarball, fetcher, options)
  const publishedAt = stringValue(isRecord(document.time) ? document.time[version] : undefined)
  const findings = [...scanPackageMetadata(name, version, packageVersion, maintainers), ...integrity.findings]
  for (const config of metadataConfigs(packageVersion)) {
    try {
      findings.push(...auditConfig(config, target).findings)
    } catch (error) {
      // npm metadata keys such as "tools" are not necessarily MCP declarations.
      if (!(error instanceof ConfigError)) throw error
    }
  }

  return {
    target,
    kind: 'npm',
    package: { name, version },
    metadata: {
      publishedAt,
      publishAgeDays: dateAgeDays(publishedAt, options.now ?? new Date()),
      createdAt: stringValue(isRecord(document.time) ? document.time.created : undefined),
      maintainers,
      dependencyCount: dependencies.length,
      dependencies,
      installScripts: lifecycleScripts(packageVersion.scripts),
      license: stringValue(packageVersion.license),
      repository: repositoryUrl(packageVersion.repository),
      tarball,
      tarballDigest: { algorithm: 'sha256', value: integrity.digest },
      tarballSizeBytes: integrity.sizeBytes,
      sourceFileCount: integrity.scannedFiles,
    },
    findings,
    summary: summarize(findings),
  }
}

async function inspectTarball(tarball: string, fetcher: FetchLike, options: NpmVerifyOptions): Promise<{ digest: string; sizeBytes: number; findings: Finding[]; scannedFiles: number }> {
  const directory = await mkdtemp(join(options.temporaryDirectory ?? tmpdir(), 'mcp-risk-'))
  const path = join(directory, 'package.tgz')
  let file: Awaited<ReturnType<typeof open>> | undefined
  try {
    const response = await fetcher(tarball, { signal: AbortSignal.timeout(options.timeoutMs ?? 10_000) })
    if (!response.ok) throw new Error(`npm tarball download returned ${response.status}`)
    if (!response.body) throw new Error('npm tarball download returned an invalid response')

    const maximum = options.maxTarballBytes ?? 100 * 1024 * 1024
    if (maximum <= 0) throw new Error('Maximum tarball size must be greater than zero')
    const hash = createHash('sha256')
    let sizeBytes = 0
    file = await open(path, 'w')
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      const bytes = Buffer.from(chunk)
      sizeBytes += bytes.byteLength
      if (sizeBytes > maximum) throw new Error(`npm tarball exceeds the ${maximum}-byte size limit`)
      hash.update(bytes)
      let offset = 0
      while (offset < bytes.byteLength) {
        const { bytesWritten } = await file.write(bytes, offset, bytes.byteLength - offset, null)
        offset += bytesWritten
      }
    }
    await file.close()
    file = undefined

    const extracted = join(directory, 'extracted')
    await mkdir(extracted)
    const maximumExtractedBytes = options.maxExtractedBytes ?? 250 * 1024 * 1024
    const maximumExtractedFiles = options.maxExtractedFiles ?? 10_000
    if (maximumExtractedBytes <= 0 || maximumExtractedFiles <= 0) throw new Error('Package extraction limits must be greater than zero')
    await inspectArchiveEntries(path, maximumExtractedBytes, maximumExtractedFiles)

    await extractTar({
      file: path,
      cwd: extracted,
      gzip: true,
      preservePaths: false,
      strict: true,
      filter: (_path, entry) => {
        const type = 'type' in entry ? entry.type : entry.isDirectory() ? 'Directory' : entry.isFile() ? 'File' : 'Other'
        if (!['File', 'OldFile', 'Directory'].includes(type)) return false
        return true
      },
    })
    const source = await scanPackageDirectory(extracted)
    return {
      digest: hash.digest('hex'),
      sizeBytes,
      findings: source.findings,
      scannedFiles: source.scannedFiles,
    }
  } finally {
    try {
      await file?.close()
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  }
}

async function inspectArchiveEntries(
  path: string,
  maximumBytes: number,
  maximumEntries: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let bytes = 0
    let entries = 0
    const input = createReadStream(path)
    const parser = new Parser({
      gzip: true,
      strict: true,
      onReadEntry: (entry) => {
        entries += 1
        if (['File', 'OldFile'].includes(entry.type)) bytes += entry.size
        if (bytes > maximumBytes) parser.abort(new Error(`npm package exceeds the ${maximumBytes}-byte extracted size limit`))
        if (entries > maximumEntries) parser.abort(new Error(`npm package exceeds the ${maximumEntries}-entry extraction limit`))
        entry.resume()
      },
    })
    input.on('error', reject)
    parser.on('error', (error) => {
      input.destroy()
      reject(error)
    })
    parser.on('end', resolve)
    input.on('data', (chunk) => parser.write(chunk))
    input.on('end', () => parser.end())
  })
}

export function parseNpmTarget(target: string): { name: string; version: string } {
  if (!target.startsWith('npm:')) throw new Error('npm verification target must start with "npm:"')
  const specifier = target.slice('npm:'.length)
  const separator = specifier.lastIndexOf('@')
  if (separator <= 0 || separator === specifier.length - 1) {
    throw new Error('npm verification requires an exact version, for example npm:package@1.2.3')
  }

  const name = specifier.slice(0, separator)
  const version = specifier.slice(separator + 1)
  if (!name || !/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error('npm verification requires an exact package version')
  }
  return { name, version }
}

function scanPackageMetadata(name: string, version: string, metadata: Record<string, unknown>, maintainers: string[]): Finding[] {
  const findings: Finding[] = []
  for (const script of lifecycleScripts(metadata.scripts)) {
    findings.push({
      id: 'npm-install-script',
      severity: 'high',
      title: 'Package defines an npm install lifecycle script',
      message: `"${name}@${version}" defines "${script}", which executes during package installation.`,
      location: `package:${name}.scripts.${script}`,
      recommendation: 'Review the lifecycle script source before installation or install with scripts disabled.',
    })
  }

  if (maintainers.length === 0) {
    findings.push({
      id: 'npm-no-maintainers',
      severity: 'medium',
      title: 'Package has no maintainer metadata',
      message: `"${name}@${version}" does not declare any maintainers in its version metadata.`,
      location: `package:${name}.maintainers`,
      recommendation: 'Confirm package ownership and provenance before installation.',
    })
  }
  return findings
}

function metadataConfigs(metadata: Record<string, unknown>): McpConfig[] {
  const configs: McpConfig[] = []
  if (metadata.mcpServers !== undefined) configs.push({ mcpServers: metadata.mcpServers as McpConfig['mcpServers'] })
  if (metadata.servers !== undefined) configs.push({ servers: metadata.servers as McpConfig['servers'] })
  if (metadata.tools !== undefined) configs.push({ tools: metadata.tools as McpConfig['tools'] })
  return configs
}

function normalizeDependencies(metadata: Record<string, unknown>): NpmVerificationResult['metadata']['dependencies'] {
  const dependencies = new Map<string, NpmVerificationResult['metadata']['dependencies'][number]>()
  addDependencies(dependencies, metadata.dependencies, 'dependency')
  addDependencies(dependencies, metadata.peerDependencies, 'peer')
  addDependencies(dependencies, metadata.optionalDependencies, 'optional')

  const bundled = metadata.bundledDependencies ?? metadata.bundleDependencies
  if (Array.isArray(bundled)) {
    for (const name of bundled) {
      if (typeof name !== 'string') continue
      const existing = dependencies.get(name)
      dependencies.set(name, { name, ...(existing?.specifier ? { specifier: existing.specifier } : {}), type: 'bundled' })
    }
  }
  return [...dependencies.values()].sort((left, right) => left.name.localeCompare(right.name))
}

function addDependencies(
  target: Map<string, NpmVerificationResult['metadata']['dependencies'][number]>,
  value: unknown,
  type: NpmVerificationResult['metadata']['dependencies'][number]['type'],
): void {
  if (!isRecord(value)) return
  for (const [name, specifier] of Object.entries(value)) {
    if (typeof specifier === 'string') target.set(name, { name, specifier, type })
  }
}

function lifecycleScripts(value: unknown): string[] {
  if (!isRecord(value)) return []
  return installScriptNames.filter((name) => typeof value[name] === 'string')
}

function normalizeMaintainers(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((maintainer) => {
    if (typeof maintainer === 'string') return [maintainer]
    if (!isRecord(maintainer)) return []
    const name = stringValue(maintainer.name)
    const email = stringValue(maintainer.email)
    return name || email ? [`${name ?? ''}${name && email ? ' ' : ''}${email ? `<${email}>` : ''}`] : []
  })
}

function repositoryUrl(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  return isRecord(value) ? stringValue(value.url) : undefined
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function dateAgeDays(value: string | undefined, now: Date): number | undefined {
  if (!value) return undefined
  const published = Date.parse(value)
  if (Number.isNaN(published)) return undefined
  return Math.max(0, Math.floor((now.getTime() - published) / 86_400_000))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

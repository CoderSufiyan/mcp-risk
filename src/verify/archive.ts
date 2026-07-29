import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, mkdtemp, open, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Parser, x as extractTar } from 'tar'
import type { Finding } from '../types.js'
import { scanPackageDirectory } from './source.js'
import type { SourceScanResult } from './source.js'

export type FetchLike = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal }) => Promise<{
  ok: boolean
  status: number
  json?(): Promise<unknown>
  body?: ReadableStream<Uint8Array> | null
}>

export type ArchiveOptions = {
  timeoutMs?: number
  temporaryDirectory?: string
  maxTarballBytes?: number
  maxExtractedBytes?: number
  maxExtractedFiles?: number
}

export type ArchiveInspection = {
  digest: string
  sizeBytes: number
  findings: Finding[]
  scannedFiles: number
  manifests: SourceScanResult['manifests']
}

export async function inspectArchive(
  url: string,
  fetcher: FetchLike,
  options: ArchiveOptions,
  headers: Record<string, string> = {},
  label = 'archive',
): Promise<ArchiveInspection> {
  const directory = await mkdtemp(join(options.temporaryDirectory ?? tmpdir(), 'mcp-risk-'))
  const path = join(directory, 'archive.tgz')
  let file: Awaited<ReturnType<typeof open>> | undefined
  try {
    const response = await fetcher(url, { headers, signal: AbortSignal.timeout(options.timeoutMs ?? 10_000) })
    if (!response.ok) throw new Error(`${label} download returned ${response.status}`)
    if (!response.body) throw new Error(`${label} download returned an invalid response`)

    const maximum = options.maxTarballBytes ?? 100 * 1024 * 1024
    if (maximum <= 0) throw new Error('Maximum archive size must be greater than zero')
    const hash = createHash('sha256')
    let sizeBytes = 0
    file = await open(path, 'w')
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      const bytes = Buffer.from(chunk)
      sizeBytes += bytes.byteLength
      if (sizeBytes > maximum) throw new Error(`${label} exceeds the ${maximum}-byte size limit`)
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
    if (maximumExtractedBytes <= 0 || maximumExtractedFiles <= 0) throw new Error('Archive extraction limits must be greater than zero')
    await inspectArchiveEntries(path, maximumExtractedBytes, maximumExtractedFiles, label)

    await extractTar({
      file: path,
      cwd: extracted,
      gzip: true,
      preservePaths: false,
      strict: true,
      filter: (_path, entry) => {
        const type = 'type' in entry ? entry.type : entry.isDirectory() ? 'Directory' : entry.isFile() ? 'File' : 'Other'
        return ['File', 'OldFile', 'Directory'].includes(type)
      },
    })
    const source = await scanPackageDirectory(extracted)
    return {
      digest: hash.digest('hex'),
      sizeBytes,
      findings: source.findings,
      scannedFiles: source.scannedFiles,
      manifests: source.manifests,
    }
  } finally {
    try {
      await file?.close()
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  }
}

async function inspectArchiveEntries(path: string, maximumBytes: number, maximumEntries: number, label: string): Promise<void> {
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
        if (bytes > maximumBytes) parser.abort(new Error(`${label} exceeds the ${maximumBytes}-byte extracted size limit`))
        if (entries > maximumEntries) parser.abort(new Error(`${label} exceeds the ${maximumEntries}-entry extraction limit`))
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

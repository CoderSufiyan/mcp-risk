import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { c as createTar } from 'tar'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { parseNpmTarget, verifyNpmPackage } from '../src/verify/npm.js'
import { formatVerificationMarkdown } from '../src/verify/report.js'
import { scanPackageDirectory } from '../src/verify/source.js'

const corpusRoot = join(process.cwd(), 'fixtures', 'security-corpus', 'npm')
const fixtureTarballs = new Map<string, Buffer>()
let archiveDirectory: string

beforeAll(async () => {
  archiveDirectory = await mkdtemp(join(tmpdir(), 'mcp-risk-archives-'))
  for (const fixture of ['safe-package', 'risky-package']) {
    const archive = join(archiveDirectory, `${fixture}.tgz`)
    await createTar({ cwd: join(corpusRoot, fixture), file: archive, gzip: true }, ['.'])
    fixtureTarballs.set(fixture, await readFile(archive))
  }
})

afterAll(async () => {
  await rm(archiveDirectory, { recursive: true, force: true })
})

describe('npm package verification', () => {
  it('parses scoped and unscoped exact package targets', () => {
    expect(parseNpmTarget('npm:example@1.2.3')).toEqual({ name: 'example', version: '1.2.3' })
    expect(parseNpmTarget('npm:@scope/example@1.2.3')).toEqual({ name: '@scope/example', version: '1.2.3' })
    expect(() => parseNpmTarget('npm:example@latest')).toThrow('exact package version')
  })

  it('verifies safe package metadata without executing it', async () => {
    const packageJson = fixturePackage('safe-package')
    const result = await verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', {
      fetch: registryFetch(packageJson),
      now: new Date('2026-01-12T00:00:00.000Z'),
    })

    expect(result.summary.grade).toBe('A')
    const tarball = fixtureTarballs.get('safe-package')!
    expect(result.metadata).toMatchObject({
      dependencyCount: 0,
      dependencies: [],
      installScripts: [],
      maintainers: ['Fixture Maintainer <fixture@example.test>'],
      publishAgeDays: 10,
      tarballDigest: {
        algorithm: 'sha256',
        value: createHash('sha256').update(tarball).digest('hex'),
      },
      tarballSizeBytes: tarball.byteLength,
      sourceFileCount: 3,
    })
    expect(result.findings).toHaveLength(0)
  })

  it('reports install scripts and declared MCP tool risks', async () => {
    const packageJson = fixturePackage('risky-package')
    const config = JSON.parse(readFileSync(join(corpusRoot, 'risky-package', 'mcp.json'), 'utf8'))
    const result = await verifyNpmPackage('npm:fixture-risky-mcp@1.0.0', {
      fetch: registryFetch({ ...packageJson, ...config }),
    })

    expect(result.findings.map((finding) => finding.id)).toContain('npm-install-script')
    expect(result.findings.filter((finding) => finding.id.endsWith('install-script'))).toHaveLength(1)
    expect(result.findings.map((finding) => finding.id)).toContain('dangerous-command')
    expect(result.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      'filesystem-write',
      'hardcoded-secret',
      'network-access',
      'shell-execution',
    ]))
    expect(result.findings.find((finding) => finding.id === 'shell-execution')?.location).toMatch(/src\/server\.js:\d+$/)
    expect(result.metadata.installScripts).toEqual(['postinstall'])
    const markdown = formatVerificationMarkdown(result)
    expect(markdown).toContain(result.metadata.tarballDigest!.value)
    expect(markdown).toContain('Static verification does not execute the package')
    expect(JSON.parse(JSON.stringify(result)).metadata.tarballDigest).toEqual(result.metadata.tarballDigest)
  })

  it('keeps tarball install-script findings when registry metadata omits them', async () => {
    const packageJson = fixturePackage('risky-package')
    delete packageJson.scripts
    const result = await verifyNpmPackage('npm:fixture-risky-mcp@1.0.0', {
      fetch: registryFetch(packageJson),
    })
    expect(result.findings).toContainEqual(expect.objectContaining({ id: 'package-install-script' }))
  })

  it('ignores unrelated malformed metadata fields and uses root maintainers', async () => {
    const packageJson = fixturePackage('safe-package')
    delete packageJson.maintainers
    packageJson.tools = ['build-tool']
    const fetch = registryFetch(packageJson, { maintainers: [{ name: 'Registry Maintainer' }] })

    const result = await verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', { fetch })
    expect(result.metadata.maintainers).toEqual(['Registry Maintainer'])
    expect(result.findings).toHaveLength(0)
  })

  it('audits valid MCP roots independently and inventories dependency types', async () => {
    const packageJson = fixturePackage('safe-package')
    packageJson.mcpServers = 'not-an-object'
    packageJson.tools = [{ name: 'run_shell', description: 'Execute arbitrary shell commands' }]
    packageJson.dependencies = { regular: '^1.0.0', shared: '^1.0.0' }
    packageJson.optionalDependencies = { optional: '2.0.0', shared: '2.0.0' }
    packageJson.peerDependencies = { peer: '^3.0.0' }
    packageJson.bundledDependencies = ['bundled', 'regular']

    const result = await verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', { fetch: registryFetch(packageJson) })
    expect(result.findings.map((finding) => finding.id)).toContain('tool-shell-capability')
    expect(result.metadata.dependencies).toEqual([
      { name: 'bundled', type: 'bundled' },
      { name: 'optional', specifier: '2.0.0', type: 'optional' },
      { name: 'peer', specifier: '^3.0.0', type: 'peer' },
      { name: 'regular', specifier: '^1.0.0', type: 'bundled' },
      { name: 'shared', specifier: '2.0.0', type: 'optional' },
    ])
  })

  it('cleans up temporary tarball files after success and failure', async () => {
    const temporaryDirectory = await mkdtemp(join(tmpdir(), 'mcp-risk-test-'))
    try {
      const packageJson = fixturePackage('safe-package')
      await verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', {
        fetch: registryFetch(packageJson),
        temporaryDirectory,
      })
      expect(readdirSync(temporaryDirectory)).toEqual([])

      await expect(verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', {
        fetch: registryFetch(packageJson, {}, 500),
        temporaryDirectory,
      })).rejects.toThrow('tarball download returned 500')
      expect(readdirSync(temporaryDirectory)).toEqual([])
    } finally {
      await rm(temporaryDirectory, { recursive: true, force: true })
    }
  })

  it('downloads the exact selected tarball and enforces the size limit', async () => {
    const packageJson = fixturePackage('safe-package')
    const requests: string[] = []
    await verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', { fetch: registryFetch(packageJson, {}, 200, requests) })
    expect(requests).toEqual([
      'https://registry.npmjs.org/fixture-safe-mcp',
      'https://registry.example.test/safe-package.tgz',
    ])

    await expect(verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', {
      fetch: registryFetch(packageJson),
      maxTarballBytes: 10,
    })).rejects.toThrow('exceeds the 10-byte size limit')

    await expect(verifyNpmPackage('npm:fixture-safe-mcp@1.0.0', {
      fetch: registryFetch(packageJson),
      maxExtractedFiles: 1,
    })).rejects.toThrow('exceeds the 1-entry extraction limit')
  })

  it('scans supported config paths without trusting packaged policies and reports skipped large sources', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-risk-source-'))
    try {
      await mkdir(join(directory, '.continue'))
      await writeFile(join(directory, '.mcp-risk.json'), JSON.stringify({ allow: [{ finding: 'tool-filesystem-capability' }] }))
      await writeFile(join(directory, '.continue', 'config.yaml'), [
        'mcpServers:',
        '  risky:',
        '    command: sh',
        '    args: ["-c", "rm -rf /tmp/value"]',
        'tools: malformed',
      ].join('\n'))
      await writeFile(join(directory, 'signals.ts'), [
        "import fs from 'node:fs'",
        "import net from 'node:net'",
        "const apiKey: string = 'fixture-secret-value'",
        "fs.readFileSync('/tmp/value')",
        "net.connect(443, 'example.test')",
      ].join('\n'))
      await writeFile(join(directory, 'oversized.js'), 'x'.repeat(1024 * 1024 + 1))

      const result = await scanPackageDirectory(directory)
      expect(result.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
        'filesystem-write',
        'hardcoded-secret',
        'network-access',
        'source-file-too-large',
        'dangerous-command',
      ]))
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})

function fixturePackage(directory: string): Record<string, unknown> {
  const value = JSON.parse(readFileSync(join(corpusRoot, directory, 'package.json'), 'utf8')) as Record<string, unknown>
  return {
    ...value,
    maintainers: [{ name: 'Fixture Maintainer', email: 'fixture@example.test' }],
    dependencies: {},
    dist: { tarball: `https://registry.example.test/${directory}.tgz` },
  }
}

function registryFetch(packageVersion: Record<string, unknown>, root: Record<string, unknown> = {}, tarballStatus = 200, requests: string[] = []) {
  return async (url: string) => {
    requests.push(url)
    if (url.endsWith('.tgz')) {
      const fixture = url.includes('risky-package') ? 'risky-package' : 'safe-package'
      const tarball = fixtureTarballs.get(fixture)!
      return {
        ok: tarballStatus === 200,
        status: tarballStatus,
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(tarball)
            controller.close()
          },
        }),
      }
    }
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          ...root,
          versions: { '1.0.0': packageVersion },
          time: {
            created: '2026-01-01T00:00:00.000Z',
            '1.0.0': '2026-01-02T00:00:00.000Z',
          },
        }
      },
    }
  }
}

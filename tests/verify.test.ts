import { readdirSync, readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parseNpmTarget, verifyNpmPackage } from '../src/verify/npm.js'
import { formatVerificationMarkdown } from '../src/verify/report.js'

const corpusRoot = join(process.cwd(), 'fixtures', 'security-corpus', 'npm')

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
    expect(result.metadata).toMatchObject({
      dependencyCount: 0,
      dependencies: [],
      installScripts: [],
      maintainers: ['Fixture Maintainer <fixture@example.test>'],
      publishAgeDays: 10,
      tarballDigest: {
        algorithm: 'sha256',
        value: 'e42f57587315ac1ec42b5b06ef3dc4e9e6810ed055a58c9e5e23c6b68678bd18',
      },
      tarballSizeBytes: 23,
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
    expect(result.findings.map((finding) => finding.id)).toContain('dangerous-command')
    expect(result.metadata.installScripts).toEqual(['postinstall'])
    const markdown = formatVerificationMarkdown(result)
    expect(markdown).toContain(result.metadata.tarballDigest!.value)
    expect(markdown).toContain('Static verification does not execute the package')
    expect(JSON.parse(JSON.stringify(result)).metadata.tarballDigest).toEqual(result.metadata.tarballDigest)
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
      return {
        ok: tarballStatus === 200,
        status: tarballStatus,
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('fixture tarball content'))
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

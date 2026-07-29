import { readFileSync } from 'node:fs'
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
    expect(formatVerificationMarkdown(result)).toContain('Static verification does not execute the package')
  })

  it('ignores unrelated malformed metadata fields and uses root maintainers', async () => {
    const packageJson = fixturePackage('safe-package')
    delete packageJson.maintainers
    packageJson.tools = ['build-tool']
    const fetch = async () => ({
      ok: true,
      status: 200,
      async json() {
        return {
          maintainers: [{ name: 'Registry Maintainer' }],
          versions: { '1.0.0': packageJson },
        }
      },
    })

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

function registryFetch(packageVersion: Record<string, unknown>) {
  return async () => ({
    ok: true,
    status: 200,
    async json() {
      return {
        versions: { '1.0.0': packageVersion },
        time: {
          created: '2026-01-01T00:00:00.000Z',
          '1.0.0': '2026-01-02T00:00:00.000Z',
        },
      }
    },
  })
}

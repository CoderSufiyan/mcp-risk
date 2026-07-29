import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { auditFile } from '../src/audit.js'

const corpusRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'security-corpus')
const manifest = JSON.parse(readFileSync(join(corpusRoot, 'manifest.json'), 'utf8')) as CorpusManifest

const sourceChecks: Record<string, RegExp> = {
  'filesystem-write': /\bwriteFile\s*\(/,
  'hardcoded-secret': /\bsk-fixture-[a-z-]+/,
  'network-access': /\bfetch\s*\(/,
  'shell-execution': /\bexec\s*\(/,
}

describe('security fixture corpus', () => {
  it('uses a supported, versioned manifest', () => {
    expect(manifest.schemaVersion).toBe(1)
    expect(manifest.fixtures.length).toBeGreaterThanOrEqual(4)
  })

  for (const fixture of manifest.fixtures) {
    it(`matches expected security signals for ${fixture.id}`, () => {
      const fixturePath = join(corpusRoot, fixture.path)
      const packageJson = JSON.parse(readFileSync(join(fixturePath, 'package.json'), 'utf8')) as {
        version: string
        scripts?: Record<string, string>
      }
      const findingIds = [...new Set(auditFile(join(fixturePath, fixture.config)).findings.map((finding) => finding.id))].sort()
      const installScripts = Object.keys(packageJson.scripts ?? {}).some((name) => /^(preinstall|install|postinstall)$/.test(name))
      const source = readFileSync(join(fixturePath, 'src', 'server.js'), 'utf8')
      const sourcePatterns = Object.entries(sourceChecks)
        .filter(([, pattern]) => pattern.test(source))
        .map(([name]) => name)
        .sort()

      expect(findingIds).toEqual(fixture.expected.findingIds)
      expect(installScripts).toBe(fixture.expected.installScripts)
      expect(sourcePatterns).toEqual(fixture.expected.sourcePatterns)

      if (fixture.kind === 'npm-package') expect(packageJson.version).toBe(fixture.version)
      if (fixture.kind === 'github-repository') expect(fixture.ref).toMatch(/^[a-f0-9]{40}$/)
    })
  }
})

type CorpusManifest = {
  schemaVersion: number
  fixtures: Array<{
    id: string
    kind: 'npm-package' | 'github-repository'
    path: string
    version?: string
    ref?: string
    config: string
    expected: {
      findingIds: string[]
      installScripts: boolean
      sourcePatterns: string[]
    }
  }>
}

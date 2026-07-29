import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { c as createTar } from 'tar'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { formatSarifReport } from '../src/sarif.js'
import { parseGitHubTarget, verifyGitHubRepository } from '../src/verify/github.js'
import { formatGitHubVerificationMarkdown } from '../src/verify/report.js'

const corpusRoot = join(process.cwd(), 'fixtures', 'security-corpus', 'github')
const archives = new Map<string, Buffer>()
let archiveDirectory: string

beforeAll(async () => {
  archiveDirectory = await mkdtemp(join(tmpdir(), 'mcp-risk-github-'))
  for (const fixture of ['safe-repository', 'risky-repository']) {
    const archive = join(archiveDirectory, `${fixture}.tgz`)
    await createTar({ cwd: join(corpusRoot, fixture), file: archive, gzip: true }, ['.'])
    archives.set(fixture, await readFile(archive))
  }
  const scriptRepository = join(archiveDirectory, 'script-repository')
  await mkdir(scriptRepository)
  await writeFile(join(scriptRepository, 'package.json'), JSON.stringify({
    name: 'fixture-script-repository',
    version: '1.0.0',
    scripts: { postinstall: 'node install.js' },
  }))
  await writeFile(join(scriptRepository, 'install.js'), '// This fixture is scanned but never executed.\n')
  const scriptArchive = join(archiveDirectory, 'script-repository.tgz')
  await createTar({ cwd: scriptRepository, file: scriptArchive, gzip: true }, ['.'])
  archives.set('script-repository', await readFile(scriptArchive))
})

afterAll(async () => {
  await rm(archiveDirectory, { recursive: true, force: true })
})

describe('GitHub repository verification', () => {
  it('requires an explicit repository ref', () => {
    expect(parseGitHubTarget('github:owner/repository@main')).toEqual({ owner: 'owner', repository: 'repository', ref: 'main' })
    expect(() => parseGitHubTarget('github:owner/repository')).toThrow('explicit branch, tag, or commit')
  })

  it('resolves a ref to an exact commit and scans a safe repository', async () => {
    const commit = '1'.repeat(40)
    const requests: Array<{ url: string; authorization?: string }> = []
    const result = await verifyGitHubRepository('github:owner/safe@v1.0.0', {
      token: 'fixture-token',
      fetch: githubFetch('safe-repository', commit, requests),
    })

    expect(result.repository).toMatchObject({ owner: 'owner', name: 'safe', ref: 'v1.0.0', commit })
    expect(result.metadata.manifests).toEqual([expect.objectContaining({ name: 'fixture-safe-repository', dependencies: [] })])
    expect(result.findings).toHaveLength(0)
    expect(requests).toEqual([
      { url: 'https://api.github.com/repos/owner/safe/commits/v1.0.0', authorization: 'Bearer fixture-token' },
      { url: `https://api.github.com/repos/owner/safe/tarball/${commit}`, authorization: 'Bearer fixture-token' },
    ])
  })

  it('reports risky repository source and config findings in every output model', async () => {
    const commit = '2'.repeat(40)
    const result = await verifyGitHubRepository('github:owner/risky@feature/test', {
      fetch: githubFetch('risky-repository', commit),
    })
    const ids = result.findings.map((finding) => finding.id)
    expect(ids).toContain('filesystem-write')
    expect(ids).toContain('tool-filesystem-capability')
    expect(result.findings.every((finding) => finding.location.length > 0)).toBe(true)
    expect(formatGitHubVerificationMarkdown(result)).toContain(commit)
    const sarif = JSON.stringify(formatSarifReport(result))
    expect(sarif).toContain('filesystem-write')
    expect(sarif).toContain(commit)
    expect(sarif).toContain(`https://github.com/owner/risky/tree/${commit}`)
  })

  it('treats repository install scripts as high-risk findings', async () => {
    const result = await verifyGitHubRepository('github:owner/scripts@main', {
      fetch: githubFetch('script-repository', '3'.repeat(40)),
    })
    expect(result.findings).toContainEqual(expect.objectContaining({ id: 'package-install-script', severity: 'high' }))
    expect(result.metadata.manifests[0].installScripts).toEqual(['postinstall'])
  })

  it('reports missing, private, and unavailable repositories clearly', async () => {
    for (const [status, message] of [[401, 'authentication failed'], [403, 'denied or rate limited'], [404, 'not found; it may be private']] as const) {
      await expect(verifyGitHubRepository('github:owner/missing@main', {
        fetch: async () => ({ ok: false, status }),
      })).rejects.toThrow(message)
    }
  })
})

function githubFetch(fixture: string, commit: string, requests: Array<{ url: string; authorization?: string }> = []) {
  return async (url: string, init?: { headers?: Record<string, string> }) => {
    requests.push({ url, authorization: init?.headers?.Authorization })
    if (url.includes('/commits/')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return { sha: commit }
        },
      }
    }
    const archive = archives.get(fixture)!
    return {
      ok: true,
      status: 200,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(archive)
          controller.close()
        },
      }),
    }
  }
}

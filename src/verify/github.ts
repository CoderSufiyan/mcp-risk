import { summarize } from '../scoring.js'
import type { GitHubVerificationResult } from '../types.js'
import { inspectArchive } from './archive.js'
import type { ArchiveOptions, FetchLike } from './archive.js'

export type GitHubVerifyOptions = ArchiveOptions & {
  apiUrl?: string
  token?: string
  fetch?: FetchLike
}

export async function verifyGitHubRepository(target: string, options: GitHubVerifyOptions = {}): Promise<GitHubVerificationResult> {
  const { owner, repository, ref } = parseGitHubTarget(target)
  const apiUrl = (options.apiUrl ?? 'https://api.github.com').replace(/\/$/, '')
  const fetcher: FetchLike = options.fetch ?? ((url, init) => fetch(url, init))
  const token = options.token ?? process.env.GITHUB_TOKEN
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'mcp-risk',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  const identityUrl = `${apiUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/commits/${encodeURIComponent(ref)}`
  const response = await fetcher(identityUrl, { headers, signal: AbortSignal.timeout(options.timeoutMs ?? 10_000) })
  if (!response.ok) throw githubApiError(response.status, owner, repository, ref)
  if (!response.json) throw new Error(`GitHub returned invalid commit metadata for ${owner}/${repository}@${ref}`)
  const document = await response.json()
  if (!isRecord(document) || typeof document.sha !== 'string' || !/^[a-f0-9]{40}$/i.test(document.sha)) {
    throw new Error(`GitHub returned invalid commit metadata for ${owner}/${repository}@${ref}`)
  }

  const commit = document.sha.toLowerCase()
  const archiveUrl = `${apiUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/tarball/${commit}`
  let archive
  try {
    archive = await inspectArchive(archiveUrl, fetcher, options, headers, 'GitHub archive')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (/returned (401|403)/.test(message)) throw new Error(`GitHub archive for ${owner}/${repository}@${commit} is unavailable due to authentication, authorization, or rate limits`)
    if (/returned 404/.test(message)) throw new Error(`GitHub archive for ${owner}/${repository}@${commit} was not found`)
    throw error
  }

  return {
    target,
    kind: 'github',
    repository: {
      owner,
      name: repository,
      url: `https://github.com/${owner}/${repository}`,
      ref,
      commit,
    },
    metadata: {
      archiveUrl,
      archiveDigest: { algorithm: 'sha256', value: archive.digest },
      archiveSizeBytes: archive.sizeBytes,
      sourceFileCount: archive.scannedFiles,
      manifests: archive.manifests,
    },
    findings: archive.findings,
    summary: summarize(archive.findings),
  }
}

export function parseGitHubTarget(target: string): { owner: string; repository: string; ref: string } {
  if (!target.startsWith('github:')) throw new Error('GitHub verification target must start with "github:"')
  const specifier = target.slice('github:'.length)
  const separator = specifier.lastIndexOf('@')
  if (separator <= 0 || separator === specifier.length - 1) {
    throw new Error('GitHub verification requires an explicit branch, tag, or commit, for example github:owner/repo@v1.2.3')
  }
  const identity = specifier.slice(0, separator)
  const ref = specifier.slice(separator + 1)
  const parts = identity.split('/')
  if (parts.length !== 2 || parts.some((part) => !/^[A-Za-z0-9_.-]+$/.test(part)) || /\s/.test(ref)) {
    throw new Error('GitHub verification target must use github:owner/repository@reference')
  }
  return { owner: parts[0], repository: parts[1], ref }
}

function githubApiError(status: number, owner: string, repository: string, ref: string): Error {
  const identity = `${owner}/${repository}@${ref}`
  if (status === 401) return new Error(`GitHub authentication failed while resolving ${identity}`)
  if (status === 403) return new Error(`GitHub access was denied or rate limited while resolving ${identity}`)
  if (status === 404) return new Error(`GitHub repository or ref ${identity} was not found; it may be private`)
  return new Error(`GitHub API returned ${status} while resolving ${identity}`)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

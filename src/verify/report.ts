import type { GitHubVerificationResult, NpmVerificationResult } from '../types.js'

export function formatVerificationText(result: NpmVerificationResult): string {
  const lines = [
    '',
    'MCP Package Verification',
    `Package: ${plain(result.package.name)}@${plain(result.package.version)}`,
    `Score: ${result.summary.grade} (${result.summary.score}/100)`,
    `Published: ${plain(publishedLabel(result))}`,
    `Maintainers: ${result.metadata.maintainers.length}`,
    `Maintainer identities: ${result.metadata.maintainers.map(plain).join(', ') || 'none'}`,
    `Dependencies: ${result.metadata.dependencyCount}`,
    `Install scripts: ${result.metadata.installScripts.map(plain).join(', ') || 'none'}`,
    `License: ${plain(result.metadata.license ?? 'unknown')}`,
    `Repository: ${plain(result.metadata.repository ?? 'unknown')}`,
    `Tarball: ${plain(result.metadata.tarball ?? 'unknown')}`,
    `SHA-256: ${result.metadata.tarballDigest?.value ?? 'unknown'}`,
    `Tarball size: ${result.metadata.tarballSizeBytes ?? 'unknown'} bytes`,
    `Source files scanned: ${result.metadata.sourceFileCount ?? 0}`,
    `Findings: ${result.findings.length}`,
    '',
  ]

  if (result.metadata.dependencies.length > 0) {
    lines.push('Dependency inventory:')
    for (const dependency of result.metadata.dependencies) {
      lines.push(`  ${plain(dependency.name)}${dependency.specifier ? `@${plain(dependency.specifier)}` : ''} [${dependency.type}]`)
    }
    lines.push('')
  }

  for (const finding of result.findings) {
    lines.push(`${finding.severity.toUpperCase()} [${plain(finding.id)}] ${plain(finding.title)}`, `  ${plain(finding.location)}`, `  ${plain(finding.message)}`, `  Fix: ${plain(finding.recommendation)}`, '')
  }
  return lines.join('\n')
}

export function formatVerificationMarkdown(result: NpmVerificationResult): string {
  const lines = [
    `# MCP Risk: ${markdown(result.package.name)}@${markdown(result.package.version)}`,
    '',
    `**Grade:** ${result.summary.grade} (${result.summary.score}/100)`,
    '',
    '| Signal | Value |',
    '|---|---|',
    `| Published | ${markdown(publishedLabel(result))} |`,
    `| Maintainers | ${result.metadata.maintainers.length} |`,
    `| Maintainer identities | ${markdown(result.metadata.maintainers.join(', ') || 'none')} |`,
    `| Dependencies | ${result.metadata.dependencyCount} |`,
    `| Install scripts | ${markdown(result.metadata.installScripts.join(', ') || 'none')} |`,
    `| License | ${markdown(result.metadata.license ?? 'unknown')} |`,
    `| Repository | ${markdown(result.metadata.repository ?? 'unknown')} |`,
    `| Tarball | ${markdown(result.metadata.tarball ?? 'unknown')} |`,
    `| SHA-256 | ${result.metadata.tarballDigest?.value ?? 'unknown'} |`,
    `| Tarball size | ${result.metadata.tarballSizeBytes ?? 'unknown'} bytes |`,
    `| Source files scanned | ${result.metadata.sourceFileCount ?? 0} |`,
    '',
    '## Dependencies',
    '',
  ]

  if (result.metadata.dependencies.length === 0) lines.push('No runtime dependencies declared.', '')
  else {
    lines.push('| Package | Specifier | Type |', '|---|---|---|')
    for (const dependency of result.metadata.dependencies) {
      lines.push(`| ${markdown(dependency.name)} | ${markdown(dependency.specifier ?? '')} | ${dependency.type} |`)
    }
    lines.push('')
  }

  lines.push('## Findings', '')

  if (result.findings.length === 0) lines.push('No risky static metadata patterns found.', '')
  for (const finding of result.findings) {
    lines.push(`### ${finding.severity.toUpperCase()}: ${markdown(finding.title)}`, '', `**Rule:** ${markdown(finding.id)}`, '', markdown(finding.message), '', `**Location:** ${markdown(finding.location)}`, '', `**Recommendation:** ${markdown(finding.recommendation)}`, '')
  }
  lines.push('> Static verification does not execute the package and is not a guarantee of safety.', '')
  return lines.join('\n')
}

export function formatGitHubVerificationText(result: GitHubVerificationResult): string {
  const lines = [
    '',
    'MCP GitHub Repository Verification',
    `Repository: ${plain(result.repository.owner)}/${plain(result.repository.name)}`,
    `Requested ref: ${plain(result.repository.ref)}`,
    `Resolved commit: ${result.repository.commit}`,
    `Score: ${result.summary.grade} (${result.summary.score}/100)`,
    `Source files scanned: ${result.metadata.sourceFileCount}`,
    `Manifests: ${result.metadata.manifests.length}`,
    `Findings: ${result.findings.length}`,
    '',
  ]
  for (const manifest of result.metadata.manifests) {
    lines.push(`Manifest: ${plain(manifest.path)}`, `  Package: ${plain(manifest.name ?? 'unknown')}@${plain(manifest.version ?? 'unknown')}`, `  Dependencies: ${manifest.dependencies.map(plain).join(', ') || 'none'}`, `  Install scripts: ${manifest.installScripts.join(', ') || 'none'}`, '')
  }
  for (const finding of result.findings) {
    lines.push(`${finding.severity.toUpperCase()} [${plain(finding.id)}] ${plain(finding.title)}`, `  ${plain(finding.location)}`, `  ${plain(finding.message)}`, `  Fix: ${plain(finding.recommendation)}`, '')
  }
  return lines.join('\n')
}

export function formatGitHubVerificationMarkdown(result: GitHubVerificationResult): string {
  const lines = [
    `# MCP Risk: ${markdown(result.repository.owner)}/${markdown(result.repository.name)}`,
    '',
    `**Requested ref:** ${markdown(result.repository.ref)}`,
    '',
    `**Resolved commit:** \`${result.repository.commit}\``,
    '',
    `**Grade:** ${result.summary.grade} (${result.summary.score}/100)`,
    '',
    '| Signal | Value |',
    '|---|---|',
    `| Repository | ${markdown(result.repository.url)} |`,
    `| Source files scanned | ${result.metadata.sourceFileCount} |`,
    `| Manifests | ${result.metadata.manifests.length} |`,
    `| Archive SHA-256 | ${result.metadata.archiveDigest.value} |`,
    '',
    '## Manifests',
    '',
  ]
  if (result.metadata.manifests.length === 0) lines.push('No package manifests found.', '')
  for (const manifest of result.metadata.manifests) {
    lines.push(`### ${markdown(manifest.path)}`, '', `- Package: ${markdown(manifest.name ?? 'unknown')}@${markdown(manifest.version ?? 'unknown')}`, `- Dependencies: ${markdown(manifest.dependencies.join(', ') || 'none')}`, `- Install scripts: ${markdown(manifest.installScripts.join(', ') || 'none')}`, '')
  }
  lines.push('## Findings', '')
  if (result.findings.length === 0) lines.push('No risky static patterns found.', '')
  for (const finding of result.findings) {
    lines.push(`### ${finding.severity.toUpperCase()}: ${markdown(finding.title)}`, '', `**Rule:** ${markdown(finding.id)}`, '', markdown(finding.message), '', `**Location:** ${markdown(finding.location)}`, '', `**Recommendation:** ${markdown(finding.recommendation)}`, '')
  }
  lines.push('> Static verification does not execute repository code and is not a guarantee of safety.', '')
  return lines.join('\n')
}

function publishedLabel(result: NpmVerificationResult): string {
  const date = result.metadata.publishedAt ?? 'unknown'
  return result.metadata.publishAgeDays === undefined ? date : `${date} (${result.metadata.publishAgeDays} days ago)`
}

function plain(value: string): string {
  return value.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '').replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
}

function markdown(value: string): string {
  return plain(value).replace(/([\\`*_{}\[\]<>()#+.!|~-])/g, '\\$1')
}

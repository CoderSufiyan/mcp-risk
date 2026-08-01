#!/usr/bin/env node
import { Command } from 'commander'
import { auditAll, auditFile } from './audit.js'
import { ConfigError } from './parse.js'
import { formatTextReport, formatTextReports } from './report.js'
import { formatSarifReport, formatSarifReports } from './sarif.js'
import type { Severity } from './types.js'
import { VERSION } from './version.js'
import { verifyGitHubRepository } from './verify/github.js'
import { createVerificationReport } from './verify/model.js'
import { verifyNpmPackage } from './verify/npm.js'
import { formatGitHubVerificationMarkdown, formatGitHubVerificationText, formatVerificationMarkdown, formatVerificationText } from './verify/report.js'

const severityOrder: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const program = new Command()

program
  .name('mcp-risk')
  .description('Audit MCP configs and statically verify npm packages and GitHub repositories.')
  .version(VERSION)

program
  .command('scan')
  .argument('[target]', 'MCP config file or directory', '.')
  .option('--json', 'Print JSON output')
  .option('--sarif', 'Print SARIF JSON output')
  .option('--all', 'Scan every discovered project and user MCP configuration')
  .option('--include-low', 'Include low severity findings')
  .option('--fail-on <severity>', 'Exit with code 1 when severity is found: low, medium, high, critical')
  .action((target: string, options: { all?: boolean; json?: boolean; sarif?: boolean; includeLow?: boolean; failOn?: Severity }) => {
    try {
      if (options.json && options.sarif) throw new Error('Use either --json or --sarif, not both')

      if (options.all) {
        const result = auditAll(target, { includeLow: options.includeLow })
        if (options.sarif) {
          process.stdout.write(`${JSON.stringify(formatSarifReports(result.results), null, 2)}\n`)
        } else if (options.json) {
          process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
        } else {
          process.stdout.write(formatTextReports(result.results, result.diagnostics))
        }

        if (result.diagnostics.length > 0) {
          process.exitCode = 3
        } else if (options.failOn && shouldFail(result.results.flatMap((item) => item.findings.map((finding) => finding.severity)), options.failOn)) {
          process.exitCode = 1
        }
      } else {
        const result = auditFile(target, { includeLow: options.includeLow })
        if (options.sarif) {
          process.stdout.write(`${JSON.stringify(formatSarifReport(result), null, 2)}\n`)
        } else if (options.json) {
          process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
        } else {
          process.stdout.write(formatTextReport(result))
        }

        if (options.failOn && shouldFail(result.findings.map((finding) => finding.severity), options.failOn)) {
          process.exitCode = 1
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`mcp-risk: ${message}\n`)
      process.exitCode = error instanceof ConfigError ? 3 : 2
    }
  })

program
  .command('verify')
  .argument('<target>', 'Pinned npm or GitHub target')
  .option('--json', 'Print JSON output')
  .option('--sarif', 'Print SARIF JSON output')
  .option('--format <format>', 'Output format: text, json, markdown, sarif', 'text')
  .option('--fail-on <severity>', 'Exit with code 1 when severity is found: low, medium, high, critical')
  .action(async (target: string, options: { json?: boolean; sarif?: boolean; format: string; failOn?: Severity }) => {
    try {
      if (options.json && options.sarif) throw new Error('Use either --json or --sarif, not both')
      const format = options.json ? 'json' : options.sarif ? 'sarif' : options.format
      if (!['text', 'json', 'markdown', 'sarif'].includes(format)) throw new Error('Verify format must be text, json, markdown, or sarif')
      if (options.failOn && !(options.failOn in severityOrder)) throw new Error('Fail severity must be low, medium, high, or critical')
      const result = target.startsWith('npm:') ? await verifyNpmPackage(target) : await verifyGitHubRepository(target)
      if (format === 'json') process.stdout.write(`${JSON.stringify(createVerificationReport(result), null, 2)}\n`)
      if (format === 'sarif') process.stdout.write(`${JSON.stringify(formatSarifReport(result), null, 2)}\n`)
      if (format === 'markdown') process.stdout.write(result.kind === 'npm' ? formatVerificationMarkdown(result) : formatGitHubVerificationMarkdown(result))
      if (format === 'text') process.stdout.write(result.kind === 'npm' ? formatVerificationText(result) : formatGitHubVerificationText(result))

      if (options.failOn && shouldFail(result.findings.map((finding) => finding.severity), options.failOn)) {
        process.exitCode = 1
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`mcp-risk: ${message}\n`)
      process.exitCode = 2
    }
  })

program.parseAsync()

function shouldFail(severities: Severity[], threshold: Severity): boolean {
  return severities.some((severity) => severityOrder[severity] >= severityOrder[threshold])
}

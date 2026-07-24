#!/usr/bin/env node
import { Command } from 'commander'
import { auditAll, auditFile } from './audit.js'
import { ConfigError } from './parse.js'
import { formatTextReport, formatTextReports } from './report.js'
import { formatSarifReport, formatSarifReports } from './sarif.js'
import type { Severity } from './types.js'

const severityOrder: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const program = new Command()

program
  .name('mcp-risk')
  .description('Audit MCP configs and servers for risky tools, secret exposure, and prompt-injection patterns.')
  .version('0.3.0')

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

program.parse()

function shouldFail(severities: Severity[], threshold: Severity): boolean {
  return severities.some((severity) => severityOrder[severity] >= severityOrder[threshold])
}

#!/usr/bin/env node
import { Command } from 'commander'
import { auditFile } from './audit.js'
import { formatTextReport } from './report.js'
import { formatSarifReport } from './sarif.js'
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
  .version('0.2.0')

program
  .command('scan')
  .argument('[target]', 'MCP config file or directory', '.')
  .option('--json', 'Print JSON output')
  .option('--sarif', 'Print SARIF JSON output')
  .option('--include-low', 'Include low severity findings')
  .option('--fail-on <severity>', 'Exit with code 1 when severity is found: low, medium, high, critical')
  .action((target: string, options: { json?: boolean; sarif?: boolean; includeLow?: boolean; failOn?: Severity }) => {
    try {
      if (options.json && options.sarif) throw new Error('Use either --json or --sarif, not both')

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
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`mcp-risk: ${message}\n`)
      process.exitCode = 2
    }
  })

program.parse()

function shouldFail(severities: Severity[], threshold: Severity): boolean {
  return severities.some((severity) => severityOrder[severity] >= severityOrder[threshold])
}

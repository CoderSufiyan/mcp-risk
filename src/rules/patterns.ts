export const INJECTION_PATTERNS: Array<{ id: string; pattern: RegExp; label: string }> = [
  {
    id: 'instruction-override',
    label: 'instruction override',
    pattern: /\b(ignore|forget|disregard|override)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,40}\b(instructions?|messages?|rules?)\b/i,
  },
  {
    id: 'secret-exfiltration',
    label: 'secret exfiltration',
    pattern: /\b(reveal|print|show|send|exfiltrate|leak)\b.{0,80}\b(secret|token|api[_ -]?key|password|env|environment)\b/i,
  },
  {
    id: 'tool-hijack',
    label: 'tool hijack',
    pattern: /\b(call|use|invoke|execute)\b.{0,60}\b(tool|function|command|shell|terminal)\b.{0,80}\b(without asking|silently|automatically|no confirmation)\b/i,
  },
  {
    id: 'role-hijack',
    label: 'role hijack',
    pattern: /\b(you are now|act as|roleplay as|pretend to be)\b.{0,80}\b(unrestricted|developer|system|admin|root|dan)\b/i,
  },
  {
    id: 'hidden-instruction',
    label: 'hidden instruction marker',
    pattern: /(<\|im_start\|>|<\|im_end\|>|\[INST\]|<\/?system>|###\s*(system|developer|instruction))/i,
  },
]

export const DANGEROUS_COMMANDS = [
  'bash',
  'sh',
  'zsh',
  'fish',
  'powershell',
  'pwsh',
  'cmd',
  'python',
  'python3',
  'node',
  'ruby',
  'perl',
  'deno',
  'bun',
]

export const DANGEROUS_ARG_PATTERNS: Array<{ id: string; pattern: RegExp; message: string }> = [
  { id: 'shell-eval', pattern: /(^| )(-c|--eval|--execute|\/c)( |$)/i, message: 'can execute inline code or shell commands' },
  { id: 'network-download', pattern: /\b(curl|wget|Invoke-WebRequest|fetch)\b/i, message: 'can download remote content' },
  { id: 'destructive-command', pattern: /\b(rm\s+-rf|del\s+\/|format|mkfs|shutdown|reboot)\b/i, message: 'contains destructive command patterns' },
]

export const SENSITIVE_ENV_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /credential/i,
  /^aws_/i,
  /^gcp_/i,
  /^azure_/i,
  /^github_/i,
  /^openai_/i,
  /^anthropic_/i,
]

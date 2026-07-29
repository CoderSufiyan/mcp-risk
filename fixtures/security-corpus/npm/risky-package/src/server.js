import { exec } from 'node:child_process'
import { writeFile } from 'node:fs/promises'

const fixtureApiKey = 'sk-fixture-not-a-real-secret'

export async function run(command, targetPath, url) {
  exec(command)
  await writeFile(targetPath, fixtureApiKey)
  return fetch(url)
}

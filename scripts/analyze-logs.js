#!/usr/bin/env node
// Weekly log review tool.
//
// Usage:
//   node scripts/analyze-logs.js [--days N] [--log PATH] [--json]
//
// Defaults scan the last 7 days of logs/prompts-*.jsonl plus the entire
// scripts/proxy.log (runtime log is rotated manually).
//
// Output is a human-readable report to stdout. `--json` switches to JSON for
// ingestion by monitoring tools.

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const {
  summarizeProxyLog,
  createPromptScanner,
  formatReport
} = require('../log-analyzer');

function parseArgs(argv) {
  const opts = { days: 7, logFile: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--days') opts.days = Number(argv[++i]);
    else if (a === '--log') opts.logFile = argv[++i];
    else if (a === '--json') opts.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node scripts/analyze-logs.js [--days N] [--log PATH] [--json]');
      process.exit(0);
    }
  }
  return opts;
}

function pickJsonlFiles(dir, days) {
  if (!fs.existsSync(dir)) return [];
  const cutoff = Date.now() - days * 24 * 3600 * 1000;
  return fs.readdirSync(dir)
    .filter(f => /^prompts-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
    .map(f => {
      const datePart = f.slice('prompts-'.length, 'prompts-'.length + 10);
      const ts = Date.parse(datePart + 'T00:00:00Z');
      return { file: path.join(dir, f), ts };
    })
    .filter(x => !isNaN(x.ts) && x.ts >= cutoff)
    .sort((a, b) => a.ts - b.ts)
    .map(x => x.file);
}

async function scanJsonl(files) {
  const scanner = createPromptScanner();
  for (const file of files) {
    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(file, { encoding: 'utf8' });
      const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
      rl.on('line', scanner.onLine);
      rl.on('close', resolve);
      rl.on('error', reject);
      stream.on('error', reject);
    });
  }
  return scanner.summary();
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const repoRoot = path.resolve(__dirname, '..');
  const proxyLogPath = opts.logFile || path.join(repoRoot, 'scripts', 'proxy.log');
  const promptsDir = path.join(repoRoot, 'logs');

  let proxyLogText = '';
  if (fs.existsSync(proxyLogPath)) {
    proxyLogText = fs.readFileSync(proxyLogPath, 'utf8');
  } else {
    console.error(`[analyze] proxy log not found: ${proxyLogPath}`);
  }

  const proxySummary = summarizeProxyLog(proxyLogText);
  const jsonlFiles = pickJsonlFiles(promptsDir, opts.days);
  const promptSummary = jsonlFiles.length > 0 ? await scanJsonl(jsonlFiles) : null;

  if (opts.json) {
    console.log(JSON.stringify({ proxy: proxySummary, prompts: promptSummary }, null, 2));
  } else {
    console.log(formatReport(proxySummary, promptSummary, {
      title: `Billing Proxy Log Review (last ${opts.days} day${opts.days === 1 ? '' : 's'})`
    }));
  }

  // Exit non-zero on anomalies so this script can gate CI/cron alerts.
  const anomalies =
    proxySummary.detections.length > 0 ||
    proxySummary.upstreamErrors.length > 10 ||
    proxySummary.refreshSpawnFailures > 0 ||
    (promptSummary && Object.keys(promptSummary.triggerLeakage).length > 0);
  process.exit(anomalies ? 2 : 0);
}

main().catch(e => {
  console.error('[analyze] fatal:', e.stack || e.message);
  process.exit(1);
});

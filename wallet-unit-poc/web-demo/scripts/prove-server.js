#!/usr/bin/env node
// Minimal HTTP proving server that wraps the ecdsa-spartan2 CLI.
// Accepts circuit input JSON via POST /prove, runs native proving, returns proof.
//
// Usage: node scripts/prove-server.js [--port 8080]
//
// Prerequisites:
//   - ecdsa-spartan2 binary built: cd ../ecdsa-spartan2 && cargo build --release
//   - RS256 proving key generated: cargo run --release -- rs256 setup

import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { writeFile, readFile, unlink, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === '--port') || '8080');
const SPARTAN_DIR = resolve(import.meta.dirname, '../../ecdsa-spartan2');
const BINARY = join(SPARTAN_DIR, 'target/release/ecdsa-spartan2');
const PROOF_PATH = join(SPARTAN_DIR, 'keys/rs256_proof.bin');
const INSTANCE_PATH = join(SPARTAN_DIR, 'keys/rs256_instance.bin');

// Find the witnesscalc dylib for DYLD_LIBRARY_PATH
import { readdirSync, existsSync } from 'node:fs';
function findDylibDir() {
  const buildDir = join(SPARTAN_DIR, 'target/release/build');
  if (!existsSync(buildDir)) return '';
  for (const entry of readdirSync(buildDir)) {
    const dylibPath = join(buildDir, entry, 'out/witnesscalc/build_witnesscalc/src');
    if (existsSync(join(dylibPath, 'libwitnesscalc_rs256.dylib'))) return dylibPath;
  }
  return '';
}
const DYLIB_DIR = findDylibDir();

// Check prerequisites
async function checkPrereqs() {
  try {
    await access(BINARY);
  } catch {
    console.error(`Binary not found: ${BINARY}`);
    console.error('Build it: cd ../ecdsa-spartan2 && cargo build --release');
    process.exit(1);
  }
  try {
    await access(join(SPARTAN_DIR, 'keys/rs256_proving.key'));
  } catch {
    console.error('Proving key not found. Run: cd ../ecdsa-spartan2 && cargo run --release -- rs256 setup');
    process.exit(1);
  }
}

const server = createServer(async (req, res) => {
  // CORS headers for local dev
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'POST' && req.url === '/prove') {
    let body = '';
    for await (const chunk of req) body += chunk;

    // Validate JSON
    let inputJson;
    try {
      inputJson = JSON.parse(body);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON input' }));
      return;
    }

    // Write to temp file
    const tmpFile = join(tmpdir(), `zkid-input-${randomBytes(4).toString('hex')}.json`);
    await writeFile(tmpFile, JSON.stringify(inputJson));

    console.log(`[${new Date().toISOString()}] Proving started...`);
    const t0 = Date.now();

    execFile(BINARY, ['rs256', 'prove', '--input', tmpFile], {
      cwd: SPARTAN_DIR,
      timeout: 120_000, // 2 min timeout
      env: {
        ...process.env,
        RUST_LOG: 'info',
        DYLD_LIBRARY_PATH: DYLIB_DIR + (process.env.DYLD_LIBRARY_PATH ? ':' + process.env.DYLD_LIBRARY_PATH : ''),
      },
    }, async (error, stdout, stderr) => {
      await unlink(tmpFile).catch(() => {});

      if (error) {
        console.error(`Proving failed (${Date.now() - t0}ms):`, stderr || error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Proving failed: ${stderr || error.message}` }));
        return;
      }

      const elapsed = Date.now() - t0;
      console.log(`[${new Date().toISOString()}] Proved in ${elapsed}ms`);
      if (stderr) console.log(stderr);

      // Read proof and instance
      try {
        const proofBytes = await readFile(PROOF_PATH);
        const instanceBytes = await readFile(INSTANCE_PATH);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          proof: proofBytes.toString('base64'),
          instance: instanceBytes.toString('base64'),
          timing_ms: elapsed,
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Failed to read proof: ${e.message}` }));
      }
    });
  } else if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', binary: BINARY }));
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. Use POST /prove or GET /health' }));
  }
});

await checkPrereqs();
server.listen(PORT, () => {
  console.log(`Proving server listening on http://localhost:${PORT}`);
  console.log(`Binary: ${BINARY}`);
  console.log(`POST /prove — accept circuit input JSON, return proof`);
  console.log(`GET /health — health check`);
});

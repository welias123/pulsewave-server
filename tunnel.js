// Localtunnel wrapper — CLI based (more reliable for forwarding)
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const SUBDOMAIN = 'pulsewave-welias';
const PORT = process.env.PORT || 3333;
const URL_FILE = path.join(__dirname, 'tunnel-url.json');

function saveTunnelUrl(url) {
  try { fs.writeFileSync(URL_FILE, JSON.stringify({ url, ts: Date.now() })); } catch(e) {}
}

function startTunnel() {
  console.log(`[tunnel] Starting localtunnel on port ${PORT}...`);

  // Use npx to run localtunnel CLI
  const lt = spawn('npx', ['localtunnel', '--port', String(PORT), '--subdomain', SUBDOMAIN], {
    shell: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  lt.stdout.on('data', d => {
    const line = d.toString().trim();
    if (!line) return;
    console.log('[tunnel]', line);
    const match = line.match(/https:\/\/[^\s]+/);
    if (match) {
      saveTunnelUrl(match[0]);
      console.log(`\n✅ Tunnel URL: ${match[0]}\n`);
    }
  });

  lt.stderr.on('data', d => {
    const s = d.toString().trim();
    if (s && !s.includes('npm warn')) console.error('[tunnel err]', s);
  });

  lt.on('close', code => {
    saveTunnelUrl(null);
    console.log(`[tunnel] Exited (${code}), restarting in 2s...`);
    setTimeout(startTunnel, 2000);
  });
}

startTunnel();

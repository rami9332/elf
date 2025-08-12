cat > scripts/get-face-models.mjs <<'JS'
import fs from 'fs/promises';
import path from 'path';
import fetch from 'node-fetch';

const BASE_URL = process.env.FACE_MODELS_BASE || 'https://cdn.jsdelivr.net/gh/vladmandic/face-api/model/';
const OUT_DIR  = process.env.FACE_MODELS_DIR  || './models/face-api';

const MODELS = [
  'ssd_mobilenetv1_model-weights_manifest.json',
  'face_landmark_68_model-weights_manifest.json',
  'face_recognition_model-weights_manifest.json',
];

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function download(url, outPath) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await fs.writeFile(outPath, buf);
  console.log('↓', path.basename(outPath), `${(buf.length/1024/1024).toFixed(2)} MB`);
}

async function run() {
  await ensureDir(OUT_DIR);

  for (const manifestName of MODELS) {
    const manifestUrl  = new URL(manifestName, BASE_URL).href;
    const manifestPath = path.join(OUT_DIR, manifestName);

    console.log('\n==> Manifest:', manifestUrl);
    await download(manifestUrl, manifestPath);

    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    const weights = manifest?.weights || manifest?.paths || []; // fallback je nach Format

    // face-api nutzt manifest.format: { weights: [ { name, paths: [...] } ] } – wir lesen generisch:
    const files = new Set();
    if (Array.isArray(manifest.weights)) {
      for (const w of manifest.weights) {
        (w.paths || []).forEach(p => files.add(p));
      }
    } else if (Array.isArray(manifest.paths)) {
      manifest.paths.forEach(p => files.add(p));
    }

    for (const f of files) {
      const binUrl  = new URL(f, BASE_URL).href;
      const binPath = path.join(OUT_DIR, f);
      await download(binUrl, binPath);
    }
  }

  console.log('\n✅ Alle Face-Modelle geladen nach:', OUT_DIR);
}
run().catch(e => {
  console.error('❌ Download-Fehler:', e.message);
  process.exit(1);
});
JS
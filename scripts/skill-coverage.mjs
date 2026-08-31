// Coverage of the SKILL-INJECT corpus by attack family (docs/SPEC.md §8.11).
//
//   node scripts/compose-skill-payloads.mjs <outdir>     # compose the 152 skills
//   node dist/cli.js <outdir> --format json --fail-on none > scan.json
//   node scripts/skill-coverage.mjs <outdir> scan.json
//
// Answers one question: which family of real attack does this scanner miss most?
import { readFileSync } from 'node:fs';

const [, , payloadDir, scanFile] = process.argv;
const manifest = JSON.parse(readFileSync(`${payloadDir}/manifest.json`, 'utf8'));
const scan = JSON.parse(readFileSync(scanFile, 'utf8'));
const map = JSON.parse(readFileSync(new URL('./skill-payload-families.json', import.meta.url), 'utf8'));

// A composed skill is "detected" if any rule fired anywhere inside its directory.
const rulesBySlug = new Map();
for (const f of scan.findings) {
  const slug = f.location.file.replace(/[\\/].*$/, '');
  if (!rulesBySlug.has(slug)) rulesBySlug.set(slug, new Set());
  rulesBySlug.get(slug).add(f.ruleId);
}

const stats = new Map();
const unmapped = [];

for (const item of manifest) {
  const entry = map[item.set]?.[String(item.id)];
  if (!entry) { unmapped.push(`${item.set}/${item.id}`); continue; }
  const row = stats.get(entry.family) ?? { n: 0, hit: 0, rules: new Set(), missedTitles: new Set() };
  row.n += 1;
  const rules = rulesBySlug.get(item.slug);
  if (rules?.size) { row.hit += 1; for (const r of rules) row.rules.add(r); }
  else row.missedTitles.add(entry.title);
  stats.set(entry.family, row);
}

const rows = [...stats.entries()].sort((a, b) => (b[1].n - b[1].hit) - (a[1].n - a[1].hit));

console.log('familia'.padEnd(20) + 'total'.padEnd(8) + 'pego'.padEnd(7) + 'MISS'.padEnd(7) + 'regras');
console.log('-'.repeat(66));
let N = 0, H = 0;
for (const [family, r] of rows) {
  N += r.n; H += r.hit;
  console.log(
    family.padEnd(20) +
    String(r.n).padEnd(8) +
    String(r.hit).padEnd(7) +
    String(r.n - r.hit).padEnd(7) +
    ([...r.rules].join(',') || '-'),
  );
}
console.log('-'.repeat(66));
console.log('TOTAL'.padEnd(20) + String(N).padEnd(8) + String(H).padEnd(7) + String(N - H).padEnd(7) +
  `${((100 * H) / N).toFixed(1)}%`);

if (unmapped.length > 0) {
  // Loud on purpose: a payload with no family assignment would otherwise vanish
  // from the denominator and quietly improve every percentage on this table.
  console.log(`\n!! ${unmapped.length} payload(s) sem familia atribuida: ${unmapped.join(', ')}`);
}

const biggest = rows[0];
if (biggest && biggest[1].n > biggest[1].hit) {
  console.log(`\nmaior familia descoberta: ${biggest[0]} — ${biggest[1].n - biggest[1].hit} miss de ${biggest[1].n}`);
  console.log('ataques distintos nela:');
  for (const t of [...biggest[1].missedTitles].sort()) console.log('  -', t);
}

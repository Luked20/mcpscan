// Reproduces skill-inject's own injection procedure (scripts/build_sandbox.py):
//   * line_injection      -> inserted as a new line at task.line_num in the body
//   * description_injection -> appended to the `description:` value in the frontmatter
// One composed skill per (injection, placement), so each is scannable on its own.
import { readdirSync, readFileSync, writeFileSync, mkdirSync, cpSync, existsSync, rmSync } from 'node:fs';
import { join, basename } from 'node:path';

const BENCH = 'E:/temp/skill-inject-bench';
const OUT = process.argv[2];

// --- index the base skills by directory name, at any depth -----------------
const skillDir = new Map();
(function walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const p = join(dir, e.name);
    if (existsSync(join(p, 'SKILL.md'))) skillDir.set(e.name, p);
    walk(p);
  }
})(join(BENCH, 'data/skills'));

// --- the two injection procedures, ported verbatim -------------------------
function injectAtLine(text, instruction, lineNumber) {
  const lines = text.split('\n');
  if (lineNumber < 1 || lineNumber > lines.length + 1) return null;
  lines.splice(lineNumber - 1, 0, instruction);
  return lines.join('\n');
}

function injectIntoDescription(text, instruction) {
  const lines = text.split('\n');
  if (lines[0]?.trim() !== '---') return null;
  // These files are CRLF, so compare trimmed — the closing fence reads "---\r".
  const close = lines.findIndex((l, i) => i > 0 && l.trim() === '---');
  if (close < 0) return null;
  for (let i = 1; i < close; i++) {
    const l = lines[i] ?? '';
    if (!l.startsWith('description:')) continue;
    const trimmed = l.trimEnd();
    // Quoted value: splice in before the closing quote, as build_sandbox.py does.
    const last = trimmed[trimmed.length - 1];
    lines[i] = (last === '"' || last === "'")
      ? trimmed.slice(0, -1) + instruction + last
      : trimmed + instruction;
    return lines.join('\n');
  }
  return null;
}

// --- compose ---------------------------------------------------------------
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const manifest = [];
let skipped = 0;

for (const [set, file] of [['obvious', 'obvious_injections.json'], ['contextual', 'contextual_injections.json']]) {
  const items = JSON.parse(readFileSync(join(BENCH, 'data', file), 'utf8'));
  for (const inj of items) {
    const task = (inj.tasks ?? []).find((t) => t.skill && skillDir.has(t.skill));
    if (!task) { skipped++; continue; }
    const src = skillDir.get(task.skill);
    const original = readFileSync(join(src, 'SKILL.md'), 'utf8');

    for (const placement of ['description', 'line']) {
      const instruction = placement === 'description'
        ? inj.instructions?.description_injection
        : (task.injection_prefix ?? '') + (inj.instructions?.line_injection ?? '');
      if (!instruction) continue;

      const composed = placement === 'description'
        ? injectIntoDescription(original, instruction)
        : injectAtLine(original, instruction, task.line_num);
      if (composed === null) { skipped++; continue; }

      const slug = `${set}-${String(inj.id).padStart(2, '0')}-${placement}`;
      const dir = join(OUT, slug);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'SKILL.md'), composed);

      // Ship the auxiliary scripts the injection references — SKILL003/SKILL004
      // reason about what a skill carries, not only what it says.
      for (const [name, rel] of Object.entries(inj.task_scripts ?? {})) {
        const from = join(BENCH, 'data', rel);
        if (!existsSync(from)) continue;
        mkdirSync(join(dir, 'scripts'), { recursive: true });
        cpSync(from, join(dir, 'scripts', basename(name)));
      }

      manifest.push({ slug, set, id: inj.id, title: inj.title, type: inj.type, placement, skill: task.skill, instruction });
    }
  }
}

writeFileSync(join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 1));
console.log(`compostas ${manifest.length} skills envenenadas (${skipped} puladas) em ${OUT}`);

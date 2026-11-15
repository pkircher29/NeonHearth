/// <reference types="node" />
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// Guards against the two CSS regressions the review found: a `var(--name)` that nothing defines (the declaration
// silently drops, so a state loses its colour), and `var(--x)NN` (hex-alpha glued to a var(), which is invalid CSS).

const root = join(process.cwd(), 'src');
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? files(path) : /\.(svelte|css|ts)$/.test(entry) && !/\.test\.ts$/.test(entry) ? [path] : [];
  });
}
const sources = files(root).map((path) => ({ path: relative(root, path).replaceAll('\\', '/'), text: readFileSync(path, 'utf8') }));
const defined = new Set(sources.flatMap(({ text }) => [...text.matchAll(/(--[a-zA-Z0-9-]+)\s*:/g)].map((match) => match[1]!)));

describe('CSS custom properties', () => {
  it('every var(--name) without a fallback is defined in app.css, ui.css or a component', () => {
    const missing: string[] = [];
    for (const { path, text } of sources) {
      for (const match of text.matchAll(/var\(\s*(--[a-zA-Z0-9-]+)\s*([,)])/g)) {
        if (match[2] === ',') continue; // has a fallback
        if (!defined.has(match[1]!)) missing.push(`${path}: ${match[1]}`);
      }
    }
    expect([...new Set(missing)]).toEqual([]);
  });

  it('never glues a hex alpha onto a var(): use color-mix(in srgb, var(--x) N%, transparent)', () => {
    const bad: string[] = [];
    for (const { path, text } of sources) {
      for (const match of text.matchAll(/var\(\s*--[a-zA-Z0-9-]+\s*\)[0-9a-fA-F]{2}(?![0-9a-fA-F-])/g)) bad.push(`${path}: ${match[0]}`);
    }
    expect(bad).toEqual([]);
  });

  it('the Flow Map palette tokens it probes exist, so the design tokens are not silently ignored', () => {
    for (const name of ['--fire-orange', '--fire-gold', '--fire-violet', '--fire-magenta', '--alert', '--ink', '--muted']) expect(defined.has(name), name).toBe(true);
  });
});

import fs from 'fs';
import path from 'path';
const css = fs.readFileSync(path.join(__dirname, '../../app/globals.css'), 'utf8');
function tokens(theme: 'light' | 'dark') {
  const values: Record<string, string> = {};
  for (const block of css.matchAll(/:root(?:\[data-theme='(light)'\])?\s*\{([^}]*)\}/g)) {
    if (block[1] && theme !== 'light') continue;
    for (const property of block[2].matchAll(/(--[\w-]+):\s*([^;]+);/g)) values[property[1]] = property[2].trim();
  }
  return values;
}
function luminance(hex: string) {
  const channels = hex.replace('#', '').match(/../g)!.map(value => parseInt(value, 16) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
  return .2126 * channels[0] + .7152 * channels[1] + .0722 * channels[2];
}
function ratio(first: string, second: string) { const [a, b] = [luminance(first), luminance(second)].sort((a, b) => b - a); return (a + .05) / (b + .05); }
test.each(['dark', 'light'] as const)('%s semantic text and control tokens meet their contrast targets', theme => {
  const palette = tokens(theme);
  for (const background of ['--bg-base', '--bg-surface', '--bg-surface-raised', '--bg-overlay']) {
    for (const text of ['--text-primary', '--text-secondary', '--text-muted', '--text-link', '--danger']) {
      expect({ theme, text, background, ratio: ratio(palette[text], palette[background]) }.ratio).toBeGreaterThanOrEqual(4.5);
    }
  }
  expect(ratio('#ffffff', palette['--accent'])).toBeGreaterThanOrEqual(4.5);
  expect(ratio(palette['--control-border'], palette['--bg-input'])).toBeGreaterThanOrEqual(3);
  expect(ratio(palette['--focus-ring'], palette['--bg-surface'])).toBeGreaterThanOrEqual(3);
});
test.each(['dark', 'light'] as const)('%s header text remains readable on the dark header and its menus', theme => {
  const palette = tokens(theme);
  for (const block of css.matchAll(/\.od-app-topbar\s*\{([^}]*)\}/g)) {
    for (const property of block[1].matchAll(/(--[\w-]+):\s*([^;]+);/g)) palette[property[1]] = property[2].trim();
  }
  for (const background of ['#1f1f1f', palette['--bg-surface'], palette['--bg-surface-raised']]) {
    for (const text of ['--text-primary', '--text-secondary', '--text-muted', '--text-link', '--danger']) expect(ratio(palette[text], background)).toBeGreaterThanOrEqual(4.5);
  }
  expect(ratio(palette['--control-border'], palette['--bg-input'])).toBeGreaterThanOrEqual(3);
});

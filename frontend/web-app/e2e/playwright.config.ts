import { defineConfig } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Locate the pre-installed Chromium binary under PLAYWRIGHT_BROWSERS_PATH
 * (defaults to /opt/pw-browsers in this container). We do NOT run
 * `playwright install` — the browser is baked into the image already.
 *
 * Prefers the full "chrome" binary (chromium-*) over headless_shell so we
 * get a real Chromium build with the standard DOM/rendering stack.
 */
function findChromiumExecutable(): string {
  const browsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';

  const candidates = [
    // e.g. /opt/pw-browsers/chromium-1194/chrome-linux/chrome
    ...globDirs(browsersPath, /^chromium-\d+$/).map(dir =>
      path.join(browsersPath, dir, 'chrome-linux', 'chrome')
    ),
    // fallback: headless_shell build
    ...globDirs(browsersPath, /^chromium_headless_shell-\d+$/).map(dir =>
      path.join(browsersPath, dir, 'chrome-linux', 'headless_shell')
    ),
    // fallback: the convenience symlink some images ship
    path.join(browsersPath, 'chromium'),
  ];

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }

  throw new Error(
    `Could not find a Chromium executable under PLAYWRIGHT_BROWSERS_PATH=${browsersPath}. ` +
      `Looked at: ${candidates.join(', ')}`
  );
}

function globDirs(base: string, pattern: RegExp): string[] {
  if (!fs.existsSync(base)) return [];
  return fs.readdirSync(base).filter(name => pattern.test(name));
}

export const CHROMIUM_EXECUTABLE_PATH = findChromiumExecutable();

// Port for the ephemeral `next dev` instance the webServer block below spins
// up. Chosen to be unlikely to collide with anything else in the container.
export const E2E_PORT = Number(process.env.E2E_PORT || 3999);
export const E2E_BASE_URL = `http://127.0.0.1:${E2E_PORT}`;

export default defineConfig({
  testDir: './',
  testMatch: '**/*.spec.ts',
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  outputDir: './test-results',

  use: {
    baseURL: E2E_BASE_URL,
    headless: true,
    // Viewport width is deliberately kept BELOW Tailwind's `lg` breakpoint
    // (1024px). The app's sidebar (<aside>) is off-canvas by default
    // (`-translate-x-full`) and only docks on-screen at `lg:translate-x-0`.
    // At lg widths that docked, fixed-position sidebar physically overlaps
    // the DevicesView tab bar (its 240px column sits on top of the "Treiber"
    // tab at x≈150), so any click on the tab lands on a sidebar item instead
    // (empirically: it hit "Benutzer" and navigated to the Users view).
    // Below lg the sidebar is off-canvas, the tab bar is unobstructed, and a
    // normal (non-forced) click works. 1000px is still a comfortable desktop
    // width for the drivers table itself.
    viewport: { width: 1000, height: 900 },
    launchOptions: {
      executablePath: CHROMIUM_EXECUTABLE_PATH,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },

  // Start a real `next dev` server for the test run. No real backend is
  // required — the tests intercept every `/api/**` call via page.route()
  // and serve fixtures, so the Next.js rewrite proxies in next.config.js
  // never actually get hit.
  webServer: {
    command: `npm run dev -- -p ${E2E_PORT}`,
    url: E2E_BASE_URL,
    cwd: path.resolve(__dirname, '..'),
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});

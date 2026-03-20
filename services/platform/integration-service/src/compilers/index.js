'use strict';
// =============================================================================
// OpenDirectory — Policy Compiler (Dispatcher)
// Delegates to platform-specific compilers.
// =============================================================================

const { compileWindows } = require('./WindowsPolicyCompiler');
const { compileLinux } = require('./LinuxPolicyCompiler');
const { compileMacOS } = require('./MacOSPolicyCompiler');
const { compileNetworkDrives } = require('./NetworkDrivesCompiler');
const { compilePrinters } = require('./PrintersCompiler');
const { uuid, now } = require('./helpers');

/**
 * Main compiler entry point.
 * Accepts a platform-agnostic policy and returns compiled artifacts per platform.
 */
function compile(policy) {
  const platforms = policy.targets?.platforms || ['windows', 'linux', 'macos'];
  const result = {
    policy_id: policy.id,
    policy_name: policy.name,
    version: policy.version || '1.0',
    compiled_at: new Date().toISOString(),
    artifacts: {},
  };

  if (platforms.includes('windows') || platforms.includes('all')) {
    result.artifacts.windows = compileWindows(policy);
  }
  if (platforms.includes('linux') || platforms.includes('all')) {
    result.artifacts.linux = compileLinux(policy);
  }
  if (platforms.includes('macos') || platforms.includes('all')) {
    result.artifacts.macos = compileMacOS(policy);
  }

  // Network drives and printers are compiled separately (cross-platform)
  if (policy.settings?.networkDrives?.length) {
    const driveArtifacts = compileNetworkDrives(policy);
    for (const plat of Object.keys(driveArtifacts)) {
      if (result.artifacts[plat]) {
        result.artifacts[plat].push(...driveArtifacts[plat]);
      }
    }
  }

  if (policy.settings?.printers?.length) {
    const printerArtifacts = compilePrinters(policy);
    for (const plat of Object.keys(printerArtifacts)) {
      if (result.artifacts[plat]) {
        result.artifacts[plat].push(...printerArtifacts[plat]);
      }
    }
  }

  return result;
}

module.exports = { compile, compileWindows, compileLinux, compileMacOS, compileNetworkDrives, compilePrinters };

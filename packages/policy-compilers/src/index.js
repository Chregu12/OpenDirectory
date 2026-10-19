'use strict';
// =============================================================================
// @opendirectory/policy-compilers
//
// Shared Policy Compiler package — re-exports all compiler modules so that
// any service can depend on this package instead of importing directly from
// services/platform/integration-service/src/compilers (which violates
// microservice boundaries).
// =============================================================================

const { compileWindows, WindowsPolicyCompiler } = require('./WindowsPolicyCompiler');
const { compileLinux, LinuxPolicyCompiler } = require('./LinuxPolicyCompiler');
const { compileMacOS, MacOSPolicyCompiler } = require('./MacOSPolicyCompiler');
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

module.exports = {
  compile, compileWindows, compileLinux, compileMacOS, compileNetworkDrives, compilePrinters,
  // RSoP (Resultant Set of Policy) class-based compilers: consume the merged/flattened
  // output of an RSOP engine and return a structured effective-settings payload, as
  // opposed to the compile*() functions above which turn authored policy.settings into
  // deployable file artifacts. See the class doc-comments in each compiler module.
  WindowsPolicyCompiler, LinuxPolicyCompiler, MacOSPolicyCompiler,
};

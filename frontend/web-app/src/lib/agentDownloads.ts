export const agentPackageVersion = '1.5.0';
const release = `https://github.com/Chregu12/OpenDirectory/releases/download/agent-v${agentPackageVersion}/`;
const packages = [
 { platform: 'linux', architecture: 'x86_64', label: 'Linux · x64', extension: 'tar.gz' },
 { platform: 'linux', architecture: 'aarch64', label: 'Linux · ARM64', extension: 'tar.gz' },
 { platform: 'macos', architecture: 'x86_64', label: 'macOS · Intel', extension: 'tar.gz' },
 { platform: 'macos', architecture: 'aarch64', label: 'macOS · Apple Silicon', extension: 'tar.gz' },
 { platform: 'windows', architecture: 'x86_64', label: 'Windows · x64', extension: 'zip' },
];
export function agentDownloads(platform: string) {
 return packages.filter(item => item.platform === platform).map(item => ({ ...item, href: release + `opendirectory-agent-${agentPackageVersion}-${item.platform}-${item.architecture}.${item.extension}` }));
}
export const agentInstallGuide = `https://github.com/Chregu12/OpenDirectory/blob/agent-v${agentPackageVersion}/agent-rust/PACKAGE-README.md`;

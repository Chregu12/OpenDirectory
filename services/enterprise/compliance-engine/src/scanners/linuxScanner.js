'use strict';

/**
 * LinuxScanner – defines Linux-specific compliance check definitions for
 * CIS, BSI and custom baselines.
 */
class LinuxScanner {
  constructor({ logger }) {
    this.logger = logger;

    this.checkCatalog = {
      // ---------------------------------------------------------------
      // Sysctl parameter checks
      // ---------------------------------------------------------------
      sysctl: [
        {
          id: 'linux-sysctl-ip-forward',
          title: 'IP forwarding disabled',
          category: 'Network Hardening',
          severity: 'high',
          check: { type: 'sysctl', key: 'net.ipv4.ip_forward', operator: '==', value: 0 },
          remediation: { type: 'sysctl_set', key: 'net.ipv4.ip_forward', value: 0 },
        },
        {
          id: 'linux-sysctl-icmp-redirects',
          title: 'ICMP redirects not accepted',
          category: 'Network Hardening',
          severity: 'medium',
          check: { type: 'sysctl', key: 'net.ipv4.conf.all.accept_redirects', operator: '==', value: 0 },
          remediation: { type: 'sysctl_set', key: 'net.ipv4.conf.all.accept_redirects', value: 0 },
        },
        {
          id: 'linux-sysctl-syn-cookies',
          title: 'TCP SYN cookies enabled',
          category: 'Network Hardening',
          severity: 'high',
          check: { type: 'sysctl', key: 'net.ipv4.tcp_syncookies', operator: '==', value: 1 },
          remediation: { type: 'sysctl_set', key: 'net.ipv4.tcp_syncookies', value: 1 },
        },
        {
          id: 'linux-sysctl-aslr',
          title: 'Address Space Layout Randomization (ASLR) enabled',
          category: 'Kernel Hardening',
          severity: 'critical',
          check: { type: 'sysctl', key: 'kernel.randomize_va_space', operator: '==', value: 2 },
          remediation: { type: 'sysctl_set', key: 'kernel.randomize_va_space', value: 2 },
        },
        {
          id: 'linux-sysctl-core-dumps',
          title: 'Core dumps restricted',
          category: 'Kernel Hardening',
          severity: 'medium',
          check: { type: 'sysctl', key: 'fs.suid_dumpable', operator: '==', value: 0 },
          remediation: { type: 'sysctl_set', key: 'fs.suid_dumpable', value: 0 },
        },
      ],

      // ---------------------------------------------------------------
      // Service status (systemd)
      // ---------------------------------------------------------------
      services: [
        {
          id: 'linux-svc-sshd-running',
          title: 'SSH daemon running (if required)',
          category: 'Remote Access',
          severity: 'low',
          check: { type: 'service_status', name: 'sshd', operator: '==', value: 'running' },
          remediation: { type: 'systemd_start', name: 'sshd' },
        },
        {
          id: 'linux-svc-cron-running',
          title: 'Cron daemon running',
          category: 'System Services',
          severity: 'medium',
          check: { type: 'service_status', name: 'cron', operator: '==', value: 'running' },
          remediation: { type: 'systemd_start', name: 'cron' },
        },
        {
          id: 'linux-svc-auditd-running',
          title: 'Audit daemon running',
          category: 'Audit',
          severity: 'high',
          check: { type: 'service_status', name: 'auditd', operator: '==', value: 'running' },
          remediation: { type: 'systemd_start', name: 'auditd' },
        },
        {
          id: 'linux-svc-avahi-disabled',
          title: 'Avahi daemon disabled',
          category: 'Service Hardening',
          severity: 'medium',
          check: { type: 'service_status', name: 'avahi-daemon', operator: '==', value: 'disabled' },
          remediation: { type: 'systemd_disable', name: 'avahi-daemon' },
        },
      ],

      // ---------------------------------------------------------------
      // Firewall rules (iptables / nftables / ufw)
      // ---------------------------------------------------------------
      firewall: [
        {
          id: 'linux-fw-enabled',
          title: 'Firewall enabled (ufw/iptables/nftables)',
          category: 'Firewall',
          severity: 'critical',
          check: { type: 'firewall', profile: 'enabled', operator: '==', value: true },
          remediation: { type: 'command', command: 'sudo ufw enable' },
        },
        {
          id: 'linux-fw-default-deny',
          title: 'Default firewall policy is deny incoming',
          category: 'Firewall',
          severity: 'high',
          check: { type: 'firewall', profile: 'default_incoming', operator: '==', value: 'deny' },
          remediation: { type: 'command', command: 'sudo ufw default deny incoming' },
        },
      ],

      // ---------------------------------------------------------------
      // LUKS encryption
      // ---------------------------------------------------------------
      encryption: [
        {
          id: 'linux-enc-luks',
          title: 'Disk encryption (LUKS) enabled on root volume',
          category: 'Encryption',
          severity: 'critical',
          check: { type: 'encryption', target: 'root', operator: '==', value: true },
          remediation: { type: 'manual', instructions: 'Re-install with full disk encryption or use cryptsetup to encrypt' },
        },
      ],

      // ---------------------------------------------------------------
      // SELinux / AppArmor
      // ---------------------------------------------------------------
      mac: [
        {
          id: 'linux-mac-selinux-enforcing',
          title: 'SELinux in Enforcing mode (RHEL/CentOS)',
          category: 'Mandatory Access Control',
          severity: 'critical',
          check: { type: 'selinux', operator: '==', value: 'Enforcing' },
          remediation: { type: 'command', command: 'sudo setenforce 1 && sudo sed -i "s/SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config' },
        },
        {
          id: 'linux-mac-apparmor-enabled',
          title: 'AppArmor enabled (Debian/Ubuntu)',
          category: 'Mandatory Access Control',
          severity: 'critical',
          check: { type: 'apparmor', operator: '==', value: true },
          remediation: { type: 'command', command: 'sudo systemctl enable apparmor && sudo systemctl start apparmor' },
        },
      ],

      // ---------------------------------------------------------------
      // SSH configuration
      // ---------------------------------------------------------------
      ssh: [
        {
          id: 'linux-ssh-root-login',
          title: 'SSH root login disabled',
          category: 'SSH',
          severity: 'critical',
          check: { type: 'file_content', path: '/etc/ssh/sshd_config', key: 'PermitRootLogin', operator: '==', value: 'no' },
          remediation: { type: 'file_edit', path: '/etc/ssh/sshd_config', key: 'PermitRootLogin', value: 'no' },
        },
        {
          id: 'linux-ssh-password-auth',
          title: 'SSH password authentication disabled',
          category: 'SSH',
          severity: 'high',
          check: { type: 'file_content', path: '/etc/ssh/sshd_config', key: 'PasswordAuthentication', operator: '==', value: 'no' },
          remediation: { type: 'file_edit', path: '/etc/ssh/sshd_config', key: 'PasswordAuthentication', value: 'no' },
        },
        {
          id: 'linux-ssh-x11-forwarding',
          title: 'SSH X11 forwarding disabled',
          category: 'SSH',
          severity: 'medium',
          check: { type: 'file_content', path: '/etc/ssh/sshd_config', key: 'X11Forwarding', operator: '==', value: 'no' },
          remediation: { type: 'file_edit', path: '/etc/ssh/sshd_config', key: 'X11Forwarding', value: 'no' },
        },
        {
          id: 'linux-ssh-max-auth-tries',
          title: 'SSH MaxAuthTries <= 4',
          category: 'SSH',
          severity: 'medium',
          check: { type: 'file_content', path: '/etc/ssh/sshd_config', key: 'MaxAuthTries', operator: '<=', value: 4 },
          remediation: { type: 'file_edit', path: '/etc/ssh/sshd_config', key: 'MaxAuthTries', value: '4' },
        },
        {
          id: 'linux-ssh-protocol',
          title: 'SSH Protocol version 2 only',
          category: 'SSH',
          severity: 'high',
          check: { type: 'file_content', path: '/etc/ssh/sshd_config', key: 'Protocol', operator: '==', value: '2' },
          remediation: { type: 'file_edit', path: '/etc/ssh/sshd_config', key: 'Protocol', value: '2' },
        },
      ],

      // ---------------------------------------------------------------
      // PAM settings
      // ---------------------------------------------------------------
      pam: [
        {
          id: 'linux-pam-password-quality',
          title: 'Password quality enforcement (pam_pwquality)',
          category: 'Authentication',
          severity: 'high',
          check: { type: 'pam', module: 'pam_pwquality', key: 'minlen', operator: '>=', value: 14 },
          remediation: { type: 'pam_config', module: 'pam_pwquality', key: 'minlen', value: 14 },
        },
        {
          id: 'linux-pam-faillock',
          title: 'Account lockout after 5 failed attempts',
          category: 'Authentication',
          severity: 'high',
          check: { type: 'pam', module: 'pam_faillock', key: 'deny', operator: '<=', value: 5 },
          remediation: { type: 'pam_config', module: 'pam_faillock', key: 'deny', value: 5 },
        },
      ],

      // ---------------------------------------------------------------
      // File permissions
      // ---------------------------------------------------------------
      permissions: [
        {
          id: 'linux-perm-passwd',
          title: '/etc/passwd permissions are 644',
          category: 'File Permissions',
          severity: 'high',
          check: { type: 'file_permissions', path: '/etc/passwd', operator: '==', value: '644' },
          remediation: { type: 'command', command: 'sudo chmod 644 /etc/passwd' },
        },
        {
          id: 'linux-perm-shadow',
          title: '/etc/shadow permissions are 640 or stricter',
          category: 'File Permissions',
          severity: 'critical',
          check: { type: 'file_permissions', path: '/etc/shadow', operator: '<=', value: '640' },
          remediation: { type: 'command', command: 'sudo chmod 640 /etc/shadow' },
        },
        {
          id: 'linux-perm-crontab',
          title: '/etc/crontab permissions are 600',
          category: 'File Permissions',
          severity: 'medium',
          check: { type: 'file_permissions', path: '/etc/crontab', operator: '==', value: '600' },
          remediation: { type: 'command', command: 'sudo chmod 600 /etc/crontab' },
        },
      ],

      // ---------------------------------------------------------------
      // Package update compliance
      // ---------------------------------------------------------------
      updates: [
        {
          id: 'linux-upd-compliant',
          title: 'All security updates installed',
          category: 'Patch Management',
          severity: 'critical',
          check: { type: 'software_update', operator: '==', value: true },
          remediation: { type: 'command', command: 'sudo apt-get update && sudo apt-get upgrade -y' },
        },
      ],
    };
  }

  getChecksForBaseline(baselineId) {
    const allChecks = [];
    for (const category of Object.values(this.checkCatalog)) {
      allChecks.push(...category);
    }
    return allChecks;
  }

  getChecksByCategory(category) {
    return this.checkCatalog[category] || [];
  }

  getCategories() {
    return Object.keys(this.checkCatalog);
  }
}

module.exports = LinuxScanner;

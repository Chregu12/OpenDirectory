'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * Compiles merged RSoP results into Linux-native configuration formats:
 * - sysctl settings
 * - PAM password / auth configuration
 * - systemd unit overrides
 * - iptables / nftables firewall rules
 * - LUKS / dm-crypt encryption directives
 * - SSH daemon configuration
 * - unattended-upgrades / dnf-automatic settings
 */
class LinuxPolicyCompiler {
  /**
   * Compile the full RSoP result into a Linux-native payload.
   *
   * @param {object} rsopResult - Output from RSOPEngine.calculateRSOP()
   * @returns {object} Linux-formatted policy payload
   */
  compile(rsopResult) {
    const { settings, sources, appliedPolicies } = rsopResult;

    logger.info('Compiling RSoP for Linux', {
      settingCount: Object.keys(settings).length,
      policyCount: appliedPolicies.length
    });

    return {
      platform: 'linux',
      compiledAt: new Date().toISOString(),
      sysctl: this.compileSysctl(settings),
      pam: this.compilePAM(settings),
      systemd: this.compileSystemd(settings),
      firewall: this.compileFirewall(settings),
      encryption: this.compileEncryption(settings),
      ssh: this.compileSSH(settings),
      updates: this.compileUpdates(settings),
      users: this.compileUserPolicy(settings),
      sources
    };
  }

  /**
   * Compile sysctl kernel parameters.
   */
  compileSysctl(settings) {
    const params = {};

    // Network hardening
    if (settings['network.ipForwarding'] !== undefined) {
      params['net.ipv4.ip_forward'] = settings['network.ipForwarding'] ? 1 : 0;
    }
    if (settings['network.icmpRedirects'] !== undefined) {
      params['net.ipv4.conf.all.accept_redirects'] = settings['network.icmpRedirects'] ? 1 : 0;
      params['net.ipv6.conf.all.accept_redirects'] = settings['network.icmpRedirects'] ? 1 : 0;
    }
    if (settings['network.sourceRouting'] !== undefined) {
      params['net.ipv4.conf.all.accept_source_route'] = settings['network.sourceRouting'] ? 1 : 0;
    }
    if (settings['network.synCookies'] !== undefined) {
      params['net.ipv4.tcp_syncookies'] = settings['network.synCookies'] ? 1 : 0;
    }
    if (settings['network.rpFilter'] !== undefined) {
      params['net.ipv4.conf.all.rp_filter'] = settings['network.rpFilter'] ? 1 : 0;
    }

    // Kernel hardening
    if (settings['kernel.sysrq'] !== undefined) {
      params['kernel.sysrq'] = Number(settings['kernel.sysrq']);
    }
    if (settings['kernel.coreDumps'] !== undefined) {
      params['fs.suid_dumpable'] = settings['kernel.coreDumps'] ? 1 : 0;
    }
    if (settings['kernel.aslr'] !== undefined) {
      params['kernel.randomize_va_space'] = settings['kernel.aslr'] ? 2 : 0;
    }
    if (settings['kernel.dmesgRestrict'] !== undefined) {
      params['kernel.dmesg_restrict'] = settings['kernel.dmesgRestrict'] ? 1 : 0;
    }
    if (settings['kernel.kptrRestrict'] !== undefined) {
      params['kernel.kptr_restrict'] = settings['kernel.kptrRestrict'] ? 2 : 0;
    }

    // Pass-through sysctl settings
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('sysctl.')) {
        const param = key.replace('sysctl.', '').replace(/\./g, '.');
        params[param] = value;
      }
    }

    return params;
  }

  /**
   * Compile PAM (Pluggable Authentication Modules) password policy.
   */
  compilePAM(settings) {
    return {
      passwordQuality: {
        minlen: settings['password.minLength'] || 12,
        dcredit: settings['password.requireDigit'] !== false ? -1 : 0,
        ucredit: settings['password.requireUppercase'] !== false ? -1 : 0,
        lcredit: settings['password.requireLowercase'] !== false ? -1 : 0,
        ocredit: settings['password.requireSymbol'] !== false ? -1 : 0,
        minclass: settings['password.minClasses'] || 3,
        maxrepeat: settings['password.maxRepeat'] || 3,
        maxclassrepeat: settings['password.maxClassRepeat'] || 4,
        dictcheck: settings['password.dictionaryCheck'] !== false ? 1 : 0,
        enforcing: settings['password.complexity'] !== false ? 1 : 0
      },
      passwordHistory: {
        remember: settings['password.history'] || 24
      },
      accountLockout: {
        deny: settings['lockout.threshold'] || 5,
        unlockTime: (settings['lockout.duration'] || 30) * 60,
        failInterval: (settings['lockout.window'] || 30) * 60,
        evenDenyRoot: settings['lockout.lockRoot'] || false
      },
      passwordAging: {
        maxDays: settings['password.maxAge'] || 90,
        minDays: settings['password.minAge'] || 1,
        warnDays: settings['password.warnAge'] || 14
      },
      sessionLimits: {
        maxLogins: settings['session.maxLogins'] || 10,
        maxSystemLogins: settings['session.maxSystemLogins'] || 64
      }
    };
  }

  /**
   * Compile systemd service configurations.
   */
  compileSystemd(settings) {
    const services = {};

    // SSH daemon
    if (settings['ssh.enabled'] !== undefined) {
      services['sshd'] = {
        enabled: settings['ssh.enabled'],
        state: settings['ssh.enabled'] ? 'started' : 'stopped'
      };
    }

    // Firewall
    if (settings['firewall.enabled'] !== undefined) {
      services['firewalld'] = {
        enabled: settings['firewall.enabled'],
        state: settings['firewall.enabled'] ? 'started' : 'stopped'
      };
    }

    // Automatic updates
    if (settings['updates.autoInstall'] !== undefined) {
      services['unattended-upgrades'] = {
        enabled: settings['updates.autoInstall'],
        state: settings['updates.autoInstall'] ? 'started' : 'stopped'
      };
    }

    // Audit daemon
    if (settings['audit.enabled'] !== undefined) {
      services['auditd'] = {
        enabled: settings['audit.enabled'],
        state: settings['audit.enabled'] ? 'started' : 'stopped'
      };
    }

    // Pass-through service settings
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('systemd.')) {
        const parts = key.replace('systemd.', '').split('.');
        const svc = parts[0];
        const prop = parts.slice(1).join('.');
        if (!services[svc]) services[svc] = {};
        services[svc][prop] = value;
      }
    }

    return services;
  }

  /**
   * Compile iptables/nftables firewall rules.
   */
  compileFirewall(settings) {
    const config = {
      enabled: settings['firewall.enabled'] !== undefined ? settings['firewall.enabled'] : true,
      backend: settings['firewall.backend'] || 'nftables',
      defaultInputPolicy: settings['firewall.defaultInbound'] || 'drop',
      defaultOutputPolicy: settings['firewall.defaultOutbound'] || 'accept',
      defaultForwardPolicy: settings['firewall.defaultForward'] || 'drop',
      rules: []
    };

    // Always allow loopback and established connections
    config.rules.push(
      { chain: 'input', rule: '-i lo -j ACCEPT', comment: 'Allow loopback' },
      { chain: 'input', rule: '-m state --state ESTABLISHED,RELATED -j ACCEPT', comment: 'Allow established' }
    );

    // SSH
    if (settings['ssh.enabled'] !== false) {
      const sshPort = settings['ssh.port'] || 22;
      config.rules.push({
        chain: 'input',
        rule: `-p tcp --dport ${sshPort} -j ACCEPT`,
        comment: `Allow SSH on port ${sshPort}`
      });
    }

    // Custom firewall rules
    const ruleEntries = {};
    for (const [key, value] of Object.entries(settings)) {
      if (key.startsWith('firewall.rules.')) {
        const parts = key.replace('firewall.rules.', '').split('.');
        const ruleId = parts[0];
        const prop = parts.slice(1).join('.');
        if (!ruleEntries[ruleId]) ruleEntries[ruleId] = {};
        ruleEntries[ruleId][prop] = value;
      }
    }

    for (const [id, rule] of Object.entries(ruleEntries)) {
      const chain = rule.direction === 'outbound' ? 'output' : 'input';
      const action = rule.action === 'block' ? 'DROP' : 'ACCEPT';
      let iptRule = '';

      if (rule.protocol) iptRule += `-p ${rule.protocol} `;
      if (rule.localPort) iptRule += `--dport ${rule.localPort} `;
      if (rule.remoteAddress) iptRule += `-s ${rule.remoteAddress} `;
      iptRule += `-j ${action}`;

      config.rules.push({
        chain,
        rule: iptRule.trim(),
        comment: rule.name || id
      });
    }

    return config;
  }

  /**
   * Compile LUKS/dm-crypt encryption settings.
   */
  compileEncryption(settings) {
    return {
      luks: {
        required: settings['encryption.required'] !== false,
        algorithm: settings['encryption.algorithm'] || 'AES-256',
        cipher: settings['encryption.cipher'] || 'aes-xts-plain64',
        keySize: settings['encryption.keySize'] || 512,
        hash: settings['encryption.hash'] || 'sha256',
        iterTime: settings['encryption.iterTime'] || 5000,
        escrowServer: settings['encryption.escrowServer'] || null
      }
    };
  }

  /**
   * Compile SSH daemon (sshd_config) settings.
   */
  compileSSH(settings) {
    return {
      port: settings['ssh.port'] || 22,
      permitRootLogin: settings['ssh.permitRootLogin'] || 'no',
      passwordAuthentication: settings['ssh.passwordAuth'] !== undefined
        ? (settings['ssh.passwordAuth'] ? 'yes' : 'no')
        : 'no',
      pubkeyAuthentication: 'yes',
      maxAuthTries: settings['ssh.maxAuthTries'] || 3,
      loginGraceTime: settings['ssh.loginGraceTime'] || 60,
      clientAliveInterval: settings['ssh.clientAliveInterval'] || 300,
      clientAliveCountMax: settings['ssh.clientAliveCountMax'] || 3,
      allowTcpForwarding: settings['ssh.allowTcpForwarding'] !== undefined
        ? (settings['ssh.allowTcpForwarding'] ? 'yes' : 'no')
        : 'no',
      x11Forwarding: settings['ssh.x11Forwarding'] !== undefined
        ? (settings['ssh.x11Forwarding'] ? 'yes' : 'no')
        : 'no',
      protocol: 2,
      useDNS: 'no',
      banner: settings['ssh.banner'] || '/etc/issue.net',
      allowUsers: settings['ssh.allowUsers'] || null,
      allowGroups: settings['ssh.allowGroups'] || null
    };
  }

  /**
   * Compile automatic update settings (unattended-upgrades / dnf-automatic).
   */
  compileUpdates(settings) {
    return {
      autoInstall: settings['updates.autoInstall'] !== false,
      securityOnly: settings['updates.securityOnly'] || false,
      autoReboot: settings['updates.autoReboot'] || false,
      rebootTime: settings['updates.rebootTime'] || '03:00',
      maxDeferDays: settings['updates.maxDeferDays'] || 7,
      blacklist: settings['updates.blacklist'] || [],
      mailReport: settings['updates.mailReport'] || null,
      removeUnused: settings['updates.removeUnused'] !== false
    };
  }

  /**
   * Compile user/group policy settings.
   */
  compileUserPolicy(settings) {
    return {
      umask: settings['users.umask'] || '027',
      shellTimeout: settings['users.shellTimeout'] || 900,
      loginDefs: {
        passMaxDays: settings['password.maxAge'] || 90,
        passMinDays: settings['password.minAge'] || 1,
        passWarnAge: settings['password.warnAge'] || 14,
        passMinLen: settings['password.minLength'] || 12,
        loginRetries: settings['lockout.threshold'] || 5,
        loginTimeout: settings['lockout.loginTimeout'] || 60
      },
      secureTTY: settings['users.secureTTY'] || ['tty1'],
      suRestrict: settings['users.suRestrictGroup'] || 'wheel'
    };
  }
}

module.exports = { LinuxPolicyCompiler };

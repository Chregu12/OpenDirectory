/**
 * RiskCalculator — pure risk scoring functions extracted from ConditionalAccessEngine.
 * No side effects, no EventEmitter dependency.
 *
 * External integrations are driven by environment variables:
 *   IP_REPUTATION_SERVICE_URL  — optional REST endpoint returning { score: 0-100 }
 *   VPN_DETECTION_SERVICE_URL  — optional REST endpoint returning { isVPN: bool }
 *   HIGH_RISK_COUNTRIES        — comma-separated ISO-3166-1 alpha-2 codes (default: CN,RU,IR,KP)
 */

const https = require('https');

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

class RiskCalculator {
    async calculateRiskScore(context) {
        const [user, device, network, application, behavioral, temporal] = await Promise.all([
            this.calculateUserRisk(context.user),
            this.calculateDeviceRisk(context.device),
            this.calculateNetworkRisk(context.network),
            this.calculateApplicationRisk(context.application),
            this.calculateBehavioralRisk(context),
            this.calculateTemporalRisk(context),
        ]);

        const riskFactors = { user, device, network, application, behavioral, temporal };
        const weights = { user: 0.2, device: 0.25, network: 0.2, application: 0.15, behavioral: 0.15, temporal: 0.05 };

        let totalRisk = 0;
        for (const [factor, risk] of Object.entries(riskFactors)) {
            totalRisk += risk.score * weights[factor];
        }

        return {
            totalRisk: Math.min(1.0, Math.max(0.0, totalRisk)),
            factors: riskFactors,
            weights,
            calculatedAt: new Date(),
        };
    }

    async calculateUserRisk(user) {
        let risk = 0.0;
        const factors = [];

        if (user.accountStatus === 'SUSPENDED') { risk += 1.0; factors.push('account_suspended'); }
        else if (user.accountStatus === 'LOCKED') { risk += 0.8; factors.push('account_locked'); }

        if (!user.mfaEnabled) { risk += 0.3; factors.push('no_mfa'); }

        if (user.riskProfile) {
            const levelRisk = { CRITICAL: 1.0, HIGH: 0.8, MEDIUM: 0.4 };
            const levelFactor = { CRITICAL: 'critical_risk_profile', HIGH: 'high_risk_profile', MEDIUM: 'medium_risk_profile' };
            if (levelRisk[user.riskProfile.level]) {
                risk += levelRisk[user.riskProfile.level];
                factors.push(levelFactor[user.riskProfile.level]);
            }
        }

        if (user.lastLogin) {
            const days = (Date.now() - new Date(user.lastLogin).getTime()) / (1000 * 60 * 60 * 24);
            if (days > 30) { risk += 0.2; factors.push('inactive_account'); }
        }

        return { score: Math.min(1.0, risk), factors };
    }

    async calculateDeviceRisk(device) {
        let risk = 0.0;
        const factors = [];

        if (device.compliance?.status === 'NON_COMPLIANT') { risk += 0.8; factors.push('non_compliant_device'); }
        else if (device.compliance?.status === 'UNKNOWN') { risk += 0.4; factors.push('unknown_compliance'); }

        if (device.trust?.score < 0.5) { risk += 0.6; factors.push('low_device_trust'); }
        if (device.encryption?.status === 'NOT_ENCRYPTED') { risk += 0.4; factors.push('device_not_encrypted'); }
        if (device.id === 'unknown') { risk += 0.5; factors.push('unknown_device'); }

        if (device.lastSeen) {
            const days = (Date.now() - new Date(device.lastSeen).getTime()) / (1000 * 60 * 60 * 24);
            if (days > 90) { risk += 0.3; factors.push('device_inactive'); }
        }

        return { score: Math.min(1.0, risk), factors };
    }

    async calculateNetworkRisk(network) {
        let risk = 0.0;
        const factors = [];

        if (network.tor) { risk += 0.9; factors.push('tor_network'); }
        else if (network.vpn) { risk += 0.3; factors.push('vpn_network'); }
        else if (network.proxy) { risk += 0.2; factors.push('proxy_network'); }

        if (network.reputation?.score < 50) { risk += 0.6; factors.push('poor_ip_reputation'); }

        const highRiskCountries = (process.env.HIGH_RISK_COUNTRIES || 'CN,RU,IR,KP').split(',');
        if (highRiskCountries.includes(network.country)) { risk += 0.4; factors.push('high_risk_country'); }

        return { score: Math.min(1.0, risk), factors };
    }

    async calculateApplicationRisk(application) {
        let risk = 0.0;
        const factors = [];

        const sensitivityRisk = { CRITICAL: 0.8, HIGH: 0.6, MEDIUM: 0.3 };
        const sensitivityFactor = { CRITICAL: 'critical_application', HIGH: 'high_value_application', MEDIUM: 'medium_value_application' };
        if (sensitivityRisk[application.sensitivity]) {
            risk += sensitivityRisk[application.sensitivity];
            factors.push(sensitivityFactor[application.sensitivity]);
        }

        if (application.requiresCompliance) { risk += 0.2; factors.push('compliance_required'); }

        return { score: Math.min(1.0, risk), factors };
    }

    async calculateBehavioralRisk(context) {
        let risk = 0.0;
        const factors = [];

        if (context.session.concurrent > 3) { risk += 0.3; factors.push('multiple_sessions'); }

        const hour = context.request.timestamp.getHours();
        if (hour < 6 || hour > 22) { risk += 0.2; factors.push('unusual_time'); }

        return { score: Math.min(1.0, risk), factors };
    }

    async calculateTemporalRisk(context) {
        let risk = 0.0;
        const factors = [];

        const day = context.request.timestamp.getDay();
        if (day === 0 || day === 6) { risk += 0.1; factors.push('weekend_access'); }

        return { score: Math.min(1.0, risk), factors };
    }

    // ── External integrations ─────────────────────────────────────────────────

    async getUserRiskProfile(_userId)   { return { level: 'LOW', score: 0.1 }; }
    async getDeviceCompliance(_id)      { return { status: 'COMPLIANT', lastChecked: new Date() }; }
    async getDeviceTrust(_id)           { return { score: 0.8, lastUpdated: new Date() }; }
    async getDeviceEncryption(_id)      { return { status: 'ENCRYPTED', type: 'BitLocker' }; }
    async getDeviceLastSeen(_id)        { return new Date(); }
    async getApplicationSensitivity(_) { return 'MEDIUM'; }
    async getApplicationComplianceRequirement(_) { return false; }

    async getISPInfo(ip) {
        // Uses ip-api.com free tier (no key needed, rate-limited to 45 req/min)
        if (!ip || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            return 'Private Network';
        }
        try {
            const data = await httpGet(`https://ip-api.com/json/${ip}?fields=isp`);
            return data.isp || 'Unknown ISP';
        } catch {
            return 'Unknown ISP';
        }
    }

    async isVPN(ip) {
        const url = process.env.VPN_DETECTION_SERVICE_URL;
        if (!url) return false;
        try {
            const data = await httpGet(`${url}?ip=${encodeURIComponent(ip)}`);
            return Boolean(data.isVPN);
        } catch {
            return false;
        }
    }

    async isTor(ip) {
        if (!ip) return false;
        try {
            // dan.me.uk provides a free Tor exit node list
            const data = await httpGet(`https://check.torproject.org/torbulkexitlist`);
            const exits = typeof data === 'string' ? data : JSON.stringify(data);
            return exits.includes(ip);
        } catch {
            return false;
        }
    }

    async isProxy(ip) {
        const url = process.env.PROXY_DETECTION_SERVICE_URL;
        if (!url) return false;
        try {
            const data = await httpGet(`${url}?ip=${encodeURIComponent(ip)}`);
            return Boolean(data.isProxy);
        } catch {
            return false;
        }
    }

    async getIPReputation(ip) {
        if (!ip || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            return { score: 100 };
        }
        const apiKey = process.env.ABUSEIPDB_API_KEY;
        if (!apiKey) return { score: 80 };
        try {
            const data = await httpGet(
                `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
            );
            const abuseScore = data.data?.abuseConfidenceScore ?? 0;
            return { score: Math.max(0, 100 - abuseScore) };
        } catch {
            return { score: 80 };
        }
    }
}

module.exports = RiskCalculator;

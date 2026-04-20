/**
 * ConditionEvaluator — pure condition-checking functions extracted from ConditionalAccessEngine.
 * No side effects, no external dependencies.
 */

class ConditionEvaluator {
    evaluateUserConditions(conditions, user) {
        const failed = [];
        let met = true;

        if (conditions.riskLevel && !conditions.riskLevel.includes(user.riskProfile?.level)) {
            met = false; failed.push('user_risk_level');
        }
        if (conditions.roles && !conditions.roles.some(r => user.roles.includes(r))) {
            met = false; failed.push('user_roles');
        }
        if (conditions.groups && !conditions.groups.some(g => user.groups.includes(g))) {
            met = false; failed.push('user_groups');
        }

        return { met, failed };
    }

    evaluateDeviceConditions(conditions, device) {
        const failed = [];
        let met = true;

        if (conditions.compliance && !conditions.compliance.includes(device.compliance?.status)) {
            met = false; failed.push('device_compliance');
        }
        if (conditions.trust && device.trust?.score < conditions.trust.minimum) {
            met = false; failed.push('device_trust');
        }
        if (conditions.encryption && !conditions.encryption.includes(device.encryption?.status)) {
            met = false; failed.push('device_encryption');
        }

        return { met, failed };
    }

    evaluateLocationConditions(conditions, network) {
        const failed = [];
        let met = true;

        if (conditions.countries) {
            if (conditions.countries.blocked?.includes(network.country)) { met = false; failed.push('blocked_country'); }
            if (conditions.countries.allowed && !conditions.countries.allowed.includes(network.country)) {
                met = false; failed.push('country_not_allowed');
            }
        }
        if (conditions.anonymousNetworks === true && (network.vpn || network.tor || network.proxy)) {
            met = false; failed.push('anonymous_network');
        }
        if (conditions.ipReputation && network.reputation?.score < conditions.ipReputation.minimum) {
            met = false; failed.push('poor_ip_reputation');
        }

        return { met, failed };
    }

    evaluateApplicationConditions(conditions, application) {
        const failed = [];
        let met = true;

        if (conditions.sensitivity && !conditions.sensitivity.includes(application.sensitivity)) {
            met = false; failed.push('application_sensitivity');
        }
        if (conditions.requiresCompliance && application.requiresCompliance) {
            met = false; failed.push('application_compliance_required');
        }

        return { met, failed };
    }

    evaluateRiskConditions(conditions, riskAssessment) {
        const failed = [];
        let met = true;

        if (conditions.maximum && riskAssessment.totalRisk > conditions.maximum) { met = false; failed.push('risk_too_high'); }
        if (conditions.minimum && riskAssessment.totalRisk < conditions.minimum) { met = false; failed.push('risk_too_low'); }

        return { met, failed };
    }

    evaluateTimeConditions(conditions, timestamp) {
        const failed = [];
        let met = true;
        const now = new Date(timestamp);
        const hour = now.getHours();
        const day = now.getDay();

        if (conditions.allowedHours && !conditions.allowedHours.includes(hour)) { met = false; failed.push('outside_allowed_hours'); }
        if (conditions.allowedDays && !conditions.allowedDays.includes(day)) { met = false; failed.push('outside_allowed_days'); }

        return { met, failed };
    }
}

module.exports = ConditionEvaluator;

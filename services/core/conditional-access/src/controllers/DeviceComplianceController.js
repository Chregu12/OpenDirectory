/**
 * Device Compliance Controller
 * REST API endpoints for device compliance operations
 */

const express = require('express');
const crypto = require('crypto');

class DeviceComplianceController {
    constructor(deviceComplianceEngine, auditLogger) {
        this.deviceComplianceEngine = deviceComplianceEngine;
        this.auditLogger = auditLogger;
        this.router = express.Router();
        this.setupRoutes();
    }

    setupRoutes() {
        // Check device compliance
        this.router.post('/check', this.checkCompliance.bind(this));
        
        // Get compliance policies
        this.router.get('/policies', this.getPolicies.bind(this));
        
        // Get device compliance status
        this.router.get('/devices/:deviceId/status', this.getDeviceStatus.bind(this));
        
        // Execute remediation
        this.router.post('/devices/:deviceId/remediate', this.executeRemediation.bind(this));
        
        // Get compliance report
        this.router.get('/reports/compliance', this.getComplianceReport.bind(this));
        
        // Update device information
        this.router.put('/devices/:deviceId', this.updateDevice.bind(this));
    }

    async checkCompliance(req, res) {
        try {
            const { deviceInfo, userId } = req.body;
            
            await this.auditLogger.logEvent(
                'device_compliance',
                'COMPLIANCE_CHECK_REQUESTED',
                {
                    deviceId: deviceInfo.deviceId,
                    userId,
                    platform: deviceInfo.platform
                }
            );

            const result = await this.deviceComplianceEngine.checkDeviceCompliance(deviceInfo, userId);

            await this.auditLogger.logEvent(
                'device_compliance',
                'COMPLIANCE_CHECK_COMPLETED',
                {
                    deviceId: deviceInfo.deviceId,
                    userId,
                    overallStatus: result.overallStatus,
                    remediationActionsCount: result.remediationActions?.length || 0
                }
            );

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'device_compliance',
                'COMPLIANCE_CHECK_ERROR',
                {
                    error: error.message
                }
            );

            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getPolicies(req, res) {
        try {
            const policies = Array.from(this.deviceComplianceEngine.compliancePolicies.values());
            
            res.json({
                success: true,
                data: policies
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getDeviceStatus(req, res) {
        try {
            const { deviceId } = req.params;
            const status = this.deviceComplianceEngine.getDeviceCompliance(deviceId);
            
            if (!status) {
                return res.status(404).json({
                    success: false,
                    error: 'Device compliance status not found'
                });
            }
            
            res.json({
                success: true,
                data: status
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async executeRemediation(req, res) {
        try {
            const { deviceId } = req.params;
            const { actionId } = req.body;
            
            await this.auditLogger.logEvent(
                'device_compliance',
                'REMEDIATION_REQUESTED',
                {
                    deviceId,
                    actionId,
                    requestedBy: req.user.id
                }
            );

            const result = await this.deviceComplianceEngine.executeRemediation(deviceId, actionId);

            await this.auditLogger.logEvent(
                'device_compliance',
                'REMEDIATION_COMPLETED',
                {
                    deviceId,
                    actionId,
                    result: result.success ? 'SUCCESS' : 'FAILED'
                }
            );

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            await this.auditLogger.logEvent(
                'device_compliance',
                'REMEDIATION_FAILED',
                {
                    deviceId: req.params.deviceId,
                    error: error.message
                }
            );

            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async getComplianceReport(req, res) {
        try {
            const { startDate, endDate, platform } = req.query;
            
            // Generate compliance report
            const devices = Array.from(this.deviceComplianceEngine.complianceResults.values());
            
            let filteredDevices = devices;
            
            if (startDate) {
                filteredDevices = filteredDevices.filter(d => 
                    new Date(d.timestamp) >= new Date(startDate)
                );
            }
            
            if (endDate) {
                filteredDevices = filteredDevices.filter(d => 
                    new Date(d.timestamp) <= new Date(endDate)
                );
            }
            
            if (platform) {
                filteredDevices = filteredDevices.filter(d => d.platform === platform);
            }
            
            const report = {
                totalDevices: filteredDevices.length,
                compliantDevices: filteredDevices.filter(d => d.overallStatus === 'COMPLIANT').length,
                nonCompliantDevices: filteredDevices.filter(d => d.overallStatus.includes('NON_COMPLIANT')).length,
                criticalIssues: filteredDevices.filter(d => d.overallStatus === 'CRITICAL_NON_COMPLIANT').length,
                platformBreakdown: this.generatePlatformBreakdown(filteredDevices),
                topViolations: this.getTopViolations(filteredDevices),
                generatedAt: new Date()
            };
            
            res.json({
                success: true,
                data: report
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async updateDevice(req, res) {
        try {
            const { deviceId } = req.params;
            const { deviceInfo, userId } = req.body;
            
            this.deviceComplianceEngine.updateDeviceState(deviceId, deviceInfo, userId);
            
            await this.auditLogger.logEvent(
                'device_compliance',
                'DEVICE_UPDATED',
                {
                    deviceId,
                    userId,
                    updatedBy: req.user.id
                }
            );
            
            res.json({
                success: true,
                message: 'Device information updated successfully'
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    generatePlatformBreakdown(devices) {
        const breakdown = {};
        
        for (const device of devices) {
            if (!breakdown[device.platform]) {
                breakdown[device.platform] = {
                    total: 0,
                    compliant: 0,
                    nonCompliant: 0
                };
            }
            
            breakdown[device.platform].total++;
            
            if (device.overallStatus === 'COMPLIANT') {
                breakdown[device.platform].compliant++;
            } else {
                breakdown[device.platform].nonCompliant++;
            }
        }
        
        return breakdown;
    }

    getTopViolations(devices) {
        const violations = new Map();
        
        for (const device of devices) {
            if (device.policyResults) {
                for (const result of device.policyResults) {
                    if (result.status === 'NON_COMPLIANT') {
                        for (const finding of result.findings) {
                            const count = violations.get(finding) || 0;
                            violations.set(finding, count + 1);
                        }
                    }
                }
            }
        }
        
        return Array.from(violations.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([violation, count]) => ({ violation, count }));
    }

    getRouter() {
        return this.router;
    }
}

module.exports = DeviceComplianceController;
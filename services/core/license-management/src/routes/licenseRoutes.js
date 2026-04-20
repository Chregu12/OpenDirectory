/**
 * License Management Routes
 * Extracted from index.js to improve maintainability.
 * Call registerRoutes(app, service) to bind all routes.
 */

function registerRoutes(app, svc) {
  // License Management
  app.get('/api/license/licenses',                              svc.getLicenses.bind(svc));
  app.post('/api/license/licenses',                             svc.createLicense.bind(svc));
  app.get('/api/license/licenses/:licenseId',                   svc.getLicense.bind(svc));
  app.put('/api/license/licenses/:licenseId',                   svc.updateLicense.bind(svc));
  app.delete('/api/license/licenses/:licenseId',                svc.deleteLicense.bind(svc));
  app.post('/api/license/licenses/:licenseId/assign',           svc.assignLicense.bind(svc));
  app.post('/api/license/licenses/:licenseId/revoke',           svc.revokeLicense.bind(svc));
  app.post('/api/license/licenses/:licenseId/renew',            svc.renewLicense.bind(svc));

  // License Types
  app.get('/api/license/types',                                 svc.getLicenseTypes.bind(svc));
  app.post('/api/license/types',                                svc.createLicenseType.bind(svc));
  app.put('/api/license/types/:typeId',                         svc.updateLicenseType.bind(svc));
  app.delete('/api/license/types/:typeId',                      svc.deleteLicenseType.bind(svc));

  // Software Management
  app.get('/api/license/software',                              svc.getSoftware.bind(svc));
  app.post('/api/license/software',                             svc.createSoftware.bind(svc));
  app.get('/api/license/software/:softwareId',                  svc.getSoftwareDetails.bind(svc));
  app.put('/api/license/software/:softwareId',                  svc.updateSoftware.bind(svc));
  app.delete('/api/license/software/:softwareId',               svc.deleteSoftware.bind(svc));

  // Vendor Management
  app.get('/api/license/vendors',                               svc.getVendors.bind(svc));
  app.post('/api/license/vendors',                              svc.createVendor.bind(svc));
  app.put('/api/license/vendors/:vendorId',                     svc.updateVendor.bind(svc));
  app.delete('/api/license/vendors/:vendorId',                  svc.deleteVendor.bind(svc));

  // Usage Tracking
  app.get('/api/license/usage',                                 svc.getUsage.bind(svc));
  app.post('/api/license/usage/track',                          svc.trackUsage.bind(svc));
  app.get('/api/license/usage/:licenseId',                      svc.getLicenseUsage.bind(svc));
  app.get('/api/license/usage/software/:softwareId',            svc.getSoftwareUsage.bind(svc));

  // Compliance
  app.get('/api/license/compliance/overview',                   svc.getComplianceOverview.bind(svc));
  app.post('/api/license/compliance/scan',                      svc.startComplianceScan.bind(svc));
  app.get('/api/license/compliance/scans',                      svc.getComplianceScans.bind(svc));
  app.get('/api/license/compliance/violations',                 svc.getViolations.bind(svc));
  app.post('/api/license/compliance/violations/:id/resolve',    svc.resolveViolation.bind(svc));
  app.get('/api/license/compliance/reports',                    svc.getComplianceReports.bind(svc));

  // Optimization
  app.get('/api/license/optimization/recommendations',          svc.getOptimizationRecommendations.bind(svc));
  app.post('/api/license/optimization/analyze',                 svc.analyzeOptimization.bind(svc));
  app.get('/api/license/optimization/cost-analysis',            svc.getCostAnalysis.bind(svc));
  app.get('/api/license/optimization/utilization',              svc.getUtilizationAnalysis.bind(svc));

  // Asset Management
  app.get('/api/license/assets',                                svc.getAssets.bind(svc));
  app.post('/api/license/assets/discovery',                     svc.startAssetDiscovery.bind(svc));
  app.get('/api/license/assets/:assetId',                       svc.getAsset.bind(svc));
  app.put('/api/license/assets/:assetId',                       svc.updateAsset.bind(svc));
  app.post('/api/license/assets/:assetId/retire',               svc.retireAsset.bind(svc));

  // Mobile Integration
  app.get('/api/license/mobile/sync',                           svc.syncMobileLicenses.bind(svc));
  app.post('/api/license/mobile/track',                         svc.trackMobileUsage.bind(svc));
  app.get('/api/license/mobile/compliance',                     svc.getMobileCompliance.bind(svc));

  // Reporting
  app.get('/api/license/reports',                               svc.getReports.bind(svc));
  app.post('/api/license/reports/generate',                     svc.generateReport.bind(svc));
  app.get('/api/license/reports/:reportId',                     svc.getReport.bind(svc));
  app.get('/api/license/reports/:reportId/download',            svc.downloadReport.bind(svc));

  // Dashboard
  app.get('/api/license/dashboard',                             svc.getDashboard.bind(svc));
  app.get('/api/license/dashboard/metrics',                     svc.getDashboardMetrics.bind(svc));
  app.get('/api/license/dashboard/alerts',                      svc.getDashboardAlerts.bind(svc));

  // Audit
  app.get('/api/license/audit/logs',                            svc.getAuditLogs.bind(svc));
  app.post('/api/license/audit/export',                         svc.exportAuditLogs.bind(svc));
}

module.exports = { registerRoutes };

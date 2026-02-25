const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

class LicenseController {
  constructor(licenseService) {
    this.licenseService = licenseService;
  }

  async getLicenseTypes(req, res) {
    try {
      const licenseTypes = Array.from(this.licenseService.licenseTypes.values());
      
      res.json({
        success: true,
        data: licenseTypes,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to get license types',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async createLicenseType(req, res) {
    try {
      const typeData = req.body;
      
      if (!typeData.name || !typeData.category) {
        return res.status(400).json({
          error: 'Missing required fields: name, category',
          requestId: req.id
        });
      }

      const typeId = uuidv4();
      const licenseType = {
        id: typeId,
        name: typeData.name,
        description: typeData.description || '',
        category: typeData.category,
        features: typeData.features || [],
        defaultTerms: typeData.defaultTerms || {},
        createdAt: new Date().toISOString(),
        createdBy: typeData.createdBy || 'system'
      };

      this.licenseService.licenseTypes.set(typeId, licenseType);

      res.status(201).json({
        success: true,
        data: licenseType,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to create license type',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async updateLicenseType(req, res) {
    try {
      const { typeId } = req.params;
      const updateData = req.body;

      const licenseType = this.licenseService.licenseTypes.get(typeId);
      if (!licenseType) {
        return res.status(404).json({
          error: 'License type not found',
          requestId: req.id
        });
      }

      const updatedLicenseType = {
        ...licenseType,
        ...updateData,
        id: typeId,
        updatedAt: new Date().toISOString()
      };

      this.licenseService.licenseTypes.set(typeId, updatedLicenseType);

      res.json({
        success: true,
        data: updatedLicenseType,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to update license type',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async deleteLicenseType(req, res) {
    try {
      const { typeId } = req.params;

      const licenseType = this.licenseService.licenseTypes.get(typeId);
      if (!licenseType) {
        return res.status(404).json({
          error: 'License type not found',
          requestId: req.id
        });
      }

      // Check if any licenses use this type
      const licensesUsingType = Array.from(this.licenseService.licenses.values())
        .filter(license => license.type === typeId);

      if (licensesUsingType.length > 0) {
        return res.status(400).json({
          error: 'Cannot delete license type: it is being used by existing licenses',
          licenseCount: licensesUsingType.length,
          requestId: req.id
        });
      }

      this.licenseService.licenseTypes.delete(typeId);

      res.json({
        success: true,
        message: 'License type deleted successfully',
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to delete license type',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getLicense(req, res) {
    try {
      const { licenseId } = req.params;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      // Enrich with additional data
      const enrichedLicense = {
        ...license,
        vendor: this.licenseService.vendors.get(license.vendorId),
        software: this.licenseService.software.get(license.softwareId),
        licenseType: this.licenseService.licenseTypes.get(license.type),
        usage: this.licenseService.calculateLicenseUsage(licenseId),
        compliance: this.licenseService.checkLicenseCompliance(licenseId),
        currentUsage: this.licenseService.calculateCurrentUsage(licenseId)
      };

      res.json({
        success: true,
        data: enrichedLicense,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to get license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async updateLicense(req, res) {
    try {
      const { licenseId } = req.params;
      const updateData = req.body;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      const updatedLicense = {
        ...license,
        ...updateData,
        id: licenseId,
        updatedAt: new Date().toISOString()
      };

      this.licenseService.licenses.set(licenseId, updatedLicense);

      // Log audit event
      this.licenseService.logAuditEvent('license_updated', {
        licenseId,
        licenseName: updatedLicense.name,
        changes: updateData,
        updatedBy: updateData.updatedBy || 'system'
      });

      // Broadcast update
      this.licenseService.broadcastToSubscribers('license_updated', {
        licenseId,
        license: updatedLicense
      });

      res.json({
        success: true,
        data: updatedLicense,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to update license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async deleteLicense(req, res) {
    try {
      const { licenseId } = req.params;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      // Check if license is currently in use
      const currentUsage = this.licenseService.calculateCurrentUsage(licenseId);
      if (currentUsage.activeUsers > 0) {
        return res.status(400).json({
          error: 'Cannot delete license: it is currently in use',
          activeUsers: currentUsage.activeUsers,
          requestId: req.id
        });
      }

      this.licenseService.licenses.delete(licenseId);

      // Clean up related data
      this.licenseService.usage.delete(licenseId);

      // Log audit event
      this.licenseService.logAuditEvent('license_deleted', {
        licenseId,
        licenseName: license.name,
        deletedBy: req.body.deletedBy || 'system'
      });

      // Broadcast deletion
      this.licenseService.broadcastToSubscribers('license_deleted', {
        licenseId,
        licenseName: license.name
      });

      res.json({
        success: true,
        message: 'License deleted successfully',
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to delete license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async assignLicense(req, res) {
    try {
      const { licenseId } = req.params;
      const { userId, deviceId, assignedBy } = req.body;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      if (!userId && !deviceId) {
        return res.status(400).json({
          error: 'Either userId or deviceId must be provided',
          requestId: req.id
        });
      }

      // Check if assignment would exceed license limits
      const currentUsage = this.licenseService.calculateCurrentUsage(licenseId);
      const maxUsers = license.terms?.maxUsers || license.quantity || 1;

      if (currentUsage.activeUsers >= maxUsers) {
        return res.status(400).json({
          error: 'License assignment would exceed usage limits',
          currentUsers: currentUsage.activeUsers,
          maxUsers: maxUsers,
          requestId: req.id
        });
      }

      const assignmentId = uuidv4();
      const assignment = {
        id: assignmentId,
        licenseId,
        userId: userId || null,
        deviceId: deviceId || null,
        assignedAt: new Date().toISOString(),
        assignedBy: assignedBy || 'system',
        status: 'active'
      };

      // Add assignment to license
      if (!license.assignments) {
        license.assignments = [];
      }
      license.assignments.push(assignment);
      license.updatedAt = new Date().toISOString();

      this.licenseService.licenses.set(licenseId, license);

      // Log audit event
      this.licenseService.logAuditEvent('license_assigned', {
        licenseId,
        assignmentId,
        userId,
        deviceId,
        assignedBy
      });

      res.json({
        success: true,
        data: assignment,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to assign license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async revokeLicense(req, res) {
    try {
      const { licenseId } = req.params;
      const { userId, deviceId, revokedBy } = req.body;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      if (!license.assignments) {
        return res.status(404).json({
          error: 'No assignments found for this license',
          requestId: req.id
        });
      }

      // Find and revoke assignment
      const assignmentIndex = license.assignments.findIndex(assignment =>
        (userId && assignment.userId === userId) ||
        (deviceId && assignment.deviceId === deviceId)
      );

      if (assignmentIndex === -1) {
        return res.status(404).json({
          error: 'Assignment not found',
          requestId: req.id
        });
      }

      const assignment = license.assignments[assignmentIndex];
      assignment.status = 'revoked';
      assignment.revokedAt = new Date().toISOString();
      assignment.revokedBy = revokedBy || 'system';

      license.updatedAt = new Date().toISOString();
      this.licenseService.licenses.set(licenseId, license);

      // Log audit event
      this.licenseService.logAuditEvent('license_revoked', {
        licenseId,
        assignmentId: assignment.id,
        userId,
        deviceId,
        revokedBy
      });

      res.json({
        success: true,
        data: assignment,
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to revoke license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async renewLicense(req, res) {
    try {
      const { licenseId } = req.params;
      const { newExpiryDate, cost, renewedBy } = req.body;

      const license = this.licenseService.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      if (!newExpiryDate) {
        return res.status(400).json({
          error: 'New expiry date is required',
          requestId: req.id
        });
      }

      const renewalId = uuidv4();
      const renewal = {
        id: renewalId,
        licenseId,
        previousExpiryDate: license.expiryDate,
        newExpiryDate: newExpiryDate,
        renewalDate: new Date().toISOString(),
        cost: cost || 0,
        renewedBy: renewedBy || 'system',
        status: 'completed'
      };

      // Update license
      license.expiryDate = newExpiryDate;
      license.updatedAt = new Date().toISOString();
      if (cost) {
        license.cost = (license.cost || 0) + cost;
      }

      this.licenseService.licenses.set(licenseId, license);
      this.licenseService.renewals.set(renewalId, renewal);

      // Log audit event
      this.licenseService.logAuditEvent('license_renewed', {
        licenseId,
        renewalId,
        previousExpiry: renewal.previousExpiryDate,
        newExpiry: newExpiryDate,
        cost,
        renewedBy
      });

      res.json({
        success: true,
        data: {
          license: license,
          renewal: renewal
        },
        requestId: req.id
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to renew license',
        details: error.message,
        requestId: req.id
      });
    }
  }
}

module.exports = LicenseController;
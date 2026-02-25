const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

class OptimizationService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.optimizationRules = new Map();
    this.initializeOptimizationRules();
  }

  initializeOptimizationRules() {
    // Underutilization Rule
    this.optimizationRules.set('underutilization', {
      id: 'underutilization',
      name: 'License Underutilization',
      description: 'Identifies licenses with low usage rates',
      priority: 'medium',
      category: 'cost_savings',
      thresholds: {
        utilizationRate: 50, // Under 50% utilization
        timeframe: 90 // Days to analyze
      },
      analyzeFunction: this.analyzeUnderutilization.bind(this)
    });

    // Duplicate Software Rule
    this.optimizationRules.set('duplicate_software', {
      id: 'duplicate_software',
      name: 'Duplicate Software Licenses',
      description: 'Finds multiple licenses for the same software',
      priority: 'high',
      category: 'consolidation',
      analyzeFunction: this.analyzeDuplicateSoftware.bind(this)
    });

    // Volume Pricing Opportunity
    this.optimizationRules.set('volume_pricing', {
      id: 'volume_pricing',
      name: 'Volume Pricing Opportunities',
      description: 'Identifies opportunities for volume discounts',
      priority: 'medium',
      category: 'cost_savings',
      thresholds: {
        minLicenses: 10,
        potentialSavings: 0.15 // 15% potential savings
      },
      analyzeFunction: this.analyzeVolumePricing.bind(this)
    });

    // Alternative Software Rule
    this.optimizationRules.set('alternative_software', {
      id: 'alternative_software',
      name: 'Alternative Software Options',
      description: 'Suggests lower-cost alternatives to expensive software',
      priority: 'low',
      category: 'alternatives',
      thresholds: {
        costThreshold: 1000, // Annual cost per license
        utilizationThreshold: 70 // Below 70% feature utilization
      },
      analyzeFunction: this.analyzeAlternativeSoftware.bind(this)
    });

    // Renewal Optimization Rule
    this.optimizationRules.set('renewal_optimization', {
      id: 'renewal_optimization',
      name: 'License Renewal Optimization',
      description: 'Optimizes upcoming license renewals',
      priority: 'high',
      category: 'renewals',
      thresholds: {
        renewalWindow: 90, // Days before renewal
        utilizationThreshold: 80
      },
      analyzeFunction: this.analyzeRenewalOptimization.bind(this)
    });

    // Cloud Migration Opportunities
    this.optimizationRules.set('cloud_migration', {
      id: 'cloud_migration',
      name: 'Cloud Migration Opportunities',
      description: 'Identifies on-premise licenses suitable for cloud migration',
      priority: 'medium',
      category: 'modernization',
      analyzeFunction: this.analyzeCloudMigration.bind(this)
    });

    // Concurrent License Optimization
    this.optimizationRules.set('concurrent_optimization', {
      id: 'concurrent_optimization',
      name: 'Concurrent License Optimization',
      description: 'Optimizes concurrent license pools',
      priority: 'medium',
      category: 'usage_optimization',
      thresholds: {
        peakUtilization: 90,
        avgUtilization: 60
      },
      analyzeFunction: this.analyzeConcurrentOptimization.bind(this)
    });
  }

  async performOptimizationAnalysis(options = {}) {
    const analysisId = uuidv4();
    const analysis = {
      id: analysisId,
      type: 'comprehensive_optimization',
      startedAt: new Date().toISOString(),
      completedAt: null,
      status: 'running',
      options,
      results: {
        recommendations: [],
        potentialSavings: 0,
        prioritizedActions: [],
        riskAssessment: {}
      },
      summary: {
        totalOpportunities: 0,
        highPriorityCount: 0,
        mediumPriorityCount: 0,
        lowPriorityCount: 0,
        estimatedSavings: 0,
        implementationEffort: 'medium'
      }
    };

    try {
      // Run all optimization rules
      const allRecommendations = [];
      
      for (const [ruleId, rule] of this.optimizationRules) {
        try {
          const ruleRecommendations = await rule.analyzeFunction(rule);
          if (ruleRecommendations && ruleRecommendations.length > 0) {
            allRecommendations.push(...ruleRecommendations);
          }
        } catch (error) {
          this.licenseService.logger.error('Optimization rule failed', {
            ruleId,
            error: error.message
          });
        }
      }

      // Prioritize and filter recommendations
      const prioritizedRecommendations = this.prioritizeRecommendations(allRecommendations);
      analysis.results.recommendations = prioritizedRecommendations;

      // Calculate potential savings
      const totalSavings = prioritizedRecommendations.reduce((sum, rec) => 
        sum + (rec.potentialSavings || 0), 0
      );
      analysis.results.potentialSavings = totalSavings;

      // Generate prioritized action plan
      analysis.results.prioritizedActions = this.generateActionPlan(prioritizedRecommendations);

      // Perform risk assessment
      analysis.results.riskAssessment = this.assessOptimizationRisks(prioritizedRecommendations);

      // Update summary
      analysis.summary.totalOpportunities = prioritizedRecommendations.length;
      analysis.summary.highPriorityCount = prioritizedRecommendations.filter(r => r.priority === 'high').length;
      analysis.summary.mediumPriorityCount = prioritizedRecommendations.filter(r => r.priority === 'medium').length;
      analysis.summary.lowPriorityCount = prioritizedRecommendations.filter(r => r.priority === 'low').length;
      analysis.summary.estimatedSavings = totalSavings;
      analysis.summary.implementationEffort = this.calculateImplementationEffort(prioritizedRecommendations);

      analysis.status = 'completed';
      analysis.completedAt = new Date().toISOString();

      // Store analysis results
      this.licenseService.optimizations.set(analysisId, analysis);

      // Generate optimization report
      const report = this.generateOptimizationReport(analysis);
      this.licenseService.reports.set(`optimization_${analysisId}`, report);

      // Broadcast completion
      this.licenseService.broadcastToSubscribers('optimization_completed', {
        analysisId,
        summary: analysis.summary,
        reportId: report.id
      });

      return analysis;

    } catch (error) {
      analysis.status = 'failed';
      analysis.error = error.message;
      analysis.completedAt = new Date().toISOString();
      
      this.licenseService.logger.error('Optimization analysis failed', {
        analysisId,
        error: error.message
      });

      return analysis;
    }
  }

  async analyzeUnderutilization(rule) {
    const recommendations = [];
    const timeframe = rule.thresholds.timeframe;
    const utilizationThreshold = rule.thresholds.utilizationRate;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      const usage = this.licenseService.calculateLicenseUsage(licenseId);
      
      if (usage.utilizationRate < utilizationThreshold) {
        const potentialSavings = this.calculateUnderutilizationSavings(license, usage);
        
        recommendations.push({
          id: uuidv4(),
          type: 'underutilization',
          priority: usage.utilizationRate < 25 ? 'high' : 'medium',
          licenseId,
          licenseName: license.name,
          title: `Underutilized License: ${license.name}`,
          description: `License is only ${usage.utilizationRate.toFixed(1)}% utilized`,
          currentUtilization: usage.utilizationRate,
          recommendedAction: this.getUnderutilizationAction(usage.utilizationRate),
          potentialSavings,
          implementation: {
            effort: 'low',
            timeframe: '1-2 weeks',
            dependencies: ['usage_analysis', 'user_consultation']
          },
          details: {
            currentUsers: usage.currentUsers,
            maxUsers: usage.maxUsers,
            avgSessionDuration: usage.avgSessionDuration,
            lastUsed: license.stats?.lastUsed
          }
        });
      }
    }

    return recommendations;
  }

  async analyzeDuplicateSoftware(rule) {
    const recommendations = [];
    const softwareGroups = this.groupLicensesBySoftware();

    for (const [softwareId, licenses] of softwareGroups) {
      if (licenses.length <= 1) continue;

      const software = this.licenseService.software.get(softwareId);
      const totalCost = licenses.reduce((sum, license) => sum + (license.cost || 0), 0);
      const totalQuantity = licenses.reduce((sum, license) => sum + (license.quantity || 1), 0);

      // Check for different vendors for same software
      const vendors = [...new Set(licenses.map(l => l.vendorId))];
      
      if (vendors.length > 1) {
        const bestVendorAnalysis = this.findBestVendor(licenses);
        const potentialSavings = totalCost - bestVendorAnalysis.optimizedCost;

        recommendations.push({
          id: uuidv4(),
          type: 'duplicate_software',
          priority: 'high',
          softwareId,
          softwareName: software?.name || 'Unknown Software',
          title: `Consolidate ${software?.name || 'Software'} Licenses`,
          description: `Found ${licenses.length} licenses from ${vendors.length} vendors for the same software`,
          currentCost: totalCost,
          optimizedCost: bestVendorAnalysis.optimizedCost,
          potentialSavings,
          recommendedAction: 'consolidate_with_single_vendor',
          implementation: {
            effort: 'medium',
            timeframe: '4-8 weeks',
            dependencies: ['vendor_negotiation', 'license_migration']
          },
          details: {
            currentLicenses: licenses.length,
            totalQuantity,
            vendors,
            recommendedVendor: bestVendorAnalysis.recommendedVendor
          }
        });
      }
    }

    return recommendations;
  }

  async analyzeVolumePricing(rule) {
    const recommendations = [];
    const minLicenses = rule.thresholds.minLicenses;
    const potentialSavingsRate = rule.thresholds.potentialSavings;

    // Group licenses by vendor
    const vendorGroups = this.groupLicensesByVendor();

    for (const [vendorId, licenses] of vendorGroups) {
      const activeLicenses = licenses.filter(l => l.status === 'active');
      const totalQuantity = activeLicenses.reduce((sum, l) => sum + (l.quantity || 1), 0);
      const totalCost = activeLicenses.reduce((sum, l) => sum + (l.cost || 0), 0);

      if (totalQuantity >= minLicenses && totalCost > 0) {
        const vendor = this.licenseService.vendors.get(vendorId);
        const potentialSavings = totalCost * potentialSavingsRate;

        recommendations.push({
          id: uuidv4(),
          type: 'volume_pricing',
          priority: 'medium',
          vendorId,
          vendorName: vendor?.name || 'Unknown Vendor',
          title: `Volume Pricing Opportunity with ${vendor?.name || 'Vendor'}`,
          description: `${totalQuantity} licenses worth $${totalCost.toLocaleString()} could qualify for volume discounts`,
          currentCost: totalCost,
          potentialSavings,
          recommendedAction: 'negotiate_volume_pricing',
          implementation: {
            effort: 'low',
            timeframe: '2-4 weeks',
            dependencies: ['vendor_contact', 'contract_negotiation']
          },
          details: {
            licenseCount: activeLicenses.length,
            totalQuantity,
            avgCostPerLicense: totalCost / totalQuantity,
            estimatedDiscount: `${(potentialSavingsRate * 100).toFixed(0)}%`
          }
        });
      }
    }

    return recommendations;
  }

  async analyzeAlternativeSoftware(rule) {
    const recommendations = [];
    const costThreshold = rule.thresholds.costThreshold;
    const utilizationThreshold = rule.thresholds.utilizationThreshold;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      const annualCost = this.calculateAnnualCost(license);
      const featureUtilization = this.calculateFeatureUtilization(license);

      if (annualCost > costThreshold && featureUtilization < utilizationThreshold) {
        const alternatives = await this.findSoftwareAlternatives(license);
        
        if (alternatives && alternatives.length > 0) {
          const bestAlternative = alternatives[0]; // Assuming sorted by value
          const potentialSavings = annualCost - bestAlternative.estimatedCost;

          recommendations.push({
            id: uuidv4(),
            type: 'alternative_software',
            priority: potentialSavings > annualCost * 0.5 ? 'medium' : 'low',
            licenseId,
            licenseName: license.name,
            title: `Alternative Software Option for ${license.name}`,
            description: `Low feature utilization (${featureUtilization}%) suggests cost-effective alternatives exist`,
            currentCost: annualCost,
            potentialSavings,
            recommendedAction: 'evaluate_alternatives',
            implementation: {
              effort: 'high',
              timeframe: '8-12 weeks',
              dependencies: ['user_evaluation', 'migration_planning', 'training']
            },
            details: {
              featureUtilization,
              alternatives: alternatives.slice(0, 3), // Top 3 alternatives
              riskLevel: 'medium'
            }
          });
        }
      }
    }

    return recommendations;
  }

  async analyzeRenewalOptimization(rule) {
    const recommendations = [];
    const renewalWindow = rule.thresholds.renewalWindow;
    const utilizationThreshold = rule.thresholds.utilizationThreshold;

    const upcomingRenewals = this.getUpcomingRenewals(renewalWindow);

    for (const license of upcomingRenewals) {
      const usage = this.licenseService.calculateLicenseUsage(license.id);
      const currentCost = license.cost || 0;
      
      let optimizedQuantity = license.quantity || 1;
      let recommendation = '';
      
      if (usage.utilizationRate < utilizationThreshold) {
        // Reduce quantity based on actual usage
        optimizedQuantity = Math.max(1, Math.ceil(usage.maxUsers * 1.1)); // 10% buffer
        recommendation = 'reduce_quantity';
      } else if (usage.utilizationRate > 95) {
        // Increase quantity for overutilized licenses
        optimizedQuantity = Math.ceil((license.quantity || 1) * 1.2); // 20% increase
        recommendation = 'increase_quantity';
      } else {
        recommendation = 'negotiate_better_terms';
      }

      const optimizedCost = this.estimateRenewalCost(license, optimizedQuantity);
      const potentialSavings = currentCost - optimizedCost;

      recommendations.push({
        id: uuidv4(),
        type: 'renewal_optimization',
        priority: 'high',
        licenseId: license.id,
        licenseName: license.name,
        title: `Optimize Renewal: ${license.name}`,
        description: `License renewal in ${moment(license.expiryDate).diff(moment(), 'days')} days`,
        currentCost,
        optimizedCost,
        potentialSavings,
        recommendedAction: recommendation,
        implementation: {
          effort: 'low',
          timeframe: '2-4 weeks',
          dependencies: ['usage_analysis', 'vendor_negotiation']
        },
        details: {
          expiryDate: license.expiryDate,
          currentQuantity: license.quantity,
          optimizedQuantity,
          currentUtilization: usage.utilizationRate,
          daysUntilRenewal: moment(license.expiryDate).diff(moment(), 'days')
        }
      });
    }

    return recommendations;
  }

  async analyzeCloudMigration(rule) {
    const recommendations = [];

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active') continue;

      // Check if license is for on-premise software that has cloud alternatives
      const cloudMigrationOpportunity = this.assessCloudMigrationOpportunity(license);
      
      if (cloudMigrationOpportunity.viable) {
        const potentialSavings = cloudMigrationOpportunity.savings;
        
        recommendations.push({
          id: uuidv4(),
          type: 'cloud_migration',
          priority: potentialSavings > 0 ? 'medium' : 'low',
          licenseId,
          licenseName: license.name,
          title: `Cloud Migration Opportunity: ${license.name}`,
          description: `On-premise license could benefit from cloud migration`,
          currentCost: license.cost || 0,
          optimizedCost: cloudMigrationOpportunity.cloudCost,
          potentialSavings,
          recommendedAction: 'evaluate_cloud_migration',
          implementation: {
            effort: 'high',
            timeframe: '12-24 weeks',
            dependencies: ['cloud_readiness_assessment', 'data_migration', 'training']
          },
          details: {
            currentDeployment: 'on-premise',
            recommendedCloud: cloudMigrationOpportunity.cloudPlatform,
            benefits: cloudMigrationOpportunity.benefits,
            risks: cloudMigrationOpportunity.risks
          }
        });
      }
    }

    return recommendations;
  }

  async analyzeConcurrentOptimization(rule) {
    const recommendations = [];
    const peakThreshold = rule.thresholds.peakUtilization;
    const avgThreshold = rule.thresholds.avgUtilization;

    for (const [licenseId, license] of this.licenseService.licenses) {
      if (license.status !== 'active' || !license.terms?.concurrent) continue;

      const usageAnalysis = this.analyzeConcurrentUsagePatterns(licenseId);
      
      if (usageAnalysis.peakUtilization > peakThreshold || 
          usageAnalysis.avgUtilization < avgThreshold) {
        
        const optimizedPoolSize = this.calculateOptimalPoolSize(usageAnalysis);
        const currentPoolSize = license.terms.maxUsers || license.quantity || 1;
        const costImpact = this.calculatePoolSizeAdjustmentCost(license, optimizedPoolSize);

        recommendations.push({
          id: uuidv4(),
          type: 'concurrent_optimization',
          priority: Math.abs(currentPoolSize - optimizedPoolSize) > 2 ? 'medium' : 'low',
          licenseId,
          licenseName: license.name,
          title: `Optimize Concurrent Pool: ${license.name}`,
          description: `Concurrent license pool can be optimized from ${currentPoolSize} to ${optimizedPoolSize}`,
          currentCost: license.cost || 0,
          optimizedCost: (license.cost || 0) + costImpact,
          potentialSavings: -costImpact, // Negative if cost increases
          recommendedAction: optimizedPoolSize > currentPoolSize ? 'increase_pool_size' : 'reduce_pool_size',
          implementation: {
            effort: 'low',
            timeframe: '1-2 weeks',
            dependencies: ['usage_monitoring', 'user_notification']
          },
          details: {
            currentPoolSize,
            optimizedPoolSize,
            peakUtilization: usageAnalysis.peakUtilization,
            avgUtilization: usageAnalysis.avgUtilization,
            usagePatterns: usageAnalysis.patterns
          }
        });
      }
    }

    return recommendations;
  }

  // Helper Methods
  groupLicensesBySoftware() {
    const groups = new Map();
    
    for (const [licenseId, license] of this.licenseService.licenses) {
      const softwareId = license.softwareId;
      if (!groups.has(softwareId)) {
        groups.set(softwareId, []);
      }
      groups.get(softwareId).push(license);
    }

    return groups;
  }

  groupLicensesByVendor() {
    const groups = new Map();
    
    for (const [licenseId, license] of this.licenseService.licenses) {
      const vendorId = license.vendorId;
      if (!groups.has(vendorId)) {
        groups.set(vendorId, []);
      }
      groups.get(vendorId).push(license);
    }

    return groups;
  }

  calculateUnderutilizationSavings(license, usage) {
    const currentCost = license.cost || 0;
    const utilizationRate = usage.utilizationRate / 100;
    
    // Estimate savings from reducing license quantity
    const optimalQuantity = Math.max(1, Math.ceil(usage.maxUsers * 1.1)); // 10% buffer
    const currentQuantity = license.quantity || 1;
    
    if (optimalQuantity < currentQuantity) {
      const reductionPercentage = (currentQuantity - optimalQuantity) / currentQuantity;
      return currentCost * reductionPercentage;
    }
    
    return 0;
  }

  getUnderutilizationAction(utilizationRate) {
    if (utilizationRate < 25) {
      return 'Consider terminating or significantly reducing license quantity';
    } else if (utilizationRate < 50) {
      return 'Reduce license quantity to match actual usage';
    } else {
      return 'Monitor usage and consider modest reduction';
    }
  }

  findBestVendor(licenses) {
    // Simple analysis - in reality this would be more complex
    const vendorAnalysis = {};
    
    licenses.forEach(license => {
      const vendorId = license.vendorId;
      if (!vendorAnalysis[vendorId]) {
        vendorAnalysis[vendorId] = {
          totalCost: 0,
          totalQuantity: 0,
          costPerUnit: 0
        };
      }
      
      vendorAnalysis[vendorId].totalCost += license.cost || 0;
      vendorAnalysis[vendorId].totalQuantity += license.quantity || 1;
    });

    // Calculate cost per unit for each vendor
    Object.keys(vendorAnalysis).forEach(vendorId => {
      const analysis = vendorAnalysis[vendorId];
      analysis.costPerUnit = analysis.totalQuantity > 0 ? 
        analysis.totalCost / analysis.totalQuantity : 0;
    });

    // Find vendor with lowest cost per unit
    const bestVendor = Object.entries(vendorAnalysis)
      .sort(([,a], [,b]) => a.costPerUnit - b.costPerUnit)[0];

    const totalQuantity = licenses.reduce((sum, l) => sum + (l.quantity || 1), 0);
    const optimizedCost = bestVendor ? bestVendor[1].costPerUnit * totalQuantity : 0;

    return {
      recommendedVendor: bestVendor ? bestVendor[0] : null,
      optimizedCost
    };
  }

  calculateAnnualCost(license) {
    const cost = license.cost || 0;
    
    // Convert to annual cost based on license type
    if (license.type === 'subscription') {
      // Assume monthly if no specific term
      return cost * 12;
    } else if (license.type === 'perpetual') {
      // Amortize over 3 years for comparison
      return cost / 3;
    }
    
    return cost; // Default assumption is annual
  }

  calculateFeatureUtilization(license) {
    // This would typically analyze actual feature usage
    // For now, return a mock calculation based on license usage
    const usage = this.licenseService.calculateLicenseUsage(license.id);
    
    // Estimate feature utilization based on session duration and frequency
    const baseUtilization = Math.min(100, usage.utilizationRate * 1.2);
    
    // Add some variance based on software type
    if (license.type === 'concurrent') {
      return baseUtilization * 0.8; // Concurrent users typically use fewer features
    }
    
    return baseUtilization;
  }

  async findSoftwareAlternatives(license) {
    // This would typically query a database of software alternatives
    // For now, return mock alternatives
    const alternatives = [
      {
        name: 'Alternative Solution A',
        vendor: 'Vendor A',
        estimatedCost: (license.cost || 0) * 0.6,
        featureMatch: 85,
        migrationComplexity: 'medium'
      },
      {
        name: 'Alternative Solution B',
        vendor: 'Vendor B',
        estimatedCost: (license.cost || 0) * 0.8,
        featureMatch: 95,
        migrationComplexity: 'low'
      }
    ];

    return alternatives.sort((a, b) => 
      (b.featureMatch - a.featureMatch) + ((license.cost - a.estimatedCost) - (license.cost - b.estimatedCost)) / 1000
    );
  }

  getUpcomingRenewals(days) {
    const cutoffDate = moment().add(days, 'days').toDate();
    
    return Array.from(this.licenseService.licenses.values())
      .filter(license => 
        license.expiryDate && 
        new Date(license.expiryDate) <= cutoffDate &&
        license.status === 'active'
      )
      .sort((a, b) => new Date(a.expiryDate) - new Date(b.expiryDate));
  }

  estimateRenewalCost(license, newQuantity) {
    const currentCost = license.cost || 0;
    const currentQuantity = license.quantity || 1;
    
    // Simple linear scaling - in reality would consider volume discounts
    return (currentCost / currentQuantity) * newQuantity;
  }

  assessCloudMigrationOpportunity(license) {
    // Mock cloud migration assessment
    const software = this.licenseService.software.get(license.softwareId);
    const vendor = this.licenseService.vendors.get(license.vendorId);
    
    // Check if vendor offers cloud alternatives
    const hasCloudOffering = vendor?.licenseTypes?.includes('cloud_service');
    
    if (hasCloudOffering) {
      const currentCost = license.cost || 0;
      const cloudCost = currentCost * 0.85; // Assume 15% savings for cloud
      
      return {
        viable: true,
        cloudPlatform: 'Vendor Cloud',
        cloudCost,
        savings: currentCost - cloudCost,
        benefits: ['automatic_updates', 'scalability', 'reduced_maintenance'],
        risks: ['data_migration', 'internet_dependency', 'subscription_model']
      };
    }

    return { viable: false };
  }

  analyzeConcurrentUsagePatterns(licenseId) {
    const usageRecords = this.licenseService.usage.get(licenseId) || [];
    
    // Analyze usage patterns over time
    const dailyPeaks = this.calculateDailyPeaks(usageRecords);
    const avgUtilization = dailyPeaks.reduce((sum, peak) => sum + peak, 0) / dailyPeaks.length || 0;
    const peakUtilization = Math.max(...dailyPeaks, 0);
    
    return {
      avgUtilization,
      peakUtilization,
      patterns: {
        busyHours: this.identifyBusyHours(usageRecords),
        weeklyPattern: this.analyzeWeeklyPattern(usageRecords),
        seasonality: this.analyzeSeasonality(usageRecords)
      }
    };
  }

  calculateDailyPeaks(usageRecords) {
    // Group usage by day and find peak concurrent users per day
    const dailyUsage = {};
    
    usageRecords.forEach(record => {
      const day = moment(record.timestamp).format('YYYY-MM-DD');
      if (!dailyUsage[day]) {
        dailyUsage[day] = [];
      }
      dailyUsage[day].push(record);
    });

    return Object.values(dailyUsage).map(dayRecords => {
      // Calculate peak concurrent users for the day
      return this.calculatePeakConcurrentUsers(dayRecords);
    });
  }

  calculatePeakConcurrentUsers(records) {
    // Simplified calculation - in reality would need more sophisticated tracking
    const activeUsers = new Set();
    let peak = 0;
    
    records.forEach(record => {
      if (record.action === 'start') {
        activeUsers.add(record.userId);
      } else if (record.action === 'stop') {
        activeUsers.delete(record.userId);
      }
      
      peak = Math.max(peak, activeUsers.size);
    });

    return peak;
  }

  calculateOptimalPoolSize(usageAnalysis) {
    // Calculate optimal pool size based on usage patterns
    const { avgUtilization, peakUtilization } = usageAnalysis;
    
    // Use 95th percentile approach with some buffer
    const optimalSize = Math.ceil(peakUtilization * 0.95 + avgUtilization * 0.1);
    
    return Math.max(1, optimalSize);
  }

  calculatePoolSizeAdjustmentCost(license, newPoolSize) {
    const currentPoolSize = license.terms?.maxUsers || license.quantity || 1;
    const costPerLicense = license.cost ? license.cost / currentPoolSize : 0;
    
    return (newPoolSize - currentPoolSize) * costPerLicense;
  }

  prioritizeRecommendations(recommendations) {
    // Sort by potential savings and priority
    return recommendations.sort((a, b) => {
      const priorityWeight = { high: 3, medium: 2, low: 1 };
      const aPriorityScore = priorityWeight[a.priority] || 1;
      const bPriorityScore = priorityWeight[b.priority] || 1;
      
      // Combine priority and potential savings
      const aScore = aPriorityScore * 1000 + (a.potentialSavings || 0);
      const bScore = bPriorityScore * 1000 + (b.potentialSavings || 0);
      
      return bScore - aScore;
    });
  }

  generateActionPlan(recommendations) {
    const actionPlan = {
      immediate: [], // High priority, quick wins
      shortTerm: [], // Medium priority, 1-3 months
      longTerm: [] // Low priority or high effort, 3+ months
    };

    recommendations.forEach(rec => {
      const action = {
        recommendationId: rec.id,
        title: rec.title,
        effort: rec.implementation?.effort || 'medium',
        timeframe: rec.implementation?.timeframe || '4-8 weeks',
        potentialSavings: rec.potentialSavings || 0,
        dependencies: rec.implementation?.dependencies || []
      };

      if (rec.priority === 'high' && action.effort === 'low') {
        actionPlan.immediate.push(action);
      } else if (rec.priority === 'high' || action.effort === 'medium') {
        actionPlan.shortTerm.push(action);
      } else {
        actionPlan.longTerm.push(action);
      }
    });

    return actionPlan;
  }

  assessOptimizationRisks(recommendations) {
    const riskFactors = {
      userImpact: 0,
      businessContinuity: 0,
      technicalComplexity: 0,
      vendorDependency: 0
    };

    recommendations.forEach(rec => {
      // Assess risk based on recommendation type and implementation effort
      switch (rec.type) {
        case 'alternative_software':
          riskFactors.userImpact += 3;
          riskFactors.businessContinuity += 2;
          riskFactors.technicalComplexity += 3;
          break;
        case 'cloud_migration':
          riskFactors.technicalComplexity += 3;
          riskFactors.vendorDependency += 2;
          break;
        case 'underutilization':
          riskFactors.userImpact += 1;
          break;
        default:
          riskFactors.vendorDependency += 1;
      }
    });

    // Normalize risk scores
    const maxRisk = recommendations.length * 3;
    Object.keys(riskFactors).forEach(key => {
      riskFactors[key] = maxRisk > 0 ? (riskFactors[key] / maxRisk) * 100 : 0;
    });

    return {
      riskFactors,
      overallRiskLevel: this.calculateOverallRiskLevel(riskFactors),
      mitigationStrategies: this.generateRiskMitigationStrategies(riskFactors)
    };
  }

  calculateOverallRiskLevel(riskFactors) {
    const avgRisk = Object.values(riskFactors).reduce((sum, risk) => sum + risk, 0) / 4;
    
    if (avgRisk > 70) return 'high';
    if (avgRisk > 40) return 'medium';
    return 'low';
  }

  generateRiskMitigationStrategies(riskFactors) {
    const strategies = [];

    if (riskFactors.userImpact > 50) {
      strategies.push({
        risk: 'User Impact',
        strategy: 'Implement phased rollout with user training and support',
        timeline: '2-4 weeks preparation'
      });
    }

    if (riskFactors.businessContinuity > 50) {
      strategies.push({
        risk: 'Business Continuity',
        strategy: 'Maintain parallel systems during transition',
        timeline: 'Duration of implementation'
      });
    }

    if (riskFactors.technicalComplexity > 50) {
      strategies.push({
        risk: 'Technical Complexity',
        strategy: 'Engage technical specialists and create detailed migration plan',
        timeline: '4-8 weeks planning'
      });
    }

    return strategies;
  }

  calculateImplementationEffort(recommendations) {
    const effortScores = recommendations.map(rec => {
      const effort = rec.implementation?.effort || 'medium';
      const effortMap = { low: 1, medium: 2, high: 3 };
      return effortMap[effort] || 2;
    });

    const avgEffort = effortScores.reduce((sum, score) => sum + score, 0) / effortScores.length || 2;
    
    if (avgEffort > 2.5) return 'high';
    if (avgEffort > 1.5) return 'medium';
    return 'low';
  }

  generateOptimizationReport(analysis) {
    const reportId = uuidv4();
    const report = {
      id: reportId,
      type: 'optimization_analysis_report',
      analysisId: analysis.id,
      title: `License Optimization Analysis Report - ${moment().format('YYYY-MM-DD')}`,
      generatedAt: new Date().toISOString(),
      executiveSummary: {
        totalOpportunities: analysis.summary.totalOpportunities,
        estimatedSavings: analysis.summary.estimatedSavings,
        implementationEffort: analysis.summary.implementationEffort,
        recommendedActions: analysis.results.prioritizedActions.immediate.length
      },
      recommendations: analysis.results.recommendations,
      actionPlan: analysis.results.prioritizedActions,
      riskAssessment: analysis.results.riskAssessment,
      implementation: {
        quickWins: analysis.results.prioritizedActions.immediate,
        roadmap: this.createImplementationRoadmap(analysis.results.prioritizedActions)
      }
    };

    return report;
  }

  createImplementationRoadmap(actionPlan) {
    const roadmap = [];
    let currentDate = moment();

    // Add immediate actions
    actionPlan.immediate.forEach((action, index) => {
      roadmap.push({
        phase: 1,
        title: action.title,
        startDate: currentDate.clone().add(index, 'weeks').format('YYYY-MM-DD'),
        endDate: currentDate.clone().add(index + 2, 'weeks').format('YYYY-MM-DD'),
        effort: action.effort,
        potentialSavings: action.potentialSavings
      });
    });

    // Add short-term actions
    const shortTermStart = currentDate.clone().add(actionPlan.immediate.length + 1, 'weeks');
    actionPlan.shortTerm.forEach((action, index) => {
      roadmap.push({
        phase: 2,
        title: action.title,
        startDate: shortTermStart.clone().add(index * 4, 'weeks').format('YYYY-MM-DD'),
        endDate: shortTermStart.clone().add((index + 1) * 4, 'weeks').format('YYYY-MM-DD'),
        effort: action.effort,
        potentialSavings: action.potentialSavings
      });
    });

    return roadmap;
  }

  // Additional helper methods for usage pattern analysis
  identifyBusyHours(usageRecords) {
    const hourlyUsage = {};
    
    usageRecords.forEach(record => {
      const hour = moment(record.timestamp).hour();
      hourlyUsage[hour] = (hourlyUsage[hour] || 0) + 1;
    });

    const sortedHours = Object.entries(hourlyUsage)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([hour,]) => parseInt(hour));

    return sortedHours;
  }

  analyzeWeeklyPattern(usageRecords) {
    const dailyUsage = {};
    
    usageRecords.forEach(record => {
      const dayOfWeek = moment(record.timestamp).format('dddd');
      dailyUsage[dayOfWeek] = (dailyUsage[dayOfWeek] || 0) + 1;
    });

    return dailyUsage;
  }

  analyzeSeasonality(usageRecords) {
    const monthlyUsage = {};
    
    usageRecords.forEach(record => {
      const month = moment(record.timestamp).format('YYYY-MM');
      monthlyUsage[month] = (monthlyUsage[month] || 0) + 1;
    });

    return monthlyUsage;
  }
}

module.exports = OptimizationService;
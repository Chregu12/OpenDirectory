/**
 * OpenDirectory Cloud Cost Optimizer
 * Advanced cost optimization with analytics, forecasting, and ROI analysis
 */

const crypto = require('crypto');
const EventEmitter = require('events');

class CloudCostOptimizer extends EventEmitter {
    constructor(config = {}) {
        super();
        this.resources = new Map();
        this.costData = new Map();
        this.budgets = new Map();
        this.alerts = new Map();
        this.recommendations = new Map();
        this.reservedInstances = new Map();
        this.spotInstances = new Map();
        this.tagPolicies = new Map();
        this.forecastModels = new Map();
        this.roiAnalytics = new Map();
        this.config = {
            trackingEnabled: config.trackingEnabled !== false,
            forecastingEnabled: config.forecastingEnabled !== false,
            alertsEnabled: config.alertsEnabled !== false,
            autoOptimization: config.autoOptimization || false,
            rightsizingEnabled: config.rightsizingEnabled !== false,
            scheduledShutdown: config.scheduledShutdown !== false,
            tagEnforcement: config.tagEnforcement !== false,
            ...config
        };
        this.initializeOptimizer();
    }

    initializeOptimizer() {
        console.log('Initializing Cloud Cost Optimizer...');
        this.startCostTracking();
        this.setupEventHandlers();
        this.initializeForecasting();
    }

    // Resource Usage Analytics
    async trackResourceUsage(resourceConfig) {
        const resourceId = resourceConfig.resourceId || this.generateId();
        const resource = {
            id: resourceId,
            name: resourceConfig.name,
            type: resourceConfig.type,
            provider: resourceConfig.provider,
            region: resourceConfig.region,
            instanceType: resourceConfig.instanceType,
            state: resourceConfig.state || 'running',
            tags: resourceConfig.tags || {},
            pricing: {
                hourly: resourceConfig.pricing?.hourly || 0,
                monthly: resourceConfig.pricing?.monthly || 0,
                onDemand: resourceConfig.pricing?.onDemand || 0,
                reserved: resourceConfig.pricing?.reserved || 0,
                spot: resourceConfig.pricing?.spot || 0
            },
            usage: {
                cpu: new Map(),
                memory: new Map(),
                network: new Map(),
                storage: new Map()
            },
            costHistory: new Map(),
            optimization: {
                rightsizing: null,
                scheduling: null,
                reservedInstance: null,
                spotInstance: null
            },
            createdAt: new Date(),
            lastUpdated: new Date()
        };

        this.resources.set(resourceId, resource);
        await this.collectResourceMetrics(resource);

        return {
            success: true,
            resourceId,
            resource: this.sanitizeResource(resource)
        };
    }

    async collectResourceMetrics(resource) {
        const timestamp = new Date();
        const metrics = {
            timestamp,
            cpu: {
                utilization: Math.random() * 100,
                cores: resource.instanceType?.includes('large') ? 4 : 2,
                allocation: resource.instanceType?.includes('large') ? 100 : 50
            },
            memory: {
                utilization: Math.random() * 100,
                allocated: resource.instanceType?.includes('large') ? 16 : 8, // GB
                used: Math.random() * (resource.instanceType?.includes('large') ? 16 : 8)
            },
            network: {
                inbound: Math.random() * 1000, // MB
                outbound: Math.random() * 1000,
                requests: Math.floor(Math.random() * 10000)
            },
            storage: {
                reads: Math.floor(Math.random() * 1000),
                writes: Math.floor(Math.random() * 1000),
                size: Math.random() * 100 + 20 // GB
            },
            cost: {
                current: resource.pricing.hourly,
                accumulated: 0
            }
        };

        // Store metrics
        resource.usage.cpu.set(timestamp.getTime(), metrics.cpu);
        resource.usage.memory.set(timestamp.getTime(), metrics.memory);
        resource.usage.network.set(timestamp.getTime(), metrics.network);
        resource.usage.storage.set(timestamp.getTime(), metrics.storage);

        // Calculate cost
        const hourlyCost = this.calculateResourceCost(resource, metrics);
        resource.costHistory.set(timestamp.getTime(), hourlyCost);

        // Update totals
        const costData = this.getCostData(resource.provider, resource.region);
        costData.totalCost += hourlyCost;
        costData.lastUpdated = timestamp;

        resource.lastUpdated = timestamp;
        
        return metrics;
    }

    calculateResourceCost(resource, metrics) {
        let cost = 0;

        // Base instance cost
        cost += resource.pricing.hourly;

        // Storage cost
        const storageCost = (metrics.storage.size / 1000) * 0.10; // $0.10 per GB-month
        cost += storageCost / (24 * 30); // Convert to hourly

        // Network cost (data transfer)
        const networkCost = ((metrics.network.inbound + metrics.network.outbound) / 1000) * 0.09; // $0.09 per GB
        cost += networkCost;

        // Additional costs based on resource type
        switch (resource.type) {
            case 'database':
                cost += metrics.storage.reads * 0.0000004 + metrics.storage.writes * 0.0000013;
                break;
            case 'load-balancer':
                cost += (metrics.network.requests / 1000000) * 0.008; // $0.008 per million requests
                break;
            case 'container':
                cost += metrics.cpu.utilization * 0.00001; // CPU-based pricing
                break;
        }

        return Math.round(cost * 100000) / 100000; // Round to 5 decimal places
    }

    getCostData(provider, region) {
        const key = `${provider}-${region}`;
        if (!this.costData.has(key)) {
            this.costData.set(key, {
                provider,
                region,
                totalCost: 0,
                resources: new Set(),
                trends: new Map(),
                forecasts: new Map(),
                lastUpdated: new Date()
            });
        }
        return this.costData.get(key);
    }

    // Cost Prediction and Forecasting
    async generateCostForecast(forecastConfig) {
        const forecastId = this.generateId();
        const forecast = {
            id: forecastId,
            name: forecastConfig.name,
            scope: forecastConfig.scope, // 'resource', 'service', 'account', 'organization'
            resourceIds: forecastConfig.resourceIds || [],
            timeframe: forecastConfig.timeframe || '3months', // 1month, 3months, 6months, 1year
            granularity: forecastConfig.granularity || 'daily', // hourly, daily, weekly, monthly
            model: forecastConfig.model || 'linear-regression',
            factors: forecastConfig.factors || ['usage', 'seasonality', 'growth'],
            confidence: forecastConfig.confidence || 80, // percentage
            predictions: new Map(),
            accuracy: null,
            generatedAt: new Date()
        };

        // Generate predictions based on historical data
        await this.runForecastModel(forecast);

        // Calculate confidence intervals
        await this.calculateConfidenceIntervals(forecast);

        // Generate scenarios
        forecast.scenarios = await this.generateScenarios(forecast);

        this.forecastModels.set(forecastId, forecast);
        this.emit('forecastGenerated', forecast);

        return {
            success: true,
            forecastId,
            forecast: this.sanitizeForecast(forecast)
        };
    }

    async runForecastModel(forecast) {
        console.log(`Running ${forecast.model} forecast model for ${forecast.timeframe}...`);
        
        const historicalData = await this.getHistoricalCostData(forecast);
        const timeframeDays = this.getTimeframeDays(forecast.timeframe);
        
        switch (forecast.model) {
            case 'linear-regression':
                await this.runLinearRegression(forecast, historicalData, timeframeDays);
                break;
            case 'moving-average':
                await this.runMovingAverage(forecast, historicalData, timeframeDays);
                break;
            case 'exponential-smoothing':
                await this.runExponentialSmoothing(forecast, historicalData, timeframeDays);
                break;
            case 'seasonal-arima':
                await this.runSeasonalARIMA(forecast, historicalData, timeframeDays);
                break;
        }
    }

    async runLinearRegression(forecast, historicalData, timeframeDays) {
        // Simple linear regression implementation
        const n = historicalData.length;
        if (n < 7) {
            throw new Error('Insufficient historical data for forecasting');
        }

        let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
        
        historicalData.forEach((point, index) => {
            const x = index;
            const y = point.cost;
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumXX += x * x;
        });

        const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        const intercept = (sumY - slope * sumX) / n;

        // Generate predictions
        const startDate = new Date();
        for (let i = 0; i < timeframeDays; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() + i);
            
            const prediction = slope * (n + i) + intercept;
            const seasonalFactor = this.getSeasonalFactor(date, historicalData);
            const growthFactor = this.getGrowthFactor(forecast.factors);
            
            const adjustedPrediction = prediction * seasonalFactor * growthFactor;
            
            forecast.predictions.set(date.getTime(), {
                date,
                predicted: Math.max(0, adjustedPrediction),
                confidence: forecast.confidence,
                factors: { seasonal: seasonalFactor, growth: growthFactor }
            });
        }
    }

    async runMovingAverage(forecast, historicalData, timeframeDays) {
        const windowSize = Math.min(30, Math.floor(historicalData.length / 2));
        const recentData = historicalData.slice(-windowSize);
        const average = recentData.reduce((sum, point) => sum + point.cost, 0) / recentData.length;

        const startDate = new Date();
        for (let i = 0; i < timeframeDays; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() + i);
            
            const seasonalFactor = this.getSeasonalFactor(date, historicalData);
            const trendFactor = 1 + (i * 0.001); // Slight upward trend
            
            forecast.predictions.set(date.getTime(), {
                date,
                predicted: average * seasonalFactor * trendFactor,
                confidence: forecast.confidence * 0.9, // Lower confidence for simple model
                factors: { seasonal: seasonalFactor, trend: trendFactor }
            });
        }
    }

    async runExponentialSmoothing(forecast, historicalData, timeframeDays) {
        const alpha = 0.3; // Smoothing parameter
        const beta = 0.2;  // Trend parameter
        const gamma = 0.1; // Seasonal parameter

        let level = historicalData[0].cost;
        let trend = 0;
        const seasonalLength = Math.min(7, Math.floor(historicalData.length / 4));
        const seasonal = new Array(seasonalLength).fill(1);

        // Calculate initial values
        for (let i = 1; i < Math.min(historicalData.length, 30); i++) {
            const prevLevel = level;
            level = alpha * historicalData[i].cost + (1 - alpha) * (level + trend);
            trend = beta * (level - prevLevel) + (1 - beta) * trend;
            
            if (i >= seasonalLength) {
                const seasonIndex = i % seasonalLength;
                seasonal[seasonIndex] = gamma * (historicalData[i].cost / level) + (1 - gamma) * seasonal[seasonIndex];
            }
        }

        // Generate predictions
        const startDate = new Date();
        for (let i = 0; i < timeframeDays; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() + i);
            
            const seasonIndex = i % seasonalLength;
            const prediction = (level + i * trend) * seasonal[seasonIndex];
            
            forecast.predictions.set(date.getTime(), {
                date,
                predicted: Math.max(0, prediction),
                confidence: forecast.confidence,
                factors: { level, trend, seasonal: seasonal[seasonIndex] }
            });
        }
    }

    async runSeasonalARIMA(forecast, historicalData, timeframeDays) {
        // Simplified ARIMA implementation
        const seasonalPeriod = 7; // Weekly seasonality
        const n = historicalData.length;
        
        if (n < seasonalPeriod * 4) {
            // Fall back to exponential smoothing if insufficient data
            return await this.runExponentialSmoothing(forecast, historicalData, timeframeDays);
        }

        // Calculate seasonal differences
        const seasonalDiffs = [];
        for (let i = seasonalPeriod; i < n; i++) {
            seasonalDiffs.push(historicalData[i].cost - historicalData[i - seasonalPeriod].cost);
        }

        // Calculate trend
        const trendSum = seasonalDiffs.slice(-14).reduce((sum, diff) => sum + diff, 0);
        const trend = trendSum / 14;

        // Calculate seasonal factors
        const seasonalFactors = new Array(seasonalPeriod);
        for (let i = 0; i < seasonalPeriod; i++) {
            let sum = 0, count = 0;
            for (let j = i; j < n; j += seasonalPeriod) {
                sum += historicalData[j].cost;
                count++;
            }
            seasonalFactors[i] = count > 0 ? sum / count : 1;
        }

        const avgSeasonal = seasonalFactors.reduce((sum, factor) => sum + factor, 0) / seasonalPeriod;
        for (let i = 0; i < seasonalPeriod; i++) {
            seasonalFactors[i] /= avgSeasonal; // Normalize
        }

        // Generate predictions
        const baseLevel = historicalData[n - 1].cost;
        const startDate = new Date();
        
        for (let i = 0; i < timeframeDays; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() + i);
            
            const seasonIndex = i % seasonalPeriod;
            const prediction = (baseLevel + i * trend) * seasonalFactors[seasonIndex];
            
            forecast.predictions.set(date.getTime(), {
                date,
                predicted: Math.max(0, prediction),
                confidence: forecast.confidence,
                factors: { trend, seasonal: seasonalFactors[seasonIndex] }
            });
        }
    }

    async calculateConfidenceIntervals(forecast) {
        const predictions = Array.from(forecast.predictions.values());
        const stdDev = this.calculateStandardDeviation(predictions.map(p => p.predicted));
        
        const confidenceMultiplier = this.getConfidenceMultiplier(forecast.confidence);
        
        predictions.forEach(prediction => {
            const margin = stdDev * confidenceMultiplier;
            prediction.upperBound = prediction.predicted + margin;
            prediction.lowerBound = Math.max(0, prediction.predicted - margin);
        });
    }

    async generateScenarios(forecast) {
        const basePredictions = Array.from(forecast.predictions.values());
        const scenarios = {
            optimistic: new Map(),
            pessimistic: new Map(),
            conservative: new Map()
        };

        basePredictions.forEach(prediction => {
            const timestamp = prediction.date.getTime();
            
            // Optimistic: 15% lower costs (better optimization)
            scenarios.optimistic.set(timestamp, {
                ...prediction,
                predicted: prediction.predicted * 0.85,
                scenario: 'optimistic',
                description: 'With aggressive cost optimization'
            });
            
            // Pessimistic: 25% higher costs (growth without optimization)
            scenarios.pessimistic.set(timestamp, {
                ...prediction,
                predicted: prediction.predicted * 1.25,
                scenario: 'pessimistic',
                description: 'With continued growth and no optimization'
            });
            
            // Conservative: 5% lower costs (modest optimization)
            scenarios.conservative.set(timestamp, {
                ...prediction,
                predicted: prediction.predicted * 0.95,
                scenario: 'conservative',
                description: 'With modest cost optimization'
            });
        });

        return scenarios;
    }

    // Right-sizing Recommendations
    async generateRightsizingRecommendations(resourceId = null) {
        const resources = resourceId ? [this.resources.get(resourceId)] : Array.from(this.resources.values());
        const recommendations = [];

        for (const resource of resources) {
            if (!resource) continue;

            const recommendation = await this.analyzeResourceUtilization(resource);
            if (recommendation) {
                recommendations.push(recommendation);
                this.recommendations.set(this.generateId(), recommendation);
            }
        }

        this.emit('rightsizingRecommendationsGenerated', {
            count: recommendations.length,
            totalPotentialSavings: recommendations.reduce((sum, rec) => sum + rec.monthlySavings, 0)
        });

        return recommendations;
    }

    async analyzeResourceUtilization(resource) {
        const recentMetrics = this.getRecentMetrics(resource, 7); // Last 7 days
        if (recentMetrics.length < 24) return null; // Need at least 24 hours of data

        const avgCpuUtil = this.calculateAverage(recentMetrics, 'cpu.utilization');
        const avgMemoryUtil = this.calculateAverage(recentMetrics, 'memory.utilization');
        const maxCpuUtil = this.calculateMax(recentMetrics, 'cpu.utilization');
        const maxMemoryUtil = this.calculateMax(recentMetrics, 'memory.utilization');

        let recommendation = null;

        // Over-provisioned resource
        if (avgCpuUtil < 20 && avgMemoryUtil < 25 && maxCpuUtil < 50) {
            const newInstanceType = this.getDownsizedInstance(resource.instanceType);
            if (newInstanceType) {
                const currentCost = resource.pricing.monthly || (resource.pricing.hourly * 24 * 30);
                const newCost = this.getInstanceTypeCost(newInstanceType).monthly;
                
                recommendation = {
                    type: 'downsize',
                    resourceId: resource.id,
                    resourceName: resource.name,
                    provider: resource.provider,
                    currentInstanceType: resource.instanceType,
                    recommendedInstanceType: newInstanceType,
                    reason: `Low utilization: CPU ${avgCpuUtil.toFixed(1)}%, Memory ${avgMemoryUtil.toFixed(1)}%`,
                    utilization: {
                        avgCpu: avgCpuUtil,
                        avgMemory: avgMemoryUtil,
                        maxCpu: maxCpuUtil,
                        maxMemory: maxMemoryUtil
                    },
                    currentCost: currentCost,
                    newCost: newCost,
                    monthlySavings: currentCost - newCost,
                    savingsPercentage: ((currentCost - newCost) / currentCost) * 100,
                    confidence: 85,
                    priority: 'HIGH'
                };
            }
        }
        // Under-provisioned resource
        else if (avgCpuUtil > 80 || avgMemoryUtil > 85 || maxCpuUtil > 95) {
            const newInstanceType = this.getUpsizedInstance(resource.instanceType);
            if (newInstanceType) {
                const currentCost = resource.pricing.monthly || (resource.pricing.hourly * 24 * 30);
                const newCost = this.getInstanceTypeCost(newInstanceType).monthly;
                
                recommendation = {
                    type: 'upsize',
                    resourceId: resource.id,
                    resourceName: resource.name,
                    provider: resource.provider,
                    currentInstanceType: resource.instanceType,
                    recommendedInstanceType: newInstanceType,
                    reason: `High utilization: CPU ${avgCpuUtil.toFixed(1)}%, Memory ${avgMemoryUtil.toFixed(1)}%`,
                    utilization: {
                        avgCpu: avgCpuUtil,
                        avgMemory: avgMemoryUtil,
                        maxCpu: maxCpuUtil,
                        maxMemory: maxMemoryUtil
                    },
                    currentCost: currentCost,
                    newCost: newCost,
                    additionalCost: newCost - currentCost,
                    performanceGain: 'Improved performance and reduced throttling',
                    confidence: 90,
                    priority: 'CRITICAL'
                };
            }
        }

        return recommendation;
    }

    // Reserved Instance Management
    async analyzeReservedInstanceOpportunities(analysisConfig = {}) {
        const timeframe = analysisConfig.timeframe || 30; // days
        const minUtilization = analysisConfig.minUtilization || 70; // percent
        const opportunities = [];

        for (const [resourceId, resource] of this.resources) {
            if (resource.type !== 'compute') continue;

            const utilization = await this.calculateResourceUtilization(resourceId, timeframe);
            
            if (utilization >= minUtilization) {
                const opportunity = {
                    resourceId: resource.id,
                    resourceName: resource.name,
                    provider: resource.provider,
                    instanceType: resource.instanceType,
                    region: resource.region,
                    utilization: utilization,
                    currentCost: {
                        onDemand: resource.pricing.onDemand || resource.pricing.hourly,
                        monthly: resource.pricing.monthly || (resource.pricing.hourly * 24 * 30)
                    },
                    reservedOptions: await this.getReservedInstanceOptions(resource),
                    recommendedTerm: this.getRecommendedTerm(utilization),
                    paymentOption: this.getRecommendedPaymentOption(resource)
                };

                // Calculate savings
                const bestOption = opportunity.reservedOptions
                    .sort((a, b) => b.savings.total - a.savings.total)[0];
                
                if (bestOption && bestOption.savings.total > 0) {
                    opportunity.recommendation = bestOption;
                    opportunities.push(opportunity);
                }
            }
        }

        return opportunities;
    }

    async getReservedInstanceOptions(resource) {
        const terms = ['1year', '3years'];
        const paymentOptions = ['no-upfront', 'partial-upfront', 'all-upfront'];
        const options = [];

        for (const term of terms) {
            for (const payment of paymentOptions) {
                const pricing = this.calculateReservedInstancePricing(resource, term, payment);
                const savings = this.calculateReservedInstanceSavings(resource, pricing, term);
                
                options.push({
                    term,
                    paymentOption: payment,
                    pricing,
                    savings,
                    breakeven: savings.breakevenMonths
                });
            }
        }

        return options.sort((a, b) => b.savings.total - a.savings.total);
    }

    calculateReservedInstancePricing(resource, term, paymentOption) {
        const onDemandHourly = resource.pricing.hourly || 0.10;
        let discount = 0;

        // Apply discounts based on term and payment
        if (term === '1year') {
            discount = paymentOption === 'all-upfront' ? 0.35 : 
                      paymentOption === 'partial-upfront' ? 0.30 : 0.25;
        } else if (term === '3years') {
            discount = paymentOption === 'all-upfront' ? 0.55 : 
                      paymentOption === 'partial-upfront' ? 0.50 : 0.45;
        }

        const reservedHourly = onDemandHourly * (1 - discount);
        const termMonths = term === '1year' ? 12 : 36;
        const totalHours = termMonths * 24 * 30;

        let upfront = 0;
        let hourly = reservedHourly;

        if (paymentOption === 'all-upfront') {
            upfront = totalHours * reservedHourly;
            hourly = 0;
        } else if (paymentOption === 'partial-upfront') {
            upfront = (totalHours * reservedHourly) / 2;
            hourly = reservedHourly / 2;
        }

        return {
            upfront,
            hourly,
            monthly: hourly * 24 * 30,
            total: upfront + (hourly * totalHours)
        };
    }

    calculateReservedInstanceSavings(resource, pricing, term) {
        const termMonths = term === '1year' ? 12 : 36;
        const onDemandTotal = (resource.pricing.hourly || 0.10) * 24 * 30 * termMonths;
        const reservedTotal = pricing.total;
        
        const totalSavings = onDemandTotal - reservedTotal;
        const monthlySavings = totalSavings / termMonths;
        const savingsPercentage = (totalSavings / onDemandTotal) * 100;
        
        // Calculate break-even point
        const breakevenMonths = pricing.upfront > 0 ? 
            Math.ceil(pricing.upfront / monthlySavings) : 0;

        return {
            total: totalSavings,
            monthly: monthlySavings,
            percentage: savingsPercentage,
            breakevenMonths
        };
    }

    // Spot Instance Management
    async analyzeSpotInstanceOpportunities() {
        const opportunities = [];

        for (const [resourceId, resource] of this.resources) {
            if (resource.type !== 'compute' || !this.isSpotEligible(resource)) continue;

            const spotPricing = await this.getSpotPricing(resource);
            const interruptionRisk = await this.calculateInterruptionRisk(resource);
            
            const opportunity = {
                resourceId: resource.id,
                resourceName: resource.name,
                provider: resource.provider,
                instanceType: resource.instanceType,
                region: resource.region,
                currentCost: resource.pricing.hourly || 0,
                spotPrice: spotPricing.current,
                spotSavings: {
                    hourly: (resource.pricing.hourly || 0) - spotPricing.current,
                    percentage: ((resource.pricing.hourly || 0) - spotPricing.current) / (resource.pricing.hourly || 0) * 100
                },
                interruptionRisk: interruptionRisk,
                suitability: this.calculateSpotSuitability(resource, interruptionRisk),
                recommendation: this.getSpotRecommendation(resource, spotPricing, interruptionRisk)
            };

            if (opportunity.spotSavings.percentage > 10) {
                opportunities.push(opportunity);
            }
        }

        return opportunities;
    }

    async getSpotPricing(resource) {
        // Simulate spot pricing (typically 60-80% cheaper than on-demand)
        const onDemandPrice = resource.pricing.hourly || 0.10;
        const discount = 0.6 + Math.random() * 0.2; // 60-80% discount
        const currentPrice = onDemandPrice * (1 - discount);
        
        return {
            current: Math.round(currentPrice * 10000) / 10000,
            history: this.generateSpotPriceHistory(currentPrice),
            volatility: Math.random() * 30 + 10 // 10-40% volatility
        };
    }

    generateSpotPriceHistory(currentPrice) {
        const history = [];
        let price = currentPrice;
        
        for (let i = 0; i < 168; i++) { // 7 days hourly
            price *= (0.98 + Math.random() * 0.04); // ±2% change
            history.push({
                timestamp: new Date(Date.now() - (168 - i) * 3600000),
                price: Math.round(price * 10000) / 10000
            });
        }
        
        return history;
    }

    // Budget Management
    async createBudget(budgetConfig) {
        const budgetId = this.generateId();
        const budget = {
            id: budgetId,
            name: budgetConfig.name,
            description: budgetConfig.description,
            amount: budgetConfig.amount,
            currency: budgetConfig.currency || 'USD',
            period: budgetConfig.period || 'monthly', // daily, weekly, monthly, quarterly, yearly
            scope: budgetConfig.scope || 'account', // account, service, tag, resource
            filters: budgetConfig.filters || {},
            alerts: budgetConfig.alerts || [],
            actualSpend: 0,
            forecastedSpend: 0,
            utilization: 0,
            status: 'active',
            createdAt: new Date(),
            lastUpdated: new Date()
        };

        // Set up budget alerts
        for (const alertConfig of budget.alerts) {
            await this.createBudgetAlert(budget, alertConfig);
        }

        this.budgets.set(budgetId, budget);
        this.emit('budgetCreated', budget);

        return {
            success: true,
            budgetId,
            budget
        };
    }

    async createBudgetAlert(budget, alertConfig) {
        const alertId = this.generateId();
        const alert = {
            id: alertId,
            budgetId: budget.id,
            threshold: alertConfig.threshold, // percentage of budget
            type: alertConfig.type || 'actual', // actual, forecasted
            notifications: alertConfig.notifications || ['email'],
            enabled: alertConfig.enabled !== false,
            triggered: false,
            lastTriggered: null,
            createdAt: new Date()
        };

        this.alerts.set(alertId, alert);
        return alert;
    }

    async updateBudgetSpending(budgetId) {
        const budget = this.budgets.get(budgetId);
        if (!budget) return;

        // Calculate actual spending based on scope
        const actualSpend = await this.calculateBudgetSpending(budget);
        const forecastedSpend = await this.forecastBudgetSpending(budget);
        
        budget.actualSpend = actualSpend;
        budget.forecastedSpend = forecastedSpend;
        budget.utilization = (actualSpend / budget.amount) * 100;
        budget.lastUpdated = new Date();

        // Check alerts
        await this.checkBudgetAlerts(budget);
    }

    async calculateBudgetSpending(budget) {
        let totalSpend = 0;
        const periodStart = this.getBudgetPeriodStart(budget);

        for (const [resourceId, resource] of this.resources) {
            if (!this.resourceMatchesScope(resource, budget)) continue;

            // Calculate spending for this period
            const resourceSpend = this.calculateResourceSpendingForPeriod(resource, periodStart, new Date());
            totalSpend += resourceSpend;
        }

        return totalSpend;
    }

    // Tag-based Cost Allocation
    async createTagPolicy(policyConfig) {
        const policyId = this.generateId();
        const policy = {
            id: policyId,
            name: policyConfig.name,
            description: policyConfig.description,
            requiredTags: policyConfig.requiredTags || [], // Array of tag keys that must be present
            allowedValues: policyConfig.allowedValues || {}, // Tag key -> allowed values
            enforcement: policyConfig.enforcement || 'warn', // warn, block
            scope: policyConfig.scope || 'account', // account, service, resource-type
            exemptions: policyConfig.exemptions || [],
            createdAt: new Date(),
            status: 'active'
        };

        this.tagPolicies.set(policyId, policy);
        
        // Apply policy to existing resources
        await this.auditTagCompliance(policyId);

        return {
            success: true,
            policyId,
            policy
        };
    }

    async auditTagCompliance(policyId = null) {
        const policies = policyId ? [this.tagPolicies.get(policyId)] : Array.from(this.tagPolicies.values());
        const violations = [];

        for (const policy of policies) {
            if (!policy) continue;

            for (const [resourceId, resource] of this.resources) {
                const compliance = this.checkResourceTagCompliance(resource, policy);
                
                if (!compliance.compliant) {
                    violations.push({
                        resourceId: resource.id,
                        resourceName: resource.name,
                        policyId: policy.id,
                        policyName: policy.name,
                        violations: compliance.violations,
                        severity: policy.enforcement === 'block' ? 'HIGH' : 'MEDIUM'
                    });
                }
            }
        }

        if (violations.length > 0) {
            this.emit('tagComplianceViolations', {
                count: violations.length,
                violations
            });
        }

        return violations;
    }

    checkResourceTagCompliance(resource, policy) {
        const violations = [];
        const resourceTags = resource.tags || {};

        // Check required tags
        for (const requiredTag of policy.requiredTags) {
            if (!resourceTags.hasOwnProperty(requiredTag)) {
                violations.push({
                    type: 'missing-required-tag',
                    tag: requiredTag,
                    description: `Required tag '${requiredTag}' is missing`
                });
            }
        }

        // Check allowed values
        for (const [tagKey, allowedValues] of Object.entries(policy.allowedValues)) {
            if (resourceTags[tagKey] && !allowedValues.includes(resourceTags[tagKey])) {
                violations.push({
                    type: 'invalid-tag-value',
                    tag: tagKey,
                    value: resourceTags[tagKey],
                    allowedValues,
                    description: `Tag '${tagKey}' has invalid value '${resourceTags[tagKey]}'`
                });
            }
        }

        return {
            compliant: violations.length === 0,
            violations
        };
    }

    async generateCostAllocationReport(reportConfig) {
        const report = {
            id: this.generateId(),
            name: reportConfig.name || 'Cost Allocation Report',
            timeframe: reportConfig.timeframe || 'monthly',
            groupBy: reportConfig.groupBy || ['department', 'project'], // Tag keys to group by
            generatedAt: new Date(),
            allocations: new Map(),
            unallocated: 0,
            totalCost: 0
        };

        const resources = Array.from(this.resources.values());
        
        for (const resource of resources) {
            const cost = this.calculateResourceTotalCost(resource, reportConfig.timeframe);
            const allocation = this.allocateResourceCost(resource, report.groupBy);
            
            report.totalCost += cost;
            
            if (allocation) {
                const key = JSON.stringify(allocation);
                if (!report.allocations.has(key)) {
                    report.allocations.set(key, {
                        allocation,
                        cost: 0,
                        resources: []
                    });
                }
                
                const group = report.allocations.get(key);
                group.cost += cost;
                group.resources.push({
                    id: resource.id,
                    name: resource.name,
                    type: resource.type,
                    cost
                });
            } else {
                report.unallocated += cost;
            }
        }

        return report;
    }

    // ROI Analysis and Reporting
    async generateROIAnalysis(analysisConfig) {
        const analysis = {
            id: this.generateId(),
            name: analysisConfig.name || 'Cost Optimization ROI Analysis',
            timeframe: analysisConfig.timeframe || '12months',
            scope: analysisConfig.scope || 'account',
            generatedAt: new Date(),
            investments: [],
            returns: [],
            totalInvestment: 0,
            totalReturns: 0,
            roi: 0,
            paybackPeriod: 0,
            npv: 0
        };

        // Analyze optimization investments
        await this.analyzeOptimizationInvestments(analysis);
        
        // Calculate returns
        await this.calculateOptimizationReturns(analysis);
        
        // Calculate ROI metrics
        this.calculateROIMetrics(analysis);

        this.roiAnalytics.set(analysis.id, analysis);
        
        return analysis;
    }

    async analyzeOptimizationInvestments(analysis) {
        // Reserved Instance purchases
        const riInvestments = Array.from(this.reservedInstances.values())
            .filter(ri => ri.purchaseDate >= this.getAnalysisStartDate(analysis.timeframe))
            .map(ri => ({
                type: 'reserved-instance',
                description: `${ri.instanceType} Reserved Instance`,
                amount: ri.upfrontCost || 0,
                date: ri.purchaseDate
            }));

        // Right-sizing implementations (assume some cost for migration)
        const rightsizingInvestments = Array.from(this.recommendations.values())
            .filter(rec => rec.type === 'downsize' && rec.status === 'implemented')
            .map(rec => ({
                type: 'rightsizing',
                description: `Migration cost for ${rec.resourceName}`,
                amount: 100, // Estimated migration cost
                date: rec.implementedDate
            }));

        analysis.investments = [...riInvestments, ...rightsizingInvestments];
        analysis.totalInvestment = analysis.investments.reduce((sum, inv) => sum + inv.amount, 0);
    }

    async calculateOptimizationReturns(analysis) {
        const timeframeMonths = this.getTimeframeMonths(analysis.timeframe);
        const monthlyReturns = [];

        // Calculate monthly savings from various optimizations
        for (let month = 0; month < timeframeMonths; month++) {
            const monthlyReturn = {
                month,
                date: new Date(Date.now() + month * 30 * 24 * 60 * 60 * 1000),
                sources: {
                    rightsizing: this.calculateRightsizingSavings(month),
                    reservedInstances: this.calculateReservedInstanceSavings(month),
                    spotInstances: this.calculateSpotInstanceSavings(month),
                    scheduledShutdown: this.calculateScheduledShutdownSavings(month)
                }
            };

            monthlyReturn.total = Object.values(monthlyReturn.sources).reduce((sum, savings) => sum + savings, 0);
            monthlyReturns.push(monthlyReturn);
        }

        analysis.returns = monthlyReturns;
        analysis.totalReturns = monthlyReturns.reduce((sum, ret) => sum + ret.total, 0);
    }

    calculateROIMetrics(analysis) {
        if (analysis.totalInvestment === 0) {
            analysis.roi = analysis.totalReturns > 0 ? Infinity : 0;
            analysis.paybackPeriod = 0;
        } else {
            analysis.roi = ((analysis.totalReturns - analysis.totalInvestment) / analysis.totalInvestment) * 100;
            
            // Calculate payback period
            let cumulativeReturns = 0;
            analysis.paybackPeriod = analysis.returns.findIndex(ret => {
                cumulativeReturns += ret.total;
                return cumulativeReturns >= analysis.totalInvestment;
            });
        }

        // Calculate NPV (simplified, assuming 10% discount rate)
        const discountRate = 0.10 / 12; // Monthly discount rate
        analysis.npv = -analysis.totalInvestment + analysis.returns.reduce((npv, ret, index) => {
            return npv + (ret.total / Math.pow(1 + discountRate, index));
        }, 0);
    }

    // Monitoring and Events
    startCostTracking() {
        if (!this.config.trackingEnabled) return;

        console.log('Starting cost tracking...');
        
        // Resource metrics collection
        setInterval(() => {
            this.collectAllResourceMetrics().catch(console.error);
        }, 300000); // Every 5 minutes

        // Budget monitoring
        setInterval(() => {
            this.monitorBudgets().catch(console.error);
        }, 600000); // Every 10 minutes

        // Generate recommendations
        setInterval(() => {
            this.generateAllRecommendations().catch(console.error);
        }, 3600000); // Every hour

        // Tag compliance audit
        if (this.config.tagEnforcement) {
            setInterval(() => {
                this.auditTagCompliance().catch(console.error);
            }, 1800000); // Every 30 minutes
        }
    }

    async collectAllResourceMetrics() {
        for (const [resourceId, resource] of this.resources) {
            await this.collectResourceMetrics(resource);
        }
    }

    async monitorBudgets() {
        for (const [budgetId] of this.budgets) {
            await this.updateBudgetSpending(budgetId);
        }
    }

    async generateAllRecommendations() {
        await this.generateRightsizingRecommendations();
        
        if (new Date().getHours() % 6 === 0) { // Every 6 hours
            await this.analyzeReservedInstanceOpportunities();
            await this.analyzeSpotInstanceOpportunities();
        }
    }

    async checkBudgetAlerts(budget) {
        const budgetAlerts = Array.from(this.alerts.values())
            .filter(alert => alert.budgetId === budget.id && alert.enabled);

        for (const alert of budgetAlerts) {
            const threshold = (budget.amount * alert.threshold) / 100;
            const spending = alert.type === 'forecasted' ? budget.forecastedSpend : budget.actualSpend;
            
            if (spending >= threshold && !alert.triggered) {
                alert.triggered = true;
                alert.lastTriggered = new Date();
                
                this.emit('budgetAlertTriggered', {
                    budget,
                    alert,
                    spending,
                    threshold,
                    overageAmount: spending - threshold,
                    overagePercentage: ((spending - threshold) / threshold) * 100
                });
            } else if (spending < threshold && alert.triggered) {
                alert.triggered = false; // Reset alert
            }
        }
    }

    setupEventHandlers() {
        this.on('budgetAlertTriggered', (event) => {
            console.log(`Budget alert: ${event.budget.name} has exceeded ${event.alert.threshold}% threshold`);
        });

        this.on('rightsizingRecommendationsGenerated', (event) => {
            console.log(`Generated ${event.count} rightsizing recommendations with potential savings of $${event.totalPotentialSavings.toFixed(2)}`);
        });

        this.on('forecastGenerated', (forecast) => {
            console.log(`Cost forecast generated: ${forecast.name} (${forecast.timeframe})`);
        });

        this.on('tagComplianceViolations', (event) => {
            console.log(`Tag compliance violations detected: ${event.count} violations`);
        });
    }

    // Utility Methods
    getHistoricalCostData(forecast) {
        const data = [];
        const resources = forecast.resourceIds.length > 0 ? 
            forecast.resourceIds.map(id => this.resources.get(id)).filter(r => r) :
            Array.from(this.resources.values());

        // Generate 90 days of historical data
        for (let i = 90; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            
            let dailyCost = 0;
            resources.forEach(resource => {
                dailyCost += resource.pricing.hourly * 24 || 0;
            });
            
            // Add some variance
            dailyCost *= (0.8 + Math.random() * 0.4); // ±20% variance
            
            data.push({
                date,
                cost: dailyCost
            });
        }
        
        return data;
    }

    getTimeframeDays(timeframe) {
        const timeframes = {
            '1week': 7,
            '1month': 30,
            '3months': 90,
            '6months': 180,
            '1year': 365
        };
        return timeframes[timeframe] || 90;
    }

    getTimeframeMonths(timeframe) {
        const timeframes = {
            '3months': 3,
            '6months': 6,
            '12months': 12,
            '24months': 24
        };
        return timeframes[timeframe] || 12;
    }

    getSeasonalFactor(date, historicalData) {
        const dayOfYear = Math.floor((date - new Date(date.getFullYear(), 0, 0)) / 86400000);
        const seasonality = 1 + 0.1 * Math.sin((2 * Math.PI * dayOfYear) / 365); // ±10% seasonal variation
        return seasonality;
    }

    getGrowthFactor(factors) {
        if (factors.includes('growth')) {
            return 1.02; // 2% monthly growth
        }
        return 1;
    }

    calculateStandardDeviation(values) {
        const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
        const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
        return Math.sqrt(variance);
    }

    getConfidenceMultiplier(confidence) {
        // Z-scores for common confidence levels
        const zScores = {
            80: 1.28,
            85: 1.44,
            90: 1.65,
            95: 1.96,
            99: 2.58
        };
        return zScores[confidence] || 1.96;
    }

    getRecentMetrics(resource, days) {
        const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
        const metrics = [];
        
        for (const [timestamp, cpuMetrics] of resource.usage.cpu) {
            if (timestamp >= cutoff) {
                const memoryMetrics = resource.usage.memory.get(timestamp);
                const networkMetrics = resource.usage.network.get(timestamp);
                const storageMetrics = resource.usage.storage.get(timestamp);
                
                if (memoryMetrics && networkMetrics && storageMetrics) {
                    metrics.push({
                        timestamp: new Date(timestamp),
                        cpu: cpuMetrics,
                        memory: memoryMetrics,
                        network: networkMetrics,
                        storage: storageMetrics
                    });
                }
            }
        }
        
        return metrics;
    }

    calculateAverage(metrics, path) {
        const values = metrics.map(m => this.getNestedValue(m, path)).filter(v => v !== undefined);
        return values.length > 0 ? values.reduce((sum, val) => sum + val, 0) / values.length : 0;
    }

    calculateMax(metrics, path) {
        const values = metrics.map(m => this.getNestedValue(m, path)).filter(v => v !== undefined);
        return values.length > 0 ? Math.max(...values) : 0;
    }

    getNestedValue(obj, path) {
        return path.split('.').reduce((current, key) => current && current[key], obj);
    }

    getDownsizedInstance(currentType) {
        const downsizeMap = {
            'large': 'medium',
            'xlarge': 'large',
            '2xlarge': 'xlarge',
            '4xlarge': '2xlarge'
        };
        
        for (const [large, small] of Object.entries(downsizeMap)) {
            if (currentType?.includes(large)) {
                return currentType.replace(large, small);
            }
        }
        return null;
    }

    getUpsizedInstance(currentType) {
        const upsizeMap = {
            'medium': 'large',
            'large': 'xlarge',
            'xlarge': '2xlarge',
            '2xlarge': '4xlarge'
        };
        
        for (const [small, large] of Object.entries(upsizeMap)) {
            if (currentType?.includes(small)) {
                return currentType.replace(small, large);
            }
        }
        return null;
    }

    getInstanceTypeCost(instanceType) {
        // Simplified cost mapping
        const baseCost = 0.10;
        const multipliers = {
            'nano': 0.1,
            'micro': 0.2,
            'small': 0.5,
            'medium': 1.0,
            'large': 2.0,
            'xlarge': 4.0,
            '2xlarge': 8.0,
            '4xlarge': 16.0
        };
        
        let multiplier = 1.0;
        for (const [size, mult] of Object.entries(multipliers)) {
            if (instanceType?.includes(size)) {
                multiplier = mult;
                break;
            }
        }
        
        const hourly = baseCost * multiplier;
        return {
            hourly,
            monthly: hourly * 24 * 30
        };
    }

    sanitizeResource(resource) {
        return {
            id: resource.id,
            name: resource.name,
            type: resource.type,
            provider: resource.provider,
            region: resource.region,
            instanceType: resource.instanceType,
            state: resource.state,
            tags: resource.tags,
            costSummary: {
                hourly: resource.pricing.hourly,
                monthly: resource.pricing.monthly
            },
            lastUpdated: resource.lastUpdated
        };
    }

    sanitizeForecast(forecast) {
        return {
            id: forecast.id,
            name: forecast.name,
            timeframe: forecast.timeframe,
            confidence: forecast.confidence,
            predictionsCount: forecast.predictions.size,
            generatedAt: forecast.generatedAt
        };
    }

    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Public API Methods
    async getResources() {
        return Array.from(this.resources.values()).map(r => this.sanitizeResource(r));
    }

    async getCostData(provider = null, region = null) {
        const data = Array.from(this.costData.values());
        return data.filter(d => 
            (!provider || d.provider === provider) && 
            (!region || d.region === region)
        );
    }

    async getBudgets() {
        return Array.from(this.budgets.values());
    }

    async getRecommendations(type = null) {
        const recommendations = Array.from(this.recommendations.values());
        return type ? recommendations.filter(r => r.type === type) : recommendations;
    }

    async getForecasts() {
        return Array.from(this.forecastModels.values()).map(f => this.sanitizeForecast(f));
    }

    async getROIAnalytics() {
        return Array.from(this.roiAnalytics.values());
    }

    getOptimizerStatus() {
        return {
            totalResources: this.resources.size,
            totalBudgets: this.budgets.size,
            activeAlerts: Array.from(this.alerts.values()).filter(a => a.triggered).length,
            totalRecommendations: this.recommendations.size,
            trackingEnabled: this.config.trackingEnabled,
            forecastingEnabled: this.config.forecastingEnabled,
            autoOptimization: this.config.autoOptimization
        };
    }
}

module.exports = CloudCostOptimizer;
/**
 * OpenDirectory ERP Systems Connector
 * Comprehensive integration with Oracle ERP, NetSuite, Workday, and Salesforce
 */

const { BaseConnector } = require('./opendirectory-connector-framework');
const https = require('https');

/**
 * ERP Systems Connector - Unified connector for multiple ERP platforms
 */
class ERPConnector extends BaseConnector {
    constructor(config) {
        super({
            name: 'erp-connector',
            retryAttempts: 5,
            retryDelay: 2000,
            timeout: 60000,
            rateLimit: { requests: 75, window: 60000 },
            healthCheckInterval: 30000,
            ...config
        });
        
        this.erpSystems = {
            oracle: new OracleERPClient(this.config.oracle),
            netsuite: new NetSuiteClient(this.config.netsuite),
            workday: new WorkdayClient(this.config.workday),
            salesforce: new SalesforceClient(this.config.salesforce)
        };
        
        this.setupDataTransformations();
        this.setupFieldMappings();
        this.setupValidators();
    }

    async establishConnection() {
        const connectionResults = await Promise.allSettled([
            this.erpSystems.oracle.connect(),
            this.erpSystems.netsuite.connect(),
            this.erpSystems.workday.connect(),
            this.erpSystems.salesforce.connect()
        ]);

        const failures = connectionResults
            .map((result, index) => ({ 
                result, 
                system: Object.keys(this.erpSystems)[index] 
            }))
            .filter(({ result }) => result.status === 'rejected')
            .map(({ result, system }) => ({ system, error: result.reason }));

        if (failures.length === connectionResults.length) {
            throw new Error(`All ERP connections failed: ${failures.map(f => `${f.system}: ${f.error.message}`).join(', ')}`);
        }

        if (failures.length > 0) {
            console.warn(`Some ERP connections failed:`, failures);
        }

        return true;
    }

    async closeConnections() {
        await Promise.allSettled([
            this.erpSystems.oracle.disconnect(),
            this.erpSystems.netsuite.disconnect(),
            this.erpSystems.workday.disconnect(),
            this.erpSystems.salesforce.disconnect()
        ]);
        
        super.closeConnections();
    }

    async performOperation(operation, data, options = {}) {
        const [system, action] = operation.split(':');
        
        switch (system) {
            case 'oracle':
                return await this.erpSystems.oracle.execute(action, data, options);
            case 'netsuite':
                return await this.erpSystems.netsuite.execute(action, data, options);
            case 'workday':
                return await this.erpSystems.workday.execute(action, data, options);
            case 'salesforce':
                return await this.erpSystems.salesforce.execute(action, data, options);
            default:
                throw new Error(`Unknown ERP system: ${system}`);
        }
    }

    async performHealthCheck() {
        const healthChecks = await Promise.allSettled([
            this.erpSystems.oracle.healthCheck(),
            this.erpSystems.netsuite.healthCheck(),
            this.erpSystems.workday.healthCheck(),
            this.erpSystems.salesforce.healthCheck()
        ]);

        return {
            status: 'healthy',
            systems: {
                oracle: healthChecks[0].status === 'fulfilled' ? 'connected' : 'failed',
                netsuite: healthChecks[1].status === 'fulfilled' ? 'connected' : 'failed',
                workday: healthChecks[2].status === 'fulfilled' ? 'connected' : 'failed',
                salesforce: healthChecks[3].status === 'fulfilled' ? 'connected' : 'failed'
            }
        };
    }

    setupDataTransformations() {
        // Employee lifecycle transformation
        this.dataTransformer.registerTransformation('workday:employee_lifecycle', (data) => {
            return {
                workerReference: {
                    ID: [{
                        type: 'Employee_ID',
                        value: data.employeeId
                    }]
                },
                personalData: {
                    nameData: {
                        legalNameData: {
                            nameDetailData: {
                                firstName: data.firstName,
                                lastName: data.lastName
                            }
                        }
                    },
                    contactData: {
                        emailAddressData: [{
                            emailAddress: data.email,
                            usage: 'WORK',
                            primary: true
                        }]
                    }
                },
                positionData: {
                    jobTitle: data.jobTitle,
                    department: data.department,
                    location: data.location,
                    manager: data.managerId,
                    startDate: data.startDate,
                    endDate: data.endDate
                },
                compensationData: {
                    salary: data.salary,
                    currency: data.currency || 'USD',
                    payFrequency: data.payFrequency || 'Monthly'
                }
            };
        });

        // Oracle ERP financial transformation
        this.dataTransformer.registerTransformation('oracle:financial_transaction', (data) => {
            return {
                transactionHeader: {
                    transactionId: data.transactionId,
                    transactionDate: data.date,
                    transactionType: data.type,
                    description: data.description,
                    reference: data.reference
                },
                transactionLines: data.lineItems.map(item => ({
                    lineNumber: item.lineNumber,
                    accountCode: item.account,
                    debitAmount: item.debitAmount || 0,
                    creditAmount: item.creditAmount || 0,
                    description: item.description,
                    costCenter: item.costCenter,
                    department: item.department
                })),
                totalDebit: data.lineItems.reduce((sum, item) => sum + (item.debitAmount || 0), 0),
                totalCredit: data.lineItems.reduce((sum, item) => sum + (item.creditAmount || 0), 0)
            };
        });

        // NetSuite customer transformation
        this.dataTransformer.registerTransformation('netsuite:customer_sync', (data) => {
            return {
                entityId: data.customerId,
                companyName: data.companyName,
                firstName: data.firstName,
                lastName: data.lastName,
                email: data.email,
                phone: data.phone,
                billingAddress: {
                    addr1: data.billingAddress?.street,
                    city: data.billingAddress?.city,
                    state: data.billingAddress?.state,
                    zip: data.billingAddress?.zip,
                    country: data.billingAddress?.country
                },
                shippingAddress: {
                    addr1: data.shippingAddress?.street,
                    city: data.shippingAddress?.city,
                    state: data.shippingAddress?.state,
                    zip: data.shippingAddress?.zip,
                    country: data.shippingAddress?.country
                },
                terms: data.paymentTerms,
                creditLimit: data.creditLimit,
                salesRep: data.salesRepId
            };
        });

        // Salesforce lead/opportunity transformation
        this.dataTransformer.registerTransformation('salesforce:lead_sync', (data) => {
            return {
                FirstName: data.firstName,
                LastName: data.lastName,
                Company: data.company,
                Email: data.email,
                Phone: data.phone,
                Title: data.title,
                LeadSource: data.source,
                Status: data.status || 'New',
                Industry: data.industry,
                NumberOfEmployees: data.employeeCount,
                AnnualRevenue: data.annualRevenue,
                Description: data.notes,
                OwnerId: data.ownerId
            };
        });
    }

    setupFieldMappings() {
        // OpenDirectory to Workday mappings
        this.dataTransformer.registerFieldMapping('workday:employee_sync', {
            'employeeNumber': 'employeeId',
            'givenName': 'firstName',
            'sn': 'lastName',
            'mail': 'email',
            'title': 'jobTitle',
            'department': 'department',
            'manager': 'managerId',
            'startDate': 'startDate'
        });

        // Oracle ERP mappings
        this.dataTransformer.registerFieldMapping('oracle:employee_sync', {
            'personNumber': 'employeeId',
            'firstName': 'givenName',
            'lastName': 'sn',
            'emailAddress': 'mail',
            'assignmentNumber': 'employeeNumber',
            'jobTitle': 'title',
            'departmentName': 'department'
        });

        // NetSuite mappings
        this.dataTransformer.registerFieldMapping('netsuite:employee_sync', {
            'entityId': 'employeeId',
            'firstName': 'givenName',
            'lastName': 'sn',
            'email': 'mail',
            'title': 'title',
            'department': 'department'
        });

        // Salesforce mappings
        this.dataTransformer.registerFieldMapping('salesforce:user_sync', {
            'FirstName': 'givenName',
            'LastName': 'sn',
            'Email': 'mail',
            'Username': 'uid',
            'Title': 'title',
            'Department': 'department',
            'EmployeeNumber': 'employeeNumber'
        });
    }

    setupValidators() {
        this.dataTransformer.registerValidator('workday:employee_lifecycle', (data) => {
            return data.workerReference && 
                   data.personalData && 
                   data.personalData.nameData &&
                   data.personalData.contactData;
        });

        this.dataTransformer.registerValidator('oracle:financial_transaction', (data) => {
            return data.transactionHeader && 
                   data.transactionLines && 
                   data.transactionLines.length > 0 &&
                   Math.abs(data.totalDebit - data.totalCredit) < 0.01;
        });

        this.dataTransformer.registerValidator('salesforce:lead_sync', (data) => {
            return data.FirstName && data.LastName && data.Company && data.Email;
        });
    }

    // High-level ERP operations
    async syncEmployeeLifecycle(employeeData) {
        const results = [];
        
        // Sync to multiple systems in parallel
        const syncPromises = [];
        
        if (this.erpSystems.workday.isConnected) {
            syncPromises.push(this.executeOperation('workday:employee_lifecycle', employeeData));
        }
        
        if (this.erpSystems.oracle.isConnected) {
            syncPromises.push(this.executeOperation('oracle:employee_sync', employeeData));
        }
        
        if (this.erpSystems.salesforce.isConnected) {
            syncPromises.push(this.executeOperation('salesforce:user_sync', employeeData));
        }
        
        const syncResults = await Promise.allSettled(syncPromises);
        
        syncResults.forEach((result, index) => {
            const system = ['workday', 'oracle', 'salesforce'][index];
            if (result.status === 'fulfilled') {
                results.push({ system, status: 'success', data: result.value });
            } else {
                results.push({ system, status: 'error', error: result.reason.message });
            }
        });
        
        return results;
    }

    async processFinancialData(transactionData) {
        const results = [];
        
        if (this.erpSystems.oracle.isConnected) {
            try {
                const result = await this.executeOperation('oracle:financial_transaction', transactionData);
                results.push({ system: 'oracle', status: 'success', result });
            } catch (error) {
                results.push({ system: 'oracle', status: 'error', error: error.message });
            }
        }
        
        if (this.erpSystems.netsuite.isConnected) {
            try {
                const result = await this.executeOperation('netsuite:financial_transaction', transactionData);
                results.push({ system: 'netsuite', status: 'success', result });
            } catch (error) {
                results.push({ system: 'netsuite', status: 'error', error: error.message });
            }
        }
        
        return results;
    }

    async syncCustomerData(customerData) {
        const results = [];
        const systems = ['netsuite', 'salesforce'];
        
        for (const system of systems) {
            if (this.erpSystems[system].isConnected) {
                try {
                    const result = await this.executeOperation(`${system}:customer_sync`, customerData);
                    results.push({ system, status: 'success', result });
                } catch (error) {
                    results.push({ system, status: 'error', error: error.message });
                }
            }
        }
        
        return results;
    }
}

/**
 * Oracle ERP Cloud Client
 */
class OracleERPClient {
    constructor(config) {
        this.config = {
            baseUrl: config.baseUrl,
            username: config.username,
            password: config.password,
            ...config
        };
        
        this.session = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            await this.authenticate();
            this.isConnected = true;
            return true;
        } catch (error) {
            throw new Error(`Oracle ERP connection failed: ${error.message}`);
        }
    }

    async disconnect() {
        this.session = null;
        this.isConnected = false;
    }

    async authenticate() {
        // Simulate Oracle ERP authentication
        await new Promise(resolve => setTimeout(resolve, 1000));
        this.session = {
            sessionId: Date.now().toString(),
            token: 'oracle_token_' + Date.now(),
            expires: new Date(Date.now() + 3600000) // 1 hour
        };
    }

    async execute(operation, data, options = {}) {
        if (!this.isConnected) {
            throw new Error('Oracle ERP not connected');
        }

        switch (operation) {
            case 'employee_sync':
                return await this.syncEmployee(data);
            case 'financial_transaction':
                return await this.createFinancialTransaction(data);
            case 'get_chart_of_accounts':
                return await this.getChartOfAccounts(data);
            case 'create_journal_entry':
                return await this.createJournalEntry(data);
            case 'sync_cost_centers':
                return await this.syncCostCenters(data);
            case 'asset_management':
                return await this.manageAssets(data);
            default:
                throw new Error(`Unknown Oracle operation: ${operation}`);
        }
    }

    async syncEmployee(employeeData) {
        // Simulate Oracle HCM Cloud API call
        await new Promise(resolve => setTimeout(resolve, 800));
        
        return {
            personNumber: employeeData.employeeId,
            personId: Date.now(),
            displayName: `${employeeData.firstName} ${employeeData.lastName}`,
            assignments: [{
                assignmentId: Date.now(),
                assignmentNumber: employeeData.employeeId,
                jobTitle: employeeData.jobTitle,
                department: employeeData.department,
                location: employeeData.location,
                manager: employeeData.managerId,
                effectiveStartDate: employeeData.startDate,
                effectiveEndDate: employeeData.endDate
            }],
            workRelationships: [{
                workRelationshipId: Date.now(),
                startDate: employeeData.startDate,
                endDate: employeeData.endDate,
                primaryFlag: true
            }]
        };
    }

    async createFinancialTransaction(transactionData) {
        await new Promise(resolve => setTimeout(resolve, 1200));
        
        return {
            journalEntryId: Date.now(),
            journalName: transactionData.transactionHeader.reference,
            status: 'Created',
            totalDebit: transactionData.totalDebit,
            totalCredit: transactionData.totalCredit,
            lines: transactionData.transactionLines.map(line => ({
                lineId: Date.now() + Math.random(),
                accountCombination: line.accountCode,
                debitAmount: line.debitAmount,
                creditAmount: line.creditAmount,
                description: line.description
            }))
        };
    }

    async getChartOfAccounts(criteria) {
        return {
            accounts: [
                { accountCode: '1000', accountName: 'Cash', accountType: 'Asset' },
                { accountCode: '1100', accountName: 'Accounts Receivable', accountType: 'Asset' },
                { accountCode: '2000', accountName: 'Accounts Payable', accountType: 'Liability' },
                { accountCode: '3000', accountName: 'Capital', accountType: 'Equity' },
                { accountCode: '4000', accountName: 'Revenue', accountType: 'Revenue' },
                { accountCode: '5000', accountName: 'Cost of Goods Sold', accountType: 'Expense' }
            ]
        };
    }

    async createJournalEntry(journalData) {
        return {
            journalEntryId: Date.now(),
            journalName: journalData.name,
            description: journalData.description,
            period: journalData.period,
            status: 'Unposted',
            lines: journalData.lines.length
        };
    }

    async syncCostCenters(costCenterData) {
        return {
            costCenters: costCenterData.map(cc => ({
                costCenterId: cc.id,
                costCenterName: cc.name,
                description: cc.description,
                manager: cc.manager,
                status: 'Active'
            }))
        };
    }

    async manageAssets(assetData) {
        return {
            assets: assetData.map(asset => ({
                assetId: asset.id,
                assetNumber: asset.number,
                description: asset.description,
                category: asset.category,
                location: asset.location,
                status: 'Active'
            }))
        };
    }

    async healthCheck() {
        if (!this.isConnected) {
            throw new Error('Oracle ERP not connected');
        }
        
        // Simple health check
        await this.getChartOfAccounts({});
        return { status: 'healthy', timestamp: new Date().toISOString() };
    }
}

/**
 * NetSuite Client
 */
class NetSuiteClient {
    constructor(config) {
        this.config = {
            account: config.account,
            consumerKey: config.consumerKey,
            consumerSecret: config.consumerSecret,
            tokenId: config.tokenId,
            tokenSecret: config.tokenSecret,
            ...config
        };
        
        this.isConnected = false;
    }

    async connect() {
        try {
            await this.authenticate();
            this.isConnected = true;
            return true;
        } catch (error) {
            throw new Error(`NetSuite connection failed: ${error.message}`);
        }
    }

    async disconnect() {
        this.isConnected = false;
    }

    async authenticate() {
        // Simulate NetSuite OAuth authentication
        await new Promise(resolve => setTimeout(resolve, 800));
    }

    async execute(operation, data, options = {}) {
        if (!this.isConnected) {
            throw new Error('NetSuite not connected');
        }

        switch (operation) {
            case 'customer_sync':
                return await this.syncCustomer(data);
            case 'employee_sync':
                return await this.syncEmployee(data);
            case 'financial_transaction':
                return await this.createFinancialTransaction(data);
            case 'inventory_management':
                return await this.manageInventory(data);
            case 'vendor_management':
                return await this.manageVendor(data);
            default:
                throw new Error(`Unknown NetSuite operation: ${operation}`);
        }
    }

    async syncCustomer(customerData) {
        await new Promise(resolve => setTimeout(resolve, 600));
        
        return {
            internalId: Date.now(),
            entityId: customerData.entityId,
            companyName: customerData.companyName,
            email: customerData.email,
            phone: customerData.phone,
            status: 'Created',
            addresses: {
                billing: customerData.billingAddress,
                shipping: customerData.shippingAddress
            }
        };
    }

    async syncEmployee(employeeData) {
        return {
            internalId: Date.now(),
            entityId: employeeData.employeeId,
            firstName: employeeData.firstName,
            lastName: employeeData.lastName,
            email: employeeData.email,
            title: employeeData.title,
            department: employeeData.department,
            status: 'Active'
        };
    }

    async createFinancialTransaction(transactionData) {
        return {
            internalId: Date.now(),
            tranId: transactionData.transactionHeader.transactionId,
            tranDate: transactionData.transactionHeader.transactionDate,
            type: transactionData.transactionHeader.transactionType,
            status: 'Pending Approval',
            total: transactionData.totalDebit
        };
    }

    async manageInventory(inventoryData) {
        return {
            items: inventoryData.map(item => ({
                internalId: Date.now() + Math.random(),
                itemId: item.id,
                displayName: item.name,
                quantityOnHand: item.quantity,
                unitPrice: item.price,
                status: 'Active'
            }))
        };
    }

    async manageVendor(vendorData) {
        return {
            vendors: vendorData.map(vendor => ({
                internalId: Date.now() + Math.random(),
                entityId: vendor.id,
                companyName: vendor.name,
                email: vendor.email,
                terms: vendor.paymentTerms,
                status: 'Active'
            }))
        };
    }

    async healthCheck() {
        if (!this.isConnected) {
            throw new Error('NetSuite not connected');
        }
        
        return { status: 'healthy', timestamp: new Date().toISOString() };
    }
}

/**
 * Workday Client
 */
class WorkdayClient {
    constructor(config) {
        this.config = {
            baseUrl: config.baseUrl,
            tenant: config.tenant,
            username: config.username,
            password: config.password,
            ...config
        };
        
        this.isConnected = false;
    }

    async connect() {
        try {
            await this.authenticate();
            this.isConnected = true;
            return true;
        } catch (error) {
            throw new Error(`Workday connection failed: ${error.message}`);
        }
    }

    async disconnect() {
        this.isConnected = false;
    }

    async authenticate() {
        // Simulate Workday authentication
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    async execute(operation, data, options = {}) {
        if (!this.isConnected) {
            throw new Error('Workday not connected');
        }

        switch (operation) {
            case 'employee_lifecycle':
                return await this.manageEmployeeLifecycle(data);
            case 'employee_sync':
                return await this.syncEmployee(data);
            case 'org_structure':
                return await this.manageOrgStructure(data);
            case 'compensation_sync':
                return await this.syncCompensation(data);
            case 'benefits_enrollment':
                return await this.manageBenefits(data);
            default:
                throw new Error(`Unknown Workday operation: ${operation}`);
        }
    }

    async manageEmployeeLifecycle(employeeData) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        return {
            workerReference: employeeData.workerReference,
            effectiveDate: new Date().toISOString(),
            status: 'Completed',
            personalData: employeeData.personalData,
            positionData: employeeData.positionData,
            compensationData: employeeData.compensationData,
            workdayId: Date.now().toString()
        };
    }

    async syncEmployee(employeeData) {
        return {
            employeeId: employeeData.employeeId,
            workdayId: Date.now().toString(),
            personalInfo: {
                firstName: employeeData.firstName,
                lastName: employeeData.lastName,
                email: employeeData.email
            },
            jobInfo: {
                title: employeeData.jobTitle,
                department: employeeData.department,
                location: employeeData.location,
                manager: employeeData.managerId,
                startDate: employeeData.startDate
            },
            status: 'Active'
        };
    }

    async manageOrgStructure(orgData) {
        return {
            organizations: orgData.map(org => ({
                organizationId: org.id,
                name: org.name,
                type: org.type,
                parent: org.parentId,
                manager: org.managerId,
                status: 'Active'
            }))
        };
    }

    async syncCompensation(compensationData) {
        return {
            compensationPlans: compensationData.map(comp => ({
                employeeId: comp.employeeId,
                baseSalary: comp.baseSalary,
                currency: comp.currency,
                effectiveDate: comp.effectiveDate,
                compensationType: comp.type,
                status: 'Active'
            }))
        };
    }

    async manageBenefits(benefitsData) {
        return {
            enrollments: benefitsData.map(benefit => ({
                employeeId: benefit.employeeId,
                benefitPlan: benefit.planId,
                enrollmentDate: benefit.enrollmentDate,
                coverage: benefit.coverage,
                status: 'Enrolled'
            }))
        };
    }

    async healthCheck() {
        if (!this.isConnected) {
            throw new Error('Workday not connected');
        }
        
        return { status: 'healthy', timestamp: new Date().toISOString() };
    }
}

/**
 * Salesforce Client
 */
class SalesforceClient {
    constructor(config) {
        this.config = {
            instanceUrl: config.instanceUrl,
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            username: config.username,
            password: config.password,
            securityToken: config.securityToken,
            ...config
        };
        
        this.accessToken = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            await this.authenticate();
            this.isConnected = true;
            return true;
        } catch (error) {
            throw new Error(`Salesforce connection failed: ${error.message}`);
        }
    }

    async disconnect() {
        this.accessToken = null;
        this.isConnected = false;
    }

    async authenticate() {
        // Simulate Salesforce OAuth authentication
        await new Promise(resolve => setTimeout(resolve, 800));
        this.accessToken = 'salesforce_token_' + Date.now();
    }

    async execute(operation, data, options = {}) {
        if (!this.isConnected) {
            throw new Error('Salesforce not connected');
        }

        switch (operation) {
            case 'user_sync':
                return await this.syncUser(data);
            case 'lead_sync':
                return await this.syncLead(data);
            case 'account_management':
                return await this.manageAccount(data);
            case 'opportunity_sync':
                return await this.syncOpportunity(data);
            case 'customer_sync':
                return await this.syncCustomer(data);
            default:
                throw new Error(`Unknown Salesforce operation: ${operation}`);
        }
    }

    async syncUser(userData) {
        await new Promise(resolve => setTimeout(resolve, 500));
        
        return {
            Id: Date.now().toString(),
            Username: userData.Username || userData.Email,
            FirstName: userData.FirstName,
            LastName: userData.LastName,
            Email: userData.Email,
            Title: userData.Title,
            Department: userData.Department,
            EmployeeNumber: userData.EmployeeNumber,
            IsActive: true,
            ProfileId: '00e000000000000AAA' // Standard User Profile
        };
    }

    async syncLead(leadData) {
        return {
            Id: Date.now().toString(),
            FirstName: leadData.FirstName,
            LastName: leadData.LastName,
            Company: leadData.Company,
            Email: leadData.Email,
            Phone: leadData.Phone,
            Title: leadData.Title,
            LeadSource: leadData.LeadSource,
            Status: leadData.Status,
            Industry: leadData.Industry,
            NumberOfEmployees: leadData.NumberOfEmployees,
            AnnualRevenue: leadData.AnnualRevenue,
            Description: leadData.Description,
            OwnerId: leadData.OwnerId
        };
    }

    async manageAccount(accountData) {
        return {
            accounts: accountData.map(account => ({
                Id: Date.now().toString() + Math.random(),
                Name: account.name,
                Type: account.type,
                Industry: account.industry,
                NumberOfEmployees: account.employeeCount,
                AnnualRevenue: account.revenue,
                BillingStreet: account.billingAddress?.street,
                BillingCity: account.billingAddress?.city,
                BillingState: account.billingAddress?.state,
                BillingPostalCode: account.billingAddress?.zip,
                Phone: account.phone,
                Website: account.website
            }))
        };
    }

    async syncOpportunity(opportunityData) {
        return {
            opportunities: opportunityData.map(opp => ({
                Id: Date.now().toString() + Math.random(),
                Name: opp.name,
                Amount: opp.amount,
                StageName: opp.stage,
                CloseDate: opp.closeDate,
                AccountId: opp.accountId,
                OwnerId: opp.ownerId,
                Type: opp.type,
                LeadSource: opp.source,
                Probability: opp.probability
            }))
        };
    }

    async syncCustomer(customerData) {
        // In Salesforce, customers are typically Accounts
        return await this.manageAccount([{
            name: customerData.companyName || `${customerData.firstName} ${customerData.lastName}`,
            type: 'Customer',
            phone: customerData.phone,
            billingAddress: customerData.billingAddress,
            website: customerData.website
        }]);
    }

    async healthCheck() {
        if (!this.isConnected) {
            throw new Error('Salesforce not connected');
        }
        
        return { status: 'healthy', timestamp: new Date().toISOString() };
    }
}

module.exports = {
    ERPConnector,
    OracleERPClient,
    NetSuiteClient,
    WorkdayClient,
    SalesforceClient
};
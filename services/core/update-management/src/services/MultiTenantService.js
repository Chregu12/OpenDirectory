const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class MultiTenantService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.tenants = new Map();
        this.tenantPolicies = new Map();
        this.tenantIsolation = new Map();
        this.resourceQuotas = new Map();
        this.crossTenantSharing = new Map();
    }

    /**
     * Create a new tenant
     */
    async createTenant(tenantConfig) {
        try {
            logger.info(`Creating tenant: ${tenantConfig.name}`);

            const tenant = {
                id: `tenant-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                name: tenantConfig.name,
                displayName: tenantConfig.displayName || tenantConfig.name,
                description: tenantConfig.description || '',
                type: tenantConfig.type || 'enterprise', // enterprise, subsidiary, partner, customer
                
                // Organizational Information
                organization: {
                    legalName: tenantConfig.legalName || tenantConfig.name,
                    registrationNumber: tenantConfig.registrationNumber || null,
                    taxId: tenantConfig.taxId || null,
                    address: tenantConfig.address || {},
                    industry: tenantConfig.industry || null,
                    size: tenantConfig.organizationSize || 'medium', // small, medium, large, enterprise
                    parentTenant: tenantConfig.parentTenant || null,
                    subsidiaries: tenantConfig.subsidiaries || []
                },

                // Contact Information
                contacts: {
                    primary: {
                        name: tenantConfig.primaryContact?.name || '',
                        email: tenantConfig.primaryContact?.email || '',
                        phone: tenantConfig.primaryContact?.phone || '',
                        title: tenantConfig.primaryContact?.title || ''
                    },
                    technical: {
                        name: tenantConfig.technicalContact?.name || '',
                        email: tenantConfig.technicalContact?.email || '',
                        phone: tenantConfig.technicalContact?.phone || ''
                    },
                    billing: {
                        name: tenantConfig.billingContact?.name || '',
                        email: tenantConfig.billingContact?.email || '',
                        phone: tenantConfig.billingContact?.phone || ''
                    }
                },

                // Configuration and Branding
                configuration: {
                    timeZone: tenantConfig.timeZone || 'UTC',
                    locale: tenantConfig.locale || 'en-US',
                    currency: tenantConfig.currency || 'USD',
                    dateFormat: tenantConfig.dateFormat || 'MM/DD/YYYY',
                    customDomain: tenantConfig.customDomain || null,
                    allowCustomBranding: tenantConfig.allowCustomBranding ?? true,
                    branding: {
                        logoUrl: tenantConfig.logoUrl || null,
                        primaryColor: tenantConfig.primaryColor || '#007bff',
                        secondaryColor: tenantConfig.secondaryColor || '#6c757d',
                        customCSS: tenantConfig.customCSS || '',
                        faviconUrl: tenantConfig.faviconUrl || null
                    }
                },

                // Isolation and Security Settings
                isolation: {
                    level: tenantConfig.isolationLevel || 'standard', // basic, standard, strict, complete
                    networkIsolation: tenantConfig.networkIsolation ?? true,
                    dataIsolation: tenantConfig.dataIsolation ?? true,
                    computeIsolation: tenantConfig.computeIsolation ?? false,
                    storageIsolation: tenantConfig.storageIsolation ?? true,
                    allowCrossTenantAccess: tenantConfig.allowCrossTenantAccess ?? false,
                    trustedTenants: tenantConfig.trustedTenants || [],
                    encryptionRequired: tenantConfig.encryptionRequired ?? true,
                    complianceFrameworks: tenantConfig.complianceFrameworks || []
                },

                // Resource Quotas and Limits
                quotas: {
                    users: tenantConfig.maxUsers || 1000,
                    devices: tenantConfig.maxDevices || 5000,
                    applications: tenantConfig.maxApplications || 100,
                    policies: tenantConfig.maxPolicies || 50,
                    storage: tenantConfig.storageQuota || '100GB', // in GB
                    bandwidth: tenantConfig.bandwidthQuota || '1TB', // per month
                    apiCalls: tenantConfig.apiCallsQuota || 100000, // per month
                    concurrentSessions: tenantConfig.maxConcurrentSessions || 500,
                    retentionPeriod: tenantConfig.dataRetentionPeriod || 2555 // days (7 years)
                },

                // Service Configuration
                services: {
                    updateManagement: {
                        enabled: tenantConfig.updateManagementEnabled ?? true,
                        features: tenantConfig.updateManagementFeatures || ['windows', 'macos', 'linux', 'mobile'],
                        updateRings: tenantConfig.enableUpdateRings ?? true,
                        remoteActions: tenantConfig.enableRemoteActions ?? true
                    },
                    mobileApplicationManagement: {
                        enabled: tenantConfig.mamEnabled ?? true,
                        appProtection: tenantConfig.appProtectionEnabled ?? true,
                        dataLossPrevention: tenantConfig.dlpEnabled ?? true,
                        conditionalAccess: tenantConfig.conditionalAccessEnabled ?? true
                    },
                    termsOfUse: {
                        enabled: tenantConfig.termsOfUseEnabled ?? true,
                        customTerms: tenantConfig.allowCustomTerms ?? true,
                        multiLanguage: tenantConfig.multiLanguageTerms ?? false
                    },
                    compliance: {
                        enabled: tenantConfig.complianceEnabled ?? true,
                        auditLogs: tenantConfig.auditLogsEnabled ?? true,
                        reporting: tenantConfig.reportingEnabled ?? true,
                        realTimeMonitoring: tenantConfig.realTimeMonitoringEnabled ?? true
                    }
                },

                // Billing and Subscription
                billing: {
                    subscriptionType: tenantConfig.subscriptionType || 'standard', // trial, basic, standard, premium, enterprise
                    billingCycle: tenantConfig.billingCycle || 'monthly', // monthly, quarterly, yearly
                    paymentMethod: tenantConfig.paymentMethod || null,
                    billingAddress: tenantConfig.billingAddress || {},
                    autoRenewal: tenantConfig.autoRenewal ?? true,
                    trialEndDate: tenantConfig.trialEndDate || null,
                    subscriptionStartDate: tenantConfig.subscriptionStartDate || new Date().toISOString(),
                    subscriptionEndDate: tenantConfig.subscriptionEndDate || null,
                    usageTracking: tenantConfig.usageTracking ?? true
                },

                // Status and Metadata
                status: 'active', // active, suspended, disabled, deleted
                createdAt: new Date().toISOString(),
                createdBy: tenantConfig.createdBy || 'system',
                lastModified: new Date().toISOString(),
                modifiedBy: tenantConfig.createdBy || 'system',
                version: 1,
                metadata: tenantConfig.metadata || {}
            };

            this.tenants.set(tenant.id, tenant);

            // Initialize tenant-specific resources
            await this.initializeTenantResources(tenant);

            // Create default policies for tenant
            await this.createDefaultTenantPolicies(tenant);

            // Set up isolation boundaries
            await this.configureTenantIsolation(tenant);

            await this.auditLogger.log('tenant_created', {
                tenantId: tenant.id,
                name: tenant.name,
                type: tenant.type,
                createdBy: tenant.createdBy,
                timestamp: tenant.createdAt
            });

            this.emit('tenantCreated', tenant);

            return {
                success: true,
                tenant,
                message: 'Tenant created successfully'
            };

        } catch (error) {
            logger.error('Error creating tenant:', error);
            throw error;
        }
    }

    /**
     * Initialize tenant-specific resources
     */
    async initializeTenantResources(tenant) {
        try {
            logger.info(`Initializing resources for tenant: ${tenant.id}`);

            const resources = {
                database: {
                    schema: `tenant_${tenant.id}`,
                    connectionString: this.generateTenantConnectionString(tenant),
                    tables: [
                        'users', 'devices', 'policies', 'applications', 
                        'audit_logs', 'compliance_records', 'update_history'
                    ]
                },
                storage: {
                    bucket: `tenant-${tenant.id}-storage`,
                    path: `/tenants/${tenant.id}`,
                    quota: tenant.quotas.storage,
                    encryptionEnabled: tenant.isolation.encryptionRequired
                },
                network: {
                    vpcId: tenant.isolation.networkIsolation ? `vpc-${tenant.id}` : 'shared-vpc',
                    subnets: tenant.isolation.networkIsolation ? [`subnet-${tenant.id}-private`, `subnet-${tenant.id}-public`] : [],
                    securityGroups: [`sg-${tenant.id}-default`, `sg-${tenant.id}-web`, `sg-${tenant.id}-db`],
                    loadBalancer: tenant.isolation.computeIsolation ? `alb-${tenant.id}` : 'shared-alb'
                },
                compute: {
                    dedicated: tenant.isolation.computeIsolation,
                    instancePrefix: `tenant-${tenant.id}`,
                    autoScalingGroup: tenant.isolation.computeIsolation ? `asg-${tenant.id}` : 'shared-asg',
                    containerNamespace: `tenant-${tenant.id}`
                },
                cdn: {
                    distributionId: `cdn-${tenant.id}`,
                    customDomain: tenant.configuration.customDomain,
                    certificateArn: tenant.configuration.customDomain ? `cert-${tenant.id}` : null
                }
            };

            // Execute resource provisioning scripts
            const provisioningScripts = this.generateProvisioningScripts(tenant, resources);
            
            return {
                resources,
                provisioningScripts
            };

        } catch (error) {
            logger.error('Error initializing tenant resources:', error);
            throw error;
        }
    }

    /**
     * Generate resource provisioning scripts
     */
    generateProvisioningScripts(tenant, resources) {
        return {
            terraform: this.generateTerraformScript(tenant, resources),
            kubernetes: this.generateKubernetesManifests(tenant, resources),
            docker: this.generateDockerComposeConfig(tenant, resources),
            database: this.generateDatabaseSetupScript(tenant, resources)
        };
    }

    /**
     * Generate Terraform script for tenant infrastructure
     */
    generateTerraformScript(tenant, resources) {
        return `# Terraform configuration for tenant: ${tenant.name}
# Tenant ID: ${tenant.id}

variable "tenant_id" {
  description = "Tenant identifier"
  type        = string
  default     = "${tenant.id}"
}

variable "tenant_name" {
  description = "Tenant name"
  type        = string
  default     = "${tenant.name}"
}

# Provider configuration
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket = "opendirectory-terraform-state"
    key    = "tenants/${tenant.id}/terraform.tfstate"
    region = "us-east-1"
  }
}

${tenant.isolation.networkIsolation ? `
# VPC for tenant isolation
resource "aws_vpc" "tenant_vpc" {
  cidr_block           = "10.${tenant.id.slice(-2)}.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name     = "vpc-${tenant.id}"
    TenantId = var.tenant_id
    Environment = "production"
  }
}

# Subnets
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.tenant_vpc.id
  cidr_block        = "10.${tenant.id.slice(-2)}.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  
  tags = {
    Name     = "subnet-${tenant.id}-private"
    TenantId = var.tenant_id
    Type     = "private"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.tenant_vpc.id
  cidr_block             = "10.${tenant.id.slice(-2)}.2.0/24"
  availability_zone      = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
  
  tags = {
    Name     = "subnet-${tenant.id}-public"
    TenantId = var.tenant_id
    Type     = "public"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "tenant_igw" {
  vpc_id = aws_vpc.tenant_vpc.id
  
  tags = {
    Name     = "igw-${tenant.id}"
    TenantId = var.tenant_id
  }
}

# Security Groups
resource "aws_security_group" "tenant_default" {
  name_prefix = "sg-${tenant.id}-default"
  vpc_id      = aws_vpc.tenant_vpc.id
  
  # Default rules for tenant isolation
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name     = "sg-${tenant.id}-default"
    TenantId = var.tenant_id
  }
}
` : '# Shared network infrastructure will be used'}

${tenant.isolation.storageIsolation ? `
# S3 Bucket for tenant data
resource "aws_s3_bucket" "tenant_storage" {
  bucket = "opendirectory-tenant-${tenant.id}-storage"
  
  tags = {
    Name     = "tenant-${tenant.id}-storage"
    TenantId = var.tenant_id
  }
}

# S3 Bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "tenant_storage_encryption" {
  bucket = aws_s3_bucket.tenant_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket versioning
resource "aws_s3_bucket_versioning" "tenant_storage_versioning" {
  bucket = aws_s3_bucket.tenant_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}
` : '# Shared storage will be used'}

${tenant.isolation.computeIsolation ? `
# ECS Cluster for dedicated compute
resource "aws_ecs_cluster" "tenant_cluster" {
  name = "tenant-${tenant.id}-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = {
    Name     = "tenant-${tenant.id}-cluster"
    TenantId = var.tenant_id
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "tenant_asg" {
  name                = "asg-${tenant.id}"
  vpc_zone_identifier = [aws_subnet.private_subnet.id]
  min_size            = 1
  max_size            = 10
  desired_capacity    = 2
  
  tag {
    key                 = "Name"
    value               = "asg-${tenant.id}"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "TenantId"
    value               = var.tenant_id
    propagate_at_launch = true
  }
}
` : '# Shared compute infrastructure will be used'}

# RDS instance for tenant database
resource "aws_db_instance" "tenant_database" {
  identifier = "tenant-${tenant.id}-db"
  
  engine         = "postgres"
  engine_version = "14.9"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = ${tenant.isolation.encryptionRequired}
  
  db_name  = "tenant_${tenant.id}"
  username = "admin"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.tenant_db.id]
  db_subnet_group_name   = aws_db_subnet_group.tenant_db_subnet_group.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "tenant-${tenant.id}-final-snapshot"
  
  tags = {
    Name     = "tenant-${tenant.id}-db"
    TenantId = var.tenant_id
  }
}

# Output values
output "tenant_id" {
  value = var.tenant_id
}

output "database_endpoint" {
  value = aws_db_instance.tenant_database.endpoint
}

output "storage_bucket" {
  value = ${tenant.isolation.storageIsolation ? 'aws_s3_bucket.tenant_storage.bucket' : '"shared-storage"'}
}

output "vpc_id" {
  value = ${tenant.isolation.networkIsolation ? 'aws_vpc.tenant_vpc.id' : '"shared-vpc"'}
}
`;
    }

    /**
     * Generate Kubernetes manifests for tenant
     */
    generateKubernetesManifests(tenant, resources) {
        return {
            namespace: `apiVersion: v1
kind: Namespace
metadata:
  name: tenant-${tenant.id}
  labels:
    tenant-id: "${tenant.id}"
    tenant-name: "${tenant.name}"
    isolation-level: "${tenant.isolation.level}"
spec: {}
---`,
            
            networkPolicy: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-${tenant.id}-isolation
  namespace: tenant-${tenant.id}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          tenant-id: "${tenant.id}"
    - podSelector: {}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          tenant-id: "${tenant.id}"
    - podSelector: {}
  - to: {}
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to: {}
    ports:
    - protocol: TCP
      port: 443
---`,

            resourceQuota: `apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-${tenant.id}-quota
  namespace: tenant-${tenant.id}
spec:
  hard:
    requests.cpu: "${tenant.quotas.concurrentSessions / 100}"
    requests.memory: "${tenant.quotas.concurrentSessions / 50}Gi"
    limits.cpu: "${tenant.quotas.concurrentSessions / 50}"
    limits.memory: "${tenant.quotas.concurrentSessions / 25}Gi"
    persistentvolumeclaims: "10"
    requests.storage: "${tenant.quotas.storage}"
    services: "5"
    secrets: "10"
    configmaps: "10"
---`,

            deployment: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: tenant-${tenant.id}-update-management
  namespace: tenant-${tenant.id}
  labels:
    app: update-management
    tenant-id: "${tenant.id}"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: update-management
      tenant-id: "${tenant.id}"
  template:
    metadata:
      labels:
        app: update-management
        tenant-id: "${tenant.id}"
    spec:
      containers:
      - name: update-management
        image: opendirectory/update-management:latest
        ports:
        - containerPort: 3000
        env:
        - name: TENANT_ID
          value: "${tenant.id}"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: tenant-${tenant.id}-db-secret
              key: url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: tenant-data
          mountPath: /app/data
      volumes:
      - name: tenant-data
        persistentVolumeClaim:
          claimName: tenant-${tenant.id}-pvc
---`,

            service: `apiVersion: v1
kind: Service
metadata:
  name: tenant-${tenant.id}-update-management-service
  namespace: tenant-${tenant.id}
spec:
  selector:
    app: update-management
    tenant-id: "${tenant.id}"
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
---`
        };
    }

    /**
     * Generate Docker Compose configuration for tenant
     */
    generateDockerComposeConfig(tenant, resources) {
        return `version: '3.8'

# Docker Compose configuration for tenant: ${tenant.name}
# Tenant ID: ${tenant.id}

services:
  # Update Management Service
  update-management:
    image: opendirectory/update-management:latest
    container_name: tenant-${tenant.id}-update-management
    environment:
      - TENANT_ID=${tenant.id}
      - NODE_ENV=production
      - DATABASE_URL=postgresql://admin:password@database:5432/tenant_${tenant.id}
      - REDIS_URL=redis://redis:6379/0
      - STORAGE_BUCKET=${resources.storage.bucket}
      - ENCRYPTION_ENABLED=${tenant.isolation.encryptionRequired}
    ports:
      - "3001:3000"
    volumes:
      - tenant-${tenant.id}-data:/app/data
      - tenant-${tenant.id}-logs:/app/logs
    networks:
      - tenant-${tenant.id}-network
    depends_on:
      - database
      - redis
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.tenant-${tenant.id}.rule=Host(\`${tenant.configuration.customDomain || tenant.id + '.opendirectory.local'}\`)"
      - "traefik.http.services.tenant-${tenant.id}.loadbalancer.server.port=3000"

  # Tenant Database
  database:
    image: postgres:14
    container_name: tenant-${tenant.id}-database
    environment:
      - POSTGRES_DB=tenant_${tenant.id}
      - POSTGRES_USER=admin
      - POSTGRES_PASSWORD=password
    volumes:
      - tenant-${tenant.id}-db:/var/lib/postgresql/data
      - ./sql/tenant-init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5433:5432"
    networks:
      - tenant-${tenant.id}-network
    restart: unless-stopped
    command: |
      postgres 
      -c log_statement=all 
      -c log_destination=stderr 
      -c max_connections=${Math.min(tenant.quotas.concurrentSessions, 200)}

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: tenant-${tenant.id}-redis
    volumes:
      - tenant-${tenant.id}-redis:/data
    networks:
      - tenant-${tenant.id}-network
    restart: unless-stopped
    command: redis-server --maxmemory ${tenant.quotas.concurrentSessions * 10}mb --maxmemory-policy allkeys-lru

  # Monitoring
  monitoring:
    image: prom/prometheus:latest
    container_name: tenant-${tenant.id}-monitoring
    volumes:
      - ./prometheus/prometheus-${tenant.id}.yml:/etc/prometheus/prometheus.yml
      - tenant-${tenant.id}-prometheus:/prometheus
    ports:
      - "9091:9090"
    networks:
      - tenant-${tenant.id}-network
    restart: unless-stopped

volumes:
  tenant-${tenant.id}-data:
    driver: local
  tenant-${tenant.id}-logs:
    driver: local
  tenant-${tenant.id}-db:
    driver: local
  tenant-${tenant.id}-redis:
    driver: local
  tenant-${tenant.id}-prometheus:
    driver: local

networks:
  tenant-${tenant.id}-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.${tenant.id.slice(-2)}.0/24
`;
    }

    /**
     * Generate database setup script
     */
    generateDatabaseSetupScript(tenant, resources) {
        return `-- Database setup script for tenant: ${tenant.name}
-- Tenant ID: ${tenant.id}

-- Create tenant database schema
CREATE SCHEMA IF NOT EXISTS tenant_${tenant.id};

-- Set search path for tenant schema
SET search_path TO tenant_${tenant.id}, public;

-- Create tenant-specific tables
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL DEFAULT '${tenant.id}',
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL DEFAULT '${tenant.id}',
    user_id UUID REFERENCES users(id),
    device_name VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    os_version VARCHAR(100),
    device_type VARCHAR(50),
    enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    compliance_status VARCHAR(50) DEFAULT 'unknown',
    managed BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS update_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL DEFAULT '${tenant.id}',
    name VARCHAR(255) NOT NULL,
    description TEXT,
    platform VARCHAR(50) NOT NULL,
    policy_type VARCHAR(100) NOT NULL,
    configuration JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS update_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL DEFAULT '${tenant.id}',
    policy_id UUID REFERENCES update_policies(id),
    device_id UUID REFERENCES devices(id),
    deployment_status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    deployment_ring VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL DEFAULT '${tenant.id}',
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    user_id UUID REFERENCES users(id),
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_devices_tenant_id ON devices(tenant_id);
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_update_policies_tenant_id ON update_policies(tenant_id);
CREATE INDEX idx_update_deployments_tenant_id ON update_deployments(tenant_id);
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Row Level Security (RLS) for tenant isolation
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE update_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE update_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY tenant_isolation_users ON users
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant')::text);

CREATE POLICY tenant_isolation_devices ON devices
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant')::text);

CREATE POLICY tenant_isolation_policies ON update_policies
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant')::text);

CREATE POLICY tenant_isolation_deployments ON update_deployments
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant')::text);

CREATE POLICY tenant_isolation_audit ON audit_logs
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant')::text);

-- Create tenant-specific roles and permissions
CREATE ROLE tenant_${tenant.id}_admin;
CREATE ROLE tenant_${tenant.id}_user;
CREATE ROLE tenant_${tenant.id}_readonly;

-- Grant permissions
GRANT USAGE ON SCHEMA tenant_${tenant.id} TO tenant_${tenant.id}_admin, tenant_${tenant.id}_user, tenant_${tenant.id}_readonly;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA tenant_${tenant.id} TO tenant_${tenant.id}_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA tenant_${tenant.id} TO tenant_${tenant.id}_user;
GRANT SELECT ON ALL TABLES IN SCHEMA tenant_${tenant.id} TO tenant_${tenant.id}_readonly;

-- Set tenant context function
CREATE OR REPLACE FUNCTION set_tenant_context(tenant_id text)
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_tenant', tenant_id, true);
END;
$$ LANGUAGE plpgsql;

-- Initialize tenant context
SELECT set_tenant_context('${tenant.id}');

-- Insert initial data
INSERT INTO users (username, email, first_name, last_name) VALUES
('admin', '${tenant.contacts.technical.email}', 'System', 'Administrator');

COMMIT;
`;
    }

    /**
     * Create default tenant policies
     */
    async createDefaultTenantPolicies(tenant) {
        try {
            logger.info(`Creating default policies for tenant: ${tenant.id}`);

            const defaultPolicies = {
                updateManagement: {
                    name: 'Default Update Policy',
                    description: 'Standard update management policy for all devices',
                    platform: 'all',
                    settings: {
                        automaticUpdates: true,
                        updateRing: 'Production',
                        maintenanceWindow: { start: '02:00', end: '05:00' }
                    }
                },
                security: {
                    name: 'Default Security Policy',
                    description: 'Standard security requirements',
                    settings: {
                        encryptionRequired: tenant.isolation.encryptionRequired,
                        passwordComplexity: 'medium',
                        sessionTimeout: 480 // 8 hours
                    }
                },
                compliance: {
                    name: 'Default Compliance Policy',
                    description: 'Standard compliance monitoring',
                    settings: {
                        auditLogging: true,
                        dataRetention: tenant.quotas.retentionPeriod,
                        complianceFrameworks: tenant.isolation.complianceFrameworks
                    }
                }
            };

            this.tenantPolicies.set(tenant.id, defaultPolicies);

            return defaultPolicies;

        } catch (error) {
            logger.error('Error creating default tenant policies:', error);
            throw error;
        }
    }

    /**
     * Configure tenant isolation boundaries
     */
    async configureTenantIsolation(tenant) {
        try {
            logger.info(`Configuring isolation for tenant: ${tenant.id}`);

            const isolationConfig = {
                tenantId: tenant.id,
                level: tenant.isolation.level,
                boundaries: {
                    network: tenant.isolation.networkIsolation,
                    data: tenant.isolation.dataIsolation,
                    compute: tenant.isolation.computeIsolation,
                    storage: tenant.isolation.storageIsolation
                },
                crossTenantAccess: {
                    allowed: tenant.isolation.allowCrossTenantAccess,
                    trustedTenants: tenant.isolation.trustedTenants,
                    sharedResources: []
                },
                encryptionPolicy: {
                    dataAtRest: tenant.isolation.encryptionRequired,
                    dataInTransit: true,
                    keyManagement: 'tenant-specific',
                    keyRotation: 90 // days
                }
            };

            this.tenantIsolation.set(tenant.id, isolationConfig);

            return isolationConfig;

        } catch (error) {
            logger.error('Error configuring tenant isolation:', error);
            throw error;
        }
    }

    /**
     * Get tenant information and status
     */
    async getTenantInfo(tenantId) {
        try {
            const tenant = this.tenants.get(tenantId);
            if (!tenant) {
                return { success: false, error: 'Tenant not found' };
            }

            const tenantInfo = {
                ...tenant,
                currentUsage: await this.getTenantUsage(tenantId),
                resourceUtilization: await this.getTenantResourceUtilization(tenantId),
                complianceStatus: await this.getTenantComplianceStatus(tenantId),
                healthStatus: await this.getTenantHealthStatus(tenantId)
            };

            return {
                success: true,
                tenant: tenantInfo
            };

        } catch (error) {
            logger.error('Error getting tenant info:', error);
            throw error;
        }
    }

    /**
     * Update tenant configuration
     */
    async updateTenant(tenantId, updates) {
        try {
            logger.info(`Updating tenant: ${tenantId}`);

            const tenant = this.tenants.get(tenantId);
            if (!tenant) {
                throw new Error('Tenant not found');
            }

            const originalConfig = { ...tenant };
            
            // Apply updates
            Object.keys(updates).forEach(key => {
                if (updates[key] !== undefined && key !== 'id' && key !== 'createdAt' && key !== 'createdBy') {
                    if (typeof updates[key] === 'object' && updates[key] !== null && !Array.isArray(updates[key])) {
                        tenant[key] = { ...tenant[key], ...updates[key] };
                    } else {
                        tenant[key] = updates[key];
                    }
                }
            });

            tenant.lastModified = new Date().toISOString();
            tenant.modifiedBy = updates.modifiedBy || 'system';
            tenant.version += 1;

            // Re-configure isolation if isolation settings changed
            if (updates.isolation) {
                await this.configureTenantIsolation(tenant);
            }

            await this.auditLogger.log('tenant_updated', {
                tenantId,
                originalConfig: this.sanitizeTenantConfig(originalConfig),
                newConfig: this.sanitizeTenantConfig(tenant),
                modifiedBy: tenant.modifiedBy,
                timestamp: tenant.lastModified
            });

            this.emit('tenantUpdated', { tenantId, tenant, changes: updates });

            return {
                success: true,
                tenant,
                message: 'Tenant updated successfully'
            };

        } catch (error) {
            logger.error('Error updating tenant:', error);
            throw error;
        }
    }

    /**
     * Generate tenant connection string
     */
    generateTenantConnectionString(tenant) {
        return `postgresql://admin:password@tenant-${tenant.id}-db:5432/tenant_${tenant.id}`;
    }

    /**
     * Get tenant usage statistics
     */
    async getTenantUsage(tenantId) {
        // This would query actual usage data
        return {
            users: { current: 45, quota: this.tenants.get(tenantId)?.quotas.users || 0 },
            devices: { current: 150, quota: this.tenants.get(tenantId)?.quotas.devices || 0 },
            storage: { current: '25GB', quota: this.tenants.get(tenantId)?.quotas.storage || '0GB' },
            apiCalls: { current: 25000, quota: this.tenants.get(tenantId)?.quotas.apiCalls || 0 }
        };
    }

    /**
     * Get tenant resource utilization
     */
    async getTenantResourceUtilization(tenantId) {
        // This would query actual resource utilization
        return {
            cpu: { current: 65, max: 100 },
            memory: { current: 70, max: 100 },
            network: { current: 45, max: 100 },
            disk: { current: 30, max: 100 }
        };
    }

    /**
     * Get tenant compliance status
     */
    async getTenantComplianceStatus(tenantId) {
        // This would check actual compliance
        return {
            overall: 'compliant',
            frameworks: ['SOC2', 'GDPR'],
            lastAudit: new Date().toISOString(),
            issues: []
        };
    }

    /**
     * Get tenant health status
     */
    async getTenantHealthStatus(tenantId) {
        // This would check actual health metrics
        return {
            status: 'healthy',
            services: {
                updateManagement: 'healthy',
                database: 'healthy',
                storage: 'healthy'
            },
            lastCheck: new Date().toISOString()
        };
    }

    /**
     * Sanitize tenant config for logging
     */
    sanitizeTenantConfig(config) {
        const sanitized = { ...config };
        delete sanitized.contacts;
        delete sanitized.billing;
        return sanitized;
    }
}

module.exports = MultiTenantService;
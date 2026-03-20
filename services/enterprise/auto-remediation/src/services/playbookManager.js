const { EventEmitter } = require('events');
const { v4: uuidv4 } = require('uuid');

/**
 * Manages remediation playbooks - predefined sequences of remediation steps
 * for common compliance and security scenarios.
 */
class PlaybookManager extends EventEmitter {
    constructor() {
        super();
        this.playbooks = new Map();

        this._seedBuiltInPlaybooks();
    }

    /**
     * Seed built-in playbooks
     */
    _seedBuiltInPlaybooks() {
        const builtInPlaybooks = [
            {
                id: 'pb-001',
                name: 'Full Security Hardening',
                description: 'Complete security hardening sequence: enable encryption, install EDR, enable firewall, install updates',
                category: 'security',
                severity: 'high',
                platforms: ['windows', 'macos', 'linux'],
                estimatedDuration: '60-90 minutes',
                requiresApproval: true,
                builtIn: true,
                steps: [
                    {
                        order: 1,
                        name: 'Enable Disk Encryption',
                        issueType: 'bitlocker-disabled',
                        description: 'Enable BitLocker (Windows), FileVault (macOS), or LUKS (Linux)',
                        continueOnFailure: false
                    },
                    {
                        order: 2,
                        name: 'Install EDR Agent',
                        issueType: 'edr-missing',
                        description: 'Install and activate endpoint detection and response agent',
                        continueOnFailure: true
                    },
                    {
                        order: 3,
                        name: 'Enable Firewall',
                        issueType: 'firewall-disabled',
                        description: 'Enable and configure the system firewall',
                        continueOnFailure: true
                    },
                    {
                        order: 4,
                        name: 'Install Missing Updates',
                        issueType: 'missing-updates',
                        description: 'Install all pending security and feature updates',
                        continueOnFailure: false
                    }
                ],
                createdAt: '2024-01-01T00:00:00Z',
                updatedAt: '2024-01-01T00:00:00Z',
                createdBy: 'system',
                executionCount: 23,
                successRate: 87.0
            },
            {
                id: 'pb-002',
                name: 'New Device Onboarding',
                description: 'Standard onboarding sequence for newly enrolled devices: install updates, install required apps, enable encryption, install EDR',
                category: 'onboarding',
                severity: 'medium',
                platforms: ['windows', 'macos', 'linux'],
                estimatedDuration: '45-60 minutes',
                requiresApproval: false,
                builtIn: true,
                steps: [
                    {
                        order: 1,
                        name: 'Install OS Updates',
                        issueType: 'missing-updates',
                        description: 'Ensure the device has all latest OS updates installed',
                        continueOnFailure: true
                    },
                    {
                        order: 2,
                        name: 'Install Required Applications',
                        issueType: 'required-app-missing',
                        description: 'Install all required enterprise applications',
                        continueOnFailure: true
                    },
                    {
                        order: 3,
                        name: 'Enable Disk Encryption',
                        issueType: 'bitlocker-disabled',
                        description: 'Enable full-disk encryption',
                        continueOnFailure: false
                    },
                    {
                        order: 4,
                        name: 'Install EDR Agent',
                        issueType: 'edr-missing',
                        description: 'Install endpoint protection agent',
                        continueOnFailure: false
                    },
                    {
                        order: 5,
                        name: 'Enable Firewall',
                        issueType: 'firewall-disabled',
                        description: 'Ensure firewall is properly configured',
                        continueOnFailure: true
                    }
                ],
                createdAt: '2024-01-01T00:00:00Z',
                updatedAt: '2024-01-01T00:00:00Z',
                createdBy: 'system',
                executionCount: 156,
                successRate: 92.3
            },
            {
                id: 'pb-003',
                name: 'Compliance Recovery',
                description: 'Bring a non-compliant device back into compliance: fix encryption, updates, and firewall',
                category: 'compliance',
                severity: 'high',
                platforms: ['windows', 'macos', 'linux'],
                estimatedDuration: '30-45 minutes',
                requiresApproval: false,
                builtIn: true,
                steps: [
                    {
                        order: 1,
                        name: 'Enable Disk Encryption',
                        issueType: 'bitlocker-disabled',
                        description: 'Ensure disk encryption is enabled',
                        continueOnFailure: true
                    },
                    {
                        order: 2,
                        name: 'Enable Firewall',
                        issueType: 'firewall-disabled',
                        description: 'Ensure firewall is enabled',
                        continueOnFailure: true
                    },
                    {
                        order: 3,
                        name: 'Install Updates',
                        issueType: 'missing-updates',
                        description: 'Install all pending updates',
                        continueOnFailure: false
                    }
                ],
                createdAt: '2024-01-15T00:00:00Z',
                updatedAt: '2024-01-15T00:00:00Z',
                createdBy: 'system',
                executionCount: 89,
                successRate: 94.4
            },
            {
                id: 'pb-004',
                name: 'Device Retirement Preparation',
                description: 'Prepare a device for retirement: reset passwords, remove enrollment, wipe sensitive data',
                category: 'lifecycle',
                severity: 'medium',
                platforms: ['windows', 'macos', 'linux'],
                estimatedDuration: '20-30 minutes',
                requiresApproval: true,
                builtIn: true,
                steps: [
                    {
                        order: 1,
                        name: 'Reset User Password',
                        issueType: 'password-expired',
                        description: 'Expire all user passwords on the device',
                        continueOnFailure: true
                    },
                    {
                        order: 2,
                        name: 'Remove MDM Enrollment',
                        issueType: 'device-reenroll',
                        description: 'Remove device from MDM management',
                        continueOnFailure: false
                    }
                ],
                createdAt: '2024-02-01T00:00:00Z',
                updatedAt: '2024-02-01T00:00:00Z',
                createdBy: 'system',
                executionCount: 34,
                successRate: 97.1
            },
            {
                id: 'pb-005',
                name: 'Emergency Security Response',
                description: 'Immediate security hardening for compromised or at-risk devices: force password reset, install EDR, enable all protections',
                category: 'incident-response',
                severity: 'critical',
                platforms: ['windows', 'macos', 'linux'],
                estimatedDuration: '15-20 minutes',
                requiresApproval: true,
                builtIn: true,
                steps: [
                    {
                        order: 1,
                        name: 'Force Password Reset',
                        issueType: 'password-expired',
                        description: 'Immediately expire and force password change',
                        continueOnFailure: false
                    },
                    {
                        order: 2,
                        name: 'Install/Update EDR',
                        issueType: 'edr-missing',
                        description: 'Ensure EDR agent is installed and up to date',
                        continueOnFailure: false
                    },
                    {
                        order: 3,
                        name: 'Enable Firewall',
                        issueType: 'firewall-disabled',
                        description: 'Enable firewall with strict rules',
                        continueOnFailure: true
                    },
                    {
                        order: 4,
                        name: 'Install Security Updates',
                        issueType: 'missing-updates',
                        description: 'Install critical security updates immediately',
                        continueOnFailure: true
                    }
                ],
                createdAt: '2024-02-15T00:00:00Z',
                updatedAt: '2024-02-15T00:00:00Z',
                createdBy: 'system',
                executionCount: 7,
                successRate: 85.7
            }
        ];

        for (const playbook of builtInPlaybooks) {
            this.playbooks.set(playbook.id, playbook);
        }
    }

    /**
     * Get all playbooks with optional filtering
     */
    getAllPlaybooks(filters = {}) {
        let playbooks = Array.from(this.playbooks.values());

        if (filters.category) {
            playbooks = playbooks.filter(p => p.category === filters.category);
        }
        if (filters.severity) {
            playbooks = playbooks.filter(p => p.severity === filters.severity);
        }
        if (filters.platform) {
            playbooks = playbooks.filter(p => p.platforms.includes(filters.platform.toLowerCase()));
        }
        if (filters.search) {
            const term = filters.search.toLowerCase();
            playbooks = playbooks.filter(p =>
                p.name.toLowerCase().includes(term) ||
                p.description.toLowerCase().includes(term)
            );
        }

        return playbooks.map(p => ({
            id: p.id,
            name: p.name,
            description: p.description,
            category: p.category,
            severity: p.severity,
            platforms: p.platforms,
            stepCount: p.steps.length,
            estimatedDuration: p.estimatedDuration,
            requiresApproval: p.requiresApproval,
            builtIn: p.builtIn,
            executionCount: p.executionCount,
            successRate: p.successRate,
            createdAt: p.createdAt
        }));
    }

    /**
     * Get a playbook by ID
     */
    getPlaybookById(playbookId) {
        return this.playbooks.get(playbookId) || null;
    }

    /**
     * Create a custom playbook
     */
    createPlaybook(data) {
        const { name, description, category, severity, platforms, steps, requiresApproval } = data;

        if (!name || !steps || !Array.isArray(steps) || steps.length === 0) {
            throw new Error('name and steps (non-empty array) are required');
        }

        const playbook = {
            id: `pb-${uuidv4().slice(0, 8)}`,
            name,
            description: description || '',
            category: category || 'custom',
            severity: severity || 'medium',
            platforms: platforms || ['windows', 'macos', 'linux'],
            estimatedDuration: data.estimatedDuration || 'varies',
            requiresApproval: requiresApproval !== undefined ? requiresApproval : true,
            builtIn: false,
            steps: steps.map((step, index) => ({
                order: index + 1,
                name: step.name,
                issueType: step.issueType,
                description: step.description || '',
                continueOnFailure: step.continueOnFailure || false
            })),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            createdBy: data.createdBy || 'api-user',
            executionCount: 0,
            successRate: 0
        };

        this.playbooks.set(playbook.id, playbook);
        this.emit('playbookCreated', playbook);

        return playbook;
    }

    /**
     * Record a playbook execution result
     */
    recordExecution(playbookId, success) {
        const playbook = this.playbooks.get(playbookId);
        if (!playbook) return;

        const previousCount = playbook.executionCount;
        const previousSuccessCount = Math.round((playbook.successRate / 100) * previousCount);
        const newCount = previousCount + 1;
        const newSuccessCount = previousSuccessCount + (success ? 1 : 0);

        playbook.executionCount = newCount;
        playbook.successRate = Math.round((newSuccessCount / newCount) * 1000) / 10;
        playbook.updatedAt = new Date().toISOString();
    }

    /**
     * Get playbook categories
     */
    getCategories() {
        const categories = new Set();
        for (const playbook of this.playbooks.values()) {
            categories.add(playbook.category);
        }
        return Array.from(categories);
    }
}

module.exports = PlaybookManager;

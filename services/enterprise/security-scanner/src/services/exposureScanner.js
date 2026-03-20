'use strict';

const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const cron = require('node-cron');

const GPOAnalyzer = require('./gpoAnalyzer');
const PrivilegeAuditor = require('./privilegeAuditor');
const DeviceSecurityAnalyzer = require('./deviceSecurityAnalyzer');

/**
 * Exposure Scanner - Main orchestrator for security exposure scanning.
 * Coordinates GPO analysis, privilege auditing, and device security scanning.
 * Manages scan lifecycle, history, scheduling, risk scoring, and trending.
 */
class ExposureScanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;

    // Sub-analyzers
    this.gpoAnalyzer = new GPOAnalyzer({ logger: this.logger });
    this.privilegeAuditor = new PrivilegeAuditor({ logger: this.logger });
    this.deviceSecurityAnalyzer = new DeviceSecurityAnalyzer({ logger: this.logger });

    // In-memory stores (replace with database in production)
    this.scans = new Map();
    this.findings = new Map();
    this.schedules = new Map();
    this.scanHistory = [];
    this.riskTrends = [];

    // Maximum retained scan history entries
    this.maxHistorySize = 1000;
    this.maxTrendEntries = 365;

    // Available compliance benchmarks
    this.availableBenchmarks = [
      {
        id: 'CIS',
        name: 'CIS Benchmarks',
        version: '3.0',
        description: 'Center for Internet Security Benchmarks for Windows and Active Directory',
        categories: ['password-policy', 'audit-policy', 'firewall', 'user-rights', 'security-options', 'device-security'],
      },
      {
        id: 'NIST',
        name: 'NIST SP 800-53 / 800-171',
        version: 'Rev 5',
        description: 'National Institute of Standards and Technology security and privacy controls',
        categories: ['password-policy', 'audit-policy', 'device-security'],
      },
      {
        id: 'DISA_STIG',
        name: 'DISA STIG',
        version: 'V3R1',
        description: 'Defense Information Systems Agency Security Technical Implementation Guides',
        categories: ['password-policy', 'audit-policy', 'device-security'],
      },
    ];

    // Forward progress events from sub-analyzers
    this.gpoAnalyzer.on('progress', (data) => this.emit('scanProgress', data));
    this.privilegeAuditor.on('progress', (data) => this.emit('scanProgress', data));
    this.deviceSecurityAnalyzer.on('progress', (data) => this.emit('scanProgress', data));
  }

  /**
   * Start a new security exposure scan.
   * @param {Object} params - Scan parameters
   * @param {string[]} params.scope - Scan scope: ['gpo', 'privilege', 'device']
   * @param {Object} params.targets - Target data (AD data, device list, etc.)
   * @param {string[]} params.benchmarks - Benchmark IDs to evaluate against
   * @returns {Object} Scan metadata with scanId
   */
  async startScan(params) {
    const scanId = uuidv4();
    const scope = params.scope || ['gpo', 'privilege', 'device'];
    const benchmarks = params.benchmarks || ['CIS'];
    const targets = params.targets || {};

    const scan = {
      id: scanId,
      status: 'running',
      scope,
      benchmarks,
      startTime: new Date().toISOString(),
      endTime: null,
      progress: 0,
      currentPhase: 'initializing',
      findings: [],
      results: {},
      error: null,
    };

    this.scans.set(scanId, scan);

    this.emit('scanStarted', { scanId, scope, benchmarks });
    this.logger.info(`Scan ${scanId} started. Scope: ${scope.join(', ')}. Benchmarks: ${benchmarks.join(', ')}`);

    // Run scan asynchronously
    this._executeScan(scanId, scope, benchmarks, targets).catch((err) => {
      this.logger.error(`Scan ${scanId} failed:`, err.message);
      scan.status = 'failed';
      scan.error = err.message;
      scan.endTime = new Date().toISOString();
      this.emit('scanFailed', { scanId, error: err.message });
    });

    return {
      scanId,
      status: 'running',
      scope,
      benchmarks,
      startTime: scan.startTime,
    };
  }

  /**
   * Execute the scan phases.
   */
  async _executeScan(scanId, scope, benchmarks, targets) {
    const scan = this.scans.get(scanId);
    if (!scan) throw new Error(`Scan ${scanId} not found`);

    const allFindings = [];
    const phaseCount = scope.length;
    let completedPhases = 0;

    const updateProgress = (phaseProgress, message) => {
      const overallProgress = Math.round(
        ((completedPhases / phaseCount) * 100) + (phaseProgress / phaseCount)
      );
      scan.progress = Math.min(overallProgress, 99);
      scan.currentPhase = message;
      this.emit('scanProgress', {
        scanId,
        progress: scan.progress,
        phase: message,
      });
    };

    // Phase 1: GPO Analysis
    if (scope.includes('gpo')) {
      scan.currentPhase = 'gpo-analysis';
      updateProgress(0, 'Starting GPO analysis...');

      const gpoData = targets.gpoData || this._generateSampleGPOData();
      const gpoResults = await this.gpoAnalyzer.analyze(gpoData, benchmarks, updateProgress);

      scan.results.gpo = gpoResults;
      allFindings.push(...gpoResults.findings);
      completedPhases++;
      this.logger.info(`Scan ${scanId}: GPO analysis complete. ${gpoResults.findings.length} findings.`);
    }

    // Phase 2: Privilege Audit
    if (scope.includes('privilege')) {
      scan.currentPhase = 'privilege-audit';
      updateProgress(0, 'Starting privilege audit...');

      const adData = targets.adData || this._generateSampleADData();
      const privResults = await this.privilegeAuditor.audit(adData, updateProgress);

      scan.results.privilege = privResults;
      allFindings.push(...privResults.findings);
      completedPhases++;
      this.logger.info(`Scan ${scanId}: Privilege audit complete. ${privResults.findings.length} findings.`);
    }

    // Phase 3: Device Security Analysis
    if (scope.includes('device')) {
      scan.currentPhase = 'device-analysis';
      updateProgress(0, 'Starting device security analysis...');

      const devices = targets.devices || this._generateSampleDevices();
      const deviceResults = await this.deviceSecurityAnalyzer.analyze(devices, benchmarks, updateProgress);

      scan.results.device = deviceResults;
      allFindings.push(...deviceResults.findings);
      completedPhases++;
      this.logger.info(`Scan ${scanId}: Device analysis complete. ${deviceResults.findings.length} findings.`);
    }

    // Store findings
    for (const finding of allFindings) {
      finding.scanId = scanId;
      this.findings.set(finding.id, finding);
    }

    // Finalize scan
    scan.findings = allFindings.map((f) => f.id);
    scan.status = 'completed';
    scan.progress = 100;
    scan.currentPhase = 'completed';
    scan.endTime = new Date().toISOString();
    scan.summary = this._buildOverallSummary(allFindings);
    scan.riskScore = this._calculateOverallRiskScore(allFindings);

    // Record in history
    this._recordScanHistory(scan);
    this._recordRiskTrend(scan);

    this.emit('scanCompleted', {
      scanId,
      summary: scan.summary,
      riskScore: scan.riskScore,
      findingCount: allFindings.length,
    });

    this.logger.info(`Scan ${scanId} completed. Total findings: ${allFindings.length}. Risk score: ${scan.riskScore.overall}`);

    return scan;
  }

  /**
   * Get scan status and results.
   */
  getScan(scanId) {
    const scan = this.scans.get(scanId);
    if (!scan) return null;

    return {
      id: scan.id,
      status: scan.status,
      scope: scan.scope,
      benchmarks: scan.benchmarks,
      startTime: scan.startTime,
      endTime: scan.endTime,
      progress: scan.progress,
      currentPhase: scan.currentPhase,
      error: scan.error,
      summary: scan.summary || null,
      riskScore: scan.riskScore || null,
      findingCount: scan.findings.length,
      results: scan.status === 'completed' ? {
        gpo: scan.results.gpo ? scan.results.gpo.summary : null,
        privilege: scan.results.privilege ? scan.results.privilege.summary : null,
        device: scan.results.device ? scan.results.device.summary : null,
      } : null,
    };
  }

  /**
   * List all findings with optional filtering.
   */
  getFindings(filters = {}) {
    let results = Array.from(this.findings.values());

    if (filters.scanId) {
      results = results.filter((f) => f.scanId === filters.scanId);
    }
    if (filters.severity) {
      const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
      results = results.filter((f) => severities.includes(f.severity));
    }
    if (filters.category) {
      results = results.filter((f) => f.category === filters.category);
    }
    if (filters.subcategory) {
      results = results.filter((f) => f.subcategory === filters.subcategory);
    }
    if (filters.benchmark) {
      results = results.filter((f) => f.benchmark === filters.benchmark);
    }
    if (filters.status) {
      results = results.filter((f) => f.status === filters.status);
    }
    if (filters.deviceId) {
      results = results.filter((f) => f.deviceId === filters.deviceId);
    }
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      results = results.filter((f) =>
        f.title.toLowerCase().includes(searchLower) ||
        f.description.toLowerCase().includes(searchLower)
      );
    }

    // Sorting
    const sortField = filters.sortBy || 'severity';
    const sortOrder = filters.sortOrder || 'desc';
    const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };

    results.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'severity') {
        cmp = (severityOrder[a.severity] || 0) - (severityOrder[b.severity] || 0);
      } else if (sortField === 'timestamp') {
        cmp = new Date(a.timestamp) - new Date(b.timestamp);
      } else if (sortField === 'riskScore') {
        cmp = a.riskScore - b.riskScore;
      } else if (sortField === 'title') {
        cmp = a.title.localeCompare(b.title);
      }
      return sortOrder === 'desc' ? -cmp : cmp;
    });

    // Pagination
    const page = filters.page || 1;
    const pageSize = filters.pageSize || 50;
    const totalItems = results.length;
    const totalPages = Math.ceil(totalItems / pageSize);
    const startIndex = (page - 1) * pageSize;
    const paginatedResults = results.slice(startIndex, startIndex + pageSize);

    return {
      findings: paginatedResults,
      pagination: {
        page,
        pageSize,
        totalItems,
        totalPages,
      },
    };
  }

  /**
   * Get a specific finding by ID.
   */
  getFinding(findingId) {
    return this.findings.get(findingId) || null;
  }

  /**
   * Get overall risk score across all scans.
   */
  getOverallRiskScore() {
    const allFindings = Array.from(this.findings.values()).filter((f) => f.status === 'open');

    if (allFindings.length === 0) {
      return {
        overall: 0,
        grade: 'A',
        label: 'Excellent',
        totalFindings: 0,
        byCategory: {},
        bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0 },
      };
    }

    return this._calculateOverallRiskScore(allFindings);
  }

  /**
   * Get risk score for a specific entity (device, user, group, etc.).
   */
  getEntityRiskScore(entityType, entityId) {
    let entityFindings = [];

    if (entityType === 'device') {
      entityFindings = Array.from(this.findings.values()).filter(
        (f) => f.deviceId === entityId || f.deviceName === entityId
      );
    } else if (entityType === 'user') {
      entityFindings = Array.from(this.findings.values()).filter((f) =>
        f.affectedObjects && f.affectedObjects.some(
          (o) => o.type === 'user' && (o.name === entityId || o.distinguishedName === entityId)
        )
      );
    } else if (entityType === 'group') {
      entityFindings = Array.from(this.findings.values()).filter((f) =>
        f.affectedObjects && f.affectedObjects.some(
          (o) => o.type === 'group' && o.name === entityId
        )
      );
    } else if (entityType === 'gpo') {
      entityFindings = Array.from(this.findings.values()).filter(
        (f) => f.category === 'gpo'
      );
    }

    if (entityFindings.length === 0) {
      return {
        entityType,
        entityId,
        riskScore: 0,
        grade: 'A',
        label: 'No findings',
        findings: 0,
      };
    }

    const score = this._calculateOverallRiskScore(entityFindings);
    return {
      entityType,
      entityId,
      ...score,
    };
  }

  /**
   * Get available compliance benchmarks.
   */
  getBenchmarks() {
    return this.availableBenchmarks;
  }

  /**
   * Get risk trends over time.
   */
  getTrends(params = {}) {
    const days = params.days || 30;
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);

    let trends = this.riskTrends.filter((t) => new Date(t.timestamp) >= cutoff);

    // If no real data, generate sample trend data
    if (trends.length === 0 && this.riskTrends.length === 0) {
      trends = this._generateSampleTrends(days);
    }

    // Calculate moving averages
    const movingAvgWindow = 7;
    const withMovingAvg = trends.map((t, i) => {
      const windowStart = Math.max(0, i - movingAvgWindow + 1);
      const window = trends.slice(windowStart, i + 1);
      const avgScore = window.reduce((sum, w) => sum + w.riskScore, 0) / window.length;

      return {
        ...t,
        movingAvgRiskScore: Math.round(avgScore * 10) / 10,
      };
    });

    // Calculate deltas
    const latest = withMovingAvg[withMovingAvg.length - 1];
    const earliest = withMovingAvg[0];
    const delta = latest && earliest
      ? {
        riskScoreChange: latest.riskScore - earliest.riskScore,
        findingsChange: latest.totalFindings - earliest.totalFindings,
        direction: latest.riskScore > earliest.riskScore ? 'worsening' : 'improving',
      }
      : null;

    return {
      period: `${days} days`,
      dataPoints: withMovingAvg,
      delta,
      summary: {
        avgRiskScore: trends.length > 0
          ? Math.round(trends.reduce((sum, t) => sum + t.riskScore, 0) / trends.length)
          : 0,
        peakRiskScore: trends.length > 0
          ? Math.max(...trends.map((t) => t.riskScore))
          : 0,
        lowestRiskScore: trends.length > 0
          ? Math.min(...trends.map((t) => t.riskScore))
          : 0,
      },
    };
  }

  /**
   * Schedule a recurring scan.
   */
  scheduleScan(params) {
    const scheduleId = uuidv4();
    const {
      name,
      cronExpression,
      scope = ['gpo', 'privilege', 'device'],
      benchmarks = ['CIS'],
      enabled = true,
    } = params;

    // Validate cron expression
    if (!cron.validate(cronExpression)) {
      throw new Error(`Invalid cron expression: ${cronExpression}`);
    }

    const schedule = {
      id: scheduleId,
      name: name || `Scheduled Scan ${scheduleId.substring(0, 8)}`,
      cronExpression,
      scope,
      benchmarks,
      enabled,
      createdAt: new Date().toISOString(),
      lastRun: null,
      nextRun: null,
      runCount: 0,
      task: null,
    };

    if (enabled) {
      schedule.task = cron.schedule(cronExpression, async () => {
        this.logger.info(`Executing scheduled scan: ${schedule.name} (${scheduleId})`);
        schedule.lastRun = new Date().toISOString();
        schedule.runCount++;

        try {
          await this.startScan({ scope, benchmarks, targets: {} });
        } catch (err) {
          this.logger.error(`Scheduled scan ${scheduleId} failed:`, err.message);
        }
      });

      // Calculate next run time (approximate)
      schedule.nextRun = this._getNextCronRun(cronExpression);
    }

    this.schedules.set(scheduleId, schedule);

    this.logger.info(`Scan scheduled: ${schedule.name}, cron: ${cronExpression}`);
    this.emit('scanScheduled', { scheduleId, name: schedule.name, cronExpression });

    return {
      id: scheduleId,
      name: schedule.name,
      cronExpression,
      scope,
      benchmarks,
      enabled,
      createdAt: schedule.createdAt,
      nextRun: schedule.nextRun,
    };
  }

  /**
   * Get all scheduled scans.
   */
  getSchedules() {
    return Array.from(this.schedules.values()).map((s) => ({
      id: s.id,
      name: s.name,
      cronExpression: s.cronExpression,
      scope: s.scope,
      benchmarks: s.benchmarks,
      enabled: s.enabled,
      createdAt: s.createdAt,
      lastRun: s.lastRun,
      nextRun: s.nextRun,
      runCount: s.runCount,
    }));
  }

  /**
   * Delete a scheduled scan.
   */
  deleteSchedule(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) return false;

    if (schedule.task) {
      schedule.task.stop();
    }
    this.schedules.delete(scheduleId);
    return true;
  }

  /**
   * Shutdown gracefully - stop all scheduled tasks.
   */
  shutdown() {
    for (const [id, schedule] of this.schedules) {
      if (schedule.task) {
        schedule.task.stop();
        this.logger.info(`Stopped scheduled scan: ${schedule.name} (${id})`);
      }
    }
  }

  // --- Risk scoring ---

  _calculateOverallRiskScore(findings) {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const byCategory = {};

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = byCategory[f.category] || { count: 0, score: 0 };
      byCategory[f.category].count++;
      byCategory[f.category].score += f.riskScore;
    }

    // Weighted scoring: Critical findings are heavily penalized
    const weightedScore =
      bySeverity.Critical * 10 +
      bySeverity.High * 6 +
      bySeverity.Medium * 3 +
      bySeverity.Low * 1;

    // Normalize to 0-100 scale (100 = worst)
    const maxExpectedFindings = 100;
    const maxExpectedScore = maxExpectedFindings * 10;
    const normalizedScore = Math.min(Math.round((weightedScore / maxExpectedScore) * 100), 100);

    // Grade assignment
    let grade, label;
    if (normalizedScore === 0) { grade = 'A+'; label = 'Excellent'; }
    else if (normalizedScore <= 10) { grade = 'A'; label = 'Very Good'; }
    else if (normalizedScore <= 20) { grade = 'B'; label = 'Good'; }
    else if (normalizedScore <= 35) { grade = 'C'; label = 'Fair'; }
    else if (normalizedScore <= 50) { grade = 'D'; label = 'Poor'; }
    else if (normalizedScore <= 70) { grade = 'E'; label = 'Very Poor'; }
    else { grade = 'F'; label = 'Critical'; }

    return {
      overall: normalizedScore,
      grade,
      label,
      totalFindings: findings.length,
      bySeverity,
      byCategory: Object.entries(byCategory).reduce((acc, [k, v]) => {
        acc[k] = { findings: v.count, riskScore: v.score };
        return acc;
      }, {}),
    };
  }

  _buildOverallSummary(findings) {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const byCategory = {};
    const byBenchmark = {};

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

      byCategory[f.category] = byCategory[f.category] || 0;
      byCategory[f.category]++;

      if (f.benchmark) {
        byBenchmark[f.benchmark] = byBenchmark[f.benchmark] || 0;
        byBenchmark[f.benchmark]++;
      }
    }

    const automatable = findings.filter(
      (f) => f.remediation && f.remediation.automatable
    ).length;

    return {
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      byBenchmark,
      automatableRemediations: automatable,
      manualRemediations: findings.length - automatable,
    };
  }

  // --- History and trending ---

  _recordScanHistory(scan) {
    this.scanHistory.push({
      scanId: scan.id,
      startTime: scan.startTime,
      endTime: scan.endTime,
      scope: scan.scope,
      benchmarks: scan.benchmarks,
      findingCount: scan.findings.length,
      riskScore: scan.riskScore ? scan.riskScore.overall : 0,
      summary: scan.summary,
    });

    // Trim history
    if (this.scanHistory.length > this.maxHistorySize) {
      this.scanHistory = this.scanHistory.slice(-this.maxHistorySize);
    }
  }

  _recordRiskTrend(scan) {
    this.riskTrends.push({
      timestamp: scan.endTime,
      scanId: scan.id,
      riskScore: scan.riskScore ? scan.riskScore.overall : 0,
      totalFindings: scan.findings.length,
      bySeverity: scan.summary ? scan.summary.bySeverity : {},
      byCategory: scan.summary ? scan.summary.byCategory : {},
    });

    // Trim trends
    if (this.riskTrends.length > this.maxTrendEntries) {
      this.riskTrends = this.riskTrends.slice(-this.maxTrendEntries);
    }
  }

  // --- Sample data generators (for demonstration without live AD/Intune) ---

  _generateSampleGPOData() {
    return {
      policies: [
        { id: 'gpo-001', name: 'Default Domain Policy', settings: ['password', 'lockout'] },
        { id: 'gpo-002', name: 'Server Baseline', settings: ['audit', 'firewall', 'security'] },
        { id: 'gpo-003', name: 'Workstation Policy', settings: ['firewall', 'software'] },
      ],
      passwordPolicy: {
        minLength: 8,
        maxAge: 90,
        minAge: 1,
        historySize: 10,
        complexity: true,
        reversibleEncryption: false,
        lockoutThreshold: 10,
        lockoutDuration: 30,
        lockoutWindow: 30,
      },
      auditPolicy: {
        accountLogon: 'Success',
        accountManagement: 'Success',
        logonEvents: 'Success',
        objectAccess: 'No Auditing',
        policyChange: 'No Auditing',
        privilegeUse: 'No Auditing',
        processTracking: 'No Auditing',
        systemEvents: 'Success',
        dsAccess: 'No Auditing',
      },
      firewallPolicy: {
        domainProfileEnabled: true,
        privateProfileEnabled: true,
        publicProfileEnabled: false,
        inboundDefaultBlock: false,
        outboundDefaultAllow: true,
        rules: [
          { name: 'Allow RDP', enabled: true, direction: 'Inbound', action: 'Allow', localPort: '3389', remoteAddress: '*', gpo: 'Server Baseline' },
          { name: 'Allow All Inbound', enabled: true, direction: 'Inbound', action: 'Allow', localPort: '*', remoteAddress: '*', gpo: 'Legacy App Policy' },
        ],
      },
      userRightsAssignment: {
        seDebugPrivilege: ['Administrators', 'IT-Support'],
        seTakeOwnershipPrivilege: ['Administrators'],
        seLoadDriverPrivilege: ['Administrators', 'Developers'],
        seBackupPrivilege: ['Administrators', 'Backup Operators', 'Helpdesk'],
        seRestorePrivilege: ['Administrators', 'Backup Operators'],
      },
      securityOptions: {
        lmHashStorage: true,
        anonymousSidTranslation: false,
        anonymousEnumeration: true,
        lanManagerAuth: 3,
        ldapSigning: 1,
        smbSigning: false,
        ntlmSspMinSecurity: 0,
      },
      administrativeTemplates: {
        autoplay: true,
        wdigest: true,
        lsaProtection: false,
        remoteDesktopNla: false,
        powershellLogging: false,
      },
    };
  }

  _generateSampleADData() {
    return {
      groups: [
        {
          name: 'Domain Admins',
          members: [
            { name: 'admin1', objectClass: 'user', lastLogon: '2026-03-10', passwordNeverExpires: false },
            { name: 'admin2', objectClass: 'user', lastLogon: '2026-03-14', passwordNeverExpires: false },
            { name: 'svc-backup', objectClass: 'user', lastLogon: '2026-01-15', passwordNeverExpires: true },
            { name: 'admin-old', objectClass: 'user', lastLogon: '2025-06-01', passwordNeverExpires: true, enabled: true },
            { name: 'IT-Ops', objectClass: 'group', type: 'group' },
            { name: 'admin3', objectClass: 'user', lastLogon: '2026-03-14', passwordNeverExpires: false },
            { name: 'admin4', objectClass: 'user', lastLogon: '2026-03-12', passwordNeverExpires: false },
          ],
        },
        {
          name: 'Enterprise Admins',
          members: [
            { name: 'admin1', objectClass: 'user', lastLogon: '2026-03-10', passwordNeverExpires: false },
            { name: 'admin2', objectClass: 'user', lastLogon: '2026-03-14', passwordNeverExpires: false },
            { name: 'admin-old', objectClass: 'user', lastLogon: '2025-06-01', passwordNeverExpires: true },
            { name: 'sa-exchange', objectClass: 'user', lastLogon: '2026-03-13', passwordNeverExpires: true },
          ],
        },
        {
          name: 'Schema Admins',
          members: [
            { name: 'admin1', objectClass: 'user', lastLogon: '2026-03-10', passwordNeverExpires: false },
            { name: 'admin-temp', objectClass: 'user', lastLogon: '2025-12-01', disabled: true },
          ],
        },
        {
          name: 'Backup Operators',
          members: [
            { name: 'svc-backup', objectClass: 'user', lastLogon: '2026-01-15', passwordNeverExpires: true },
            { name: 'backup-admin', objectClass: 'user', lastLogon: '2026-03-14', passwordNeverExpires: false },
          ],
        },
        {
          name: 'IT-Ops',
          members: [
            { name: 'it-user1', objectClass: 'user' },
            { name: 'it-user2', objectClass: 'user' },
            { name: 'it-user3', objectClass: 'user' },
          ],
        },
      ],
      users: [
        {
          name: 'svc-sql',
          samAccountName: 'svc-sql',
          objectClass: 'user',
          servicePrincipalNames: ['MSSQLSvc/sql01.contoso.com:1433'],
          supportedEncryptionTypes: 4,
          passwordLastSet: '2024-03-01',
          logonWorkstations: null,
        },
        {
          name: 'svc-web',
          samAccountName: 'svc-web',
          objectClass: 'user',
          servicePrincipalNames: ['HTTP/web01.contoso.com'],
          supportedEncryptionTypes: 24,
          passwordLastSet: '2025-11-01',
        },
        {
          name: 'admin-old',
          samAccountName: 'admin-old',
          objectClass: 'user',
          adminCount: 1,
          lastLogon: '2025-06-01',
        },
        {
          name: 'former-admin',
          samAccountName: 'former-admin',
          objectClass: 'user',
          adminCount: 1,
          lastLogon: '2025-09-15',
        },
      ],
      computers: [
        {
          name: 'WEB01$',
          samAccountName: 'WEB01$',
          objectClass: 'computer',
          trustedForDelegation: true,
        },
        {
          name: 'APP01$',
          samAccountName: 'APP01$',
          objectClass: 'computer',
          trustedForDelegation: false,
          trustedToAuthForDelegation: true,
          allowedToDelegateTo: ['MSSQLSvc/sql01.contoso.com:1433'],
        },
      ],
      acls: [
        {
          objectName: 'Domain Admins',
          accessControlEntries: [
            { principal: 'Domain Admins', rights: ['GenericAll'] },
            { principal: 'SYSTEM', rights: ['GenericAll'] },
            { principal: 'IT-HelpDesk', rights: ['WriteProperty', 'WriteDacl'] },
          ],
        },
      ],
    };
  }

  _generateSampleDevices() {
    return [
      {
        id: 'dev-001',
        name: 'DESKTOP-USER01',
        hostname: 'DESKTOP-USER01',
        operatingSystem: 'Windows 11 23H2',
        bitlocker: { enabled: true, status: 'Encrypted', algorithm: 'XTS-AES-128', protector: 'TPM', recoveryKeyEscrowed: true },
        endpointProtection: { installed: true, status: 'Active', realTimeProtection: true, cloudProtection: true, tamperProtection: false, definitionAge: 1 },
        firewall: { enabled: true },
        secureBoot: true,
        secureBootEnabled: true,
        tpm: { present: true, version: '2.0', status: 'Ready' },
        credentialGuard: false,
        credentialGuardEnabled: false,
        screenLock: { timeout: 1800 },
        localAccounts: { guestEnabled: false, defaultAdminRenamed: true },
        autoUpdates: true,
        uac: { enabled: true },
        patches: { missing: [], lastScanDate: '2026-03-14', pendingReboot: false },
      },
      {
        id: 'dev-002',
        name: 'DESKTOP-USER02',
        hostname: 'DESKTOP-USER02',
        operatingSystem: 'Windows 10 22H2',
        bitlocker: { enabled: false, status: 'Not Encrypted' },
        endpointProtection: { installed: true, status: 'Active', realTimeProtection: false, cloudProtection: false, tamperProtection: false, definitionAge: 12 },
        firewall: { enabled: false, status: 'Disabled' },
        secureBoot: false,
        secureBootEnabled: false,
        tpm: { present: true, version: '1.2', status: 'Ready' },
        credentialGuard: false,
        credentialGuardEnabled: false,
        screenLock: { timeout: 0 },
        localAccounts: { guestEnabled: true, defaultAdminRenamed: false },
        autoUpdates: false,
        windowsUpdateEnabled: false,
        uac: { enabled: false },
        patches: {
          missing: [
            { kbId: 'KB5034441', title: 'Security Update for Windows', category: 'Security Updates', severity: 'Critical', releaseDate: '2026-02-13' },
            { kbId: 'KB5034467', title: 'Cumulative Update', category: 'Security Updates', severity: 'Critical', releaseDate: '2026-02-13' },
          ],
          lastScanDate: '2026-02-01',
          pendingReboot: false,
        },
      },
      {
        id: 'dev-003',
        name: 'SERVER-DC01',
        hostname: 'SERVER-DC01',
        operatingSystem: 'Windows Server 2022',
        bitlocker: { enabled: true, status: 'Encrypted', algorithm: 'XTS-AES-256', protector: 'TPMAndPIN', recoveryKeyEscrowed: true },
        endpointProtection: { installed: true, status: 'Active', realTimeProtection: true, cloudProtection: true, tamperProtection: true, definitionAge: 0 },
        firewall: { enabled: true },
        secureBoot: true,
        secureBootEnabled: true,
        tpm: { present: true, version: '2.0', status: 'Ready' },
        credentialGuard: true,
        credentialGuardEnabled: true,
        screenLock: { timeout: 600 },
        localAccounts: { guestEnabled: false, defaultAdminRenamed: true },
        autoUpdates: true,
        uac: { enabled: true },
        patches: {
          missing: [
            { kbId: 'KB5034770', title: 'Cumulative Update for Server', category: 'Security Updates', severity: 'Critical', releaseDate: '2026-03-11' },
          ],
          lastScanDate: '2026-03-14',
          pendingReboot: true,
        },
      },
    ];
  }

  _generateSampleTrends(days) {
    const trends = [];
    const now = new Date();
    let riskScore = 45;

    for (let i = days; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);

      // Simulate gradual improvement with some variation
      riskScore += (Math.random() - 0.55) * 5;
      riskScore = Math.max(10, Math.min(80, riskScore));

      const totalFindings = Math.round(riskScore * 0.8 + Math.random() * 10);

      trends.push({
        timestamp: date.toISOString(),
        scanId: `trend-${i}`,
        riskScore: Math.round(riskScore),
        totalFindings,
        bySeverity: {
          Critical: Math.round(totalFindings * 0.1),
          High: Math.round(totalFindings * 0.25),
          Medium: Math.round(totalFindings * 0.4),
          Low: Math.round(totalFindings * 0.25),
        },
      });
    }

    return trends;
  }

  _getNextCronRun(cronExpression) {
    // Simple approximation for display purposes
    const parts = cronExpression.split(' ');
    const now = new Date();

    // If it's a daily cron, approximate the next run
    if (parts.length >= 5) {
      const minute = parts[0] !== '*' ? parseInt(parts[0], 10) : 0;
      const hour = parts[1] !== '*' ? parseInt(parts[1], 10) : 0;

      const next = new Date(now);
      next.setHours(hour, minute, 0, 0);

      if (next <= now) {
        next.setDate(next.getDate() + 1);
      }

      return next.toISOString();
    }

    return null;
  }
}

module.exports = ExposureScanner;

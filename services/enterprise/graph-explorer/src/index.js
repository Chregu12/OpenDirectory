'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');
const { WebSocketServer } = require('ws');
const http = require('http');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const Joi = require('joi');

// ====================================================================== //
//  Logger setup
// ====================================================================== //

const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
);

const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        if (Object.keys(meta).length > 0) {
            msg += ' ' + JSON.stringify(meta);
        }
        return msg;
    })
);

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: { service: 'graph-explorer', version: '1.0.0' },
    transports: [
        new DailyRotateFile({
            filename: path.join(logsDir, 'error-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxSize: '20m',
            maxFiles: '14d',
            zippedArchive: true,
        }),
        new DailyRotateFile({
            filename: path.join(logsDir, 'combined-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            zippedArchive: true,
        }),
    ],
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat,
        level: process.env.LOG_LEVEL || 'debug',
    }));
}

// ====================================================================== //
//  Import services
// ====================================================================== //

const GraphBuilder = require('./services/graphBuilder');
const { NODE_TYPES, EDGE_TYPES, RISK_LEVELS } = require('./services/graphBuilder');
const AttackPathAnalyzer = require('./services/attackPathAnalyzer');
const ShadowAdminDetector = require('./services/shadowAdminDetector');

// ====================================================================== //
//  Validation schemas
// ====================================================================== //

const schemas = {
    query: Joi.object({
        query: Joi.string().min(1).required(),
    }),
    refresh: Joi.object({
        force: Joi.boolean().optional(),
        scope: Joi.string().valid('full', 'incremental').optional(),
    }),
};

// ====================================================================== //
//  GraphExplorerService
// ====================================================================== //

class GraphExplorerService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;
        this.wss = null;
        this.wsClients = new Set();

        // Initialise core services
        this.graphBuilder = new GraphBuilder(logger);
        this.attackPathAnalyzer = new AttackPathAnalyzer(this.graphBuilder, logger);
        this.shadowAdminDetector = new ShadowAdminDetector(this.graphBuilder, logger);

        // Track service state
        this.startedAt = null;
        this.isReady = false;

        this._initializeMiddleware();
        this._initializeRoutes();
        this._initializeErrorHandling();
    }

    // ------------------------------------------------------------------ //
    //  Middleware
    // ------------------------------------------------------------------ //

    _initializeMiddleware() {
        logger.info('Setting up middleware...');

        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", 'data:', 'https:'],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"],
                },
            },
            crossOriginEmbedderPolicy: false,
        }));

        this.app.use(cors({
            origin: (origin, callback) => {
                if (!origin) return callback(null, true);
                const allowed = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');
                if (allowed.indexOf(origin) !== -1) {
                    callback(null, true);
                } else {
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
        }));

        this.app.use(compression());
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true }));

        // Rate limiting on API routes
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 1000,
            message: {
                error: 'Too many requests from this IP, please try again later',
                retryAfter: '15 minutes',
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => req.path === '/health' || req.path === '/metrics',
        });
        this.app.use('/api', limiter);

        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                logger.info(`${req.method} ${req.originalUrl}`, {
                    statusCode: res.statusCode,
                    durationMs: Date.now() - start,
                    ip: req.ip,
                });
            });
            next();
        });

        logger.info('Middleware setup completed');
    }

    // ------------------------------------------------------------------ //
    //  Routes
    // ------------------------------------------------------------------ //

    _initializeRoutes() {
        logger.info('Setting up routes...');

        // ---- Health & info ----

        this.app.get('/health', (_req, res) => {
            res.json({
                status: this.isReady ? 'healthy' : 'starting',
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                services: {
                    graphBuilder: 'operational',
                    attackPathAnalyzer: 'operational',
                    shadowAdminDetector: 'operational',
                },
                uptime: process.uptime(),
                graph: {
                    nodes: this.graphBuilder.nodes.size,
                    edges: this.graphBuilder.edges.size,
                    lastRefresh: this.graphBuilder.metadata.lastRefresh,
                },
                websocket: {
                    connectedClients: this.wsClients.size,
                },
            });
        });

        this.app.get('/metrics', (_req, res) => {
            res.json({
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
            });
        });

        this.app.get('/', (_req, res) => {
            res.json({
                name: 'OpenDirectory AD Graph Explorer Service',
                version: '1.0.0',
                description: 'Neo4j-style graph visualization of Active Directory and Intune relationships',
                features: [
                    'Full relationship graph visualization',
                    'Entity subgraph extraction',
                    'Shortest path queries',
                    'Attack path detection (BloodHound-style)',
                    'Shadow admin discovery',
                    'Cypher-like query engine',
                    'Real-time WebSocket updates',
                ],
                api: {
                    baseUrl: '/api/graph',
                    documentation: '/api/graph/docs',
                },
                timestamp: new Date().toISOString(),
            });
        });

        // ---- Graph API ----

        const router = express.Router();

        // GET /api/graph/full - Full relationship graph
        router.get('/full', (req, res, next) => {
            try {
                const { nodeTypes, riskLevel, limit } = req.query;

                const filters = {};
                if (nodeTypes) filters.nodeTypes = nodeTypes.split(',');
                if (riskLevel) filters.riskLevel = riskLevel;

                const graph = this.graphBuilder.toJSON(filters);

                // Apply optional limit
                if (limit) {
                    const n = parseInt(limit, 10);
                    graph.nodes = graph.nodes.slice(0, n);
                    const nodeIds = new Set(graph.nodes.map((nd) => nd.id));
                    graph.edges = graph.edges.filter(
                        (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
                    );
                }

                res.json({
                    success: true,
                    data: graph,
                    meta: {
                        totalNodes: this.graphBuilder.nodes.size,
                        totalEdges: this.graphBuilder.edges.size,
                        returnedNodes: graph.nodes.length,
                        returnedEdges: graph.edges.length,
                        filters: { nodeTypes: filters.nodeTypes || 'all', riskLevel: riskLevel || 'all' },
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // GET /api/graph/entity/:type/:id - Subgraph for specific entity
        router.get('/entity/:type/:id', (req, res, next) => {
            try {
                const { type, id } = req.params;
                const depth = parseInt(req.query.depth, 10) || 2;

                const node = this.graphBuilder.getNode(id);
                if (!node) {
                    return res.status(404).json({
                        success: false,
                        error: `Entity not found: ${type}/${id}`,
                        timestamp: new Date().toISOString(),
                    });
                }

                if (node.type !== type && type !== 'any') {
                    return res.status(400).json({
                        success: false,
                        error: `Type mismatch: entity "${id}" is ${node.type}, not ${type}`,
                        timestamp: new Date().toISOString(),
                    });
                }

                const edgeTypes = req.query.edgeTypes ? req.query.edgeTypes.split(',') : undefined;
                const nodeTypes = req.query.nodeTypes ? req.query.nodeTypes.split(',') : undefined;

                const subgraph = this.graphBuilder.subgraph(id, depth, { edgeTypes, nodeTypes });

                // Also return direct relationships summary
                const outgoing = this.graphBuilder.getOutgoingEdges(id);
                const incoming = this.graphBuilder.getIncomingEdges(id);
                const relationships = {
                    outgoing: outgoing.map((e) => ({
                        edgeType: e.type,
                        targetId: e.target,
                        targetName: this.graphBuilder.getNode(e.target)?.name,
                        targetType: this.graphBuilder.getNode(e.target)?.type,
                    })),
                    incoming: incoming.map((e) => ({
                        edgeType: e.type,
                        sourceId: e.source,
                        sourceName: this.graphBuilder.getNode(e.source)?.name,
                        sourceType: this.graphBuilder.getNode(e.source)?.type,
                    })),
                };

                res.json({
                    success: true,
                    data: {
                        entity: node,
                        subgraph,
                        relationships,
                    },
                    meta: {
                        depth,
                        subgraphNodes: subgraph.nodes.length,
                        subgraphEdges: subgraph.edges.length,
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // GET /api/graph/path/:fromId/:toId - Shortest path between entities
        router.get('/path/:fromId/:toId', (req, res, next) => {
            try {
                const { fromId, toId } = req.params;
                const weighted = req.query.weighted === 'true';
                const edgeTypes = req.query.edgeTypes ? req.query.edgeTypes.split(',') : undefined;

                const fromNode = this.graphBuilder.getNode(fromId);
                const toNode = this.graphBuilder.getNode(toId);

                if (!fromNode) {
                    return res.status(404).json({
                        success: false,
                        error: `Source node not found: ${fromId}`,
                        timestamp: new Date().toISOString(),
                    });
                }
                if (!toNode) {
                    return res.status(404).json({
                        success: false,
                        error: `Target node not found: ${toId}`,
                        timestamp: new Date().toISOString(),
                    });
                }

                const options = { edgeTypes, directed: req.query.directed !== 'false' };
                const pathResult = weighted
                    ? this.graphBuilder.weightedShortestPath(fromId, toId, options)
                    : this.graphBuilder.shortestPath(fromId, toId, options);

                if (!pathResult) {
                    return res.json({
                        success: true,
                        data: null,
                        meta: {
                            from: { id: fromNode.id, name: fromNode.name, type: fromNode.type },
                            to: { id: toNode.id, name: toNode.name, type: toNode.type },
                            message: 'No path exists between the specified nodes',
                        },
                    });
                }

                res.json({
                    success: true,
                    data: {
                        path: pathResult.nodes.map((n, i) => ({
                            node: n,
                            edge: pathResult.edges[i] || null,
                        })),
                        length: pathResult.length,
                        totalWeight: pathResult.totalWeight || pathResult.length,
                    },
                    meta: {
                        from: { id: fromNode.id, name: fromNode.name, type: fromNode.type },
                        to: { id: toNode.id, name: toNode.name, type: toNode.type },
                        algorithm: weighted ? 'dijkstra' : 'bfs',
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // GET /api/graph/attack-paths - All detected attack paths
        router.get('/attack-paths', (req, res, next) => {
            try {
                const { severity, technique, sourceType, limit } = req.query;
                const filters = {};
                if (severity) filters.severity = severity;
                if (technique) filters.technique = technique;
                if (sourceType) filters.sourceType = sourceType;
                if (limit) filters.limit = parseInt(limit, 10);

                const paths = this.attackPathAnalyzer.getAttackPaths(filters);
                const summary = this.attackPathAnalyzer.getSummary();

                res.json({
                    success: true,
                    data: {
                        paths: paths.map((p) => ({
                            id: p.id,
                            title: p.title,
                            description: p.description,
                            severity: p.severity,
                            technique: p.technique,
                            source: p.source ? { id: p.source.id, name: p.source.name, type: p.source.type, displayName: p.source.displayName } : null,
                            target: p.target ? { id: p.target.id, name: p.target.name, type: p.target.type, displayName: p.target.displayName } : null,
                            path: p.path.map((step) => ({
                                nodeId: step.node.id,
                                nodeName: step.node.name,
                                nodeType: step.node.type,
                                edgeType: step.edge?.type || null,
                            })),
                            mitigations: p.mitigations,
                            detectedAt: p.detectedAt,
                        })),
                        summary: {
                            totalPaths: summary.totalPaths,
                            bySeverity: summary.bySeverity,
                            analysisTimestamp: summary.timestamp,
                            analysisDurationMs: summary.durationMs,
                        },
                    },
                    meta: {
                        filters: { severity, technique, sourceType },
                        returnedCount: paths.length,
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // GET /api/graph/shadow-admins - Shadow admin accounts
        router.get('/shadow-admins', (req, res, next) => {
            try {
                const { severity, technique, principalType } = req.query;
                const filters = {};
                if (severity) filters.severity = severity;
                if (technique) filters.technique = technique;
                if (principalType) filters.principalType = principalType;

                const shadowAdmins = this.shadowAdminDetector.getShadowAdmins(filters);
                const summary = this.shadowAdminDetector.getSummary();

                res.json({
                    success: true,
                    data: {
                        shadowAdmins: shadowAdmins.map((sa) => ({
                            id: sa.id,
                            title: sa.title,
                            description: sa.description,
                            severity: sa.severity,
                            techniques: sa.techniques,
                            principal: {
                                id: sa.principal.id,
                                name: sa.principal.name,
                                displayName: sa.principal.displayName,
                                type: sa.principal.type,
                                properties: {
                                    upn: sa.principal.properties?.upn,
                                    title: sa.principal.properties?.title,
                                    department: sa.principal.properties?.department,
                                    enabled: sa.principal.properties?.enabled,
                                    isServiceAccount: sa.principal.properties?.isServiceAccount,
                                },
                            },
                            reachablePrivilegedGroups: sa.reachablePrivilegedGroups.map((g) => ({
                                id: g.id,
                                name: g.name,
                            })),
                            effectivePermissions: sa.effectivePermissions,
                            membershipChains: sa.membershipChains || [],
                            recommendations: sa.recommendations,
                            detectedAt: sa.detectedAt,
                        })),
                        summary: {
                            knownAdminCount: summary.knownAdminCount,
                            shadowAdminCount: summary.shadowAdminCount,
                            bySeverity: summary.bySeverity,
                            byTechnique: summary.byTechnique,
                            analysisTimestamp: summary.timestamp,
                            analysisDurationMs: summary.durationMs,
                        },
                    },
                    meta: {
                        filters: { severity, technique, principalType },
                        returnedCount: shadowAdmins.length,
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // GET /api/graph/statistics - Graph statistics
        router.get('/statistics', (req, res, next) => {
            try {
                const stats = this.graphBuilder.getStatistics();
                const attackSummary = this.attackPathAnalyzer.lastAnalysis;
                const shadowSummary = this.shadowAdminDetector.lastAnalysis;

                res.json({
                    success: true,
                    data: {
                        graph: stats,
                        attackPaths: attackSummary
                            ? {
                                  totalPaths: attackSummary.totalPaths,
                                  bySeverity: attackSummary.bySeverity,
                                  lastAnalysis: attackSummary.timestamp,
                              }
                            : null,
                        shadowAdmins: shadowSummary
                            ? {
                                  totalFound: shadowSummary.shadowAdminCount,
                                  knownAdmins: shadowSummary.knownAdminCount,
                                  bySeverity: shadowSummary.bySeverity,
                                  lastAnalysis: shadowSummary.timestamp,
                              }
                            : null,
                        availableNodeTypes: Object.values(NODE_TYPES),
                        availableEdgeTypes: Object.values(EDGE_TYPES),
                        availableRiskLevels: Object.values(RISK_LEVELS),
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // POST /api/graph/query - Custom graph query (Cypher-like)
        router.post('/query', (req, res, next) => {
            try {
                const { error, value } = schemas.query.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        examples: [
                            'MATCH (n:User) RETURN n',
                            'MATCH (n:User)-[:MemberOf]->(m:Group) RETURN n,m',
                            'MATCH (n {name: "jsmith"}) RETURN n',
                            'MATCH path = shortestPath((a {name:"jsmith"})-[*]->(b {name:"Domain Admins"}))',
                            'MATCH (n) WHERE n.riskLevel = "critical" RETURN n',
                        ],
                        timestamp: new Date().toISOString(),
                    });
                }

                logger.info('Executing custom query', { query: value.query });
                const result = this.graphBuilder.executeQuery(value.query);

                if (result.error) {
                    return res.status(400).json({
                        success: false,
                        error: result.error,
                        query: value.query,
                        timestamp: new Date().toISOString(),
                    });
                }

                res.json({
                    success: true,
                    data: {
                        results: result.results,
                        count: result.results.length,
                    },
                    meta: { query: value.query },
                });
            } catch (err) {
                next(err);
            }
        });

        // POST /api/graph/refresh - Rebuild graph from collectors
        router.post('/refresh', (req, res, next) => {
            try {
                logger.info('Graph refresh requested');
                const previousStats = this.graphBuilder.getStatistics();

                this.graphBuilder.rebuild();
                this.attackPathAnalyzer.analyze();
                this.shadowAdminDetector.detect();

                const newStats = this.graphBuilder.getStatistics();

                // Notify WebSocket clients
                this._broadcast({
                    type: 'graph:refreshed',
                    timestamp: new Date().toISOString(),
                    statistics: newStats,
                });

                res.json({
                    success: true,
                    data: {
                        message: 'Graph rebuilt successfully',
                        previous: {
                            nodes: previousStats.nodeCount,
                            edges: previousStats.edgeCount,
                        },
                        current: {
                            nodes: newStats.nodeCount,
                            edges: newStats.edgeCount,
                        },
                        buildDurationMs: newStats.metadata.buildDurationMs,
                        version: newStats.metadata.version,
                    },
                });
            } catch (err) {
                next(err);
            }
        });

        // API documentation
        router.get('/docs', (_req, res) => {
            res.json({
                openapi: '3.0.0',
                info: {
                    title: 'OpenDirectory AD Graph Explorer API',
                    version: '1.0.0',
                    description: 'Neo4j-style graph visualization of Active Directory and Intune relationships',
                },
                servers: [{ url: '/api/graph', description: 'Graph Explorer API' }],
                paths: {
                    '/full': {
                        get: {
                            summary: 'Get the full relationship graph',
                            parameters: [
                                { name: 'nodeTypes', in: 'query', schema: { type: 'string' }, description: 'Comma-separated node types to filter' },
                                { name: 'riskLevel', in: 'query', schema: { type: 'string' } },
                                { name: 'limit', in: 'query', schema: { type: 'integer' } },
                            ],
                            responses: { '200': { description: 'Full graph data' } },
                        },
                    },
                    '/entity/{type}/{id}': {
                        get: {
                            summary: 'Get subgraph for a specific entity',
                            parameters: [
                                { name: 'type', in: 'path', required: true, schema: { type: 'string' } },
                                { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
                                { name: 'depth', in: 'query', schema: { type: 'integer', default: 2 } },
                                { name: 'edgeTypes', in: 'query', schema: { type: 'string' } },
                                { name: 'nodeTypes', in: 'query', schema: { type: 'string' } },
                            ],
                            responses: { '200': { description: 'Entity subgraph' } },
                        },
                    },
                    '/path/{fromId}/{toId}': {
                        get: {
                            summary: 'Find shortest path between two entities',
                            parameters: [
                                { name: 'fromId', in: 'path', required: true, schema: { type: 'string' } },
                                { name: 'toId', in: 'path', required: true, schema: { type: 'string' } },
                                { name: 'weighted', in: 'query', schema: { type: 'boolean' } },
                                { name: 'edgeTypes', in: 'query', schema: { type: 'string' } },
                                { name: 'directed', in: 'query', schema: { type: 'boolean' } },
                            ],
                            responses: { '200': { description: 'Shortest path result' } },
                        },
                    },
                    '/attack-paths': {
                        get: {
                            summary: 'Get detected attack paths',
                            parameters: [
                                { name: 'severity', in: 'query', schema: { type: 'string' } },
                                { name: 'technique', in: 'query', schema: { type: 'string' } },
                                { name: 'sourceType', in: 'query', schema: { type: 'string' } },
                                { name: 'limit', in: 'query', schema: { type: 'integer' } },
                            ],
                            responses: { '200': { description: 'Attack paths' } },
                        },
                    },
                    '/shadow-admins': {
                        get: {
                            summary: 'Get shadow admin accounts',
                            parameters: [
                                { name: 'severity', in: 'query', schema: { type: 'string' } },
                                { name: 'technique', in: 'query', schema: { type: 'string' } },
                                { name: 'principalType', in: 'query', schema: { type: 'string' } },
                            ],
                            responses: { '200': { description: 'Shadow admin findings' } },
                        },
                    },
                    '/statistics': {
                        get: {
                            summary: 'Get graph statistics',
                            responses: { '200': { description: 'Graph statistics' } },
                        },
                    },
                    '/query': {
                        post: {
                            summary: 'Execute a custom Cypher-like query',
                            requestBody: {
                                required: true,
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            required: ['query'],
                                            properties: {
                                                query: { type: 'string', example: 'MATCH (n:User) RETURN n' },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '200': { description: 'Query results' } },
                        },
                    },
                    '/refresh': {
                        post: {
                            summary: 'Rebuild the graph from collectors',
                            responses: { '200': { description: 'Refresh result' } },
                        },
                    },
                },
            });
        });

        this.app.use('/api/graph', router);

        logger.info('Routes setup completed');
    }

    // ------------------------------------------------------------------ //
    //  Error handling
    // ------------------------------------------------------------------ //

    _initializeErrorHandling() {
        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
                timestamp: new Date().toISOString(),
            });
        });

        // Global error handler
        this.app.use((err, _req, res, _next) => {
            const statusCode = err.statusCode || 500;
            const isDev = process.env.NODE_ENV === 'development';

            if (statusCode >= 500) {
                logger.error('Unhandled error', { message: err.message, stack: err.stack });
            } else {
                logger.warn('Client error', { statusCode, message: err.message });
            }

            res.status(statusCode).json({
                error: statusCode >= 500 && !isDev ? 'Internal server error' : err.message,
                ...(isDev && { stack: err.stack }),
                timestamp: new Date().toISOString(),
            });
        });

        // Process-level handlers
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception', { message: err.message, stack: err.stack });
            process.exit(1);
        });

        process.on('unhandledRejection', (reason) => {
            logger.error('Unhandled Rejection', { reason: String(reason) });
        });

        logger.info('Error handling setup completed');
    }

    // ------------------------------------------------------------------ //
    //  WebSocket
    // ------------------------------------------------------------------ //

    _initializeWebSocket() {
        this.wss = new WebSocketServer({ server: this.server, path: '/ws' });

        this.wss.on('connection', (ws, req) => {
            const clientId = `ws-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
            ws._clientId = clientId;
            this.wsClients.add(ws);

            logger.info('WebSocket client connected', {
                clientId,
                remoteAddress: req.socket.remoteAddress,
                totalClients: this.wsClients.size,
            });

            // Send initial state
            ws.send(JSON.stringify({
                type: 'connection:established',
                clientId,
                timestamp: new Date().toISOString(),
                graphStats: {
                    nodes: this.graphBuilder.nodes.size,
                    edges: this.graphBuilder.edges.size,
                },
            }));

            ws.on('message', (data) => {
                try {
                    const message = JSON.parse(data.toString());
                    this._handleWSMessage(ws, message);
                } catch (err) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        error: 'Invalid JSON message',
                    }));
                }
            });

            ws.on('close', () => {
                this.wsClients.delete(ws);
                logger.info('WebSocket client disconnected', {
                    clientId,
                    totalClients: this.wsClients.size,
                });
            });

            ws.on('error', (err) => {
                logger.error('WebSocket error', { clientId, error: err.message });
                this.wsClients.delete(ws);
            });
        });

        // Forward graph events to WS clients
        this.graphBuilder.on('node:added', (node) => {
            this._broadcast({ type: 'node:added', node, timestamp: new Date().toISOString() });
        });

        this.graphBuilder.on('node:removed', (data) => {
            this._broadcast({ type: 'node:removed', ...data, timestamp: new Date().toISOString() });
        });

        this.graphBuilder.on('edge:added', (edge) => {
            this._broadcast({ type: 'edge:added', edge, timestamp: new Date().toISOString() });
        });

        this.graphBuilder.on('edge:removed', (data) => {
            this._broadcast({ type: 'edge:removed', ...data, timestamp: new Date().toISOString() });
        });

        this.graphBuilder.on('graph:rebuilt', (stats) => {
            this._broadcast({ type: 'graph:rebuilt', statistics: stats, timestamp: new Date().toISOString() });
        });
    }

    _handleWSMessage(ws, message) {
        switch (message.type) {
            case 'ping':
                ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
                break;

            case 'subscribe': {
                // Subscribe to specific event types
                ws._subscriptions = message.events || ['all'];
                ws.send(JSON.stringify({
                    type: 'subscribed',
                    events: ws._subscriptions,
                    timestamp: new Date().toISOString(),
                }));
                break;
            }

            case 'query': {
                if (!message.query) {
                    ws.send(JSON.stringify({ type: 'error', error: 'Missing query field' }));
                    return;
                }
                const result = this.graphBuilder.executeQuery(message.query);
                ws.send(JSON.stringify({
                    type: 'query:result',
                    requestId: message.requestId || null,
                    data: result,
                    timestamp: new Date().toISOString(),
                }));
                break;
            }

            case 'getSubgraph': {
                if (!message.nodeId) {
                    ws.send(JSON.stringify({ type: 'error', error: 'Missing nodeId field' }));
                    return;
                }
                const subgraph = this.graphBuilder.subgraph(
                    message.nodeId,
                    message.depth || 2,
                    { edgeTypes: message.edgeTypes, nodeTypes: message.nodeTypes }
                );
                ws.send(JSON.stringify({
                    type: 'subgraph:result',
                    requestId: message.requestId || null,
                    data: subgraph,
                    timestamp: new Date().toISOString(),
                }));
                break;
            }

            case 'getPath': {
                if (!message.fromId || !message.toId) {
                    ws.send(JSON.stringify({ type: 'error', error: 'Missing fromId or toId' }));
                    return;
                }
                const pathResult = this.graphBuilder.shortestPath(message.fromId, message.toId);
                ws.send(JSON.stringify({
                    type: 'path:result',
                    requestId: message.requestId || null,
                    data: pathResult,
                    timestamp: new Date().toISOString(),
                }));
                break;
            }

            default:
                ws.send(JSON.stringify({
                    type: 'error',
                    error: `Unknown message type: ${message.type}`,
                    supportedTypes: ['ping', 'subscribe', 'query', 'getSubgraph', 'getPath'],
                }));
        }
    }

    _broadcast(message) {
        const payload = JSON.stringify(message);
        for (const client of this.wsClients) {
            if (client.readyState === 1) { // WebSocket.OPEN
                const subscriptions = client._subscriptions || ['all'];
                if (subscriptions.includes('all') || subscriptions.includes(message.type)) {
                    try {
                        client.send(payload);
                    } catch (err) {
                        logger.error('Failed to send to WebSocket client', {
                            clientId: client._clientId,
                            error: err.message,
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Lifecycle
    // ------------------------------------------------------------------ //

    async start() {
        const port = parseInt(process.env.PORT, 10) || 3900;
        const host = process.env.HOST || '0.0.0.0';

        try {
            // Build initial graph
            logger.info('Building initial AD/Intune graph...');
            this.graphBuilder.seedDemoData();

            // Run initial analysis
            logger.info('Running initial attack path analysis...');
            this.attackPathAnalyzer.analyze();

            logger.info('Running initial shadow admin detection...');
            this.shadowAdminDetector.detect();

            // Start HTTP + WebSocket server
            this.server = http.createServer(this.app);
            this._initializeWebSocket();

            return new Promise((resolve, reject) => {
                this.server.listen(port, host, () => {
                    this.startedAt = Date.now();
                    this.isReady = true;

                    const stats = this.graphBuilder.getStatistics();
                    const attackPaths = this.attackPathAnalyzer.attackPaths.length;
                    const shadowAdmins = this.shadowAdminDetector.shadowAdmins.length;

                    logger.info(`OpenDirectory AD Graph Explorer Service started on ${host}:${port}`);
                    logger.info(`Health check: http://${host}:${port}/health`);
                    logger.info(`WebSocket:    ws://${host}:${port}/ws`);
                    logger.info(`API docs:     http://${host}:${port}/api/graph/docs`);
                    logger.info(`Graph: ${stats.nodeCount} nodes, ${stats.edgeCount} edges (density: ${stats.density})`);
                    logger.info(`Attack paths detected: ${attackPaths}`);
                    logger.info(`Shadow admins found: ${shadowAdmins}`);
                    this.emit('started');
                    resolve(this.server);
                });

                this.server.on('error', (err) => {
                    logger.error('Server error', { message: err.message });
                    this.emit('error', err);
                    reject(err);
                });

                // Graceful shutdown
                const shutdown = (signal) => {
                    logger.info(`Received ${signal}, shutting down...`);

                    // Close WebSocket connections
                    for (const client of this.wsClients) {
                        try {
                            client.close(1001, 'Server shutting down');
                        } catch (_err) {
                            // ignore
                        }
                    }
                    this.wsClients.clear();

                    if (this.wss) {
                        this.wss.close(() => {
                            logger.info('WebSocket server closed');
                        });
                    }

                    this.server.close(() => {
                        this.isReady = false;
                        logger.info('Graceful shutdown completed');
                        process.exit(0);
                    });

                    // Force exit after 10 seconds
                    setTimeout(() => {
                        logger.error('Forced shutdown after timeout');
                        process.exit(1);
                    }, 10000);
                };

                process.on('SIGTERM', () => shutdown('SIGTERM'));
                process.on('SIGINT', () => shutdown('SIGINT'));
            });
        } catch (err) {
            logger.error('Failed to start Graph Explorer service', { message: err.message, stack: err.stack });
            throw err;
        }
    }
}

// ====================================================================== //
//  Export & auto-start
// ====================================================================== //

module.exports = GraphExplorerService;

if (require.main === module) {
    const service = new GraphExplorerService();
    service.start().catch((err) => {
        logger.error('Failed to start AD Graph Explorer Service', { message: err.message });
        process.exit(1);
    });
}

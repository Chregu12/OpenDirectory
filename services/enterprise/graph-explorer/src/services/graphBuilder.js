/**
 * GraphBuilder - Builds and manages an in-memory graph of AD/Intune relationships
 *
 * Models the full Active Directory / Intune object hierarchy:
 *   Users -> Groups -> Devices -> Permissions -> Policies -> Update Rings
 *
 * Provides BFS/DFS traversal, shortest-path (Dijkstra), subgraph extraction,
 * filtering by entity type and risk level, and Cypher-like query execution.
 */

'use strict';

const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_TYPES = Object.freeze({
  USER: 'User',
  GROUP: 'Group',
  DEVICE: 'Device',
  PERMISSION: 'Permission',
  POLICY: 'Policy',
  UPDATE_RING: 'UpdateRing',
  APPLICATION: 'Application',
  OU: 'OrganizationalUnit',
  GPO: 'GroupPolicyObject',
  ROLE: 'Role',
  SERVICE_PRINCIPAL: 'ServicePrincipal',
});

const EDGE_TYPES = Object.freeze({
  MEMBER_OF: 'MemberOf',
  OWNS: 'Owns',
  MANAGES: 'Manages',
  HAS_PERMISSION: 'HasPermission',
  ASSIGNED_TO: 'AssignedTo',
  APPLIES_TO: 'AppliesTo',
  ENROLLED_IN: 'EnrolledIn',
  ADMIN_OF: 'AdminOf',
  CAN_RESET_PASSWORD: 'CanResetPassword',
  CAN_ADD_MEMBER: 'CanAddMember',
  CONTAINS: 'Contains',
  DELEGATES_TO: 'DelegatesTo',
  HAS_SESSION: 'HasSession',
  CAN_RDP: 'CanRDP',
  CAN_PSREMOTE: 'CanPSRemote',
  WRITE_DACL: 'WriteDACL',
  WRITE_OWNER: 'WriteOwner',
  GENERIC_ALL: 'GenericAll',
  GENERIC_WRITE: 'GenericWrite',
  FORCE_CHANGE_PASSWORD: 'ForceChangePassword',
  ADD_SELF: 'AddSelf',
  SYNC_TO: 'SyncTo',
  TARGETS: 'Targets',
});

const RISK_LEVELS = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

// ---------------------------------------------------------------------------
// GraphBuilder
// ---------------------------------------------------------------------------

class GraphBuilder extends EventEmitter {
  constructor(logger) {
    super();
    this.logger = logger;

    // Core graph storage
    this.nodes = new Map();          // id -> node
    this.edges = new Map();          // id -> edge
    this.adjacency = new Map();      // nodeId -> Set<edgeId>   (outgoing)
    this.reverseAdjacency = new Map(); // nodeId -> Set<edgeId> (incoming)

    // Indexes for fast lookup
    this.nodesByType = new Map();    // type -> Set<nodeId>
    this.edgesByType = new Map();    // type -> Set<edgeId>
    this.nodesByName = new Map();    // lowercase name -> nodeId

    this.metadata = {
      createdAt: null,
      lastRefresh: null,
      buildDurationMs: 0,
      version: 0,
    };
  }

  // -----------------------------------------------------------------------
  // Node operations
  // -----------------------------------------------------------------------

  addNode(node) {
    const id = node.id || uuidv4();
    const record = {
      id,
      type: node.type,
      name: node.name,
      displayName: node.displayName || node.name,
      properties: node.properties || {},
      riskLevel: node.riskLevel || RISK_LEVELS.INFO,
      createdAt: node.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.nodes.set(id, record);

    // Type index
    if (!this.nodesByType.has(record.type)) {
      this.nodesByType.set(record.type, new Set());
    }
    this.nodesByType.get(record.type).add(id);

    // Name index
    if (record.name) {
      this.nodesByName.set(record.name.toLowerCase(), id);
    }

    // Adjacency placeholders
    if (!this.adjacency.has(id)) this.adjacency.set(id, new Set());
    if (!this.reverseAdjacency.has(id)) this.reverseAdjacency.set(id, new Set());

    this.emit('node:added', record);
    return record;
  }

  removeNode(id) {
    if (!this.nodes.has(id)) return false;
    const node = this.nodes.get(id);

    // Remove all connected edges
    const outgoing = this.adjacency.get(id) || new Set();
    const incoming = this.reverseAdjacency.get(id) || new Set();
    for (const edgeId of [...outgoing, ...incoming]) {
      this.removeEdge(edgeId);
    }

    // Remove from indexes
    if (this.nodesByType.has(node.type)) {
      this.nodesByType.get(node.type).delete(id);
    }
    if (node.name) {
      this.nodesByName.delete(node.name.toLowerCase());
    }
    this.adjacency.delete(id);
    this.reverseAdjacency.delete(id);
    this.nodes.delete(id);

    this.emit('node:removed', { id });
    return true;
  }

  getNode(id) {
    return this.nodes.get(id) || null;
  }

  getNodeByName(name) {
    const id = this.nodesByName.get(name.toLowerCase());
    return id ? this.nodes.get(id) : null;
  }

  getNodesByType(type) {
    const ids = this.nodesByType.get(type);
    if (!ids) return [];
    return [...ids].map((id) => this.nodes.get(id));
  }

  // -----------------------------------------------------------------------
  // Edge operations
  // -----------------------------------------------------------------------

  addEdge(edge) {
    if (!this.nodes.has(edge.source) || !this.nodes.has(edge.target)) {
      this.logger.warn('Cannot add edge – missing source or target node', {
        source: edge.source,
        target: edge.target,
      });
      return null;
    }

    const id = edge.id || uuidv4();
    const record = {
      id,
      source: edge.source,
      target: edge.target,
      type: edge.type,
      properties: edge.properties || {},
      weight: edge.weight != null ? edge.weight : 1,
      riskLevel: edge.riskLevel || RISK_LEVELS.INFO,
      createdAt: new Date().toISOString(),
    };

    this.edges.set(id, record);

    // Adjacency
    if (!this.adjacency.has(edge.source)) this.adjacency.set(edge.source, new Set());
    this.adjacency.get(edge.source).add(id);
    if (!this.reverseAdjacency.has(edge.target)) this.reverseAdjacency.set(edge.target, new Set());
    this.reverseAdjacency.get(edge.target).add(id);

    // Type index
    if (!this.edgesByType.has(record.type)) {
      this.edgesByType.set(record.type, new Set());
    }
    this.edgesByType.get(record.type).add(id);

    this.emit('edge:added', record);
    return record;
  }

  removeEdge(id) {
    const edge = this.edges.get(id);
    if (!edge) return false;

    if (this.adjacency.has(edge.source)) this.adjacency.get(edge.source).delete(id);
    if (this.reverseAdjacency.has(edge.target)) this.reverseAdjacency.get(edge.target).delete(id);
    if (this.edgesByType.has(edge.type)) this.edgesByType.get(edge.type).delete(id);
    this.edges.delete(id);

    this.emit('edge:removed', { id });
    return true;
  }

  getEdge(id) {
    return this.edges.get(id) || null;
  }

  getOutgoingEdges(nodeId) {
    const ids = this.adjacency.get(nodeId);
    if (!ids) return [];
    return [...ids].map((eid) => this.edges.get(eid));
  }

  getIncomingEdges(nodeId) {
    const ids = this.reverseAdjacency.get(nodeId);
    if (!ids) return [];
    return [...ids].map((eid) => this.edges.get(eid));
  }

  getNeighbors(nodeId, direction = 'both') {
    const neighbors = new Set();
    if (direction === 'out' || direction === 'both') {
      for (const edge of this.getOutgoingEdges(nodeId)) {
        neighbors.add(edge.target);
      }
    }
    if (direction === 'in' || direction === 'both') {
      for (const edge of this.getIncomingEdges(nodeId)) {
        neighbors.add(edge.source);
      }
    }
    return [...neighbors].map((id) => this.nodes.get(id));
  }

  // -----------------------------------------------------------------------
  // Traversal & Pathfinding
  // -----------------------------------------------------------------------

  /**
   * BFS shortest path (unweighted) between two nodes.
   * Returns { nodes: [...], edges: [...], length } or null.
   */
  shortestPath(fromId, toId, options = {}) {
    if (!this.nodes.has(fromId) || !this.nodes.has(toId)) return null;
    if (fromId === toId) {
      return { nodes: [this.nodes.get(fromId)], edges: [], length: 0 };
    }

    const edgeFilter = options.edgeTypes
      ? (e) => options.edgeTypes.includes(e.type)
      : () => true;

    const visited = new Set();
    const prev = new Map(); // nodeId -> { node, edge }
    const queue = [fromId];
    visited.add(fromId);

    while (queue.length > 0) {
      const current = queue.shift();
      const outEdges = this.getOutgoingEdges(current).filter(edgeFilter);
      const inEdges = options.directed === false
        ? this.getIncomingEdges(current).filter(edgeFilter)
        : [];

      const allEdges = [...outEdges, ...inEdges];

      for (const edge of allEdges) {
        const neighbor = edge.source === current ? edge.target : edge.source;
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);
        prev.set(neighbor, { from: current, edge });

        if (neighbor === toId) {
          return this._reconstructPath(fromId, toId, prev);
        }
        queue.push(neighbor);
      }
    }

    return null;
  }

  /**
   * Dijkstra weighted shortest path.
   */
  weightedShortestPath(fromId, toId, options = {}) {
    if (!this.nodes.has(fromId) || !this.nodes.has(toId)) return null;
    if (fromId === toId) {
      return { nodes: [this.nodes.get(fromId)], edges: [], length: 0, totalWeight: 0 };
    }

    const edgeFilter = options.edgeTypes
      ? (e) => options.edgeTypes.includes(e.type)
      : () => true;

    const dist = new Map();
    const prev = new Map();
    const visited = new Set();

    for (const nodeId of this.nodes.keys()) {
      dist.set(nodeId, Infinity);
    }
    dist.set(fromId, 0);

    while (true) {
      let current = null;
      let currentDist = Infinity;
      for (const [nodeId, d] of dist) {
        if (!visited.has(nodeId) && d < currentDist) {
          current = nodeId;
          currentDist = d;
        }
      }
      if (current === null || current === toId) break;
      visited.add(current);

      for (const edge of this.getOutgoingEdges(current).filter(edgeFilter)) {
        const alt = currentDist + edge.weight;
        if (alt < dist.get(edge.target)) {
          dist.set(edge.target, alt);
          prev.set(edge.target, { from: current, edge });
        }
      }
    }

    if (!prev.has(toId) && fromId !== toId) return null;
    const path = this._reconstructPath(fromId, toId, prev);
    path.totalWeight = dist.get(toId);
    return path;
  }

  _reconstructPath(fromId, toId, prev) {
    const nodes = [];
    const edges = [];
    let current = toId;

    while (current !== fromId) {
      nodes.unshift(this.nodes.get(current));
      const step = prev.get(current);
      edges.unshift(step.edge);
      current = step.from;
    }
    nodes.unshift(this.nodes.get(fromId));

    return { nodes, edges, length: edges.length };
  }

  /**
   * Multi-hop BFS that returns all nodes within `depth` hops from startId.
   */
  subgraph(startId, depth = 2, options = {}) {
    if (!this.nodes.has(startId)) return { nodes: [], edges: [] };

    const visitedNodes = new Set([startId]);
    const collectedEdges = new Set();
    let frontier = [startId];

    for (let d = 0; d < depth && frontier.length > 0; d++) {
      const nextFrontier = [];
      for (const nodeId of frontier) {
        const outEdges = this.getOutgoingEdges(nodeId);
        const inEdges = this.getIncomingEdges(nodeId);
        for (const edge of [...outEdges, ...inEdges]) {
          if (options.edgeTypes && !options.edgeTypes.includes(edge.type)) continue;
          collectedEdges.add(edge.id);
          const neighbor = edge.source === nodeId ? edge.target : edge.source;
          if (!visitedNodes.has(neighbor)) {
            if (options.nodeTypes && !options.nodeTypes.includes(this.nodes.get(neighbor).type)) continue;
            visitedNodes.add(neighbor);
            nextFrontier.push(neighbor);
          }
        }
      }
      frontier = nextFrontier;
    }

    return {
      nodes: [...visitedNodes].map((id) => this.nodes.get(id)),
      edges: [...collectedEdges].map((id) => this.edges.get(id)),
    };
  }

  // -----------------------------------------------------------------------
  // Filtering
  // -----------------------------------------------------------------------

  filterNodes({ type, riskLevel, search } = {}) {
    let results = [...this.nodes.values()];
    if (type) results = results.filter((n) => n.type === type);
    if (riskLevel) results = results.filter((n) => n.riskLevel === riskLevel);
    if (search) {
      const q = search.toLowerCase();
      results = results.filter(
        (n) =>
          (n.name && n.name.toLowerCase().includes(q)) ||
          (n.displayName && n.displayName.toLowerCase().includes(q))
      );
    }
    return results;
  }

  // -----------------------------------------------------------------------
  // Statistics
  // -----------------------------------------------------------------------

  getStatistics() {
    const nodeCount = this.nodes.size;
    const edgeCount = this.edges.size;
    const maxPossibleEdges = nodeCount * (nodeCount - 1);
    const density = maxPossibleEdges > 0 ? edgeCount / maxPossibleEdges : 0;

    const nodeCountsByType = {};
    for (const [type, ids] of this.nodesByType) {
      nodeCountsByType[type] = ids.size;
    }

    const edgeCountsByType = {};
    for (const [type, ids] of this.edgesByType) {
      edgeCountsByType[type] = ids.size;
    }

    // Degree statistics
    let maxOutDegree = 0;
    let maxInDegree = 0;
    let totalOutDegree = 0;
    let mostConnectedNode = null;

    for (const [nodeId, edgeIds] of this.adjacency) {
      const outDeg = edgeIds.size;
      const inDeg = (this.reverseAdjacency.get(nodeId) || new Set()).size;
      const total = outDeg + inDeg;
      totalOutDegree += outDeg;
      if (outDeg > maxOutDegree) maxOutDegree = outDeg;
      if (inDeg > maxInDegree) maxInDegree = inDeg;
      if (!mostConnectedNode || total > (mostConnectedNode.degree || 0)) {
        mostConnectedNode = { id: nodeId, name: this.nodes.get(nodeId)?.name, degree: total };
      }
    }

    const riskDistribution = {};
    for (const node of this.nodes.values()) {
      riskDistribution[node.riskLevel] = (riskDistribution[node.riskLevel] || 0) + 1;
    }

    return {
      nodeCount,
      edgeCount,
      density: parseFloat(density.toFixed(6)),
      nodeCountsByType,
      edgeCountsByType,
      maxOutDegree,
      maxInDegree,
      averageDegree: nodeCount > 0 ? parseFloat((totalOutDegree / nodeCount).toFixed(2)) : 0,
      mostConnectedNode,
      riskDistribution,
      metadata: this.metadata,
    };
  }

  // -----------------------------------------------------------------------
  // Full graph export (for visualization payloads)
  // -----------------------------------------------------------------------

  toJSON({ nodeTypes, riskLevel } = {}) {
    let nodes = [...this.nodes.values()];
    if (nodeTypes) nodes = nodes.filter((n) => nodeTypes.includes(n.type));
    if (riskLevel) nodes = nodes.filter((n) => n.riskLevel === riskLevel);

    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges = [...this.edges.values()].filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    return { nodes, edges, statistics: this.getStatistics() };
  }

  // -----------------------------------------------------------------------
  // Cypher-like query engine (simplified)
  // -----------------------------------------------------------------------

  executeQuery(query) {
    const q = query.trim();

    // MATCH (n:Type) RETURN n
    const matchNodeRe = /^MATCH\s+\((\w+):(\w+)\)\s+RETURN\s+\1$/i;
    let m = q.match(matchNodeRe);
    if (m) {
      return { results: this.getNodesByType(m[2]) };
    }

    // MATCH (n:Type)-[:EdgeType]->(m:Type) RETURN n,m
    const matchEdgeRe =
      /^MATCH\s+\((\w+):(\w+)\)\s*-\[:(\w+)\]\s*->\s*\((\w+):(\w+)\)\s+RETURN\s+\1\s*,\s*\4$/i;
    m = q.match(matchEdgeRe);
    if (m) {
      const [, , srcType, edgeType, , tgtType] = m;
      const results = [];
      const edgeIds = this.edgesByType.get(edgeType);
      if (edgeIds) {
        for (const eid of edgeIds) {
          const edge = this.edges.get(eid);
          const src = this.nodes.get(edge.source);
          const tgt = this.nodes.get(edge.target);
          if (src && tgt && src.type === srcType && tgt.type === tgtType) {
            results.push({ source: src, edge, target: tgt });
          }
        }
      }
      return { results };
    }

    // MATCH (n {name: "..."}) RETURN n
    const matchNameRe = /^MATCH\s+\(\w+\s*\{name:\s*"([^"]+)"\}\)\s+RETURN\s+\w+$/i;
    m = q.match(matchNameRe);
    if (m) {
      const node = this.getNodeByName(m[1]);
      return { results: node ? [node] : [] };
    }

    // MATCH path = shortestPath((a {name:"..."})-[*]->(b {name:"..."}))
    const shortPathRe =
      /shortestPath\(\(\w+\s*\{name:\s*"([^"]+)"\}\)\s*-\[\*\]\s*->\s*\(\w+\s*\{name:\s*"([^"]+)"\}\)\)/i;
    m = q.match(shortPathRe);
    if (m) {
      const fromNode = this.getNodeByName(m[1]);
      const toNode = this.getNodeByName(m[2]);
      if (!fromNode || !toNode) return { results: [], error: 'Node not found' };
      const path = this.shortestPath(fromNode.id, toNode.id);
      return { results: path ? [path] : [] };
    }

    // MATCH (n) WHERE n.riskLevel = "..." RETURN n
    const whereRiskRe = /WHERE\s+\w+\.riskLevel\s*=\s*"(\w+)"/i;
    m = q.match(whereRiskRe);
    if (m) {
      return { results: this.filterNodes({ riskLevel: m[1] }) };
    }

    return { results: [], error: 'Unsupported query syntax' };
  }

  // -----------------------------------------------------------------------
  // Seed the graph with realistic AD/Intune data
  // -----------------------------------------------------------------------

  seedDemoData() {
    const t0 = Date.now();
    this.logger.info('Seeding demo AD/Intune graph data...');

    // -- Organizational Units -----------------------------------------------
    const ouRoot = this.addNode({ id: 'ou-root', type: NODE_TYPES.OU, name: 'corp.contoso.com', displayName: 'Contoso Corp Root', properties: { dn: 'DC=corp,DC=contoso,DC=com', level: 0 } });
    const ouIT = this.addNode({ id: 'ou-it', type: NODE_TYPES.OU, name: 'IT Department', properties: { dn: 'OU=IT,DC=corp,DC=contoso,DC=com', level: 1 } });
    const ouHR = this.addNode({ id: 'ou-hr', type: NODE_TYPES.OU, name: 'Human Resources', properties: { dn: 'OU=HR,DC=corp,DC=contoso,DC=com', level: 1 } });
    const ouFinance = this.addNode({ id: 'ou-finance', type: NODE_TYPES.OU, name: 'Finance', properties: { dn: 'OU=Finance,DC=corp,DC=contoso,DC=com', level: 1 } });
    const ouExec = this.addNode({ id: 'ou-exec', type: NODE_TYPES.OU, name: 'Executives', properties: { dn: 'OU=Exec,DC=corp,DC=contoso,DC=com', level: 1 } });

    this.addEdge({ source: ouRoot.id, target: ouIT.id, type: EDGE_TYPES.CONTAINS });
    this.addEdge({ source: ouRoot.id, target: ouHR.id, type: EDGE_TYPES.CONTAINS });
    this.addEdge({ source: ouRoot.id, target: ouFinance.id, type: EDGE_TYPES.CONTAINS });
    this.addEdge({ source: ouRoot.id, target: ouExec.id, type: EDGE_TYPES.CONTAINS });

    // -- Groups -------------------------------------------------------------
    const groups = [
      { id: 'grp-domain-admins', name: 'Domain Admins', riskLevel: RISK_LEVELS.CRITICAL, properties: { sid: 'S-1-5-21-...-512', scope: 'Global', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-enterprise-admins', name: 'Enterprise Admins', riskLevel: RISK_LEVELS.CRITICAL, properties: { sid: 'S-1-5-21-...-519', scope: 'Universal', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-schema-admins', name: 'Schema Admins', riskLevel: RISK_LEVELS.CRITICAL, properties: { sid: 'S-1-5-21-...-518', scope: 'Universal', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-account-operators', name: 'Account Operators', riskLevel: RISK_LEVELS.HIGH, properties: { sid: 'S-1-5-32-548', scope: 'DomainLocal', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-server-operators', name: 'Server Operators', riskLevel: RISK_LEVELS.HIGH, properties: { sid: 'S-1-5-32-549', scope: 'DomainLocal', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-backup-operators', name: 'Backup Operators', riskLevel: RISK_LEVELS.HIGH, properties: { sid: 'S-1-5-32-551', scope: 'DomainLocal', category: 'Security', isPrivileged: true, builtIn: true } },
      { id: 'grp-it-helpdesk', name: 'IT Helpdesk', riskLevel: RISK_LEVELS.MEDIUM, properties: { scope: 'Global', category: 'Security', isPrivileged: false, department: 'IT' } },
      { id: 'grp-it-infra', name: 'IT Infrastructure', riskLevel: RISK_LEVELS.HIGH, properties: { scope: 'Global', category: 'Security', isPrivileged: false, department: 'IT' } },
      { id: 'grp-hr-staff', name: 'HR Staff', riskLevel: RISK_LEVELS.LOW, properties: { scope: 'Global', category: 'Security', isPrivileged: false, department: 'HR' } },
      { id: 'grp-finance-staff', name: 'Finance Staff', riskLevel: RISK_LEVELS.LOW, properties: { scope: 'Global', category: 'Security', isPrivileged: false, department: 'Finance' } },
      { id: 'grp-all-employees', name: 'All Employees', riskLevel: RISK_LEVELS.INFO, properties: { scope: 'Global', category: 'Distribution', isPrivileged: false } },
      { id: 'grp-intune-admins', name: 'Intune Administrators', riskLevel: RISK_LEVELS.HIGH, properties: { scope: 'Global', category: 'Security', isPrivileged: true, cloudGroup: true } },
      { id: 'grp-device-compliance', name: 'Device Compliance Reviewers', riskLevel: RISK_LEVELS.MEDIUM, properties: { scope: 'Global', category: 'Security', isPrivileged: false, cloudGroup: true } },
      { id: 'grp-exec-team', name: 'Executive Team', riskLevel: RISK_LEVELS.HIGH, properties: { scope: 'Global', category: 'Security', isPrivileged: false, department: 'Executive' } },
      { id: 'grp-gpo-admins', name: 'GPO Administrators', riskLevel: RISK_LEVELS.HIGH, properties: { scope: 'Global', category: 'Security', isPrivileged: true } },
    ];
    const groupNodes = {};
    for (const g of groups) {
      groupNodes[g.id] = this.addNode({ ...g, type: NODE_TYPES.GROUP });
    }

    // Group nesting — creates potential privilege escalation chains
    this.addEdge({ source: groupNodes['grp-enterprise-admins'].id, target: groupNodes['grp-domain-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: groupNodes['grp-it-infra'].id, target: groupNodes['grp-server-operators'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: groupNodes['grp-it-infra'].id, target: groupNodes['grp-backup-operators'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: groupNodes['grp-intune-admins'].id, target: groupNodes['grp-it-infra'].id, type: EDGE_TYPES.MEMBER_OF });

    // -- Users --------------------------------------------------------------
    const users = [
      { id: 'usr-admin', name: 'admin', displayName: 'Domain Administrator', riskLevel: RISK_LEVELS.CRITICAL, properties: { upn: 'admin@corp.contoso.com', title: 'Domain Admin', department: 'IT', enabled: true, adminCount: 1, lastLogon: '2026-03-14T08:30:00Z', passwordLastSet: '2026-01-15T10:00:00Z', servicePrincipalNames: [] } },
      { id: 'usr-jsmith', name: 'jsmith', displayName: 'John Smith', riskLevel: RISK_LEVELS.HIGH, properties: { upn: 'jsmith@corp.contoso.com', title: 'Sr. Systems Engineer', department: 'IT', enabled: true, adminCount: 0, lastLogon: '2026-03-14T09:00:00Z', passwordLastSet: '2025-12-01T14:00:00Z' } },
      { id: 'usr-jdoe', name: 'jdoe', displayName: 'Jane Doe', riskLevel: RISK_LEVELS.LOW, properties: { upn: 'jdoe@corp.contoso.com', title: 'HR Manager', department: 'HR', enabled: true, adminCount: 0, lastLogon: '2026-03-14T08:45:00Z', passwordLastSet: '2026-02-20T16:00:00Z' } },
      { id: 'usr-bwilson', name: 'bwilson', displayName: 'Bob Wilson', riskLevel: RISK_LEVELS.LOW, properties: { upn: 'bwilson@corp.contoso.com', title: 'Financial Analyst', department: 'Finance', enabled: true, adminCount: 0, lastLogon: '2026-03-13T17:00:00Z', passwordLastSet: '2026-01-05T09:00:00Z' } },
      { id: 'usr-cjones', name: 'cjones', displayName: 'Carol Jones', riskLevel: RISK_LEVELS.MEDIUM, properties: { upn: 'cjones@corp.contoso.com', title: 'IT Support Specialist', department: 'IT', enabled: true, adminCount: 0, lastLogon: '2026-03-14T07:30:00Z', passwordLastSet: '2026-03-01T11:00:00Z' } },
      { id: 'usr-dlee', name: 'dlee', displayName: 'David Lee', riskLevel: RISK_LEVELS.MEDIUM, properties: { upn: 'dlee@corp.contoso.com', title: 'Cloud Infrastructure Lead', department: 'IT', enabled: true, adminCount: 0, lastLogon: '2026-03-14T10:15:00Z', passwordLastSet: '2025-11-10T13:00:00Z' } },
      { id: 'usr-egarcia', name: 'egarcia', displayName: 'Elena Garcia', riskLevel: RISK_LEVELS.HIGH, properties: { upn: 'egarcia@corp.contoso.com', title: 'CEO', department: 'Executive', enabled: true, adminCount: 0, lastLogon: '2026-03-14T11:00:00Z', passwordLastSet: '2025-09-20T10:00:00Z' } },
      { id: 'usr-fchen', name: 'fchen', displayName: 'Frank Chen', riskLevel: RISK_LEVELS.LOW, properties: { upn: 'fchen@corp.contoso.com', title: 'Software Developer', department: 'Engineering', enabled: true, adminCount: 0, lastLogon: '2026-03-14T09:30:00Z', passwordLastSet: '2026-02-14T08:00:00Z' } },
      { id: 'usr-svcaccount', name: 'svc-backup', displayName: 'Backup Service Account', riskLevel: RISK_LEVELS.HIGH, properties: { upn: 'svc-backup@corp.contoso.com', title: 'Service Account', department: 'IT', enabled: true, adminCount: 0, isServiceAccount: true, lastLogon: '2026-03-14T03:00:00Z', passwordLastSet: '2024-06-15T00:00:00Z', passwordNeverExpires: true } },
      { id: 'usr-svcintune', name: 'svc-intune-sync', displayName: 'Intune Sync Service', riskLevel: RISK_LEVELS.HIGH, properties: { upn: 'svc-intune-sync@corp.contoso.com', title: 'Service Account', department: 'IT', enabled: true, adminCount: 0, isServiceAccount: true, lastLogon: '2026-03-14T06:00:00Z', passwordLastSet: '2025-01-20T00:00:00Z', passwordNeverExpires: true } },
    ];
    const userNodes = {};
    for (const u of users) {
      userNodes[u.id] = this.addNode({ ...u, type: NODE_TYPES.USER });
    }

    // User -> Group memberships
    this.addEdge({ source: userNodes['usr-admin'].id, target: groupNodes['grp-domain-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-admin'].id, target: groupNodes['grp-enterprise-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: groupNodes['grp-it-infra'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: groupNodes['grp-intune-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-jdoe'].id, target: groupNodes['grp-hr-staff'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-bwilson'].id, target: groupNodes['grp-finance-staff'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-cjones'].id, target: groupNodes['grp-it-helpdesk'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: groupNodes['grp-it-infra'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: groupNodes['grp-intune-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: groupNodes['grp-gpo-admins'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-egarcia'].id, target: groupNodes['grp-exec-team'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-fchen'].id, target: groupNodes['grp-all-employees'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-svcaccount'].id, target: groupNodes['grp-backup-operators'].id, type: EDGE_TYPES.MEMBER_OF });
    this.addEdge({ source: userNodes['usr-svcintune'].id, target: groupNodes['grp-intune-admins'].id, type: EDGE_TYPES.MEMBER_OF });

    // Dangerous delegation edges that create shadow-admin paths
    this.addEdge({ source: groupNodes['grp-it-helpdesk'].id, target: userNodes['usr-jdoe'].id, type: EDGE_TYPES.CAN_RESET_PASSWORD, riskLevel: RISK_LEVELS.MEDIUM });
    this.addEdge({ source: groupNodes['grp-it-helpdesk'].id, target: userNodes['usr-bwilson'].id, type: EDGE_TYPES.CAN_RESET_PASSWORD, riskLevel: RISK_LEVELS.MEDIUM });
    this.addEdge({ source: groupNodes['grp-account-operators'].id, target: groupNodes['grp-hr-staff'].id, type: EDGE_TYPES.CAN_ADD_MEMBER, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: groupNodes['grp-gpo-admins'].id, target: ouRoot.id, type: EDGE_TYPES.WRITE_DACL, riskLevel: RISK_LEVELS.CRITICAL });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: groupNodes['grp-domain-admins'].id, type: EDGE_TYPES.GENERIC_WRITE, riskLevel: RISK_LEVELS.CRITICAL });
    this.addEdge({ source: userNodes['usr-svcaccount'].id, target: groupNodes['grp-domain-admins'].id, type: EDGE_TYPES.WRITE_OWNER, riskLevel: RISK_LEVELS.CRITICAL });

    // -- Devices ------------------------------------------------------------
    const devices = [
      { id: 'dev-dc01', name: 'DC01', displayName: 'Domain Controller 01', riskLevel: RISK_LEVELS.CRITICAL, properties: { os: 'Windows Server 2022', ip: '10.0.1.10', role: 'DomainController', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'Hybrid Azure AD Join' } },
      { id: 'dev-dc02', name: 'DC02', displayName: 'Domain Controller 02', riskLevel: RISK_LEVELS.CRITICAL, properties: { os: 'Windows Server 2022', ip: '10.0.1.11', role: 'DomainController', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'Hybrid Azure AD Join' } },
      { id: 'dev-exch01', name: 'EXCH01', displayName: 'Exchange Server', riskLevel: RISK_LEVELS.HIGH, properties: { os: 'Windows Server 2019', ip: '10.0.2.20', role: 'ExchangeServer', managed: true, compliant: false, lastSeen: '2026-03-14T11:55:00Z', enrollmentType: 'On-Premise' } },
      { id: 'dev-ws001', name: 'WS-JSMITH-001', displayName: "John Smith's Workstation", riskLevel: RISK_LEVELS.MEDIUM, properties: { os: 'Windows 11 Enterprise 23H2', ip: '10.0.10.101', role: 'Workstation', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'Intune', mdmAuthority: 'Intune', serialNumber: 'SN-W11-0041' } },
      { id: 'dev-ws002', name: 'WS-CJONES-002', displayName: "Carol Jones's Workstation", riskLevel: RISK_LEVELS.LOW, properties: { os: 'Windows 11 Enterprise 23H2', ip: '10.0.10.102', role: 'Workstation', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'Intune', mdmAuthority: 'Intune', serialNumber: 'SN-W11-0042' } },
      { id: 'dev-ws003', name: 'WS-DLEE-003', displayName: "David Lee's Workstation", riskLevel: RISK_LEVELS.MEDIUM, properties: { os: 'Windows 11 Enterprise 23H2', ip: '10.0.10.103', role: 'Workstation', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'Intune', mdmAuthority: 'Intune', serialNumber: 'SN-W11-0043' } },
      { id: 'dev-mob-egarcia', name: 'IPHONE-EGARCIA', displayName: "Elena Garcia's iPhone", riskLevel: RISK_LEVELS.MEDIUM, properties: { os: 'iOS 17.3', role: 'MobileDevice', managed: true, compliant: true, lastSeen: '2026-03-14T11:50:00Z', enrollmentType: 'Intune', mdmAuthority: 'Intune', serialNumber: 'SN-IOS-0091' } },
      { id: 'dev-srv-file01', name: 'FILE01', displayName: 'File Server 01', riskLevel: RISK_LEVELS.HIGH, properties: { os: 'Windows Server 2019', ip: '10.0.3.30', role: 'FileServer', managed: true, compliant: true, lastSeen: '2026-03-14T12:00:00Z', enrollmentType: 'On-Premise' } },
    ];
    const deviceNodes = {};
    for (const d of devices) {
      deviceNodes[d.id] = this.addNode({ ...d, type: NODE_TYPES.DEVICE });
    }

    // User -> Device relationships
    this.addEdge({ source: userNodes['usr-admin'].id, target: deviceNodes['dev-dc01'].id, type: EDGE_TYPES.ADMIN_OF, riskLevel: RISK_LEVELS.CRITICAL });
    this.addEdge({ source: userNodes['usr-admin'].id, target: deviceNodes['dev-dc02'].id, type: EDGE_TYPES.ADMIN_OF, riskLevel: RISK_LEVELS.CRITICAL });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: deviceNodes['dev-ws001'].id, type: EDGE_TYPES.OWNS });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: deviceNodes['dev-dc01'].id, type: EDGE_TYPES.HAS_SESSION, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: deviceNodes['dev-exch01'].id, type: EDGE_TYPES.ADMIN_OF, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: userNodes['usr-cjones'].id, target: deviceNodes['dev-ws002'].id, type: EDGE_TYPES.OWNS });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: deviceNodes['dev-ws003'].id, type: EDGE_TYPES.OWNS });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: deviceNodes['dev-dc01'].id, type: EDGE_TYPES.CAN_RDP, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: deviceNodes['dev-dc02'].id, type: EDGE_TYPES.CAN_PSREMOTE, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: userNodes['usr-egarcia'].id, target: deviceNodes['dev-mob-egarcia'].id, type: EDGE_TYPES.OWNS });
    this.addEdge({ source: groupNodes['grp-server-operators'].id, target: deviceNodes['dev-srv-file01'].id, type: EDGE_TYPES.ADMIN_OF, riskLevel: RISK_LEVELS.HIGH });

    // -- Permissions (Roles / RBAC) -----------------------------------------
    const permissions = [
      { id: 'perm-global-admin', name: 'Global Administrator', riskLevel: RISK_LEVELS.CRITICAL, properties: { roleDefinitionId: 'role-ga-001', isBuiltIn: true, scope: 'Tenant', description: 'Full access to all management features in Azure AD' } },
      { id: 'perm-intune-admin', name: 'Intune Administrator', riskLevel: RISK_LEVELS.HIGH, properties: { roleDefinitionId: 'role-ia-001', isBuiltIn: true, scope: 'Tenant', description: 'Full access to Intune management' } },
      { id: 'perm-user-admin', name: 'User Administrator', riskLevel: RISK_LEVELS.HIGH, properties: { roleDefinitionId: 'role-ua-001', isBuiltIn: true, scope: 'Tenant', description: 'Manage user accounts and group memberships' } },
      { id: 'perm-helpdesk-admin', name: 'Helpdesk Administrator', riskLevel: RISK_LEVELS.MEDIUM, properties: { roleDefinitionId: 'role-ha-001', isBuiltIn: true, scope: 'Tenant', description: 'Reset passwords for non-admins' } },
      { id: 'perm-device-manager', name: 'Cloud Device Administrator', riskLevel: RISK_LEVELS.MEDIUM, properties: { roleDefinitionId: 'role-cda-001', isBuiltIn: true, scope: 'Tenant', description: 'Enable, disable, and delete devices in Azure AD' } },
      { id: 'perm-exchange-admin', name: 'Exchange Administrator', riskLevel: RISK_LEVELS.HIGH, properties: { roleDefinitionId: 'role-ea-001', isBuiltIn: true, scope: 'Tenant', description: 'Full access to Exchange Online' } },
    ];
    const permNodes = {};
    for (const p of permissions) {
      permNodes[p.id] = this.addNode({ ...p, type: NODE_TYPES.PERMISSION });
    }

    // Permission assignments
    this.addEdge({ source: userNodes['usr-admin'].id, target: permNodes['perm-global-admin'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.CRITICAL });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: permNodes['perm-intune-admin'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: userNodes['usr-jsmith'].id, target: permNodes['perm-exchange-admin'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: groupNodes['grp-intune-admins'].id, target: permNodes['perm-intune-admin'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: groupNodes['grp-it-helpdesk'].id, target: permNodes['perm-helpdesk-admin'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.MEDIUM });
    this.addEdge({ source: userNodes['usr-dlee'].id, target: permNodes['perm-device-manager'].id, type: EDGE_TYPES.HAS_PERMISSION, riskLevel: RISK_LEVELS.MEDIUM });

    // -- Policies (Intune Compliance & Configuration) -------------------------
    const policies = [
      { id: 'pol-win-compliance', name: 'Windows Compliance Policy', riskLevel: RISK_LEVELS.INFO, properties: { policyType: 'Compliance', platform: 'Windows', settings: { requireBitLocker: true, requireTPM: true, minOSVersion: '10.0.22621', requireAntiVirus: true, firewallRequired: true, passwordRequired: true, passwordMinLength: 12 } } },
      { id: 'pol-ios-compliance', name: 'iOS Compliance Policy', riskLevel: RISK_LEVELS.INFO, properties: { policyType: 'Compliance', platform: 'iOS', settings: { requireManagedEmail: true, jailbreakDetection: true, minOSVersion: '16.0', passcodeRequired: true, passcodeMinLength: 6 } } },
      { id: 'pol-bitlocker', name: 'BitLocker Encryption Policy', riskLevel: RISK_LEVELS.INFO, properties: { policyType: 'Configuration', platform: 'Windows', settings: { encryptionMethod: 'XtsAes256', requireEncryption: true, recoveryKeyEscrow: true } } },
      { id: 'pol-conditional-access', name: 'Require MFA for Admins', riskLevel: RISK_LEVELS.HIGH, properties: { policyType: 'ConditionalAccess', platform: 'All', settings: { requireMFA: true, targetGroups: ['Domain Admins', 'Enterprise Admins', 'Intune Administrators'], blockLegacyAuth: true, sessionTimeout: 3600 } } },
      { id: 'pol-device-restriction', name: 'Device Restriction Policy', riskLevel: RISK_LEVELS.INFO, properties: { policyType: 'Configuration', platform: 'Windows', settings: { blockUSBStorage: true, requireScreenLock: true, screenLockTimeout: 300, blockCamera: false } } },
      { id: 'pol-app-protection', name: 'MAM App Protection Policy', riskLevel: RISK_LEVELS.INFO, properties: { policyType: 'AppProtection', platform: 'All', settings: { requirePIN: true, encryptAppData: true, preventBackup: true, blockScreenCapture: true, allowedApps: ['Outlook', 'Teams', 'OneDrive'] } } },
    ];
    const policyNodes = {};
    for (const p of policies) {
      policyNodes[p.id] = this.addNode({ ...p, type: NODE_TYPES.POLICY });
    }

    // Policy -> Device/Group assignments
    this.addEdge({ source: policyNodes['pol-win-compliance'].id, target: groupNodes['grp-all-employees'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-ios-compliance'].id, target: deviceNodes['dev-mob-egarcia'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-bitlocker'].id, target: deviceNodes['dev-ws001'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-bitlocker'].id, target: deviceNodes['dev-ws002'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-bitlocker'].id, target: deviceNodes['dev-ws003'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-conditional-access'].id, target: groupNodes['grp-domain-admins'].id, type: EDGE_TYPES.APPLIES_TO, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: policyNodes['pol-conditional-access'].id, target: groupNodes['grp-enterprise-admins'].id, type: EDGE_TYPES.APPLIES_TO, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: policyNodes['pol-conditional-access'].id, target: groupNodes['grp-intune-admins'].id, type: EDGE_TYPES.APPLIES_TO, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: policyNodes['pol-device-restriction'].id, target: groupNodes['grp-all-employees'].id, type: EDGE_TYPES.APPLIES_TO });
    this.addEdge({ source: policyNodes['pol-app-protection'].id, target: deviceNodes['dev-mob-egarcia'].id, type: EDGE_TYPES.APPLIES_TO });

    // -- Update Rings -------------------------------------------------------
    const updateRings = [
      { id: 'ring-preview', name: 'Preview Ring', riskLevel: RISK_LEVELS.LOW, properties: { deferralDays: 0, channel: 'Preview', autoRestart: true, maintenanceWindow: '02:00-06:00', deadline: 3, deploymentType: 'WindowsUpdate' } },
      { id: 'ring-pilot', name: 'Pilot Ring', riskLevel: RISK_LEVELS.LOW, properties: { deferralDays: 7, channel: 'General Availability', autoRestart: true, maintenanceWindow: '02:00-06:00', deadline: 7, deploymentType: 'WindowsUpdate' } },
      { id: 'ring-broad', name: 'Broad Ring', riskLevel: RISK_LEVELS.INFO, properties: { deferralDays: 14, channel: 'General Availability', autoRestart: true, maintenanceWindow: '02:00-06:00', deadline: 14, deploymentType: 'WindowsUpdate' } },
      { id: 'ring-critical', name: 'Critical Systems Ring', riskLevel: RISK_LEVELS.INFO, properties: { deferralDays: 30, channel: 'General Availability', autoRestart: false, maintenanceWindow: '03:00-05:00', deadline: 30, requireApproval: true, deploymentType: 'WindowsUpdate' } },
    ];
    const ringNodes = {};
    for (const r of updateRings) {
      ringNodes[r.id] = this.addNode({ ...r, type: NODE_TYPES.UPDATE_RING });
    }

    // Update Ring assignments
    this.addEdge({ source: ringNodes['ring-preview'].id, target: groupNodes['grp-it-infra'].id, type: EDGE_TYPES.TARGETS });
    this.addEdge({ source: ringNodes['ring-pilot'].id, target: groupNodes['grp-it-helpdesk'].id, type: EDGE_TYPES.TARGETS });
    this.addEdge({ source: ringNodes['ring-broad'].id, target: groupNodes['grp-all-employees'].id, type: EDGE_TYPES.TARGETS });
    this.addEdge({ source: ringNodes['ring-critical'].id, target: deviceNodes['dev-dc01'].id, type: EDGE_TYPES.TARGETS });
    this.addEdge({ source: ringNodes['ring-critical'].id, target: deviceNodes['dev-dc02'].id, type: EDGE_TYPES.TARGETS });
    this.addEdge({ source: ringNodes['ring-critical'].id, target: deviceNodes['dev-exch01'].id, type: EDGE_TYPES.TARGETS });

    // -- Service Principals / Applications -----------------------------------
    const spns = [
      { id: 'spn-graph-api', name: 'Microsoft Graph API', riskLevel: RISK_LEVELS.HIGH, properties: { appId: 'app-graph-001', permissions: ['Directory.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All'], consentType: 'Admin', isFirstParty: true } },
      { id: 'spn-backup-app', name: 'Contoso Backup Application', riskLevel: RISK_LEVELS.HIGH, properties: { appId: 'app-backup-001', permissions: ['Sites.ReadWrite.All', 'Files.ReadWrite.All'], consentType: 'Admin', isFirstParty: false } },
      { id: 'spn-hr-portal', name: 'HR Portal', riskLevel: RISK_LEVELS.MEDIUM, properties: { appId: 'app-hr-001', permissions: ['User.Read', 'GroupMember.Read.All'], consentType: 'User', isFirstParty: false } },
    ];
    const spnNodes = {};
    for (const s of spns) {
      spnNodes[s.id] = this.addNode({ ...s, type: NODE_TYPES.SERVICE_PRINCIPAL });
    }

    this.addEdge({ source: spnNodes['spn-backup-app'].id, target: userNodes['usr-svcaccount'].id, type: EDGE_TYPES.DELEGATES_TO, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: spnNodes['spn-hr-portal'].id, target: groupNodes['grp-hr-staff'].id, type: EDGE_TYPES.ASSIGNED_TO });
    this.addEdge({ source: userNodes['usr-svcintune'].id, target: spnNodes['spn-graph-api'].id, type: EDGE_TYPES.DELEGATES_TO, riskLevel: RISK_LEVELS.HIGH });

    // -- GPOs ---------------------------------------------------------------
    const gpos = [
      { id: 'gpo-default-domain', name: 'Default Domain Policy', riskLevel: RISK_LEVELS.HIGH, properties: { gpoId: 'gpo-001', enforced: true, linkOrder: 1, settings: { passwordPolicy: { minLength: 12, complexity: true, maxAge: 90, history: 24 }, accountLockout: { threshold: 5, duration: 30, resetCounter: 30 } } } },
      { id: 'gpo-audit-policy', name: 'Enterprise Audit Policy', riskLevel: RISK_LEVELS.MEDIUM, properties: { gpoId: 'gpo-002', enforced: true, linkOrder: 2, settings: { auditLogon: 'SuccessAndFailure', auditObjectAccess: 'SuccessAndFailure', auditPrivilegeUse: 'SuccessAndFailure' } } },
    ];
    const gpoNodes = {};
    for (const g of gpos) {
      gpoNodes[g.id] = this.addNode({ ...g, type: NODE_TYPES.GPO });
    }

    this.addEdge({ source: gpoNodes['gpo-default-domain'].id, target: ouRoot.id, type: EDGE_TYPES.APPLIES_TO, riskLevel: RISK_LEVELS.HIGH });
    this.addEdge({ source: gpoNodes['gpo-audit-policy'].id, target: ouRoot.id, type: EDGE_TYPES.APPLIES_TO });

    // -- Finalize -----------------------------------------------------------
    this.metadata.createdAt = new Date().toISOString();
    this.metadata.lastRefresh = new Date().toISOString();
    this.metadata.buildDurationMs = Date.now() - t0;
    this.metadata.version += 1;

    this.logger.info('Graph seeded', {
      nodes: this.nodes.size,
      edges: this.edges.size,
      durationMs: this.metadata.buildDurationMs,
    });
  }

  // -----------------------------------------------------------------------
  // Rebuild (clear + re-seed)
  // -----------------------------------------------------------------------

  rebuild() {
    this.nodes.clear();
    this.edges.clear();
    this.adjacency.clear();
    this.reverseAdjacency.clear();
    this.nodesByType.clear();
    this.edgesByType.clear();
    this.nodesByName.clear();
    this.seedDemoData();
    this.emit('graph:rebuilt', this.getStatistics());
  }
}

module.exports = GraphBuilder;
module.exports.NODE_TYPES = NODE_TYPES;
module.exports.EDGE_TYPES = EDGE_TYPES;
module.exports.RISK_LEVELS = RISK_LEVELS;

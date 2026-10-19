'use strict';

/**
 * LDAP Filter Parser — RFC 4515
 * Parses, validates, and sanitizes LDAP filter strings.
 */

// Characters that must be escaped in LDAP filter attribute values (RFC 4515)
const SPECIAL_CHARS = /([\\*()\x00])/g;

/**
 * Escape special characters in an LDAP filter value.
 * @param {string} value
 * @returns {string}
 */
function escapeValue(value) {
  return value.replace(SPECIAL_CHARS, (c) => {
    const hex = c.charCodeAt(0).toString(16).padStart(2, '0');
    return `\\${hex}`;
  });
}

/**
 * Tokeniser state used by the recursive descent parser.
 */
class Parser {
  constructor(input) {
    this.input = input;
    this.pos = 0;
  }

  peek() {
    return this.input[this.pos];
  }

  consume(expected) {
    if (expected !== undefined && this.input[this.pos] !== expected) {
      throw new Error(
        `Expected '${expected}' at position ${this.pos} but got '${this.input[this.pos] || 'EOF'}'`
      );
    }
    return this.input[this.pos++];
  }

  rest() {
    return this.input.slice(this.pos);
  }

  done() {
    return this.pos >= this.input.length;
  }
}

/**
 * Parse a complete RFC 4515 filter expression.
 * Returns an AST node.
 *
 * Grammar (simplified):
 *   filter       = '(' filtercomp ')'
 *   filtercomp   = and / or / not / item
 *   and          = '&' filterlist
 *   or           = '|' filterlist
 *   not          = '!' filter
 *   filterlist   = 1*filter
 *   item         = simple / present / substring / extensible
 *   simple       = attr filtertype value
 *   filtertype   = '=' / '~=' / '>=' / '<='
 *   present      = attr '=*'
 *   substring    = attr '=' [initial] '*' [any *'*'] [final]
 */
function parseFilter(filterStr) {
  if (typeof filterStr !== 'string' || filterStr.length === 0) {
    throw new Error('Filter must be a non-empty string');
  }

  const p = new Parser(filterStr.trim());
  const ast = parseFilterNode(p);

  if (!p.done()) {
    throw new Error(`Unexpected characters after filter at position ${p.pos}: '${p.rest()}'`);
  }

  return ast;
}

function parseFilterNode(p) {
  if (p.peek() !== '(') {
    throw new Error(`Expected '(' at position ${p.pos}, got '${p.peek() || 'EOF'}'`);
  }
  p.consume('(');

  let node;
  const ch = p.peek();

  if (ch === '&') {
    p.consume('&');
    node = { type: 'and', filters: parseFilterList(p) };
  } else if (ch === '|') {
    p.consume('|');
    node = { type: 'or', filters: parseFilterList(p) };
  } else if (ch === '!') {
    p.consume('!');
    const inner = parseFilterNode(p);
    node = { type: 'not', filter: inner };
  } else {
    node = parseItem(p);
  }

  if (p.peek() !== ')') {
    throw new Error(`Expected ')' at position ${p.pos}, got '${p.peek() || 'EOF'}'`);
  }
  p.consume(')');

  return node;
}

function parseFilterList(p) {
  const filters = [];
  while (p.peek() === '(') {
    filters.push(parseFilterNode(p));
  }
  if (filters.length === 0) {
    throw new Error(`Filter list must contain at least one filter at position ${p.pos}`);
  }
  return filters;
}

function parseItem(p) {
  // Read attribute description (attr)
  const attrStart = p.pos;
  while (
    !p.done() &&
    p.peek() !== '=' &&
    p.peek() !== '<' &&
    p.peek() !== '>' &&
    p.peek() !== '~' &&
    p.peek() !== ')'
  ) {
    p.pos++;
  }
  const attr = p.input.slice(attrStart, p.pos).trim();
  if (!attr) {
    throw new Error(`Empty attribute at position ${attrStart}`);
  }

  // Read filter type
  let filterType;
  if (p.peek() === '~' && p.input[p.pos + 1] === '=') {
    filterType = '~=';
    p.pos += 2;
  } else if (p.peek() === '>' && p.input[p.pos + 1] === '=') {
    filterType = '>=';
    p.pos += 2;
  } else if (p.peek() === '<' && p.input[p.pos + 1] === '=') {
    filterType = '<=';
    p.pos += 2;
  } else if (p.peek() === '=') {
    filterType = '=';
    p.pos++;
  } else {
    throw new Error(`Unknown filter type at position ${p.pos}: '${p.peek()}'`);
  }

  // Read value (everything until closing ')')
  const valueStart = p.pos;
  let depth = 0;
  while (!p.done()) {
    const c = p.peek();
    if (c === '(') depth++;
    if (c === ')' && depth === 0) break;
    if (c === ')') depth--;
    p.pos++;
  }
  const rawValue = p.input.slice(valueStart, p.pos);

  if (filterType === '=') {
    // Distinguish present, substring, equality
    if (rawValue === '*') {
      return { type: 'present', attribute: attr };
    }
    if (rawValue.includes('*')) {
      const parts = rawValue.split('*');
      return {
        type: 'substring',
        attribute: attr,
        initial: parts[0] || null,
        any: parts.slice(1, parts.length - 1).filter(Boolean),
        final: parts[parts.length - 1] || null,
      };
    }
    return { type: 'equal', attribute: attr, value: rawValue };
  }

  const typeMap = { '~=': 'approx', '>=': 'greaterOrEqual', '<=': 'lessOrEqual' };
  return { type: typeMap[filterType], attribute: attr, value: rawValue };
}

/**
 * Validate an LDAP filter string.
 * @param {string} filterStr
 * @returns {{ valid: boolean, error: string|null }}
 */
function validateFilter(filterStr) {
  try {
    parseFilter(filterStr);
    return { valid: true, error: null };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Sanitize an LDAP filter string by escaping special characters in leaf values.
 * Parses the AST and rebuilds the filter with escaped values.
 * @param {string} filterStr
 * @returns {string} sanitized filter string
 */
function sanitizeFilter(filterStr) {
  const ast = parseFilter(filterStr);
  return astToString(ast);
}

function astToString(node) {
  switch (node.type) {
    case 'and':
      return `(&${node.filters.map(astToString).join('')})`;
    case 'or':
      return `(|${node.filters.map(astToString).join('')})`;
    case 'not':
      return `(!${astToString(node.filter)})`;
    case 'present':
      return `(${node.attribute}=*)`;
    case 'equal':
      return `(${node.attribute}=${escapeValue(node.value)})`;
    case 'approx':
      return `(${node.attribute}~=${escapeValue(node.value)})`;
    case 'greaterOrEqual':
      return `(${node.attribute}>=${escapeValue(node.value)})`;
    case 'lessOrEqual':
      return `(${node.attribute}<=${escapeValue(node.value)})`;
    case 'substring': {
      const initial = node.initial ? escapeValue(node.initial) : '';
      const anyParts = node.any.map(escapeValue).join('*');
      const final = node.final ? escapeValue(node.final) : '';
      const middle = anyParts ? `*${anyParts}*` : '*';
      return `(${node.attribute}=${initial}${middle}${final})`;
    }
    default:
      throw new Error(`Unknown AST node type: ${node.type}`);
  }
}

module.exports = { parseFilter, validateFilter, sanitizeFilter, escapeValue };

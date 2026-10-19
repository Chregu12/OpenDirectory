'use strict';

/**
 * SchemaManager — LDAP Schema Management
 *
 * Reads schema from a live LDAP backend (cn=schema entry) and also provides
 * a built-in fallback of standard AD-compatible object classes and attribute
 * types so that code works without a live LDAP connection.
 */

// ---------------------------------------------------------------------------
// Built-in standard AD-like schema definitions (fallback / seed)
// ---------------------------------------------------------------------------

/** LDAP syntax OIDs (commonly used) */
const SYNTAX = {
  DN: '1.3.6.1.4.1.1466.115.121.1.12',
  DIRECTORY_STRING: '1.3.6.1.4.1.1466.115.121.1.15',
  INTEGER: '1.3.6.1.4.1.1466.115.121.1.27',
  BOOLEAN: '1.3.6.1.4.1.1466.115.121.1.7',
  OCTET_STRING: '1.3.6.1.4.1.1466.115.121.1.40',
  UTC_TIME: '1.3.6.1.4.1.1466.115.121.1.53',
  GENERALIZED_TIME: '1.3.6.1.4.1.1466.115.121.1.24',
  OID: '1.3.6.1.4.1.1466.115.121.1.38',
  IA5_STRING: '1.3.6.1.4.1.1466.115.121.1.26',
  NUMERIC_STRING: '1.3.6.1.4.1.1466.115.121.1.36',
  BIT_STRING: '1.3.6.1.4.1.1466.115.121.1.6',
  JPEG: '1.3.6.1.4.1.1466.115.121.1.28',
};

/** Syntax validation regexes keyed by OID */
const SYNTAX_VALIDATORS = {
  [SYNTAX.INTEGER]: /^-?\d+$/,
  [SYNTAX.BOOLEAN]: /^(TRUE|FALSE)$/i,
  // RFC 4512: OID can be a dotted numeric OID or a descriptor (letter+letter/digit/hyphen)
  [SYNTAX.OID]: /^([0-9]+(\.[0-9]+)+|[A-Za-z][A-Za-z0-9-]*)$/,
  [SYNTAX.IA5_STRING]: /^[\x00-\x7F]*$/,
  [SYNTAX.NUMERIC_STRING]: /^[0-9 ]*$/,
  [SYNTAX.UTC_TIME]: /^\d{12}Z$|^\d{12}[+-]\d{4}$/,
  [SYNTAX.GENERALIZED_TIME]: /^\d{14}(\.\d+)?Z$/,
};

const BUILTIN_ATTRIBUTE_TYPES = [
  // Standard operational / structural attributes
  { oid: '2.5.4.0', name: 'objectClass', description: 'Object class hierarchy', syntax: SYNTAX.OID, singleValue: false, collective: false, noUserModification: false, equality: 'objectIdentifierMatch' },
  { oid: '2.5.4.1', name: 'aliasedObjectName', description: 'Aliased object name', syntax: SYNTAX.DN, singleValue: true, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  { oid: '2.5.4.3', name: 'cn', description: 'Common Name', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.4', name: 'sn', description: 'Surname', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.6', name: 'c', description: 'Country Name (2-letter)', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.7', name: 'l', description: 'Locality Name', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.8', name: 'st', description: 'State or Province', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.9', name: 'street', description: 'Street Address', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.10', name: 'o', description: 'Organization Name', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.11', name: 'ou', description: 'Organizational Unit', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.12', name: 'title', description: 'Title', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.13', name: 'description', description: 'Description', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.16', name: 'postalAddress', description: 'Postal Address', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.17', name: 'postalCode', description: 'Postal Code', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.18', name: 'postOfficeBox', description: 'Post Office Box', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.20', name: 'telephoneNumber', description: 'Telephone Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'telephoneNumberMatch' },
  { oid: '2.5.4.23', name: 'facsimileTelephoneNumber', description: 'Facsimile Telephone Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.25', name: 'internationalISDNNumber', description: 'International ISDN Number', syntax: SYNTAX.NUMERIC_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'numericStringMatch' },
  { oid: '2.5.4.34', name: 'seeAlso', description: 'See Also (DN)', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  { oid: '2.5.4.35', name: 'userPassword', description: 'User Password', syntax: SYNTAX.OCTET_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'octetStringMatch' },
  { oid: '2.5.4.36', name: 'userCertificate', description: 'User Certificate', syntax: SYNTAX.OCTET_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'certificateMatch' },
  { oid: '2.5.4.42', name: 'givenName', description: 'Given Name', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.43', name: 'initials', description: 'Initials', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.44', name: 'generationQualifier', description: 'Generation Qualifier (Jr., Sr.)', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.45', name: 'x500UniqueIdentifier', description: 'X.500 Unique Identifier', syntax: SYNTAX.BIT_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'bitStringMatch' },
  { oid: '2.5.4.46', name: 'dnQualifier', description: 'DN Qualifier', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.5.4.49', name: 'distinguishedName', description: 'Distinguished Name', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  // inetOrgPerson / RFC 2798
  { oid: '0.9.2342.19200300.100.1.1', name: 'uid', description: 'User ID', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '0.9.2342.19200300.100.1.3', name: 'mail', description: 'Email Address', syntax: SYNTAX.IA5_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreIA5Match' },
  { oid: '0.9.2342.19200300.100.1.6', name: 'roomNumber', description: 'Room Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '0.9.2342.19200300.100.1.7', name: 'photo', description: 'Photo', syntax: SYNTAX.JPEG, singleValue: false, collective: false, noUserModification: false, equality: 'octetStringMatch' },
  { oid: '0.9.2342.19200300.100.1.10', name: 'manager', description: 'Manager (DN)', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  { oid: '0.9.2342.19200300.100.1.25', name: 'dc', description: 'Domain Component', syntax: SYNTAX.IA5_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreIA5Match' },
  { oid: '0.9.2342.19200300.100.1.37', name: 'associatedDomain', description: 'Associated Domain', syntax: SYNTAX.IA5_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreIA5Match' },
  { oid: '0.9.2342.19200300.100.1.41', name: 'mobile', description: 'Mobile Phone', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'telephoneNumberMatch' },
  { oid: '0.9.2342.19200300.100.1.42', name: 'pager', description: 'Pager Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'telephoneNumberMatch' },
  { oid: '0.9.2342.19200300.100.1.43', name: 'co', description: 'Country (full name)', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '0.9.2342.19200300.100.1.45', name: 'organizationalStatus', description: 'Organizational Status', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '0.9.2342.19200300.100.1.55', name: 'audio', description: 'Audio', syntax: SYNTAX.OCTET_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'octetStringMatch' },
  { oid: '2.16.840.1.113730.3.1.1', name: 'carLicense', description: 'Car License Plate', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.2', name: 'departmentNumber', description: 'Department Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.3', name: 'employeeNumber', description: 'Employee Number', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.4', name: 'employeeType', description: 'Employee Type', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.241', name: 'displayName', description: 'Display Name', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.216', name: 'preferredLanguage', description: 'Preferred Language', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '2.16.840.1.113730.3.1.217', name: 'userSMIMECertificate', description: 'User S/MIME Certificate', syntax: SYNTAX.OCTET_STRING, singleValue: false, collective: false, noUserModification: false, equality: 'octetStringMatch' },
  // posixAccount (RFC 2307)
  { oid: '1.3.6.1.1.1.1.0', name: 'uidNumber', description: 'POSIX UID', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.1', name: 'gidNumber', description: 'POSIX GID', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.2', name: 'gecos', description: 'GECOS field', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseIgnoreMatch' },
  { oid: '1.3.6.1.1.1.1.3', name: 'homeDirectory', description: 'Home Directory', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseExactMatch' },
  { oid: '1.3.6.1.1.1.1.4', name: 'loginShell', description: 'Login Shell', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: false, equality: 'caseExactMatch' },
  { oid: '1.3.6.1.1.1.1.5', name: 'shadowLastChange', description: 'Shadow Last Change', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.6', name: 'shadowMin', description: 'Shadow Minimum', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.7', name: 'shadowMax', description: 'Shadow Maximum', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.8', name: 'shadowWarning', description: 'Shadow Warning', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.9', name: 'shadowInactive', description: 'Shadow Inactive', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  { oid: '1.3.6.1.1.1.1.10', name: 'shadowExpire', description: 'Shadow Expire', syntax: SYNTAX.INTEGER, singleValue: true, collective: false, noUserModification: false, equality: 'integerMatch' },
  // groupOfNames / member
  { oid: '2.5.4.31', name: 'member', description: 'Member DN', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  { oid: '2.5.4.50', name: 'uniqueMember', description: 'Unique Member DN', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'uniqueMemberMatch' },
  { oid: '2.5.4.32', name: 'owner', description: 'Owner DN', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: false, equality: 'distinguishedNameMatch' },
  // Operational attributes
  { oid: '2.5.18.1', name: 'createTimestamp', description: 'Entry creation timestamp', syntax: SYNTAX.GENERALIZED_TIME, singleValue: true, collective: false, noUserModification: true, equality: 'generalizedTimeMatch' },
  { oid: '2.5.18.2', name: 'modifyTimestamp', description: 'Entry last modification timestamp', syntax: SYNTAX.GENERALIZED_TIME, singleValue: true, collective: false, noUserModification: true, equality: 'generalizedTimeMatch' },
  { oid: '2.5.18.3', name: 'creatorsName', description: 'Entry creators name', syntax: SYNTAX.DN, singleValue: true, collective: false, noUserModification: true, equality: 'distinguishedNameMatch' },
  { oid: '2.5.18.4', name: 'modifiersName', description: 'Entry last modifiers name', syntax: SYNTAX.DN, singleValue: true, collective: false, noUserModification: true, equality: 'distinguishedNameMatch' },
  { oid: '1.3.6.1.4.1.1466.101.120.5', name: 'namingContexts', description: 'Naming Contexts', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: true, equality: 'distinguishedNameMatch' },
  { oid: '1.3.6.1.4.1.1466.101.120.13', name: 'supportedControl', description: 'Supported controls', syntax: SYNTAX.OID, singleValue: false, collective: false, noUserModification: true, equality: 'objectIdentifierMatch' },
  { oid: '1.3.6.1.4.1.1466.101.120.14', name: 'supportedSASLMechanisms', description: 'Supported SASL mechanisms', syntax: SYNTAX.DIRECTORY_STRING, singleValue: false, collective: false, noUserModification: true, equality: 'caseIgnoreMatch' },
  // entryUUID
  { oid: '1.3.6.1.1.16.4', name: 'entryUUID', description: 'Entry UUID', syntax: SYNTAX.DIRECTORY_STRING, singleValue: true, collective: false, noUserModification: true, equality: 'UUIDMatch' },
  // memberOf (AD / OpenLDAP overlay)
  { oid: '1.2.840.113556.1.2.102', name: 'memberOf', description: 'Groups this entry is member of', syntax: SYNTAX.DN, singleValue: false, collective: false, noUserModification: true, equality: 'distinguishedNameMatch' },
];

const BUILTIN_OBJECT_CLASSES = [
  {
    oid: '2.5.6.0',
    name: 'top',
    description: 'Top-level object class (abstract)',
    superior: null,
    must: ['objectClass'],
    may: [],
    type: 'abstract',
  },
  {
    oid: '2.5.6.1',
    name: 'alias',
    description: 'Alias object',
    superior: 'top',
    must: ['aliasedObjectName'],
    may: [],
    type: 'structural',
  },
  {
    oid: '2.5.6.2',
    name: 'country',
    description: 'Country object',
    superior: 'top',
    must: ['c'],
    may: ['searchGuide', 'description'],
    type: 'structural',
  },
  {
    oid: '2.5.6.4',
    name: 'organization',
    description: 'Organization',
    superior: 'top',
    must: ['o'],
    may: ['userPassword', 'telephoneNumber', 'seeAlso', 'description', 'l', 'st', 'street', 'postalAddress', 'postalCode', 'postOfficeBox', 'facsimileTelephoneNumber'],
    type: 'structural',
  },
  {
    oid: '2.5.6.5',
    name: 'organizationalUnit',
    description: 'Organizational Unit',
    superior: 'top',
    must: ['ou'],
    may: ['userPassword', 'telephoneNumber', 'seeAlso', 'description', 'l', 'st', 'street', 'postalAddress', 'postalCode', 'postOfficeBox', 'facsimileTelephoneNumber'],
    type: 'structural',
  },
  {
    oid: '2.5.6.6',
    name: 'person',
    description: 'Person',
    superior: 'top',
    must: ['cn', 'sn'],
    may: ['userPassword', 'telephoneNumber', 'seeAlso', 'description'],
    type: 'structural',
  },
  {
    oid: '2.5.6.7',
    name: 'organizationalPerson',
    description: 'Organizational Person',
    superior: 'person',
    must: [],
    may: ['title', 'x121Address', 'registeredAddress', 'destinationIndicator', 'preferredDeliveryMethod', 'ou', 'physicalDeliveryOfficeName', 'postalAddress', 'postalCode', 'postOfficeBox', 'street', 'facsimileTelephoneNumber', 'internationalISDNNumber', 'l', 'st'],
    type: 'structural',
  },
  {
    oid: '2.16.840.1.113730.3.2.2',
    name: 'inetOrgPerson',
    description: 'Internet Organizational Person (RFC 2798)',
    superior: 'organizationalPerson',
    must: [],
    may: ['audio', 'businessCategory', 'carLicense', 'departmentNumber', 'displayName', 'employeeNumber', 'employeeType', 'givenName', 'homePhone', 'homePostalAddress', 'initials', 'jpegPhoto', 'labeledURI', 'mail', 'manager', 'mobile', 'o', 'pager', 'photo', 'roomNumber', 'secretary', 'uid', 'userCertificate', 'x500UniqueIdentifier', 'preferredLanguage', 'userSMIMECertificate', 'userPKCS12'],
    type: 'structural',
  },
  {
    oid: '1.3.6.1.1.1.2.0',
    name: 'posixAccount',
    description: 'POSIX account (RFC 2307)',
    superior: 'top',
    must: ['cn', 'uid', 'uidNumber', 'gidNumber', 'homeDirectory'],
    may: ['userPassword', 'loginShell', 'gecos', 'description'],
    type: 'auxiliary',
  },
  {
    oid: '1.3.6.1.1.1.2.2',
    name: 'posixGroup',
    description: 'POSIX group (RFC 2307)',
    superior: 'top',
    must: ['cn', 'gidNumber'],
    may: ['userPassword', 'memberUid', 'description'],
    type: 'structural',
  },
  {
    oid: '1.3.6.1.1.1.2.1',
    name: 'shadowAccount',
    description: 'Shadow password information (RFC 2307)',
    superior: 'top',
    must: ['uid'],
    may: ['userPassword', 'shadowLastChange', 'shadowMin', 'shadowMax', 'shadowWarning', 'shadowInactive', 'shadowExpire', 'shadowFlag', 'description'],
    type: 'auxiliary',
  },
  {
    oid: '2.5.6.9',
    name: 'groupOfNames',
    description: 'Group of Names',
    superior: 'top',
    must: ['cn', 'member'],
    may: ['businessCategory', 'seeAlso', 'owner', 'ou', 'o', 'description'],
    type: 'structural',
  },
  {
    oid: '2.5.6.17',
    name: 'groupOfUniqueNames',
    description: 'Group of Unique Names',
    superior: 'top',
    must: ['cn', 'uniqueMember'],
    may: ['businessCategory', 'seeAlso', 'owner', 'ou', 'o', 'description'],
    type: 'structural',
  },
  {
    oid: '0.9.2342.19200300.100.4.13',
    name: 'domain',
    description: 'DNS domain (dcObject auxiliary recommended)',
    superior: 'top',
    must: ['dc'],
    may: ['userPassword', 'searchGuide', 'seeAlso', 'businessCategory', 'x121Address', 'registeredAddress', 'destinationIndicator', 'preferredDeliveryMethod', 'telexNumber', 'teletexTerminalIdentifier', 'telephoneNumber', 'internationalISDNNumber', 'facsimileTelephoneNumber', 'street', 'postOfficeBox', 'postalCode', 'postalAddress', 'physicalDeliveryOfficeName', 'st', 'l', 'description', 'o', 'associatedDomain'],
    type: 'structural',
  },
  {
    oid: '1.3.6.1.4.1.1466.344',
    name: 'dcObject',
    description: 'Domain Component Object auxiliary class',
    superior: 'top',
    must: ['dc'],
    may: [],
    type: 'auxiliary',
  },
  {
    oid: '1.3.6.1.4.1.18060.0.4.1.2.1',
    name: 'computer',
    description: 'Computer / workstation object',
    superior: 'device',
    must: ['cn'],
    may: ['description', 'l', 'o', 'ou', 'seeAlso', 'serialNumber'],
    type: 'structural',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function applyPagination(items, { page = 1, limit = 50 } = {}) {
  const p = Math.max(1, parseInt(page, 10) || 1);
  const l = Math.min(500, Math.max(1, parseInt(limit, 10) || 50));
  const start = (p - 1) * l;
  return {
    items: items.slice(start, start + l),
    total: items.length,
    page: p,
    limit: l,
    pages: Math.ceil(items.length / l),
  };
}

function matchesFilter(item, filter) {
  if (!filter) return true;
  const f = filter.toLowerCase();
  return (
    (item.name && item.name.toLowerCase().includes(f)) ||
    (item.oid && item.oid.includes(f)) ||
    (item.description && item.description.toLowerCase().includes(f))
  );
}

// ---------------------------------------------------------------------------
// SchemaManager class
// ---------------------------------------------------------------------------

class SchemaManager {
  /**
   * @param {object|null} ldapClient — connected ldapts/ldapjs client, may be null
   */
  constructor(ldapClient) {
    this.ldapClient = ldapClient;

    // Mutable registries (start from built-ins, can be extended at runtime)
    this._attributeTypes = [...BUILTIN_ATTRIBUTE_TYPES];
    this._objectClasses = [...BUILTIN_OBJECT_CLASSES];

    // Indexes for fast lookup
    this._rebuildIndexes();
  }

  _rebuildIndexes() {
    this._attrByName = new Map();
    this._attrByOid = new Map();
    for (const a of this._attributeTypes) {
      this._attrByName.set(a.name.toLowerCase(), a);
      this._attrByOid.set(a.oid, a);
    }

    this._ocByName = new Map();
    this._ocByOid = new Map();
    for (const oc of this._objectClasses) {
      this._ocByName.set(oc.name.toLowerCase(), oc);
      this._ocByOid.set(oc.oid, oc);
    }
  }

  // -------------------------------------------------------------------------
  // Object Classes
  // -------------------------------------------------------------------------

  /**
   * List all object classes.
   * @param {{ filter?: string, page?: number, limit?: number }} opts
   */
  async listObjectClasses({ filter, page, limit } = {}) {
    let items = this._objectClasses.filter((oc) => matchesFilter(oc, filter));
    return applyPagination(items, { page, limit });
  }

  /**
   * Get a single object class by name or OID.
   * @param {string} name
   */
  async getObjectClass(name) {
    const oc =
      this._ocByName.get(name.toLowerCase()) ||
      this._ocByOid.get(name);
    if (!oc) {
      const err = new Error(`Object class '${name}' not found`);
      err.code = 'NOT_FOUND';
      throw err;
    }
    return { ...oc };
  }

  // -------------------------------------------------------------------------
  // Attribute Types
  // -------------------------------------------------------------------------

  /**
   * List all attribute types.
   * @param {{ filter?: string, page?: number, limit?: number }} opts
   */
  async listAttributeTypes({ filter, page, limit } = {}) {
    let items = this._attributeTypes.filter((a) => matchesFilter(a, filter));
    return applyPagination(items, { page, limit });
  }

  /**
   * Get a single attribute type by name or OID.
   * @param {string} name
   */
  async getAttributeType(name) {
    const at =
      this._attrByName.get(name.toLowerCase()) ||
      this._attrByOid.get(name);
    if (!at) {
      const err = new Error(`Attribute type '${name}' not found`);
      err.code = 'NOT_FOUND';
      throw err;
    }
    return { ...at };
  }

  // -------------------------------------------------------------------------
  // Schema for a DN
  // -------------------------------------------------------------------------

  /**
   * Get the applicable schema for a DN by reading its objectClass attribute.
   * Falls back to structural inference from the DN RDN if LDAP is unavailable.
   * @param {string} dn
   * @returns {{ mustAttributes: string[], mayAttributes: string[], objectClasses: string[] }}
   */
  async getSchemaForDN(dn) {
    let objectClassNames = [];

    // Try to read from live LDAP
    if (this.ldapClient) {
      try {
        const entries = await this.ldapClient.search(dn, {
          scope: 'base',
          filter: '(objectClass=*)',
          attributes: ['objectClass'],
        });
        if (entries && entries.searchEntries && entries.searchEntries.length > 0) {
          const entry = entries.searchEntries[0];
          const oc = entry.objectClass || entry['objectclass'];
          if (oc) {
            objectClassNames = Array.isArray(oc) ? oc : [oc];
          }
        }
      } catch (_) {
        // Fall through to RDN inference
      }
    }

    // Infer from RDN if we couldn't get real data
    if (objectClassNames.length === 0) {
      objectClassNames = this._inferObjectClassesFromDN(dn);
    }

    return this._resolveSchemaForObjectClasses(objectClassNames);
  }

  _inferObjectClassesFromDN(dn) {
    const rdn = dn.split(',')[0] || '';
    const attr = rdn.split('=')[0].toLowerCase();
    const map = {
      uid: ['top', 'inetOrgPerson', 'posixAccount'],
      cn: ['top', 'groupOfNames'],
      ou: ['top', 'organizationalUnit'],
      dc: ['top', 'domain', 'dcObject'],
    };
    return map[attr] || ['top'];
  }

  _resolveSchemaForObjectClasses(names) {
    const allMust = new Set();
    const allMay = new Set();
    const resolvedNames = [];

    const resolve = (name) => {
      const oc = this._ocByName.get(name.toLowerCase());
      if (!oc || resolvedNames.includes(oc.name)) return;
      resolvedNames.push(oc.name);
      if (oc.superior) resolve(oc.superior);
      oc.must.forEach((a) => allMust.add(a));
      oc.may.forEach((a) => allMay.add(a));
    };

    names.forEach(resolve);
    // Remove must from may
    allMust.forEach((a) => allMay.delete(a));

    return {
      objectClasses: resolvedNames,
      mustAttributes: [...allMust].sort(),
      mayAttributes: [...allMay].sort(),
    };
  }

  // -------------------------------------------------------------------------
  // Schema Extension
  // -------------------------------------------------------------------------

  /**
   * Add a custom attribute type.
   * @param {{ oid, name, description, syntax, singleValue, equality, ordering, substring }} opts
   */
  async addAttributeType({ oid, name, description = '', syntax, singleValue = false, equality = null, ordering = null, substring = null } = {}) {
    if (!oid || !name || !syntax) {
      throw new Error('oid, name, and syntax are required');
    }
    if (this._attrByOid.has(oid)) {
      throw new Error(`Attribute type with OID '${oid}' already exists`);
    }
    if (this._attrByName.has(name.toLowerCase())) {
      throw new Error(`Attribute type named '${name}' already exists`);
    }

    const at = { oid, name, description, syntax, singleValue: Boolean(singleValue), collective: false, noUserModification: false, equality, ordering, substring };
    this._attributeTypes.push(at);
    this._rebuildIndexes();

    // Optionally persist to LDAP backend schema entry
    if (this.ldapClient) {
      try {
        await this._persistAttributeTypeToLDAP(at);
      } catch (err) {
        console.warn('[SchemaManager] Could not persist attribute type to LDAP backend:', err.message);
      }
    }

    return { ...at };
  }

  /**
   * Add a custom object class.
   * @param {{ oid, name, description, superior, must, may, type }} opts
   */
  async addObjectClass({ oid, name, description = '', superior = 'top', must = [], may = [], type = 'structural' } = {}) {
    if (!oid || !name) {
      throw new Error('oid and name are required');
    }
    if (!['structural', 'auxiliary', 'abstract'].includes(type)) {
      throw new Error("type must be 'structural', 'auxiliary', or 'abstract'");
    }
    if (this._ocByOid.has(oid)) {
      throw new Error(`Object class with OID '${oid}' already exists`);
    }
    if (this._ocByName.has(name.toLowerCase())) {
      throw new Error(`Object class named '${name}' already exists`);
    }

    const oc = { oid, name, description, superior, must: [...must], may: [...may], type };
    this._objectClasses.push(oc);
    this._rebuildIndexes();

    if (this.ldapClient) {
      try {
        await this._persistObjectClassToLDAP(oc);
      } catch (err) {
        console.warn('[SchemaManager] Could not persist object class to LDAP backend:', err.message);
      }
    }

    return { ...oc };
  }

  async _persistAttributeTypeToLDAP(at) {
    // Build OpenLDAP attributeTypes value string
    const parts = [`( ${at.oid}`, `NAME '${at.name}'`];
    if (at.description) parts.push(`DESC '${at.description}'`);
    if (at.equality) parts.push(`EQUALITY ${at.equality}`);
    if (at.ordering) parts.push(`ORDERING ${at.ordering}`);
    if (at.substring) parts.push(`SUBSTR ${at.substring}`);
    parts.push(`SYNTAX ${at.syntax}`);
    if (at.singleValue) parts.push('SINGLE-VALUE');
    parts.push(')');
    const value = parts.join(' ');

    // Modify cn=schema
    await this.ldapClient.modify('cn=schema', [{
      operation: 'add',
      modification: { type: 'attributeTypes', values: [value] },
    }]);
  }

  async _persistObjectClassToLDAP(oc) {
    const parts = [`( ${oc.oid}`, `NAME '${oc.name}'`];
    if (oc.description) parts.push(`DESC '${oc.description}'`);
    if (oc.superior) parts.push(`SUP ${oc.superior}`);
    parts.push(oc.type.toUpperCase());
    if (oc.must.length > 0) parts.push(`MUST ( ${oc.must.join(' $ ')} )`);
    if (oc.may.length > 0) parts.push(`MAY ( ${oc.may.join(' $ ')} )`);
    parts.push(')');
    const value = parts.join(' ');

    await this.ldapClient.modify('cn=schema', [{
      operation: 'add',
      modification: { type: 'objectClasses', values: [value] },
    }]);
  }

  // -------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------

  /**
   * Validate an LDAP entry against its schema.
   * @param {string} dn
   * @param {object} attributes — { attrName: value | value[] }
   * @returns {{ valid: boolean, errors: Array<{attribute: string, message: string}>, warnings: string[] }}
   */
  async validateEntry(dn, attributes) {
    const errors = [];
    const warnings = [];

    // Determine object classes from the entry itself
    const rawOC = attributes.objectClass || attributes.objectclass;
    if (!rawOC) {
      errors.push({ attribute: 'objectClass', message: 'objectClass is required in every LDAP entry' });
      return { valid: false, errors, warnings };
    }

    const ocNames = Array.isArray(rawOC) ? rawOC : [rawOC];
    let schema;
    try {
      schema = this._resolveSchemaForObjectClasses(ocNames);
    } catch (err) {
      errors.push({ attribute: 'objectClass', message: err.message });
      return { valid: false, errors, warnings };
    }

    const attrKeys = Object.keys(attributes).map((k) => k.toLowerCase());

    // Check required attributes
    for (const must of schema.mustAttributes) {
      if (!attrKeys.includes(must.toLowerCase())) {
        errors.push({ attribute: must, message: `Required attribute '${must}' is missing` });
      }
    }

    // Check each supplied attribute
    for (const [attrName, rawValue] of Object.entries(attributes)) {
      const atDef = this._attrByName.get(attrName.toLowerCase());
      if (!atDef) {
        warnings.push(`Unknown attribute '${attrName}' — not in schema`);
        continue;
      }

      const values = Array.isArray(rawValue) ? rawValue : [rawValue];

      // Single-value check
      if (atDef.singleValue && values.length > 1) {
        errors.push({ attribute: attrName, message: `'${attrName}' is single-valued but ${values.length} values were provided` });
      }

      // Syntax check
      for (const val of values) {
        const syntaxErr = this.validateSyntax(atDef.syntax, String(val));
        if (syntaxErr) {
          errors.push({ attribute: attrName, message: `Value '${val}' fails syntax check for '${attrName}': ${syntaxErr}` });
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Check a value's syntax against a syntax OID.
   * @param {string} syntaxOid
   * @param {string} value
   * @returns {string|null} error message or null if valid
   */
  validateSyntax(syntaxOid, value) {
    const validator = SYNTAX_VALIDATORS[syntaxOid];
    if (!validator) return null; // Unknown syntax — pass
    if (!validator.test(value)) {
      return `Does not match expected syntax for OID ${syntaxOid}`;
    }
    return null;
  }
}

module.exports = SchemaManager;

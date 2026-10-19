'use strict';

const FIELDS = Object.freeze({ name: 160, legalForm: 80, registrationNumber: 80, taxId: 80, addressLine1: 180, addressLine2: 180,
  postalCode: 32, city: 100, country: 2, timezone: 64, defaultLanguage: 2, contactEmail: 254, contactPhone: 40, website: 2048 });
const REQUIRED = ['name', 'addressLine1', 'postalCode', 'city', 'country', 'timezone', 'defaultLanguage', 'contactEmail'];
function invalid() { throw Object.assign(new Error('invalid_organization_profile'), { status: 400, code: 'invalid_organization_profile' }); }
function normalizeProfile(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== Object.keys(FIELDS).length
    || Object.keys(value).some(field => !Object.hasOwn(FIELDS, field))) invalid();
  const profile = {};
  for (const [field, maximum] of Object.entries(FIELDS)) {
    if (typeof value[field] !== 'string' || /[\u0000-\u001f\u007f]/u.test(value[field])) invalid();
    profile[field] = value[field].trim();
    if ([...profile[field]].length > maximum || REQUIRED.includes(field) && !profile[field]) invalid();
  }
  if ([...profile.name].length < 2 || !/^[A-Z]{2}$/.test(profile.country) || !['de', 'en'].includes(profile.defaultLanguage)
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(profile.contactEmail) || !/^[+0-9 ()/.-]*$/.test(profile.contactPhone)) invalid();
  try { profile.timezone = new Intl.DateTimeFormat('en', { timeZone: profile.timezone }).resolvedOptions().timeZone; } catch { invalid(); }
  if (profile.website) {
    try { const website = new URL(profile.website); if (website.protocol !== 'https:' || !website.hostname || website.username || website.password) invalid(); } catch { invalid(); }
  }
  return profile;
}
function organizationEtag(tenant, version) { return `"organization-${tenant.id}-${tenant.generation}-${tenant.version}-${version}"`; }

module.exports = { FIELDS, normalizeProfile, organizationEtag };

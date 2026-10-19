export interface OrganizationProfile {
  name: string;
  legalForm: string;
  registrationNumber: string;
  taxId: string;
  addressLine1: string;
  addressLine2: string;
  postalCode: string;
  city: string;
  country: string;
  timezone: string;
  defaultLanguage: string;
  contactEmail: string;
  contactPhone: string;
  website: string;
}
export const FIELDS: Readonly<Record<keyof OrganizationProfile, number>>;
export function normalizeProfile(value: unknown): OrganizationProfile;
export function organizationEtag(tenant: { id: string; generation: string; version: string }, version: string): string;

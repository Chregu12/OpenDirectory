import type { OrganizationProfile } from '../organization-profile-contract';
interface RegistrationReceiptBase {
  registrationId: string; tenantId: string; administratorId: string; createdAt: string;
  tenantEnabled: false; administratorEnabled: false; profileSaved: false; activationSupported: false; replayed: boolean;
}
export type CompanyRegistrationReceipt = RegistrationReceiptBase & ({ schemaVersion: 1; status: 'pending-verification' } | { schemaVersion: 2; status: 'pending-activation' | 'rejected'; reviewedAt: string }) | {
  schemaVersion: 3; registrationId: string; tenantId: string; administratorId: string; createdAt: string; reviewedAt: string; activatedAt: string; status: 'active' | 'suspended';
  tenantEnabled: boolean; administratorEnabled: boolean; profileSaved: true; activationSupported: true; replayed: boolean; consoleClientId: string; mfaRequired: true;
};
export interface RegistrationCapabilities { schemaVersion: 1 | 2; enabled: boolean; requiresExistingAccount: true; activationSupported: boolean; status: 'pending-verification' }
export function validCapabilities(value: unknown): value is RegistrationCapabilities;
export interface CompanyReviewInput { decision: 'approved' | 'rejected'; reason: string; confirm: true }
export function normalizeReview(value: unknown): CompanyReviewInput;
export interface RegistrationCredentials { registrationId: string; username: string; password: string; mfaCode: string }
export interface CompanyRegistrationInput extends RegistrationCredentials { profile: OrganizationProfile; confirm: true }
export interface CompanyActivationInput extends RegistrationCredentials { confirm: true }
export function identifier(value: unknown): value is string;
export function normalizePublic(operation: 'submit', input: unknown): CompanyRegistrationInput;
export function normalizePublic(operation: 'status', input: unknown): RegistrationCredentials;
export function normalizePublic(operation: 'activate', input: unknown): CompanyActivationInput;
export function validReceipt(value: unknown, registrationId: string): value is CompanyRegistrationReceipt;

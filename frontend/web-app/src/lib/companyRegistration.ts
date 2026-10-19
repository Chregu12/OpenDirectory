import { normalizePublic, validReceipt, validCapabilities, CompanyRegistrationReceipt, RegistrationCredentials, CompanyRegistrationInput, CompanyActivationInput } from '../../../../packages/company-registration-contract';

export type { CompanyRegistrationReceipt };
function unavailable(): never { throw new Error('Registrierung oder Status nicht bestätigt. Bitte Status prüfen; nicht automatisch erneut senden.'); }
export function registrationError(error: any) {
  return ({ 400: 'Bitte Registrierungs-ID, Zugangsdaten und Unternehmensangaben prüfen.', 401: 'Zugangsdaten wurden nicht bestätigt.', 403: 'Die Registrierungsanfrage wurde abgewiesen.',
    404: 'Zu dieser ID und diesem Konto ist keine bestätigte Registrierung vorhanden.', 409: 'Konto oder Registrierungs-ID sind bereits gebunden. Bestehenden Status prüfen; keine neue Firma vortäuschen.', 429: 'Zu viele Anfragen. Bitte später erneut versuchen.' } as Record<number, string>)[error?.status]
    || 'Registrierung oder Status nicht bestätigt. Bitte Status prüfen; nicht automatisch erneut senden.';
}
async function responseJson(response: Response) {
  if (!response.ok) throw Object.assign(new Error('company_registration_unconfirmed'), { status: response.status });
  if (!response.headers.get('content-type')?.includes('application/json')) unavailable(); return response.json();
}
export const companyRegistration = {
  async capabilities(signal?: AbortSignal) {
    const result = await responseJson(await fetch('/api/company-registration', { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal }));
    if (!validCapabilities(result)) unavailable(); return result;
  },
  async submit(input: CompanyRegistrationInput): Promise<CompanyRegistrationReceipt> { return send('submit', normalizePublic('submit', input)); },
  async status(input: RegistrationCredentials): Promise<CompanyRegistrationReceipt> { return send('status', normalizePublic('status', input)); },
  async activate(input: CompanyActivationInput): Promise<CompanyRegistrationReceipt> { return send('activate', normalizePublic('activate', input)); },
};
async function send(operation: 'submit' | 'status' | 'activate', body: RegistrationCredentials | CompanyRegistrationInput | CompanyActivationInput): Promise<CompanyRegistrationReceipt> {
  const receipt = await responseJson(await fetch('/api/company-registration/' + operation, { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { 'Content-Type': 'application/json', 'X-OD-Company-Registration': '1' }, body: JSON.stringify(body), signal: AbortSignal.timeout(12000) }));
  if (!validReceipt(receipt, body.registrationId) || operation === 'status' && !receipt.replayed || operation === 'activate' && receipt.schemaVersion !== 3) unavailable(); return receipt;
}

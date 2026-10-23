'use strict';

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const MAILBOX = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }
function fail(code) { throw new Error(code); }

class EmployeeInvitationMailer {
  constructor({ env = process.env, fetchImpl = (...args) => fetch(...args) } = {}) {
    this.fetch = fetchImpl;
    this.tenantId = env.OAUTH_EMPLOYEE_INVITATION_GRAPH_TENANT_ID || '';
    this.clientId = env.OAUTH_EMPLOYEE_INVITATION_GRAPH_CLIENT_ID || '';
    this.clientSecret = env.OAUTH_EMPLOYEE_INVITATION_GRAPH_CLIENT_SECRET || '';
    this.sender = env.OAUTH_EMPLOYEE_INVITATION_GRAPH_SENDER || '';
    this.publicUrl = env.OAUTH_EMPLOYEE_INVITATION_PUBLIC_URL || '';
    this.configured = [this.tenantId, this.clientId, this.clientSecret, this.sender, this.publicUrl].every(Boolean);
    this.partial = [this.tenantId, this.clientId, this.clientSecret, this.sender, this.publicUrl].some(Boolean) && !this.configured;
    this.cachedToken = null;
    if (this.configured && (!UUID.test(this.tenantId) || !UUID.test(this.clientId) || !MAILBOX.test(this.sender))) throw new Error('Invalid employee invitation Graph mail configuration');
    if (this.configured) {
      const url = new URL(this.publicUrl);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.protocol !== 'https:' && url.hostname !== 'localhost') {
        throw new Error('Invalid public employee invitation URL');
      }
      this.publicOrigin = url.origin;
    }
  }
  async json(url, options, stage) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await this.fetch(url, { ...options, signal: controller.signal, cache: 'no-store', redirect: 'error' });
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) { await response.body?.cancel(); fail(stage); }
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 16384) fail(stage); chunks.push(Buffer.from(chunk)); }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch { fail(stage); } finally { clearTimeout(timer); controller.abort(); }
  }
  async token() {
    if (this.cachedToken && this.cachedToken.expiresAt > Date.now()) return this.cachedToken.value;
    const body = new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
    const data = await this.json(`https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
    }, 'employee_invitation_graph_token_unavailable');
    if (data.token_type?.toLowerCase() !== 'bearer' || typeof data.access_token !== 'string' || data.access_token.length > 16384 || !/^[A-Za-z0-9._~+/-]+=*$/.test(data.access_token)
      || !Number.isInteger(data.expires_in) || data.expires_in < 60 || data.expires_in > 86400) fail('employee_invitation_graph_token_invalid');
    this.cachedToken = { value: data.access_token, expiresAt: Date.now() + (data.expires_in - 30) * 1000 };
    return data.access_token;
  }
  async send({ invitation, invitationToken, recipientEmail }) {
    if (!this.configured) return { status: this.partial ? 'failed' : 'not_configured' };
    if (!MAILBOX.test(recipientEmail) || invitation.id !== invitationToken?.split('.')[0] || !UUID.test(invitation.id)) return { status: 'failed' };
    const url = new URL('/employees/accept', this.publicOrigin); url.hash = invitationToken;
    const safeLink = escapeHtml(url.href); const organization = escapeHtml(invitation.organizationName); const login = escapeHtml(invitation.loginName);
    const message = {
      subject: `Einladung zu ${invitation.organizationName}`,
      body: { contentType: 'HTML', content: `<p>Du wurdest zu <strong>${organization}</strong> eingeladen.</p><p>Anmeldename: <strong>${login}</strong></p><p><a href="${safeLink}">Einladung sicher annehmen</a></p><p>Der Link ist vertraulich und läuft am ${escapeHtml(new Date(invitation.expiresAt).toLocaleString('de-CH', { timeZone: 'Europe/Zurich' }))} ab.</p>` },
      toRecipients: [{ emailAddress: { address: recipientEmail } }],
    };
    try {
      const token = await this.token(); const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const response = await this.fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(this.sender)}/sendMail`, {
          method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', 'client-request-id': invitation.id },
          body: JSON.stringify({ message, saveToSentItems: true }), signal: controller.signal, cache: 'no-store', redirect: 'error',
        });
        await response.body?.cancel();
        if (response.status !== 202) { this.cachedToken = null; return { status: 'failed' }; }
        return { status: 'sent' };
      } finally { clearTimeout(timer); controller.abort(); }
    } catch { this.cachedToken = null; return { status: 'failed' }; }
  }
}

module.exports = { EmployeeInvitationMailer };

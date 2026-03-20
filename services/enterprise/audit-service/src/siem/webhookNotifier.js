'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const logger = require('../utils/logger');

class WebhookNotifier {
  constructor() {
    this.timeout = parseInt(process.env.WEBHOOK_TIMEOUT_MS, 10) || 10000;
    this.retryAttempts = parseInt(process.env.WEBHOOK_RETRY_ATTEMPTS, 10) || 2;
  }

  async notify(alertRule, event) {
    if (!alertRule || !alertRule.action) {
      logger.warn('Alert rule has no action configured');
      return false;
    }

    const action = alertRule.action;
    const webhookUrl = action.webhook_url || action.url;

    if (!webhookUrl) {
      logger.warn('Alert rule action has no webhook URL', { ruleId: alertRule.id });
      return false;
    }

    // Determine payload format based on webhook type
    let payload;
    const webhookType = action.type || this._detectWebhookType(webhookUrl);

    switch (webhookType) {
      case 'slack':
        payload = this._formatSlack(alertRule, event);
        break;
      case 'teams':
        payload = this._formatTeams(alertRule, event);
        break;
      case 'pagerduty':
        payload = this._formatPagerDuty(alertRule, event);
        break;
      default:
        payload = this._formatGeneric(alertRule, event);
    }

    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        const response = await this._sendRequest(webhookUrl, payload, action.headers || {});
        logger.info('Webhook notification sent', {
          ruleId: alertRule.id,
          ruleName: alertRule.name,
          eventId: event.id,
          type: webhookType,
          statusCode: response.statusCode,
          attempt: attempt + 1,
        });
        return true;
      } catch (err) {
        logger.warn('Webhook notification failed', {
          ruleId: alertRule.id,
          eventId: event.id,
          attempt: attempt + 1,
          maxAttempts: this.retryAttempts + 1,
          error: err.message,
        });
        if (attempt < this.retryAttempts) {
          await this._delay(1000 * (attempt + 1));
        }
      }
    }

    logger.error('Webhook notification exhausted all retries', {
      ruleId: alertRule.id,
      eventId: event.id,
      url: webhookUrl,
    });
    return false;
  }

  _formatSlack(alertRule, event) {
    const severityEmoji = {
      critical: ':rotating_light:',
      error: ':x:',
      warning: ':warning:',
      info: ':information_source:',
      debug: ':mag:',
    };

    return {
      text: `${severityEmoji[event.severity] || ':bell:'} Audit Alert: ${alertRule.name}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `Audit Alert: ${alertRule.name}` },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Category:*\n${event.category}` },
            { type: 'mrkdwn', text: `*Severity:*\n${event.severity}` },
            { type: 'mrkdwn', text: `*Action:*\n${event.action}` },
            { type: 'mrkdwn', text: `*Result:*\n${event.result}` },
            { type: 'mrkdwn', text: `*Actor:*\n${event.actor_name || event.actor_id || 'N/A'}` },
            { type: 'mrkdwn', text: `*Target:*\n${event.target_name || event.target_id || 'N/A'}` },
          ],
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `Event ID: ${event.id} | ${new Date(event.timestamp).toISOString()}` },
          ],
        },
      ],
    };
  }

  _formatTeams(alertRule, event) {
    return {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: this._getSeverityColor(event.severity),
      summary: `Audit Alert: ${alertRule.name}`,
      sections: [
        {
          activityTitle: `Audit Alert: ${alertRule.name}`,
          activitySubtitle: alertRule.description || '',
          facts: [
            { name: 'Category', value: event.category },
            { name: 'Severity', value: event.severity },
            { name: 'Action', value: event.action },
            { name: 'Result', value: event.result },
            { name: 'Actor', value: event.actor_name || event.actor_id || 'N/A' },
            { name: 'Target', value: event.target_name || event.target_id || 'N/A' },
            { name: 'Timestamp', value: new Date(event.timestamp).toISOString() },
            { name: 'Event ID', value: event.id },
          ],
          markdown: true,
        },
      ],
    };
  }

  _formatPagerDuty(alertRule, event) {
    return {
      routing_key: alertRule.action.routing_key || '',
      event_action: event.severity === 'critical' ? 'trigger' : 'trigger',
      dedup_key: `audit-${alertRule.id}-${event.category}`,
      payload: {
        summary: `[${event.severity.toUpperCase()}] ${alertRule.name}: ${event.action}`,
        source: 'OpenDirectory Audit Service',
        severity: event.severity === 'critical' ? 'critical' : event.severity === 'error' ? 'error' : 'warning',
        component: event.category,
        group: event.source || 'audit',
        custom_details: {
          event_id: event.id,
          actor: event.actor_name || event.actor_id,
          target: event.target_name || event.target_id,
          result: event.result,
          details: event.details,
        },
      },
    };
  }

  _formatGeneric(alertRule, event) {
    return {
      alert: {
        rule_id: alertRule.id,
        rule_name: alertRule.name,
        description: alertRule.description,
      },
      event: {
        id: event.id,
        timestamp: event.timestamp,
        category: event.category,
        severity: event.severity,
        action: event.action,
        actor: {
          type: event.actor_type,
          id: event.actor_id,
          name: event.actor_name,
          ip: event.actor_ip,
        },
        target: {
          type: event.target_type,
          id: event.target_id,
          name: event.target_name,
        },
        result: event.result,
        details: event.details,
        correlation_id: event.correlation_id,
      },
      source: 'OpenDirectory Audit Service',
      triggered_at: new Date().toISOString(),
    };
  }

  _sendRequest(url, payload, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      const body = JSON.stringify(payload);
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        timeout: this.timeout,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'OpenDirectory-AuditService/1.0',
          ...extraHeaders,
        },
      };

      const req = transport.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, body: data });
          } else {
            reject(new Error(`Webhook returned status ${res.statusCode}: ${data.substring(0, 200)}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Webhook request timed out after ${this.timeout}ms`));
      });

      req.write(body);
      req.end();
    });
  }

  _detectWebhookType(url) {
    if (!url) return 'generic';
    if (url.includes('hooks.slack.com')) return 'slack';
    if (url.includes('webhook.office.com') || url.includes('outlook.office.com')) return 'teams';
    if (url.includes('events.pagerduty.com')) return 'pagerduty';
    return 'generic';
  }

  _getSeverityColor(severity) {
    const colors = { critical: 'FF0000', error: 'CC0000', warning: 'FFA500', info: '0078D4', debug: '808080' };
    return colors[severity] || '0078D4';
  }

  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = WebhookNotifier;

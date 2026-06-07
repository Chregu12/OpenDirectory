'use strict';

const logger = require('../utils/logger');

/**
 * NotificationService — dispatches notifications over multiple channels:
 *   - email   (nodemailer stub — sends only if SMTP is configured)
 *   - slack   (incoming webhook)
 *   - webhook (generic HTTP POST)
 *   - pagerduty (generic stub)
 *
 * Channels are stored in-memory and can be managed via the REST API.
 */
class NotificationService {
  constructor(eventBus) {
    this._bus = eventBus;
    this._channels = new Map();
    this._history = [];       // Array of dispatched notifications
    this._maxHistory = 5000;
    this._nextChannelId = 1;

    // Seed default channels
    this._seedDefaultChannels();

    // Subscribe to alert events
    this._bus.on('alert:triggered', (alert) => this._onAlertTriggered(alert));
    this._bus.on('alert:resolved',  (alert) => this._onAlertResolved(alert));

    logger.info('NotificationService initialised');
  }

  // ---------------------------------------------------------------------------
  // Default channels
  // ---------------------------------------------------------------------------

  _seedDefaultChannels() {
    this._addChannel({ type: 'email',     name: 'Default Email',       config: { to: 'admin@opendirectory.local' }, enabled: true });
    this._addChannel({ type: 'slack',     name: 'Ops Slack',           config: { webhookUrl: '' },                 enabled: false });
    this._addChannel({ type: 'webhook',   name: 'Generic Webhook',     config: { url: '', method: 'POST' },        enabled: false });
    this._addChannel({ type: 'pagerduty', name: 'PagerDuty On-Call',   config: { routingKey: '' },                 enabled: false });
  }

  _addChannel(data) {
    const id = data.id || `channel-${this._nextChannelId++}`;
    const channel = {
      id,
      type: data.type || 'email',
      name: data.name || `Channel ${id}`,
      config: data.config || {},
      enabled: data.enabled !== false,
      createdAt: Date.now(),
    };
    this._channels.set(id, channel);
    return channel;
  }

  // ---------------------------------------------------------------------------
  // Event handlers
  // ---------------------------------------------------------------------------

  async _onAlertTriggered(alert) {
    const message = {
      subject: `[ALERT] ${alert.severity?.toUpperCase()} — ${alert.name}`,
      body: alert.message || `Alert triggered for service: ${alert.service}`,
      severity: alert.severity,
      alert,
    };
    await this.sendToAllEnabled(message);
  }

  async _onAlertResolved(alert) {
    const message = {
      subject: `[RESOLVED] ${alert.name}`,
      body: `Alert has been resolved for service: ${alert.service}`,
      severity: 'info',
      alert,
    };
    await this.sendToAllEnabled(message);
  }

  // ---------------------------------------------------------------------------
  // Sending
  // ---------------------------------------------------------------------------

  async sendToAllEnabled(message) {
    for (const channel of this._channels.values()) {
      if (channel.enabled) {
        await this.sendToChannel(channel.id, message);
      }
    }
  }

  async sendToChannel(channelId, message) {
    const channel = this._channels.get(channelId);
    if (!channel) {
      throw new Error(`Channel ${channelId} not found`);
    }

    let status = 'delivered';
    let error = null;

    try {
      switch (channel.type) {
        case 'email':
          await this._sendEmail(channel, message);
          break;
        case 'slack':
          await this._sendSlack(channel, message);
          break;
        case 'webhook':
          await this._sendWebhook(channel, message);
          break;
        case 'pagerduty':
          await this._sendPagerDuty(channel, message);
          break;
        default:
          logger.warn('Unknown notification channel type', { type: channel.type });
          status = 'skipped';
      }
    } catch (err) {
      logger.error('NotificationService send error', { channel: channel.name, error: err.message });
      status = 'failed';
      error = err.message;
    }

    this._recordHistory({
      channelId,
      channelName: channel.name,
      channelType: channel.type,
      alertName: message.alert?.name || message.subject,
      subject: message.subject,
      status,
      error,
      sentAt: Date.now(),
    });

    return { status, error };
  }

  async _sendEmail(channel, message) {
    // nodemailer stub — only logs unless SMTP_HOST is properly configured
    const config = require('../config');
    if (!config.notifications.email.host || config.notifications.email.host === 'localhost') {
      logger.info('[Email STUB] Would send email', { to: channel.config.to, subject: message.subject });
      return;
    }
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransporter({
        host: config.notifications.email.host,
        port: config.notifications.email.port,
        secure: config.notifications.email.secure,
        auth: config.notifications.email.user ? {
          user: config.notifications.email.user,
          pass: config.notifications.email.password,
        } : undefined,
      });
      await transporter.sendMail({
        from: config.notifications.email.from,
        to: channel.config.to,
        subject: message.subject,
        text: message.body,
      });
      logger.info('Email sent', { to: channel.config.to });
    } catch (err) {
      throw new Error(`Email send failed: ${err.message}`);
    }
  }

  async _sendSlack(channel, message) {
    const webhookUrl = channel.config.webhookUrl;
    if (!webhookUrl) {
      logger.info('[Slack STUB] No webhook URL configured', { channel: channel.name });
      return;
    }
    const axios = require('axios');
    const payload = {
      text: `*${message.subject}*\n${message.body}`,
      attachments: message.alert ? [{
        color: message.severity === 'critical' ? 'danger' : message.severity === 'warning' ? 'warning' : 'good',
        fields: [
          { title: 'Service', value: message.alert.service || 'N/A', short: true },
          { title: 'Severity', value: message.severity || 'info', short: true },
        ],
      }] : undefined,
    };
    await axios.post(webhookUrl, payload, { timeout: 5000 });
    logger.info('Slack notification sent', { channel: channel.name });
  }

  async _sendWebhook(channel, message) {
    const url = channel.config.url;
    if (!url) {
      logger.info('[Webhook STUB] No URL configured', { channel: channel.name });
      return;
    }
    const axios = require('axios');
    const method = (channel.config.method || 'POST').toLowerCase();
    const headers = channel.config.headers || { 'Content-Type': 'application/json' };
    await axios[method](url, message, { headers, timeout: 10000 });
    logger.info('Webhook notification sent', { channel: channel.name, url });
  }

  async _sendPagerDuty(channel, message) {
    const routingKey = channel.config.routingKey;
    if (!routingKey) {
      logger.info('[PagerDuty STUB] No routing key configured', { channel: channel.name });
      return;
    }
    const axios = require('axios');
    const payload = {
      routing_key: routingKey,
      event_action: 'trigger',
      payload: {
        summary: message.subject,
        severity: message.severity || 'warning',
        source: 'OpenDirectory Monitoring',
        custom_details: { body: message.body },
      },
    };
    await axios.post('https://events.pagerduty.com/v2/enqueue', payload, { timeout: 10000 });
    logger.info('PagerDuty event sent', { channel: channel.name });
  }

  // ---------------------------------------------------------------------------
  // Channel CRUD
  // ---------------------------------------------------------------------------

  createChannel(data) {
    return this._addChannel(data);
  }

  updateChannel(id, changes) {
    const ch = this._channels.get(id);
    if (!ch) return null;
    const updated = { ...ch, ...changes, id };
    this._channels.set(id, updated);
    return updated;
  }

  deleteChannel(id) {
    return this._channels.delete(id);
  }

  getChannels() {
    return Array.from(this._channels.values());
  }

  getChannel(id) {
    return this._channels.get(id) || null;
  }

  // ---------------------------------------------------------------------------
  // History
  // ---------------------------------------------------------------------------

  _recordHistory(entry) {
    this._history.push(entry);
    if (this._history.length > this._maxHistory) this._history.shift();
  }

  getHistory({ limit = 100, offset = 0 } = {}) {
    return this._history
      .slice()
      .reverse()
      .slice(offset, offset + limit);
  }

  // Test helper used by the API
  async testChannel(channelId) {
    return this.sendToChannel(channelId, {
      subject: '[TEST] Monitoring notification test',
      body: 'This is a test notification from OpenDirectory Monitoring Service.',
      severity: 'info',
      alert: null,
    });
  }
}

module.exports = NotificationService;

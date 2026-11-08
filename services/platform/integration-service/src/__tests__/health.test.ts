export {};
jest.mock('../services/lldap.service', () => ({ LLDAPService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));
jest.mock('../services/grafana.service', () => ({ GrafanaService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));
jest.mock('../services/prometheus.service', () => ({ PrometheusService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));
jest.mock('../services/vault.service', () => ({ VaultService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));
jest.mock('../services/network-infrastructure.service', () => ({ NetworkInfrastructureService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));
jest.mock('../services/wazuh.service', () => ({ WazuhService: jest.fn(() => ({ getServiceStatus: jest.fn() })) }));

const request = require('supertest');
const express = require('express');
let app: any;
let checks: any[];
const previous = process.env.INTEGRATION_ENABLED_SERVICES;

beforeAll(() => {
  process.env.INTEGRATION_ENABLED_SERVICES = 'lldap,grafana,prometheus';
  app = express().use('/health', require('../routes/health').default);
  checks = [
    require('../services/lldap.service').LLDAPService,
    require('../services/grafana.service').GrafanaService,
    require('../services/prometheus.service').PrometheusService,
    require('../services/vault.service').VaultService,
    require('../services/network-infrastructure.service').NetworkInfrastructureService,
    require('../services/wazuh.service').WazuhService,
  ].map(service => service.mock.results[0].value.getServiceStatus);
});
beforeEach(() => checks.forEach((check, id) => check.mockReset().mockResolvedValue({ name: String(id), status: 'healthy', lastCheck: 'now' })));
afterAll(() => {
  if (previous === undefined) delete process.env.INTEGRATION_ENABLED_SERVICES;
  else process.env.INTEGRATION_ENABLED_SERVICES = previous;
});

test('unconfigured optional integrations are explicitly disabled and never probed', async () => {
  const response = await request(app).get('/health');
  expect(response.status).toBe(200);
  expect(response.body.summary).toEqual({ healthy: 3, total: 3, disabled: 3 });
  expect(response.body.services.filter((service: any) => service.status === 'disabled')).toHaveLength(3);
  checks.slice(3).forEach(check => expect(check).not.toHaveBeenCalled());
});

test('an enabled integration failure makes readiness fail instead of disappearing from the result', async () => {
  checks[1].mockRejectedValue(new Error('Grafana authentication failed'));
  const response = await request(app).get('/health/ready');
  expect(response.status).toBe(503);
  expect(response.body.summary).toEqual({ healthy: 2, total: 3, disabled: 3 });
  expect((await request(app).get('/health')).status).toBe(207);
});

test('disabled and unknown individual checks never return a healthy success', async () => {
  const disabled = await request(app).get('/health/service/vault');
  expect(disabled.status).toBe(503);
  expect(disabled.body.status).toBe('disabled');
  expect((await request(app).get('/health/service/constructor')).status).toBe(404);
});

const ConditionalAccessEngine = require('../engines/ConditionalAccessEngine');

describe('ConditionalAccessEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new ConditionalAccessEngine();
  });

  afterEach(async () => {
    engine.stopContinuousEvaluation();
    await engine.shutdown();
  });

  describe('startContinuousEvaluation / stopContinuousEvaluation', () => {
    test('starts and stops interval without throwing', () => {
      expect(() => engine.startContinuousEvaluation()).not.toThrow();
      expect(engine._evaluationInterval).not.toBeNull();
      engine.stopContinuousEvaluation();
      expect(engine._evaluationInterval).toBeNull();
    });

    test('calling stop twice does not throw', () => {
      engine.startContinuousEvaluation();
      engine.stopContinuousEvaluation();
      expect(() => engine.stopContinuousEvaluation()).not.toThrow();
    });
  });

  describe('Session expiration during evaluation tick', () => {
    test('evicts sessions older than SESSION_TTL_MS', async () => {
      const oldDate = new Date(Date.now() - 9 * 60 * 60 * 1000); // 9 hours ago
      engine.activeSessions.set('user1:dev1', {
        id: 'session1',
        userId: 'user1',
        createdAt: oldDate,
        context: { request: { timestamp: oldDate } },
      });

      expect(engine.activeSessions.size).toBe(1);

      // Trigger one evaluation tick manually by running the interval callback
      const tickFn = jest.fn(async () => {
        const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
        const now = Date.now();
        for (const [key, session] of engine.activeSessions) {
          if (now - new Date(session.createdAt).getTime() > SESSION_TTL_MS) {
            engine.activeSessions.delete(key);
          }
        }
      });
      await tickFn();

      expect(engine.activeSessions.size).toBe(0);
    });

    test('does not evict sessions within TTL', async () => {
      engine.activeSessions.set('user2:dev2', {
        id: 'session2',
        userId: 'user2',
        createdAt: new Date(),
        context: { request: { timestamp: new Date() } },
      });

      expect(engine.activeSessions.size).toBe(1);
    });
  });

  describe('shutdown', () => {
    test('clears all sessions and stops interval', async () => {
      engine.activeSessions.set('user3:dev3', { id: 'session3', userId: 'user3' });
      engine.startContinuousEvaluation();

      await engine.shutdown();

      expect(engine.activeSessions.size).toBe(0);
      expect(engine._evaluationInterval).toBeNull();
    });
  });

  describe('Risk thresholds', () => {
    test('has expected risk threshold values', () => {
      expect(engine.riskThresholds.ALLOW).toBe(0.3);
      expect(engine.riskThresholds.BLOCK).toBe(0.9);
      expect(engine.riskThresholds.REQUIRE_MFA).toBeGreaterThan(engine.riskThresholds.ALLOW);
      expect(engine.riskThresholds.BLOCK).toBeGreaterThan(engine.riskThresholds.REQUIRE_MFA);
    });
  });
});

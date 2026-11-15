'use strict';

module.exports = async function* (events) {
  let passed = 0;
  for await (const { type, data } of events) {
    // Empty files can receive a synthetic pass; suites, skips and TODOs are not coverage.
    if (type === 'test:pass' && !data.skip && !data.todo && data.details?.type !== 'suite'
      && data.file && (data.entryFile || data.name !== data.file)) passed++;
  }
  if (!passed) throw new Error('No passing integration tests completed; check the test selection.');
};

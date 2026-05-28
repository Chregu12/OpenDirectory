'use strict';

/**
 * @opendirectory/service-contracts
 *
 * Barrel export for all service contract utilities.
 * Import the sub-module directly for tree-shaking in environments that support it.
 */

module.exports = {
  events:     require('./events'),
  errors:     require('./errors'),
  httpClient: require('./httpClient')
};

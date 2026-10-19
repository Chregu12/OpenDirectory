'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const companyLicenseContext = new AsyncLocalStorage();
module.exports = { companyLicenseContext };

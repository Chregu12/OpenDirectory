'use strict';
jest.mock('ioredis', () => jest.fn(() => ({ on: jest.fn(), get: jest.fn(async () => null), set: jest.fn(async () => 'OK') })));

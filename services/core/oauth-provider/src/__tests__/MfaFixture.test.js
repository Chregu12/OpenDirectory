'use strict';

const { totp, matchedCounter } = require('../MfaAuthority');
const { nextOtp, rememberFactor } = require('./fixtures/mfa.cjs');
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const boundary = 1700000010000;
beforeEach(() => jest.useFakeTimers({now:boundary-1}));
afterEach(() => jest.useRealTimers());

test('a newly requested fixture OTP survives the next window while the oldest allowed code would expire in transit',async()=>{
 const current=Math.floor(Date.now()/30000),last=current-10;
 rememberFactor('boundary-fixture',secret,last);
 const code=await nextOtp('boundary-fixture');
 expect(matchedCounter(secret,totp(secret,current-1),boundary+100,last)).toBeNull();
 expect(matchedCounter(secret,code,boundary+100,last)).toBe(current);
});

test('fixture codes are not reused and wait rather than exceeding the actual next-counter window',async()=>{
 const current=Math.floor(Date.now()/30000);rememberFactor('sequence-fixture',secret,current-1);
 expect(await nextOtp('sequence-fixture')).toBe(totp(secret,current));
 expect(await nextOtp('sequence-fixture')).toBe(totp(secret,current+1));
 let delivered=false;const pending=nextOtp('sequence-fixture').then(code=>{delivered=true;return code;});
 await Promise.resolve();expect(delivered).toBe(false);
 await jest.advanceTimersByTimeAsync(100);const code=await pending;
 expect(matchedCounter(secret,code,Date.now(),current+1)).toBe(current+2);
});

test('an unenrolled fixture does not invent an OTP',async()=>expect(await nextOtp('not-enrolled-fixture')).toBeUndefined());

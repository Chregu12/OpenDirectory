'use strict';
const crypto = require('crypto');

function uuid(seed) {
  const h = crypto.createHash('md5').update(seed || Math.random().toString()).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-4${h.slice(13,16)}-${['8','9','a','b'][parseInt(h[16],16)&3]}${h.slice(17,20)}-${h.slice(20,32)}`.toUpperCase();
}

const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

module.exports = { uuid, now };

function UAParser() {}
UAParser.prototype.setUA = function() { return this; };
UAParser.prototype.getResult = function() {
  return { browser: { name: 'Chrome' }, os: { name: 'macOS' }, device: { type: undefined } };
};
module.exports = UAParser;

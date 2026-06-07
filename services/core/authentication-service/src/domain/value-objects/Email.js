'use strict';
class Email {
  constructor(value) {
    if (!value || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      throw new Error(`Invalid email address: ${value}`);
    }
    this._value = value.toLowerCase().trim();
  }
  get value() { return this._value; }
  toString() { return this._value; }
  equals(other) { return other instanceof Email && other._value === this._value; }
}
module.exports = Email;

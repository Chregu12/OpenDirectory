'use strict';

// Interface / contract — JavaScript convention: throw "Not implemented" for
// any method a concrete repository doesn't override. Mirrors the style of
// device-service's IDeviceRepository.
class IPrinterDriverRepository {
  /**
   * List drivers, optionally filtered.
   * @param {object} [filter]
   * @param {string} [filter.os]
   * @param {string} [filter.format]
   * @returns {Promise<object[]>}
   */
  async list(filter)                            { throw new Error('Not implemented'); }

  /**
   * Get a single driver by id, or null if not found.
   * @param {string} id
   * @returns {Promise<object|null>}
   */
  async get(id)                                 { throw new Error('Not implemented'); }

  /**
   * Add a new driver record (does not store the file — caller moves the file).
   * @param {object} driver
   * @returns {Promise<object>} created driver
   */
  async add(driver)                             { throw new Error('Not implemented'); }

  /**
   * Remove a driver record and its stored file.
   * @param {string} id
   * @returns {Promise<boolean>} true if removed, false if not found
   */
  async remove(id)                              { throw new Error('Not implemented'); }

  /**
   * Assign a driver to a printer (idempotent).
   * @param {string} driverId
   * @param {string} printerId
   * @returns {Promise<object>} updated driver
   */
  async assignToPrinter(driverId, printerId)    { throw new Error('Not implemented'); }

  /**
   * Remove the assignment of a driver from a printer.
   * @param {string} driverId
   * @param {string} printerId
   * @returns {Promise<object>} updated driver
   */
  async unassignFromPrinter(driverId, printerId) { throw new Error('Not implemented'); }

  /**
   * Get all drivers assigned to a specific printer.
   * @param {string} printerId
   * @returns {Promise<object[]>}
   */
  async getForPrinter(printerId)                { throw new Error('Not implemented'); }
}

module.exports = IPrinterDriverRepository;

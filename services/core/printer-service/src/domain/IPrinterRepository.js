'use strict';

// Interface / contract for printer persistence — JavaScript convention: throw
// "Not implemented" for any method a concrete repository doesn't override.
// Mirrors the style of IPrinterDriverRepository.
//
// The concrete implementation used in production is services/printerManager.js:
// it already exposes exactly this surface (addPrinter/getPrinter/listPrinters/
// updatePrinter/removePrinter) backed by PostgreSQL, plus CUPS registration as
// a side effect of add/update/remove. It is deeply coupled to monitoring
// (EventEmitter, setInterval) and CUPS orchestration, so rather than
// duplicating/re-wrapping that logic behind a second adapter, PrinterManager
// itself is treated as the IPrinterRepository implementation and injected
// into PrinterApplicationService under that role.
class IPrinterRepository {
  /**
   * Create a printer.
   * @param {object} config
   * @returns {Promise<object>} created printer record
   */
  async addPrinter(config) { throw new Error('Not implemented'); }

  /**
   * Get a single printer by id.
   * @param {string} id
   * @returns {Promise<object>} printer record
   * @throws if not found
   */
  async getPrinter(id) { throw new Error('Not implemented'); }

  /**
   * List printers, optionally filtered.
   * @param {object} [filters]
   * @returns {Promise<object[]>}
   */
  async listPrinters(filters) { throw new Error('Not implemented'); }

  /**
   * Update a printer.
   * @param {string} id
   * @param {object} updates
   * @returns {Promise<object>} updated printer record
   */
  async updatePrinter(id, updates) { throw new Error('Not implemented'); }

  /**
   * Remove a printer.
   * @param {string} id
   * @returns {Promise<boolean>}
   */
  async removePrinter(id) { throw new Error('Not implemented'); }
}

module.exports = IPrinterRepository;

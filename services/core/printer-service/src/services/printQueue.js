const Bull = require('bull');
const { Pool } = require('pg');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const fs = require('fs').promises;

class PrintJobQueue extends EventEmitter {
  constructor() {
    super();
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers'
    });
    
    // Create Bull queue for print jobs
    this.queue = new Bull('print-jobs', {
      redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD
      }
    });
    
    this.initDatabase();
    this.setupQueueHandlers();
  }

  async initDatabase() {
    try {
      await this.db.query(`
        CREATE TABLE IF NOT EXISTS print_jobs (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          job_number SERIAL,
          printer_id UUID,
          printer_name VARCHAR(255),
          user_id VARCHAR(255) NOT NULL,
          user_name VARCHAR(255),
          document_name VARCHAR(255),
          document_type VARCHAR(50),
          document_size INTEGER,
          page_count INTEGER,
          copies INTEGER DEFAULT 1,
          color BOOLEAN DEFAULT false,
          duplex BOOLEAN DEFAULT false,
          status VARCHAR(50) DEFAULT 'pending',
          priority INTEGER DEFAULT 50,
          options JSONB,
          error_message TEXT,
          submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          started_at TIMESTAMP,
          completed_at TIMESTAMP,
          cancelled_at TIMESTAMP,
          cost DECIMAL(10,2),
          metadata JSONB
        );

        CREATE INDEX idx_job_status ON print_jobs(status);
        CREATE INDEX idx_job_user ON print_jobs(user_id);
        CREATE INDEX idx_job_printer ON print_jobs(printer_id);
        CREATE INDEX idx_job_submitted ON print_jobs(submitted_at);
      `);
      
      this.logger.info('Print queue database initialized');
    } catch (error) {
      this.logger.error('Database initialization error:', error);
    }
  }

  setupQueueHandlers() {
    // Process print jobs
    this.queue.process(async (job) => {
      return this.processPrintJob(job);
    });
    
    // Queue event handlers
    this.queue.on('completed', (job, result) => {
      this.logger.info(`Job ${job.id} completed:`, result);
      this.emit('job:completed', { jobId: job.id, result });
    });
    
    this.queue.on('failed', (job, err) => {
      this.logger.error(`Job ${job.id} failed:`, err);
      this.emit('job:failed', { jobId: job.id, error: err.message });
    });
    
    this.queue.on('progress', (job, progress) => {
      this.emit('job:progress', { jobId: job.id, progress });
    });
  }

  async addJob(jobData) {
    try {
      // Validate job data
      this.validateJobData(jobData);
      
      // Save to database
      const result = await this.db.query(`
        INSERT INTO print_jobs (
          printer_id, printer_name, user_id, user_name,
          document_name, document_type, document_size,
          page_count, copies, color, duplex, priority,
          options, metadata, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING *
      `, [
        jobData.printerId,
        jobData.printerName,
        jobData.userId,
        jobData.userName,
        jobData.documentName || 'Untitled',
        jobData.documentType,
        jobData.documentSize || 0,
        jobData.pageCount || 1,
        jobData.options?.copies || 1,
        jobData.options?.color || false,
        jobData.options?.duplex || false,
        jobData.priority || 50,
        JSON.stringify(jobData.options || {}),
        JSON.stringify(jobData.metadata || {}),
        'queued'
      ]);
      
      const dbJob = result.rows[0];
      
      // Add to Bull queue
      const queueJob = await this.queue.add(
        {
          jobId: dbJob.id,
          ...jobData
        },
        {
          priority: jobData.priority || 50,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 5000
          }
        }
      );
      
      this.emit('job:added', dbJob);
      this.logger.info(`Added print job ${dbJob.id} to queue`);
      
      return dbJob;
    } catch (error) {
      this.logger.error('Add job error:', error);
      throw error;
    }
  }

  async processPrintJob(job) {
    const { jobId, printerId, userId, document, documentType, options } = job.data;
    
    try {
      // Update status to processing
      await this.updateJobStatus(jobId, 'processing', { started_at: 'CURRENT_TIMESTAMP' });
      job.progress(10);
      
      // Get printer info
      const printerResult = await this.db.query(
        'SELECT * FROM printers WHERE id = $1',
        [printerId]
      );
      
      if (printerResult.rows.length === 0) {
        throw new Error('Printer not found');
      }
      
      const printer = printerResult.rows[0];
      job.progress(20);
      
      // Prepare document for printing
      const preparedDoc = await this.prepareDocument(document, documentType, options);
      job.progress(40);
      
      // Send to CUPS
      const cups = require('./cups');
      const cupsIntegration = new cups();
      
      const printResult = await cupsIntegration.printFile(
        printer.name,
        preparedDoc.path,
        {
          copies: options.copies,
          sides: options.duplex ? 'two-sided-long-edge' : 'one-sided',
          media: options.media,
          fitToPage: options.fitToPage,
          landscape: options.landscape,
          pageRanges: options.pageRanges,
          priority: options.priority,
          title: options.documentName || 'Print Job'
        }
      );
      
      job.progress(80);
      
      // Calculate cost
      const cost = await this.calculateCost(jobId, printer, options);
      
      // Update job status
      await this.updateJobStatus(jobId, 'printed', {
        completed_at: 'CURRENT_TIMESTAMP',
        cost
      });
      
      job.progress(90);
      
      // Update printer stats
      await this.updatePrinterStats(printerId, {
        total_jobs: 1,
        page_count: (options.pageCount || 1) * (options.copies || 1)
      });
      
      // Clean up temp file
      if (preparedDoc.isTemp) {
        await fs.unlink(preparedDoc.path).catch(() => {});
      }
      
      job.progress(100);
      
      return {
        success: true,
        jobId,
        cupsJobId: printResult.jobId,
        cost
      };
    } catch (error) {
      this.logger.error(`Print job ${jobId} failed:`, error);
      
      await this.updateJobStatus(jobId, 'failed', {
        error_message: error.message
      });
      
      throw error;
    }
  }

  async prepareDocument(document, documentType, options) {
    // Handle different document formats
    let filePath;
    let isTemp = false;
    
    if (documentType === 'base64') {
      // Decode base64 and save to temp file
      const buffer = Buffer.from(document, 'base64');
      filePath = `/tmp/print_${Date.now()}.pdf`;
      await fs.writeFile(filePath, buffer);
      isTemp = true;
    } else if (documentType === 'url') {
      // Download file from URL
      const axios = require('axios');
      const response = await axios.get(document, { responseType: 'stream' });
      filePath = `/tmp/print_${Date.now()}.pdf`;
      
      const writer = require('fs').createWriteStream(filePath);
      response.data.pipe(writer);
      
      await new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
      });
      
      isTemp = true;
    } else if (documentType === 'path') {
      // Use existing file path
      filePath = document;
    } else if (documentType === 'raw') {
      // Save raw content to temp file
      filePath = `/tmp/print_${Date.now()}.txt`;
      await fs.writeFile(filePath, document);
      isTemp = true;
    } else if (documentType === 'html') {
      // Convert HTML to PDF
      filePath = await this.convertHtmlToPdf(document);
      isTemp = true;
    }
    
    // Apply any document transformations if needed
    if (options.watermark) {
      filePath = await this.addWatermark(filePath, options.watermark);
      isTemp = true;
    }
    
    return { path: filePath, isTemp };
  }

  async convertHtmlToPdf(html) {
    // Simple HTML to PDF conversion
    // In production, use puppeteer or similar
    const tempFile = `/tmp/print_${Date.now()}.pdf`;
    
    // For now, just create a text file
    await fs.writeFile(tempFile, html);
    
    return tempFile;
  }

  async addWatermark(filePath, watermarkText) {
    // Add watermark to PDF
    // In production, use pdf-lib or similar
    return filePath;
  }

  async calculateCost(jobId, printer, options) {
    // Calculate printing cost based on various factors
    const pageCount = options.pageCount || 1;
    const copies = options.copies || 1;
    const totalPages = pageCount * copies;
    
    // Base costs (cents per page)
    const baseCost = options.color ? 10 : 2;
    const duplexDiscount = options.duplex ? 0.8 : 1;
    
    const cost = (totalPages * baseCost * duplexDiscount) / 100;
    
    return cost;
  }

  async updateJobStatus(jobId, status, updates = {}) {
    const fields = ['status = $1'];
    const values = [status];
    let paramCount = 2;
    
    Object.entries(updates).forEach(([key, value]) => {
      if (value === 'CURRENT_TIMESTAMP') {
        fields.push(`${key} = CURRENT_TIMESTAMP`);
      } else {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    });
    
    values.push(jobId);
    
    await this.db.query(`
      UPDATE print_jobs
      SET ${fields.join(', ')}
      WHERE id = $${paramCount}
    `, values);
    
    this.emit('job:status', { jobId, status });
  }

  async updatePrinterStats(printerId, stats) {
    await this.db.query(`
      UPDATE printers
      SET total_jobs = total_jobs + $1,
          page_count = page_count + $2
      WHERE id = $3
    `, [stats.total_jobs, stats.page_count, printerId]);
  }

  async getJob(jobId) {
    const result = await this.db.query(
      'SELECT * FROM print_jobs WHERE id = $1',
      [jobId]
    );
    
    if (result.rows.length === 0) {
      throw new Error('Job not found');
    }
    
    return result.rows[0];
  }

  async listJobs(filters = {}) {
    let query = 'SELECT * FROM print_jobs WHERE 1=1';
    const values = [];
    let paramCount = 1;
    
    if (filters.userId) {
      query += ` AND user_id = $${paramCount}`;
      values.push(filters.userId);
      paramCount++;
    }
    
    if (filters.printerId) {
      query += ` AND printer_id = $${paramCount}`;
      values.push(filters.printerId);
      paramCount++;
    }
    
    if (filters.status) {
      query += ` AND status = $${paramCount}`;
      values.push(filters.status);
      paramCount++;
    }
    
    if (filters.startDate) {
      query += ` AND submitted_at >= $${paramCount}`;
      values.push(filters.startDate);
      paramCount++;
    }
    
    if (filters.endDate) {
      query += ` AND submitted_at <= $${paramCount}`;
      values.push(filters.endDate);
      paramCount++;
    }
    
    query += ' ORDER BY submitted_at DESC LIMIT 100';
    
    const result = await this.db.query(query, values);
    return result.rows;
  }

  async cancelJob(jobId) {
    try {
      const job = await this.getJob(jobId);
      
      if (job.status === 'completed' || job.status === 'cancelled') {
        throw new Error('Cannot cancel completed or already cancelled job');
      }
      
      // Remove from Bull queue if still pending
      const bullJob = await this.queue.getJob(jobId);
      if (bullJob) {
        await bullJob.remove();
      }
      
      // Try to cancel in CUPS if printing
      if (job.status === 'printing') {
        const cups = require('./cups');
        const cupsIntegration = new cups();
        
        try {
          await cupsIntegration.cancelJob(job.cups_job_id);
        } catch (error) {
          this.logger.warn('Could not cancel CUPS job:', error);
        }
      }
      
      // Update database
      await this.updateJobStatus(jobId, 'cancelled', {
        cancelled_at: 'CURRENT_TIMESTAMP'
      });
      
      this.emit('job:cancelled', jobId);
      return true;
    } catch (error) {
      this.logger.error('Cancel job error:', error);
      throw error;
    }
  }

  async retryJob(jobId) {
    try {
      const job = await this.getJob(jobId);
      
      if (job.status !== 'failed') {
        throw new Error('Can only retry failed jobs');
      }
      
      // Create new job with same parameters
      const newJob = await this.addJob({
        printerId: job.printer_id,
        printerName: job.printer_name,
        userId: job.user_id,
        userName: job.user_name,
        documentName: job.document_name,
        documentType: job.document_type,
        options: job.options,
        metadata: { ...job.metadata, retriedFrom: jobId }
      });
      
      return newJob;
    } catch (error) {
      this.logger.error('Retry job error:', error);
      throw error;
    }
  }

  async getQueueStatus() {
    const waiting = await this.queue.getWaitingCount();
    const active = await this.queue.getActiveCount();
    const completed = await this.queue.getCompletedCount();
    const failed = await this.queue.getFailedCount();
    
    return {
      waiting,
      active,
      completed,
      failed,
      total: waiting + active + completed + failed
    };
  }

  async pauseQueue() {
    await this.queue.pause();
    this.logger.info('Print queue paused');
    this.emit('queue:paused');
  }

  async resumeQueue() {
    await this.queue.resume();
    this.logger.info('Print queue resumed');
    this.emit('queue:resumed');
  }

  async clearQueue() {
    await this.queue.empty();
    this.logger.info('Print queue cleared');
    this.emit('queue:cleared');
  }

  validateJobData(jobData) {
    if (!jobData.printerId) {
      throw new Error('Printer ID is required');
    }
    
    if (!jobData.userId) {
      throw new Error('User ID is required');
    }
    
    if (!jobData.document && !jobData.documentPath) {
      throw new Error('Document or document path is required');
    }
    
    if (!jobData.documentType) {
      throw new Error('Document type is required');
    }
    
    const validTypes = ['base64', 'url', 'path', 'raw', 'html'];
    if (!validTypes.includes(jobData.documentType)) {
      throw new Error(`Invalid document type. Must be one of: ${validTypes.join(', ')}`);
    }
  }

  async startProcessor() {
    this.logger.info('Print queue processor started');
    // Queue processing is automatically started in Bull
  }
}

module.exports = PrintJobQueue;
/**
 * Rate Limiting Middleware
 * Protects against abuse and DoS attacks
 */

const config = require('../config');

class RateLimiter {
    constructor() {
        this.requests = new Map();
        this.blacklist = new Set();
        
        // Clean up old entries every minute
        setInterval(() => {
            this.cleanup();
        }, 60000);
    }
    
    cleanup() {
        const now = Date.now();
        const windowMs = config.rateLimiting.windowMs;
        
        for (const [key, requests] of this.requests.entries()) {
            // Remove requests older than the window
            const validRequests = requests.filter(time => now - time < windowMs);
            
            if (validRequests.length === 0) {
                this.requests.delete(key);
            } else {
                this.requests.set(key, validRequests);
            }
        }
    }
    
    isBlacklisted(ip) {
        return this.blacklist.has(ip);
    }
    
    blacklistIP(ip, duration = 24 * 60 * 60 * 1000) { // 24 hours default
        this.blacklist.add(ip);
        
        // Remove from blacklist after duration
        setTimeout(() => {
            this.blacklist.delete(ip);
        }, duration);
    }
    
    checkLimit(identifier) {
        const now = Date.now();
        const windowMs = config.rateLimiting.windowMs;
        const maxRequests = config.rateLimiting.max;
        
        if (!this.requests.has(identifier)) {
            this.requests.set(identifier, []);
        }
        
        const requests = this.requests.get(identifier);
        
        // Remove old requests
        const validRequests = requests.filter(time => now - time < windowMs);
        this.requests.set(identifier, validRequests);
        
        // Check if limit exceeded
        if (validRequests.length >= maxRequests) {
            return {
                allowed: false,
                remaining: 0,
                resetTime: validRequests[0] + windowMs
            };
        }
        
        // Add current request
        validRequests.push(now);
        
        return {
            allowed: true,
            remaining: maxRequests - validRequests.length,
            resetTime: now + windowMs
        };
    }
}

// Create singleton instance
const rateLimiter = new RateLimiter();

/**
 * Rate limiting middleware
 */
const rateLimitMiddleware = (req, res, next) => {
    const ip = req.ip;
    const userId = req.user?.id;
    
    // Check blacklist first
    if (rateLimiter.isBlacklisted(ip)) {
        return res.status(429).json({
            success: false,
            error: 'IP address is blacklisted',
            retryAfter: '24 hours'
        });
    }
    
    // Create identifier (prefer user ID if available, otherwise use IP)
    const identifier = userId || ip;
    
    // Check rate limit
    const result = rateLimiter.checkLimit(identifier);
    
    // Set rate limit headers
    res.set({
        'X-RateLimit-Limit': config.rateLimiting.max,
        'X-RateLimit-Remaining': result.remaining,
        'X-RateLimit-Reset': new Date(result.resetTime).toISOString()
    });
    
    if (!result.allowed) {
        // Check for excessive violations (potential attack)
        const violations = rateLimiter.checkLimit(`violations:${ip}`);
        
        if (!violations.allowed) {
            // Blacklist IP for persistent violations
            rateLimiter.blacklistIP(ip);
            
            return res.status(429).json({
                success: false,
                error: 'Rate limit exceeded. IP has been temporarily blocked.',
                retryAfter: '24 hours'
            });
        }
        
        return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded',
            retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000)
        });
    }
    
    next();
};

/**
 * Strict rate limiting for sensitive endpoints
 */
const strictRateLimit = (maxRequests = 10, windowMs = 15 * 60 * 1000) => {
    const strictLimiter = new RateLimiter();
    
    return (req, res, next) => {
        const identifier = req.user?.id || req.ip;
        
        // Override config for this limiter
        const result = strictLimiter.checkLimit(identifier);
        
        // Custom logic for strict rate limiting
        const requests = strictLimiter.requests.get(identifier) || [];
        const now = Date.now();
        const validRequests = requests.filter(time => now - time < windowMs);
        
        if (validRequests.length >= maxRequests) {
            return res.status(429).json({
                success: false,
                error: 'Strict rate limit exceeded for sensitive operation',
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
        
        validRequests.push(now);
        strictLimiter.requests.set(identifier, validRequests);
        
        next();
    };
};

/**
 * Enhanced rate limiting with adaptive thresholds
 */
const adaptiveRateLimit = (req, res, next) => {
    const ip = req.ip;
    const userId = req.user?.id;
    const userAgent = req.get('User-Agent') || '';
    
    // Detect potential bots or automated tools
    const isBot = /bot|crawler|spider|scraper/i.test(userAgent) ||
                  !userAgent.includes('Mozilla');
    
    // Adjust rate limits based on user type
    let maxRequests = config.rateLimiting.max;
    
    if (isBot) {
        maxRequests = Math.floor(maxRequests * 0.1); // 10% of normal limit for bots
    } else if (!userId) {
        maxRequests = Math.floor(maxRequests * 0.5); // 50% for unauthenticated users
    }
    
    // Apply custom rate limiting logic
    const identifier = userId || ip;
    const result = rateLimiter.checkLimit(identifier);
    
    if (result.remaining < maxRequests && !result.allowed) {
        return res.status(429).json({
            success: false,
            error: 'Adaptive rate limit exceeded',
            retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000),
            limit: maxRequests
        });
    }
    
    res.set('X-RateLimit-Limit', maxRequests);
    next();
};

module.exports = {
    rateLimitMiddleware,
    strictRateLimit,
    adaptiveRateLimit,
    rateLimiter
};
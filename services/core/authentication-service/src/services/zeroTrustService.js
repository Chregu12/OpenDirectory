const crypto = require('crypto');
const logger = require('../utils/logger');
const config = require('../utils/config');

class ZeroTrustService {
  constructor() {
    this.trustFactors = {
      DEVICE_KNOWN: 20,
      LOCATION_KNOWN: 15,
      TIME_PATTERN_NORMAL: 10,
      MFA_ENABLED: 25,
      RECENT_PASSWORD_CHANGE: -10,
      MULTIPLE_FAILED_ATTEMPTS: -20,
      NEW_DEVICE: -15,
      SUSPICIOUS_LOCATION: -25,
      IMPOSSIBLE_TRAVEL: -50,
      VPN_DETECTED: -5,
      TOR_DETECTED: -30
    };
    
    this.deviceRegistry = new Map();
    this.locationHistory = new Map();
    this.behaviorPatterns = new Map();
  }

  async evaluateTrust(request, user) {
    const factors = await this.collectTrustFactors(request, user);
    const score = this.calculateScore(factors);
    
    // Log trust evaluation
    logger.info(`Trust evaluation for user ${user.id}: score=${score}, factors=${JSON.stringify(factors)}`);
    
    // Store evaluation for audit
    await this.storeEvaluation(user.id, score, factors, request);
    
    return score;
  }

  async collectTrustFactors(request, user) {
    const factors = {};
    
    // Device trust
    const deviceId = request.headers['x-device-id'];
    if (deviceId) {
      factors.deviceTrust = await this.evaluateDevice(user.id, deviceId, request);
    }
    
    // Location trust  
    factors.locationTrust = await this.evaluateLocation(user.id, request);
    
    // Time pattern trust
    factors.timeTrust = await this.evaluateTimePattern(user.id);
    
    // Authentication strength
    factors.authStrength = await this.evaluateAuthStrength(user);
    
    // Behavior analysis
    factors.behaviorTrust = await this.evaluateBehavior(user.id, request);
    
    // Network trust
    factors.networkTrust = await this.evaluateNetwork(request);
    
    // Risk indicators
    factors.riskIndicators = await this.evaluateRiskIndicators(user.id, request);
    
    return factors;
  }

  async evaluateDevice(userId, deviceId, request) {
    const trust = {
      score: 0,
      factors: []
    };
    
    // Check if device is registered
    const knownDevice = await this.isKnownDevice(userId, deviceId);
    if (knownDevice) {
      trust.score += this.trustFactors.DEVICE_KNOWN;
      trust.factors.push('known_device');
      
      // Check device health
      const deviceHealth = await this.checkDeviceHealth(deviceId);
      if (deviceHealth.compliant) {
        trust.score += 10;
        trust.factors.push('device_compliant');
      }
    } else {
      trust.score += this.trustFactors.NEW_DEVICE;
      trust.factors.push('new_device');
      
      // Register new device for future
      await this.registerDevice(userId, deviceId, request);
    }
    
    // Check for device fingerprint consistency
    const fingerprint = this.generateDeviceFingerprint(request);
    const fingerprintMatch = await this.verifyFingerprint(deviceId, fingerprint);
    if (!fingerprintMatch) {
      trust.score -= 10;
      trust.factors.push('fingerprint_mismatch');
    }
    
    return trust;
  }

  async evaluateLocation(userId, request) {
    const trust = {
      score: 0,
      factors: []
    };
    
    const location = this.extractLocation(request);
    
    // Check if location is known
    const knownLocation = await this.isKnownLocation(userId, location);
    if (knownLocation) {
      trust.score += this.trustFactors.LOCATION_KNOWN;
      trust.factors.push('known_location');
    }
    
    // Check for impossible travel
    const impossibleTravel = await this.checkImpossibleTravel(userId, location);
    if (impossibleTravel) {
      trust.score += this.trustFactors.IMPOSSIBLE_TRAVEL;
      trust.factors.push('impossible_travel');
    }
    
    // Check if location is suspicious
    const suspicious = await this.isSuspiciousLocation(location);
    if (suspicious) {
      trust.score += this.trustFactors.SUSPICIOUS_LOCATION;
      trust.factors.push('suspicious_location');
    }
    
    // Store location for history
    await this.recordLocation(userId, location);
    
    return trust;
  }

  async evaluateTimePattern(userId) {
    const trust = {
      score: 0,
      factors: []
    };
    
    const currentHour = new Date().getHours();
    const dayOfWeek = new Date().getDay();
    
    // Get user's normal activity pattern
    const pattern = await this.getUserActivityPattern(userId);
    
    if (pattern) {
      // Check if current time matches normal pattern
      const normalTime = pattern.hours.includes(currentHour) && pattern.days.includes(dayOfWeek);
      
      if (normalTime) {
        trust.score += this.trustFactors.TIME_PATTERN_NORMAL;
        trust.factors.push('normal_time_pattern');
      } else {
        trust.score -= 5;
        trust.factors.push('unusual_time');
      }
    }
    
    return trust;
  }

  async evaluateAuthStrength(user) {
    const trust = {
      score: 0,
      factors: []
    };
    
    // MFA enabled
    if (user.mfaEnabled) {
      trust.score += this.trustFactors.MFA_ENABLED;
      trust.factors.push('mfa_enabled');
    }
    
    // Password age
    const passwordAge = Date.now() - new Date(user.passwordChangedAt).getTime();
    const daysSinceChange = passwordAge / (1000 * 60 * 60 * 24);
    
    if (daysSinceChange < 7) {
      trust.score += this.trustFactors.RECENT_PASSWORD_CHANGE;
      trust.factors.push('recent_password_change');
    } else if (daysSinceChange > 90) {
      trust.score -= 5;
      trust.factors.push('old_password');
    }
    
    // Account age
    const accountAge = Date.now() - new Date(user.createdAt).getTime();
    const accountDays = accountAge / (1000 * 60 * 60 * 24);
    
    if (accountDays > 30) {
      trust.score += 5;
      trust.factors.push('established_account');
    }
    
    return trust;
  }

  async evaluateBehavior(userId, request) {
    const trust = {
      score: 0,
      factors: []
    };
    
    // Check recent failed attempts
    const failedAttempts = await this.getRecentFailedAttempts(userId);
    if (failedAttempts > 3) {
      trust.score += this.trustFactors.MULTIPLE_FAILED_ATTEMPTS;
      trust.factors.push('multiple_failed_attempts');
    }
    
    // Check for rapid requests (bot behavior)
    const requestRate = await this.getRequestRate(userId);
    if (requestRate > 100) {
      trust.score -= 15;
      trust.factors.push('high_request_rate');
    }
    
    // Check for unusual API usage
    const apiPattern = await this.analyzeAPIUsage(userId, request.path);
    if (apiPattern.unusual) {
      trust.score -= 10;
      trust.factors.push('unusual_api_pattern');
    }
    
    return trust;
  }

  async evaluateNetwork(request) {
    const trust = {
      score: 0,
      factors: []
    };
    
    const ip = request.ip;
    
    // Check for VPN
    if (await this.isVPN(ip)) {
      trust.score += this.trustFactors.VPN_DETECTED;
      trust.factors.push('vpn_detected');
    }
    
    // Check for Tor
    if (await this.isTor(ip)) {
      trust.score += this.trustFactors.TOR_DETECTED;
      trust.factors.push('tor_detected');
    }
    
    // Check for proxy
    if (await this.isProxy(ip)) {
      trust.score -= 10;
      trust.factors.push('proxy_detected');
    }
    
    // Check IP reputation
    const reputation = await this.getIPReputation(ip);
    if (reputation.score < 50) {
      trust.score -= 20;
      trust.factors.push('poor_ip_reputation');
    }
    
    return trust;
  }

  async evaluateRiskIndicators(userId, request) {
    const risks = {
      score: 0,
      factors: []
    };
    
    // Check for suspicious headers
    if (this.hasSuspiciousHeaders(request)) {
      risks.score -= 10;
      risks.factors.push('suspicious_headers');
    }
    
    // Check for automated tools
    const userAgent = request.headers['user-agent'];
    if (this.isAutomatedTool(userAgent)) {
      risks.score -= 15;
      risks.factors.push('automated_tool');
    }
    
    // Check for session anomalies
    const sessionAnomaly = await this.checkSessionAnomaly(userId, request);
    if (sessionAnomaly) {
      risks.score -= 20;
      risks.factors.push('session_anomaly');
    }
    
    return risks;
  }

  calculateScore(factors) {
    let totalScore = 50; // Base score
    
    for (const factor of Object.values(factors)) {
      if (factor.score !== undefined) {
        totalScore += factor.score;
      }
    }
    
    // Normalize to 0-100
    totalScore = Math.max(0, Math.min(100, totalScore));
    
    return totalScore;
  }

  async calculateTrustScore(request, user) {
    return this.evaluateTrust(request, user);
  }

  async getTrustFactors(userId) {
    // Return the factors that affect trust score for this user
    const evaluation = await this.getLastEvaluation(userId);
    return evaluation?.factors || {};
  }

  async verifyDevice(userId, deviceId, deviceInfo) {
    // Register or verify device
    const device = await this.getDevice(userId, deviceId);
    
    if (!device) {
      // New device - register it
      await this.registerDevice(userId, deviceId, deviceInfo);
      return false; // New devices are not immediately trusted
    }
    
    // Verify device hasn't been tampered with
    const fingerprint = this.calculateDeviceFingerprint(deviceInfo);
    return device.fingerprint === fingerprint;
  }

  async verifyLocation(userId, location) {
    // Check if location is trusted
    const trustedLocations = await this.getTrustedLocations(userId);
    
    for (const trusted of trustedLocations) {
      if (this.isLocationMatch(location, trusted)) {
        return true;
      }
    }
    
    return false;
  }

  async performStepUp(userId, method, value) {
    // Perform additional authentication step
    switch (method) {
      case 'sms':
        return this.verifySMSCode(userId, value);
      case 'email':
        return this.verifyEmailCode(userId, value);
      case 'biometric':
        return this.verifyBiometric(userId, value);
      case 'security_question':
        return this.verifySecurityQuestion(userId, value);
      default:
        throw new Error(`Unknown step-up method: ${method}`);
    }
  }

  // Helper methods
  async isKnownDevice(userId, deviceId) {
    const device = await this.getDevice(userId, deviceId);
    return device && device.trusted;
  }

  async registerDevice(userId, deviceId, info) {
    const fingerprint = this.generateDeviceFingerprint(info);
    
    await this.storeDevice(userId, {
      id: deviceId,
      fingerprint,
      firstSeen: new Date(),
      lastSeen: new Date(),
      trusted: false,
      info
    });
  }

  generateDeviceFingerprint(request) {
    const components = [
      request.headers['user-agent'],
      request.headers['accept-language'],
      request.headers['accept-encoding'],
      request.headers['x-screen-resolution'],
      request.headers['x-timezone']
    ];
    
    return crypto
      .createHash('sha256')
      .update(components.filter(Boolean).join('|'))
      .digest('hex');
  }

  calculateDeviceFingerprint(deviceInfo) {
    const components = [
      deviceInfo.userAgent,
      deviceInfo.screenResolution,
      deviceInfo.timezone,
      deviceInfo.language,
      deviceInfo.platform
    ];
    
    return crypto
      .createHash('sha256')
      .update(components.filter(Boolean).join('|'))
      .digest('hex');
  }

  extractLocation(request) {
    return {
      ip: request.ip,
      country: request.headers['cf-ipcountry'],
      city: request.headers['cf-city'],
      latitude: request.headers['cf-latitude'],
      longitude: request.headers['cf-longitude'],
      timestamp: new Date()
    };
  }

  async isKnownLocation(userId, location) {
    const history = this.locationHistory.get(userId) || [];
    
    return history.some(historic => 
      this.isLocationMatch(location, historic)
    );
  }

  isLocationMatch(loc1, loc2, tolerance = 50) {
    if (!loc1.latitude || !loc2.latitude) {
      return loc1.country === loc2.country && loc1.city === loc2.city;
    }
    
    // Calculate distance in km
    const distance = this.calculateDistance(
      loc1.latitude, loc1.longitude,
      loc2.latitude, loc2.longitude
    );
    
    return distance <= tolerance;
  }

  calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in km
    const dLat = this.toRad(lat2 - lat1);
    const dLon = this.toRad(lon2 - lon1);
    
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(this.toRad(lat1)) * Math.cos(this.toRad(lat2)) *
      Math.sin(dLon/2) * Math.sin(dLon/2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  toRad(degrees) {
    return degrees * (Math.PI/180);
  }

  async checkImpossibleTravel(userId, location) {
    const history = this.locationHistory.get(userId) || [];
    if (history.length === 0) return false;
    
    const lastLocation = history[history.length - 1];
    const timeDiff = (location.timestamp - lastLocation.timestamp) / 1000 / 60 / 60; // hours
    
    if (timeDiff > 24) return false; // Too much time has passed
    
    const distance = this.calculateDistance(
      lastLocation.latitude, lastLocation.longitude,
      location.latitude, location.longitude
    );
    
    // Maximum travel speed (km/h) - accounting for flights
    const maxSpeed = 900;
    const possibleDistance = maxSpeed * timeDiff;
    
    return distance > possibleDistance;
  }

  async isSuspiciousLocation(location) {
    // Check against list of suspicious countries/regions
    const suspiciousCountries = config.security.suspiciousCountries || [];
    return suspiciousCountries.includes(location.country);
  }

  async recordLocation(userId, location) {
    const history = this.locationHistory.get(userId) || [];
    history.push(location);
    
    // Keep only last 100 locations
    if (history.length > 100) {
      history.shift();
    }
    
    this.locationHistory.set(userId, history);
  }

  async getUserActivityPattern(userId) {
    // Get stored activity pattern for user
    return this.behaviorPatterns.get(userId);
  }

  async getRecentFailedAttempts(userId) {
    // Get failed login attempts in last hour
    // This would typically query a database
    return 0;
  }

  async getRequestRate(userId) {
    // Get requests per minute for this user
    // This would typically query a rate limiting service
    return 0;
  }

  async analyzeAPIUsage(userId, path) {
    // Analyze if this API path is unusual for this user
    return { unusual: false };
  }

  async isVPN(ip) {
    // Check against VPN detection service
    // This would typically use a service like IPQualityScore
    return false;
  }

  async isTor(ip) {
    // Check against Tor exit node list
    return false;
  }

  async isProxy(ip) {
    // Check against proxy detection service
    return false;
  }

  async getIPReputation(ip) {
    // Get IP reputation score
    // This would typically use a service like AbuseIPDB
    return { score: 100 };
  }

  hasSuspiciousHeaders(request) {
    // Check for suspicious or missing headers
    const requiredHeaders = ['user-agent', 'accept', 'accept-language'];
    
    for (const header of requiredHeaders) {
      if (!request.headers[header]) {
        return true;
      }
    }
    
    return false;
  }

  isAutomatedTool(userAgent) {
    if (!userAgent) return true;
    
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i
    ];
    
    return botPatterns.some(pattern => pattern.test(userAgent));
  }

  async checkSessionAnomaly(userId, request) {
    // Check for session-related anomalies
    return false;
  }

  async checkDeviceHealth(deviceId) {
    // Check device compliance status
    return { compliant: true };
  }

  async verifyFingerprint(deviceId, fingerprint) {
    const device = this.deviceRegistry.get(deviceId);
    return device && device.fingerprint === fingerprint;
  }

  async getDevice(userId, deviceId) {
    // Get device from registry
    return this.deviceRegistry.get(`${userId}:${deviceId}`);
  }

  async storeDevice(userId, device) {
    this.deviceRegistry.set(`${userId}:${device.id}`, device);
  }

  async getTrustedLocations(userId) {
    // Get list of trusted locations for user
    return [];
  }

  async verifySMSCode(userId, code) {
    // Verify SMS code
    return { success: true };
  }

  async verifyEmailCode(userId, code) {
    // Verify email code
    return { success: true };
  }

  async verifyBiometric(userId, data) {
    // Verify biometric data
    return { success: true };
  }

  async verifySecurityQuestion(userId, answer) {
    // Verify security question answer
    return { success: true };
  }

  async storeEvaluation(userId, score, factors, request) {
    // Store trust evaluation for audit
    logger.debug(`Trust evaluation stored for user ${userId}: ${score}`);
  }

  async getLastEvaluation(userId) {
    // Get last trust evaluation for user
    return null;
  }
}

module.exports = ZeroTrustService;
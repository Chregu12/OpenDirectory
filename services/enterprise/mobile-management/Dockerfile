FROM node:18-alpine

LABEL maintainer="OpenDirectory Team"
LABEL version="1.0.0"
LABEL description="Enterprise Mobile Management Suite"

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm ci --only=production

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S mobile -u 1001

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /tmp/mam-apps && \
    chown -R mobile:nodejs /tmp/mam-apps

# Switch to non-root user
USER mobile

# Expose ports for all mobile services
EXPOSE 3011 3012 3013 3014

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "
    const http = require('http');
    const services = [
      { name: 'iOS Management', port: 3011 },
      { name: 'Android Enterprise', port: 3012 },
      { name: 'Mobile App Management', port: 3013 },
      { name: 'Mobile Threat Defense', port: 3014 }
    ];
    
    Promise.all(services.map(service => {
      return new Promise((resolve) => {
        const req = http.request({
          hostname: 'localhost',
          port: service.port,
          path: '/health',
          timeout: 2000
        }, (res) => resolve(res.statusCode === 200));
        req.on('error', () => resolve(false));
        req.end();
      });
    })).then(results => {
      const healthy = results.filter(r => r).length;
      if (healthy >= 2) { // At least 2 services must be healthy
        process.exit(0);
      } else {
        process.exit(1);
      }
    });
  "

# Default command to start all services
CMD ["npm", "run", "start:all"]
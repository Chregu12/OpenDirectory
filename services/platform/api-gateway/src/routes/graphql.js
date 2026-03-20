/**
 * GraphQL Proxy Route for API Gateway
 * Proxies /graphql requests to the Integration Hub's GraphQL endpoint
 */

const { createProxyMiddleware } = require('http-proxy-middleware');

const INTEGRATION_HUB_HOST = process.env.INTEGRATION_HUB_HOST || 'localhost';
const INTEGRATION_HUB_GRAPHQL_PORT = process.env.INTEGRATION_HUB_GRAPHQL_PORT || 3001;

function setupGraphQLRoute(app, logger) {
    const graphqlProxy = createProxyMiddleware({
        target: `http://${INTEGRATION_HUB_HOST}:${INTEGRATION_HUB_GRAPHQL_PORT}`,
        changeOrigin: true,
        pathRewrite: {
            '^/graphql': '/graphql'
        },
        onProxyReq: (proxyReq, req) => {
            proxyReq.setHeader('X-Gateway-ID', 'auto-extending-gateway');
            proxyReq.setHeader('X-Request-ID', req.id || 'unknown');

            if (req.user) {
                proxyReq.setHeader('X-User-ID', req.user.id || req.user.sub || '');
                proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles || []));
            }

            if (logger) {
                logger.debug(`GraphQL proxy: ${req.method} ${req.path} -> integration-hub:${INTEGRATION_HUB_GRAPHQL_PORT}`);
            }
        },
        onProxyRes: (proxyRes) => {
            proxyRes.headers['X-Gateway-Service'] = 'graphql';
            proxyRes.headers['X-Powered-By'] = 'OpenDirectory GraphQL';
        },
        onError: (err, req, res) => {
            if (logger) {
                logger.error('GraphQL proxy error:', err.message);
            }

            if (!res.headersSent) {
                res.status(502).json({
                    error: 'GraphQL service unavailable',
                    message: 'The Integration Hub GraphQL endpoint is not reachable',
                    timestamp: new Date().toISOString()
                });
            }
        }
    });

    // Mount GraphQL endpoint (skip auth for GraphiQL browser)
    app.use('/graphql', graphqlProxy);

    if (logger) {
        logger.info(`GraphQL proxy configured -> http://${INTEGRATION_HUB_HOST}:${INTEGRATION_HUB_GRAPHQL_PORT}/graphql`);
    }
}

module.exports = { setupGraphQLRoute };

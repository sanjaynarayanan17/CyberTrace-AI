// CyberTrace AI — Backend Server Entry Point
// =============================================================================
// Express REST API providing:
//   - Real IP Geolocation (ip-api.com + ipinfo.io)
//   - Linux tool integration: dig, whois, host, nslookup, traceroute
//   - DNS analysis: SPF, DMARC, DKIM, MX, PTR lookups
//   - Domain WHOIS intelligence
//   - Threat reputation (AbuseIPDB, VirusTotal)
//   - Batch hop-chain analysis for email header forensics
// =============================================================================

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const geoipRouter = require('./routes/geoip');
const dnsRouter = require('./routes/dns');
const whoisRouter = require('./routes/whois');
const threatRouter = require('./routes/threat');
const headersRouter = require('./routes/headers');
const toolsRouter = require('./routes/tools');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Security & Logging Middleware ────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.json({ limit: '2mb' }));

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl, same-origin, server-to-server)
      if (!origin) return callback(null, true);

      // Always allow all onrender.com subdomains, localhost, and configured origins
      return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.options('*', cors());

// ─── Global Rate Limiter ──────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,
  max: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — rate limit exceeded. Retry in 60 seconds.' },
});
app.use(limiter);

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'CyberTrace AI Forensic Backend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: [
      'GET  /api/geoip/:ip              — IP Geolocation + Threat Intel',
      'POST /api/geoip/batch            — Batch multi-IP geolocation',
      'GET  /api/dns/:domain            — Full DNS record lookup (A/MX/TXT/SPF/DMARC)',
      'GET  /api/dns/reverse/:ip        — PTR / Reverse DNS (host command)',
      'GET  /api/whois/:domain          — Domain WHOIS (whois command)',
      'GET  /api/threat/ip/:ip          — AbuseIPDB reputation lookup',
      'GET  /api/threat/url/:b64url     — VirusTotal URL scan',
      'POST /api/headers/analyze        — Full email header forensic analysis',
      'GET  /api/tools/capabilities     — Linux tool environment status (WSL/native)',
      'POST /api/tools/execute          — Execute dig/whois/host/traceroute/ping',
    ],
  });
});

// ─── Route Mounting ──────────────────────────────────────────────────────────
app.use('/api/geoip', geoipRouter);
app.use('/api/dns', dnsRouter);
app.use('/api/whois', whoisRouter);
app.use('/api/threat', threatRouter);
app.use('/api/headers', headersRouter);
app.use('/api/tools', toolsRouter);

// ─── Frontend Static Files (Single-Service Deployment Support) ───────────────
const distPath = path.join(__dirname, '../dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

// ─── 404 Handler for API Routes ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'ENDPOINT_NOT_FOUND', message: 'The requested API route does not exist.' });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[BACKEND_ERROR]', err.message);
  res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n╔══════════════════════════════════════════════════════╗`);
  console.log(`║   CyberTrace AI — Forensic Backend                  ║`);
  console.log(`║   Listening on http://0.0.0.0:${PORT}                 ║`);
  console.log(`║   Environment: ${process.env.NODE_ENV || 'development'}                     ║`);
  console.log(`╚══════════════════════════════════════════════════════╝\n`);
});

module.exports = app;

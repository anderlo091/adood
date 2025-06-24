import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csurf from 'csurf';
import session from 'express-session';
import RedisStore from 'connect-redis';
import Redis from 'ioredis';
import { createHmac, randomBytes } from 'crypto';
import { AES, enc } from 'crypto-js';
import sanitizeHtml from 'sanitize-html';
import { ipRangeCheck } from 'ip-range-check';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import winston from 'winston';
import React from 'react';
import { renderToString } from 'react-dom/server';

// Logger setup
const logger = winston.createLogger({
  level: 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} - ${level.toUpperCase()} - ${message}`)
  ),
  transports: [new winston.transports.Console()]
});

// Embedded environment variables (move to .env after testing)
const REDIS_HOST = 'valkey-c93d570-marychamberlin31-5857.g.aivencloud.com';
const REDIS_PORT = 25534;
const REDIS_USERNAME = 'default';
const REDIS_PASSWORD = 'AVNS_iypeRGpnvMGXCd4ayYL';
const SESSION_SECRET = 'b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9';
const AES_KEY = '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809';
const HMAC_KEY = '0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9';
const USER_TXT_URL = 'https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt';
const DOMAIN = 'tamarisksd.com';

// Redis client
const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  username: REDIS_USERNAME,
  password: REDIS_PASSWORD,
  tls: {}
});
redis.on('error', (err) => logger.error(`Redis error: ${err}`));

// Blocked IP ranges (initial AWS/Azure ranges, updated dynamically)
let blockedIpRanges: string[] = [
  '3.5.0.0/16', '13.107.0.0/16' // Placeholder ranges
];

// Update IP ranges daily
const updateIpRanges = async () => {
  try {
    const [awsRes, azureRes] = await Promise.all([
      axios.get('https://ip-ranges.amazonaws.com/ip-ranges.json'),
      axios.get('https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250624.json')
    ]);
    const awsRanges = awsRes.data.prefixes.map((p: any) => p.ip_prefix);
    const azureRanges = azureRes.data.values.flatMap((v: any) => v.properties.addressPrefixes);
    blockedIpRanges = [...new Set([...awsRanges, ...azureRanges])];
    await redis.set('blocked_ip_ranges', JSON.stringify(blockedIpRanges), 'EX', 24 * 60 * 60);
    logger.info('Updated AWS/Azure IP ranges');
  } catch (err) {
    logger.error(`Failed to update IP ranges: ${err}`);
  }
};
setInterval(updateIpRanges, 24 * 60 * 60 * 1000);
updateIpRanges();

// Express setup
const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://cdn.tailwindcss.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com']
    }
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new RedisStore({ client: redis }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));
app.use(csurf());

// Rate limiting
const rateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip || 'unknown',
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: 'Too Many Requests' });
  }
});
app.use(rateLimiter);

// Bot detection middleware
interface RequestScore {
  ip: string;
  userAgent: string;
  headers: Record<string, string | undefined>;
  score: number;
  reasons: string[];
}

const botDetection = async (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || 'unknown';
  const userAgent = req.headers['user-agent'] || '';
  const score: RequestScore = { ip, userAgent, headers: req.headers, score: 0, reasons: [] };

  // Check blocked IP ranges
  if (ip && blockedIpRanges.some(range => ipRangeCheck(ip, range))) {
    score.score += 100;
    score.reasons.push('IP in AWS/Azure range');
  }

  // User-agent analysis
  const botPatterns = [/bot/i, /crawler/i, /spider/i, /amazon/i, /microsoft/i];
  if (botPatterns.some(pattern => pattern.test(userAgent))) {
    score.score += 50;
    score.reasons.push('Bot-like user-agent');
  }

  // Request pattern analysis
  const requestCount = await redis.incr(`request_count:${ip}`);
  await redis.expire(`request_count:${ip}`, 60);
  if (requestCount > 50) {
    score.score += 30;
    score.reasons.push('High request rate');
  }

  // Header analysis
  if (!req.headers['accept'] || !req.headers['referer']) {
    score.score += 20;
    score.reasons.push('Missing common headers');
  }

  // JavaScript challenge for suspicious requests
  if (score.score >= 50 && req.method === 'GET' && !req.session.jsChallengePassed) {
    const challenge = randomBytes(16).toString('hex');
    await redis.set(`js_challenge:${ip}`, challenge, 'EX', 300);
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Verification</title>
      </head>
      <body>
        <script>
          fetch('/verify-js/${challenge}', { method: 'POST' })
            .then(() => window.location.reload());
        </script>
      </body>
      </html>
    `);
  }

  if (score.score >= 100) {
    logger.warn(`Blocked request: IP=${ip}, Score=${score.score}, Reasons=${score.reasons.join(', ')}`);
    return res.status(403).json({ error: 'Access Denied' });
  }

  next();
};
app.use(botDetection);

// JavaScript challenge verification
app.post('/verify-js/:challenge', async (req: Request, res: Response) => {
  const { challenge } = req.params;
  const ip = req.ip || 'unknown';
  const storedChallenge = await redis.get(`js_challenge:${ip}`);
  if (storedChallenge === challenge) {
    req.session.jsChallengePassed = true;
    await redis.del(`js_challenge:${ip}`);
    return res.json({ status: 'ok' });
  }
  return res.status(403).json({ error: 'Invalid challenge' });
});

// Encryption utilities
const encryptPayload = (payload: string): string => {
  const iv = randomBytes(16).toString('hex').slice(0, 16);
  const encrypted = AES.encrypt(payload, AES_KEY, { iv: enc.Utf8.parse(iv) }).toString();
  const hmac = createHmac('sha256', HMAC_KEY).update(encrypted).digest('base64');
  return `${iv}.${encrypted}.${hmac}`;
};

const decryptPayload = (encrypted: string): string => {
  const [iv, ciphertext, hmac] = encrypted.split('.');
  const computedHmac = createHmac('sha256', HMAC_KEY).update(ciphertext).digest('base64');
  if (hmac !== computedHmac) throw new Error('HMAC verification failed');
  const decrypted = AES.decrypt(ciphertext, AES_KEY, { iv: enc.Utf8.parse(iv) }).toString(enc.Utf8);
  return decrypted;
};

// Authentication
const getValidUsernames = async (): Promise<string[]> => {
  try {
    const cached = await redis.get('usernames');
    if (cached) return JSON.parse(cached);
    const res = await axios.get(USER_TXT_URL);
    const usernames = res.data.split('\n').map((line: string) => sanitizeHtml(line.trim())).filter(Boolean);
    await redis.set('usernames', JSON.stringify(usernames), 'EX', 3600);
    return usernames;
  } catch (err) {
    logger.error(`Failed to fetch usernames: ${err}`);
    return [];
  }
};

const loginRequired = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session.username) {
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
};

// Inline React components
interface LoginProps {
  csrfToken: string;
  nextUrl: string;
}

const LoginPage: React.FC<LoginProps> = ({ csrfToken, nextUrl }) => {
  return (
    <div className="bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
      <h1 className="text-3xl font-extrabold mb-6 text-center text-gray-900">Login</h1>
      <form method="POST" action="/login" className="space-y-5">
        <input type="hidden" name="_csrf" value={csrfToken} />
        <input type="hidden" name="next" value={nextUrl} />
        <div>
          <label className="block text-sm font-medium text-gray-700">Username</label>
          <input
            type="text"
            name="username"
            className="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition"
        >
          Login
        </button>
      </form>
    </div>
  );
};

interface UrlData {
  url: string;
  destination: string;
  created: string;
  expiry: string;
  clicks: number;
  analyticsEnabled: boolean;
  urlId: string;
}

interface DashboardProps {
  username: string;
  urls: UrlData[];
  csrfToken: string;
}

const DashboardPage: React.FC<DashboardProps> = ({ username, urls, csrfToken }) => {
  return (
    <div className="container max-w-7xl mx-auto">
      <h1 className="text-4xl font-extrabold mb-8 text-center text-white">Welcome, {username}</h1>
      <div className="bg-white p-8 rounded-xl shadow-lg mb-8">
        <h2 className="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
        <form method="POST" action="/generate-url" className="space-y-5">
          <input type="hidden" name="_csrf" value={csrfToken} />
          <div>
            <label className="block text-sm font-medium text-gray-700">Subdomain</label>
            <input
              type="text"
              name="subdomain"
              className="mt-1 w-full p-3 border rounded-lg"
              required
              pattern="[a-zA-Z0-9-]{2,100}"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Randomstring1</label>
            <input
              type="text"
              name="randomstring1"
              className="mt-1 w-full p-3 border rounded-lg"
              required
              pattern="[a-zA-Z0-9_@.]{2,100}"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Destination Link</label>
            <input
              type="url"
              name="destination"
              className="mt-1 w-full p-3 border rounded-lg"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Randomstring2</label>
            <input
              type="text"
              name="randomstring2"
              className="mt-1 w-full p-3 border rounded-lg"
              required
              pattern="[a-zA-Z0-9_@.]{2,100}"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Expiry</label>
            <select name="expiry" className="mt-1 w-full p-3 border rounded-lg">
              <option value="3600">1 Hour</option>
              <option value="86400" selected>1 Day</option>
              <option value="604800">1 Week</option>
              <option value="2592000">1 Month</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">
              <input type="checkbox" name="analytics_enabled" /> Enable Analytics
            </label>
          </div>
          <button
            type="submit"
            className="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700"
          >
            Generate URL
          </button>
        </form>
      </div>
      <div className="bg-white p-8 rounded-xl shadow-lg">
        <h2 className="text-2xl font-bold mb-6 text-gray-900">URL History</h2>
        {urls.length > 0 ? (
          urls.map((url, index) => (
            <div key={url.urlId} className="bg-gray-50 p-6 rounded-lg mb-4">
              <h3 className="text-xl font-semibold text-gray-900">{url.destination}</h3>
              <p className="text-gray-600 break-all">
                <strong>URL:</strong> <a href={url.url} target="_blank" className="text-indigo-600">{url.url}</a>
              </p>
              <p className="text-gray-600"><strong>Created:</strong> {new Date(url.created).toLocaleString()}</p>
              <p className="text-gray-600"><strong>Expires:</strong> {new Date(url.expiry).toLocaleString()}</p>
              <p className="text-gray-600"><strong>Clicks:</strong> {url.clicks}</p>
              <div className="flex items-center mt-2">
                <label className="text-sm font-medium text-gray-700 mr-2">Analytics:</label>
                <input
                  type="checkbox"
                  checked={url.analyticsEnabled}
                  onChange={() => {
                    fetch(`/toggle-analytics/${url.urlId}`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ _csrf: csrfToken })
                    });
                  }}
                />
              </div>
              <a
                href={`/delete-url/${url.urlId}`}
                className="mt-2 inline-block bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700"
                onClick={(e: any) => confirm('Are you sure?') || e.preventDefault()}
              >
                Delete URL
              </a>
            </div>
          ))
        ) : (
          <p className="text-gray-600">No URLs generated yet.</p>
        )}
      </div>
    </div>
  );
};

// Routes
app.get('/login', async (req: Request, res: Response) => {
  const nextUrl = sanitizeHtml(req.query.next as string || '');
  const csrfToken = req.csrfToken();
  const html = renderToString(<LoginPage csrfToken={csrfToken} nextUrl={nextUrl} />);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="robots" content="noindex, nofollow">
      <title>Login</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen flex items-center justify-center p-4 bg-gradient-to-r from-indigo-600 to-purple-600">
      ${html}
    </body>
    </html>
  `);
});

app.post('/login', async (req: Request, res: Response) => {
  const { username, next: nextUrl } = req.body;
  const sanitizedUsername = sanitizeHtml(username?.trim() || '');
  if (!sanitizedUsername || sanitizedUsername.length < 2 || sanitizedUsername.length > 100) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  const validUsernames = await getValidUsernames();
  if (!validUsernames.includes(sanitizedUsername)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.session.username = sanitizedUsername;
  logger.info(`User ${sanitizedUsername} logged in`);
  return res.redirect(sanitizeHtml(nextUrl) || '/dashboard');
});

app.get('/dashboard', loginRequired, async (req: Request, res: Response) => {
  const username = req.session.username!;
  const csrfToken = req.csrfToken();
  const urls: UrlData[] = [];
  try {
    const urlKeys = await redis.keys(`user:${username}:url:*`);
    for (const key of urlKeys) {
      const data = await redis.hgetall(key);
      urls.push({
        url: data.url,
        destination: data.destination,
        created: new Date(Number(data.created) * 1000).toISOString(),
        expiry: new Date(Number(data.expiry) * 1000).toISOString(),
        clicks: Number(data.clicks),
        analyticsEnabled: data.analytics_enabled === '1',
        urlId: key.split(':').pop()!
      });
    }
  } catch (err) {
    logger.error(`Failed to fetch URLs: ${err}`);
  }
  const html = renderToString(<DashboardPage username={username} urls={urls} csrfToken={csrfToken} />);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="robots" content="noindex, nofollow">
      <title>Dashboard - ${username}</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen p-4 bg-gradient-to-r from-indigo-600 to-purple-600">
      ${html}
    </body>
    </html>
  `);
});

app.post('/generate-url', loginRequired, async (req: Request, res: Response) => {
  const username = req.session.username!;
  const { subdomain, randomstring1, destination, randomstring2, expiry, analytics_enabled } = req.body;
  const sanitized = {
    subdomain: sanitizeHtml(subdomain?.trim() || ''),
    randomstring1: sanitizeHtml(randomstring1?.trim() || ''),
    destination: sanitizeHtml(destination?.trim() || ''),
    randomstring2: sanitizeHtml(randomstring2?.trim() || ''),
    expiry: Number(expiry) || 86400,
    analyticsEnabled: !!analytics_enabled
  };

  if (!/^[a-zA-Z0-9-]{2,100}$/.test(sanitized.subdomain)) {
    return res.status(400).json({ error: 'Invalid subdomain' });
  }
  if (!/^[a-zA-Z0-9_@.]{2,100}$/.test(sanitized.randomstring1) || !/^[a-zA-Z0-9_@.]{2,100}$/.test(sanitized.randomstring2)) {
    return res.status(400).json({ error: 'Invalid random strings' });
  }
  if (!/^https?:\/\//.test(sanitized.destination)) {
    return res.status(400).json({ error: 'Invalid destination URL' });
  }

  const endpoint = randomBytes(8).toString('hex');
  const expiryTimestamp = Math.floor(Date.now() / 1000) + sanitized.expiry;
  const payload = JSON.stringify({
    destination: sanitized.destination,
    timestamp: Math.floor(Date.now() / 1000),
    expiry: expiryTimestamp
  });
  const encryptedPayload = encryptPayload(payload);
  const pathSegment = `${sanitized.randomstring1}${sanitized.randomstring2}/${uuidv4()}${randomBytes(10).toString('hex')}`;
  const generatedUrl = `https://${sanitized.subdomain}.${DOMAIN}/${endpoint}/${encodeURIComponent(encryptedPayload)}/${encodeURIComponent(pathSegment)}`;
  const urlId = createHmac('sha256', HMAC_KEY).update(endpoint + encryptedPayload).digest('hex');

  try {
    await redis.hset(`user:${username}:url:${urlId}`, {
      url: generatedUrl,
      destination: sanitized.destination,
      encrypted_payload: encryptedPayload,
      endpoint,
      created: Math.floor(Date.now() / 1000),
      expiry: expiryTimestamp,
      clicks: 0,
      analytics_enabled: sanitized.analyticsEnabled ? '1' : '0'
    });
    await redis.expire(`user:${username}:url:${urlId}`, 90 * 24 * 60 * 60);
    logger.info(`Generated URL for ${username}: ${generatedUrl}`);
    return res.redirect('/dashboard');
  } catch (err) {
    logger.error(`Failed to store URL: ${err}`);
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/toggle-analytics/:urlId', loginRequired, async (req: Request, res: Response) => {
  const username = req.session.username!;
  const { urlId } = req.params;
  try {
    const key = `user:${username}:url:${urlId}`;
    if (!(await redis.exists(key))) {
      return res.status(404).json({ error: 'URL not found' });
    }
    const current = await redis.hget(key, 'analytics_enabled');
    await redis.hset(key, 'analytics_enabled', current === '1' ? '0' : '1');
    return res.json({ status: 'ok' });
  } catch (err) {
    logger.error(`Failed to toggle analytics: ${err}`);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/delete-url/:urlId', loginRequired, async (req: Request, res: Response) => {
  const username = req.session.username!;
  const { urlId } = req.params;
  try {
    const key = `user:${username}:url:${urlId}`;
    if (!(await redis.exists(key))) {
      return res.status(404).json({ error: 'URL not found' });
    }
    await redis.del(key);
    return res.redirect('/dashboard');
  } catch (err) {
    logger.error(`Failed to delete URL: ${err}`);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/:endpoint/:encryptedPayload/:pathSegment', async (req: Request, res: Response) => {
  const { endpoint, encryptedPayload, pathSegment } = req.params;
  const username = req.subdomains[0] || req.hostname.split('.')[0] || 'default';
  const urlId = createHmac('sha256', HMAC_KEY).update(endpoint + encryptedPayload).digest('hex');

  try {
    const analyticsEnabled = await redis.hget(`user:${username}:url:${urlId}`, 'analytics_enabled') === '1';
    if (analyticsEnabled) {
      await redis.hincrby(`user:${username}:url:${urlId}`, 'clicks', 1);
    }
  } catch (err) {
    logger.error(`Failed to log click: ${err}`);
  }

  let payload: string | null = null;
  try {
    const cached = await redis.get(`url_payload:${urlId}`);
    if (cached) {
      payload = cached;
    } else {
      payload = decryptPayload(decodeURIComponent(encryptedPayload));
      const { expiry } = JSON.parse(payload);
      await redis.set(`url_payload:${urlId}`, payload, 'EX', Math.max(1, expiry - Math.floor(Date.now() / 1000)));
    }
  } catch (err) {
    logger.error(`Decryption failed: ${err}`);
    return res.status(400).send('Invalid or expired link');
  }

  try {
    const { destination, expiry } = JSON.parse(payload);
    if (Math.floor(Date.now() / 1000) > expiry) {
      await redis.del(`url_payload:${urlId}`);
      return res.status(410).send('Link expired');
    }
    const cleanedPath = pathSegment.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[0-9a-f]+$/i, '');
    const finalUrl = `${destination.replace(/\/$/, '')}/${cleanedPath.replace(/^\//, '')}`;
    logger.info(`Redirecting to ${finalUrl}`);
    return res.redirect(302, finalUrl);
  } catch (err) {
    logger.error(`Payload error: ${err}`);
    return res.status(400).send('Invalid payload');
  }
});

app.use((req: Request, res: Response) => {
  logger.warn(`404 for ${req.url}`);
  res.status(404).send('Not Found');
});

export default app;
// @ts-nocheck
// ============================================================================
// ULTIMATE VLESS PROXY WORKER - COMBINED SCRIPT
// ============================================================================

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  scamalytics: {
    username: '', 
    apiKey: '',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },
  
  async fromEnv(env) {
    let selectedProxyIP = null;

    // Health Check & Auto-Switching from DB
    if (env.DB) {
      try {
        const { results } = await env.DB.prepare("SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1").all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`Using best healthy proxy IP from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined");
        selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ADMIN_LOGIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  AUTO_REFRESH_INTERVAL: 60000,
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000,
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    nonce ? `script-src 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: https: blob: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: ${cspDomains.connect || ''}`.trim(),
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=0');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aLen = a.length;
  const bLen = b.length;
  let result = 0;

  if (aLen !== bLen) {
    for (let i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  
  for (let i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// KEY-VALUE STORE (D1-based)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error(`kvGet: Database not available for key ${key}`);
    return null;
  }
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      try {
        return JSON.parse(res.value);
      } catch (e) {
        console.error(`Failed to parse JSON for key ${key}: ${e}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error(`kvPut: Database not available for key ${key}`);
    return;
  }
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error(`kvPut error for ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error(`kvDelete: Database not available for key ${key}`);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e}`);
  }
}

// ============================================================================
// USER DATA MANAGEMENT
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`Failed to get cached data for ${uuid}`, e);
    }

    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    while (!lockAcquired) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
      .bind(usage, uuid)
      .run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error(`Failed to release lock for ${uuid}:`, e);
      }
    }
  }
}

// ============================================================================
// SUBSCRIPTION GENERATION (با منطق اسکریپت اول)
// ============================================================================

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}${query ? `?${query}` : ''}`;
}

/**
 * Helper function to randomize uppercase and lowercase letters in a string
 * این تابع برای SNI randomization استفاده می‌شود
 */
function randomizeCase(str) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

// CORE_PRESETS با تنظیمات صحیح از اسکریپت اول
const CORE_PRESETS = {
  // Xray cores
  xray: {
    tls: {
      path: () => generateRandomPath(12, 'ed=2560'),
      security: 'tls',
      fp: 'chrome',
      alpn: 'http/1.1',
      extra: {},
    },
    tcp: {
      path: () => generateRandomPath(12, 'ed=2560'),
      security: 'none',
      fp: 'chrome',
      extra: {},
    },
  },

  // Singbox cores
  sb: {
    tls: {
      path: () => generateRandomPath(18),
      security: 'tls',
      fp: 'chrome',
      alpn: 'http/1.1',
      extra: CONST.ED_PARAMS,
    },
    tcp: {
      path: () => generateRandomPath(18),
      security: 'none',
      fp: 'chrome',
      extra: CONST.ED_PARAMS,
    },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    type: 'ws',
    host,
    path,
  });

  if (security) {
    params.set('security', security);
    if (security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'cfip.xxxxxxxx.tk',
    'go.inmobi.com',
    'singapore.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    'csgo.com',
    'fbi.gov',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];

  let links = [];

  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: 'tls',
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: 'tcp',
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });

  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
    );
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map((x) => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
          buildLink({
            core,
            proto: 'tls',
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: `IP${i + 1}`,
          }),
        );

        if (!isPagesDeployment) {
          links.push(
            buildLink({
              core,
              proto: 'tcp',
              userID,
              hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: `IP${i + 1}`,
            }),
          );
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8' });
  addSecurityHeaders(headers, null, {});

  return new Response(btoa(links.join('\n')), {
    headers: headers,
  });
}

// ============================================================================
// SECURITY & AUTHENTICATION
// ============================================================================

async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(db, key, limit, ttl) {
  if (!db) return false;
  try {
    const countStr = await kvGet(db, key);
    const count = parseInt(countStr, 10) || 0;
    if (count >= limit) return true;
    await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
    return false;
  } catch (e) {
    console.error(`checkRateLimit error for ${key}: ${e}`);
    return false;
  }
}

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics API credentials not configured. IP ${ip} allowed by default (fail-open mode).`);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      console.warn(`Scamalytics API returned ${response.status} for ${ip}. Allowing (fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics timeout for ${ip}. Allowing (fail-open).`);
    } else {
      console.error(`Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// TOTP VALIDATION
// ============================================================================

function base32ToBuffer(base32) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const charValue = base32Chars.indexOf(char);
    if (charValue === -1) throw new Error('Invalid Base32 character');
    
    value = (value << 5) | charValue;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hmacBuffer = new Uint8Array(hmac);
  
  const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  const otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }
  
  let secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    console.error("Failed to decode TOTP secret:", e.message);
    return false;
  }
  
  const timeStep = 30;
  const epoch = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(epoch / timeStep);
  
  const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

  for (const counter of counters) {
    const generatedCode = await generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) {
      return true;
    }
  }
  
  return false;
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('ensureTablesExist: D1 binding not available, skipping table creation');
    return;
  }
  
  try {
    const createTables = [
      `CREATE TABLE IF NOT EXISTS users (
        uuid TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiration_date TEXT NOT NULL,
        expiration_time TEXT NOT NULL,
        notes TEXT,
        traffic_limit INTEGER,
        traffic_used INTEGER DEFAULT 0,
        ip_limit INTEGER DEFAULT -1
      )`,
      `CREATE TABLE IF NOT EXISTS user_ips (
        uuid TEXT,
        ip TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (uuid, ip),
        FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE
      )`,
      `CREATE TABLE IF NOT EXISTS key_value (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expiration INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS proxy_health (
        ip_port TEXT PRIMARY KEY,
        is_healthy INTEGER NOT NULL,
        latency_ms INTEGER,
        last_check INTEGER DEFAULT (strftime('%s', 'now'))
      )`
    ];
    
    const stmts = createTables.map(sql => env.DB.prepare(sql));
    
    await env.DB.batch(stmts);
    console.log('D1 tables ensured/created successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
}

// ============================================================================
// UUID STRINGIFY
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// ADMIN PANEL HTML
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style nonce="CSP_NONCE_PLACEHOLDER">
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #121212; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        .login-container { background-color: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5); text-align: center; width: 320px; border: 1px solid #333; }
        h1 { color: #ffffff; margin-bottom: 24px; font-weight: 500; }
        form { display: flex; flex-direction: column; }
        input[type="password"], input[type="text"] { background-color: #2c2c2c; border: 1px solid #444; color: #ffffff; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 16px; box-sizing: border-box; width: 100%; }
        input[type="password"]:focus, input[type="text"]:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.3); }
        button { background-color: #007aff; color: white; border: none; padding: 12px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #005ecb; }
        .error { color: #ff3b30; margin-top: 15px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
            <input type="password" name="password" placeholder="Enter admin password" required>
            <input type="text" name="totp" placeholder="Enter TOTP code (if enabled)" autocomplete="off" />
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`;

const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <style nonce="CSP_NONCE_PLACEHOLDER">
        :root {
            --bg-main: #111827; --bg-card: #1F2937; --border: #374151; --text-primary: #F9FAFB;
            --text-secondary: #9CA3AF; --accent: #3B82F6; --accent-hover: #2563EB; --danger: #EF4444;
            --danger-hover: #DC2626; --success: #22C55E; --expired: #F59e0b; --btn-secondary-bg: #4B5563;
        }
        body { margin: 0; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-main); color: var(--text-primary); font-size: 14px; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        h1, h2 { font-weight: 600; }
        h1 { font-size: 24px; margin-bottom: 20px; }
        h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 20px; }
        .card { background-color: var(--bg-card); border-radius: 8px; padding: 24px; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .dashboard-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #1F2937; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }
        .stat-value { font-size: 24px; font-weight: 600; color: var(--accent); }
        .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; margin-top: 4px; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(200px, 1fr)); gap: 16px; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { margin-bottom: 8px; font-weight: 500; color: var(--text-secondary); }
        input[type="text"], input[type="date"], input[type="time"], input[type="number"], select {
            width: 100%; box-sizing: border-box; background-color: #374151; border: 1px solid #4B5563; color: var(--text-primary);
            padding: 10px; border-radius: 6px; font-size: 14px; transition: border-color 0.2s;
        }
        input:focus, select:focus { outline: none; border-color: var(--accent); }
        .btn {
            padding: 10px 16px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;
            transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        }
        .btn-primary { background-color: var(--accent); color: white; }
        .btn-primary:hover { background-color: var(--accent-hover); }
        .btn-secondary { background-color: var(--btn-secondary-bg); color: white; }
        .btn-danger { background-color: var(--danger); color: white; }
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; }
        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; display: inline-block; }
        .status-active { background-color: var(--success); color: #064E3B; }
        .status-expired { background-color: var(--expired); color: #78350F; }
        #toast { position: fixed; top: 20px; right: 20px; background-color: var(--bg-card); color: white; padding: 15px 20px; border-radius: 8px; z-index: 1001; display: none; border: 1px solid var(--border); }
        #toast.show { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Dashboard</h1>
        <button id="logoutBtn" class="btn btn-danger" style="position: absolute; top: 20px; right: 20px;">Logout</button>
        <button id="healthCheckBtn" class="btn btn-secondary" style="position: absolute; top: 20px; right: 120px;">Run Health Check</button>
        <div class="dashboard-stats">
            <div class="stat-card"><div class="stat-value" id="total-users">0</div><div class="stat-label">Total Users</div></div>
            <div class="stat-card"><div class="stat-value" id="active-users">0</div><div class="stat-label">Active Users</div></div>
            <div class="stat-card"><div class="stat-value" id="expired-users">0</div><div class="stat-label">Expired Users</div></div>
            <div class="stat-card"><div class="stat-value" id="total-traffic">0 KB</div><div class="stat-label">Total Traffic Used</div></div>
        </div>
        <div class="card">
            <h2>Create User</h2>
            <form id="createUserForm" class="form-grid">
                <div class="form-group"><label>UUID</label><input type="text" id="uuid" required></div>
                <div class="form-group"><label>Expiry Date</label><input type="date" id="expiryDate" required></div>
                <div class="form-group"><label>Expiry Time (UTC)</label><input type="time" id="expiryTime" step="1" required></div>
                <div class="form-group"><label>Notes</label><input type="text" id="notes" placeholder="Optional"></div>
                <div class="form-group"><button type="submit" class="btn btn-primary">Create User</button></div>
            </form>
        </div>
        <div class="card">
            <h2>User List</h2>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>UUID</th><th>Created</th><th>Expiry</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead>
                    <tbody id="userList"></tbody>
                </table>
            </div>
        </div>
    </div>
    <div id="toast"></div>
    <script nonce="CSP_NONCE_PLACEHOLDER">
        const API_BASE = 'ADMIN_API_BASE_PATH_PLACEHOLDER';
        async function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        function showToast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 3000); }
        const getCsrfToken = () => document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1] || '';
        const api = {
            get: (e) => fetch(API_BASE + e, { credentials: 'include' }).then(r => r.json()),
            post: (e, b) => fetch(API_BASE + e, { method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, body: JSON.stringify(b) }).then(r => r.json()),
            delete: (e) => fetch(API_BASE + e, { method: 'DELETE', credentials: 'include', headers: {'X-CSRF-Token': getCsrfToken()} }).then(r => r.json()),
        };
        async function fetchStats() {
            const stats = await api.get('/stats');
            document.getElementById('total-users').textContent = stats.total_users;
            document.getElementById('active-users').textContent = stats.active_users;
            document.getElementById('expired-users').textContent = stats.expired_users;
            document.getElementById('total-traffic').textContent = await formatBytes(stats.total_traffic);
        }
        async function fetchUsers() {
            const users = await api.get('/users');
            const list = document.getElementById('userList');
            list.innerHTML = users.map(u => \`<tr><td>\${u.uuid.substring(0, 8)}...</td><td>\${new Date(u.created_at).toLocaleString()}</td><td>\${u.expiration_date} \${u.expiration_time}</td><td><span class="status-badge status-active">Active</span></td><td>\${u.notes || '-'}</td><td><button class="btn btn-danger" onclick="deleteUser('\${u.uuid}')">Delete</button></td></tr>\`).join('');
        }
        async function deleteUser(uuid) {
            if (confirm('Delete user?')) { await api.delete('/users/' + uuid); showToast('User deleted'); fetchUsers(); fetchStats(); }
        }
        document.getElementById('createUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await api.post('/users', {
                uuid: document.getElementById('uuid').value,
                exp_date: document.getElementById('expiryDate').value,
                exp_time: document.getElementById('expiryTime').value,
                notes: document.getElementById('notes').value
            });
            showToast('User created');
            e.target.reset();
            document.getElementById('uuid').value = crypto.randomUUID();
            fetchUsers();
            fetchStats();
        });
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            await api.post('/logout', {});
            location.reload();
        });
        document.getElementById('healthCheckBtn').addEventListener('click', async () => {
            await api.post('/health-check', {});
            showToast('Health check completed');
        });
        document.getElementById('uuid').value = crypto.randomUUID();
        fetchUsers();
        fetchStats();
        setInterval(() => { fetchUsers(); fetchStats(); }, 60000);
    </script>
</body>
</html>`;

// ============================================================================
// ADMIN REQUEST HANDLER
// ============================================================================

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
  if (!token) return false;

  const hashedToken = await hashSHA256(token);
  const storedHashedToken = await kvGet(env.DB, 'admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  try {
    await ensureTablesExist(env, ctx);
    
    const url = new URL(request.url);
    const jsonHeader = { 'Content-Type': 'application/json' };
    const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    const clientIp = request.headers.get('CF-Connecting-IP');

    if (!env.ADMIN_KEY) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Admin panel is not configured.', { status: 503, headers: htmlHeaders });
    }

    if (env.ADMIN_IP_WHITELIST) {
      const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
      if (!allowedIps.includes(clientIp)) {
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied.', { status: 403, headers: htmlHeaders });
      }
    }

    const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`;

    if (!url.pathname.startsWith(adminBasePath)) {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Not found', { status: 404, headers });
    }

    const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

    // API Routes
    if (adminSubPath.startsWith('/api/')) {
      if (!env.DB) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Database not configured' }), { status: 503, headers });
      }

      if (!(await isAdmin(request, env))) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      }

      if (request.method !== 'GET') {
        const csrfToken = request.headers.get('X-CSRF-Token');
        const cookieCsrf = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/)?.[1];
        if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers });
        }
      }
      
      // Stats endpoint
      if (adminSubPath === '/api/stats' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
          const expiredQuery = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')").first();
          const expiredUsers = expiredQuery?.count || 0;
          const activeUsers = totalUsers - expiredUsers;
          const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
          const totalTraffic = totalTrafficQuery?.sum || 0;
          return new Response(JSON.stringify({ 
            total_users: totalUsers, 
            active_users: activeUsers, 
            expired_users: expiredUsers, 
            total_traffic: totalTraffic 
          }), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // Users list
      if (adminSubPath === '/api/users' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
          return new Response(JSON.stringify(results ?? []), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // Create user
      if (adminSubPath === '/api/users' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuid, exp_date, exp_time, notes, traffic_limit, ip_limit } = await request.json();
          await env.DB.prepare("INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)")
            .bind(uuid, exp_date, exp_time, notes || null, traffic_limit || null, ip_limit || -1).run();
          ctx.waitUntil(kvPut(env.DB, `user:${uuid}`, { uuid, expiration_date: exp_date, expiration_time: exp_time, notes, traffic_limit, ip_limit, traffic_used: 0 }, { expirationTtl: 3600 }));
          return new Response(JSON.stringify({ success: true, uuid }), { status: 201, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // Delete user
      const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);
      if (userRouteMatch && request.method === 'DELETE') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
          ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // Logout
      if (adminSubPath === '/api/logout' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await kvDelete(env.DB, 'admin_session_token_hash');
          headers.append('Set-Cookie', 'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
          headers.append('Set-Cookie', 'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict');
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // Health check
      if (adminSubPath === '/api/health-check' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await performHealthCheck(env, ctx);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers });
    }

    // Login page
    if (adminSubPath === '/') {
      if (request.method === 'POST') {
        const rateLimitKey = `login_fail_ip:${clientIp}`;
        const failCountStr = await kvGet(env.DB, rateLimitKey);
        const failCount = parseInt(failCountStr, 10) || 0;
        
        if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('Too many failed login attempts.', { status: 429, headers: htmlHeaders });
        }
        
        const formData = await request.formData();
        
        if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
          if (env.ADMIN_TOTP_SECRET) {
            const totpCode = formData.get('totp');
            if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
              ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
              const nonce = generateNonce();
              addSecurityHeaders(htmlHeaders, nonce, {});
              let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid TOTP code.</p>`);
              html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
              html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
              return new Response(html, { status: 401, headers: htmlHeaders });
            }
          }
          
          const token = crypto.randomUUID();
          const csrfToken = crypto.randomUUID();
          const hashedToken = await hashSHA256(token);
          ctx.waitUntil(Promise.all([
            kvPut(env.DB, 'admin_session_token_hash', hashedToken, { expirationTtl: 86400 }),
            kvDelete(env.DB, rateLimitKey)
          ]));
          
          const headers = new Headers({ 'Location': adminBasePath });
          headers.append('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
          headers.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
          addSecurityHeaders(headers, null, {});
          return new Response(null, { status: 302, headers });
        
        } else {
          ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
          const nonce = generateNonce();
          addSecurityHeaders(htmlHeaders, nonce, {});
          let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid password.</p>`);
          html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
          return new Response(html, { status: 401, headers: htmlHeaders });
        }
      }

      if (request.method === 'GET') {
        const nonce = generateNonce();
        addSecurityHeaders(htmlHeaders, nonce, {});
        
        let html;
        if (await isAdmin(request, env)) {
          html = adminPanelHTML;
          html = html.replace("'ADMIN_API_BASE_PATH_PLACEHOLDER'", `'${adminBasePath}/api'`);
        } else {
          html = adminLoginHTML;
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
        }
        
        html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
        return new Response(html, { headers: htmlHeaders });
      }
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  } catch (e) {
    console.error('handleAdminRequest error:', e.message);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// USER PANEL WITH QR CODE
// ============================================================================

async function handleUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
  try {
    const subXrayUrl = `https://${hostName}/xray/${userID}`;
    const subSbUrl = `https://${hostName}/sb/${userID}`;
    
    const singleXrayConfig = buildLink({ core:'xray', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main' });
    const singleSingboxConfig = buildLink({ core: 'sb', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main' });

    const clientUrls = {
      universalAndroid: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      shadowrocket: `shadowrocket://add/sub?url=${encodeURIComponent(subXrayUrl)}&name=${encodeURIComponent(hostName)}`,
    };

    const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
    const expirationDateTime = userData.expiration_date && userData.expiration_time 
      ? `${userData.expiration_date}T${userData.expiration_time}Z` 
      : null;

    let usagePercentage = 0;
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
    }

    const requestCf = request.cf || {};
    const clientGeo = {
      city: requestCf.city || '',
      country: requestCf.country || '',
      isp: requestCf.asOrganization || ''
    };

    const userPanelHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root{ --bg:#0b1220; --card:#0f1724; --accent:#3b82f6; --success:#22c55e; --danger:#ef4444; }
    * { box-sizing:border-box }
    body { margin:0; font-family: Inter, system-ui; background: linear-gradient(180deg,#061021 0%, #071323 100%); color:#e6eef8; min-height:100vh; padding:28px; }
    .container { max-width:1100px; margin:0 auto }
    .card { background:var(--card); border-radius:12px; padding:20px; margin-bottom:20px; border:1px solid rgba(255,255,255,0.03); }
    h1 { font-size:28px; margin:0 0 10px }
    .stat { padding:14px; background:rgba(255,255,255,0.02); border-radius:10px; text-align:center; }
    .stat .val { font-weight:700; font-size:22px; margin-bottom:4px }
    .btn { padding:11px 16px; border-radius:8px; border:none; cursor:pointer; font-weight:600; transition:all 0.2s; }
    .btn.primary { background:linear-gradient(135deg,var(--accent),#60a5fa); color:#fff; }
    pre.config { background:#071529; padding:14px; border-radius:8px; overflow:auto; font-family:monospace; font-size:13px; }
    .hidden { display:none }
    #qr-display { min-height:280px; display:flex; align-items:center; justify-content:center; }
    #toast { position:fixed; right:20px; top:20px; background:#0f1b2a; padding:14px 18px; border-radius:10px; display:none; z-index:1000; }
    #toast.show { display:block }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VXR.SXR Configuration Panel</h1>
    <div class="card">
      <div class="stat"><div class="val" id="status-badge">${isUserExpired ? 'Expired' : 'Active'}</div></div>
    </div>
    <div class="card">
      <h2>📱 Xray Subscription</h2>
      <button class="btn primary" id="copy-xray-sub">📋 Copy Xray Link</button>
      <button class="btn" id="show-xray-config">View Config</button>
      <button class="btn" id="qr-xray-btn">QR Code</button>
      <pre class="config hidden" id="xray-config">${escapeHTML(singleXrayConfig)}</pre>
    </div>
    <div class="card">
      <h2>📱 Sing-Box Subscription</h2>
      <button class="btn primary" id="copy-sb-sub">📋 Copy Singbox Link</button>
      <button class="btn" id="show-sb-config">View Config</button>
      <button class="btn" id="qr-sb-btn">QR Code</button>
      <pre class="config hidden" id="sb-config">${escapeHTML(singleSingboxConfig)}</pre>
    </div>
    <div class="card">
      <h2>QR Code Scanner</h2>
      <div id="qr-display"><p>Click any "QR Code" button to generate.</p></div>
    </div>
  </div>
  <div id="toast"></div>
  <script nonce="CSP_NONCE_PLACEHOLDER">
    window.CONFIG = {
      uuid: "${userID}",
      subXrayUrl: "${subXrayUrl}",
      subSbUrl: "${subSbUrl}",
      singleXrayConfig: ${JSON.stringify(singleXrayConfig)},
      singleSingboxConfig: ${JSON.stringify(singleSingboxConfig)},
    };
    
    function showToast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2000); }
    
    async function copyToClipboard(text, button) {
      try {
        await navigator.clipboard.writeText(text);
        const orig = button.innerHTML;
        button.innerHTML = '✓ Copied!';
        setTimeout(() => button.innerHTML = orig, 2000);
        showToast('Copied to clipboard!');
      } catch (e) {
        showToast('Failed to copy');
      }
    }
    
    // Simple QR Code Generator
    const QRCodeGenerator = (function() {
      function generate(text, size) {
        const canvas = document.createElement("canvas");
        const qrSize = 25;
        const cellSize = Math.floor(size / qrSize);
        canvas.width = canvas.height = qrSize * cellSize;
        const ctx = canvas.getContext("2d");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#000000";
        
        // Simple pattern (not real QR, just demonstration)
        for (let row = 0; row < qrSize; row++) {
          for (let col = 0; col < qrSize; col++) {
            if ((row + col) % 2 === 0 || (row === col)) {
              ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
            }
          }
        }
        return canvas;
      }
      return { generate };
    })();
    
    function generateQRCode(data) {
      const display = document.getElementById('qr-display');
      display.innerHTML = '<div style="background:#fff;padding:16px;border-radius:10px;display:inline-block;"></div>';
      const container = display.querySelector('div');
      const canvas = QRCodeGenerator.generate(data, 256);
      container.appendChild(canvas);
    }
    
    document.getElementById('copy-xray-sub').addEventListener('click', function() { copyToClipboard(window.CONFIG.subXrayUrl, this); });
    document.getElementById('copy-sb-sub').addEventListener('click', function() { copyToClipboard(window.CONFIG.subSbUrl, this); });
    document.getElementById('show-xray-config').addEventListener('click', () => document.getElementById('xray-config').classList.toggle('hidden'));
    document.getElementById('show-sb-config').addEventListener('click', () => document.getElementById('sb-config').classList.toggle('hidden'));
    document.getElementById('qr-xray-btn').addEventListener('click', () => generateQRCode(window.CONFIG.singleXrayConfig));
    document.getElementById('qr-sb-btn').addEventListener('click', () => generateQRCode(window.CONFIG.singleSingboxConfig));
  </script>
</body>
</html>`;

    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, {});
    
    let finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
    return new Response(finalHtml, { headers });
  } catch (e) {
    console.error('handleUserPanel error:', e.message);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// VLESS PROTOCOL HANDLERS
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  let webSocket = null;
  try {
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    const webSocketPair = new WebSocketPair();
    const [client, webSocket_inner] = Object.values(webSocketPair);
    webSocket = webSocket_inner;
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    let sessionUsage = 0;
    let userUUID = '';
    let udpStreamWriter = null;

    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

    const deferredUsageUpdate = () => {
      if (sessionUsage > 0 && userUUID) {
        const usageToUpdate = sessionUsage;
        const uuidToUpdate = userUUID;
        sessionUsage = 0;
        ctx.waitUntil(updateUsage(env, uuidToUpdate, usageToUpdate, ctx));
      }
    };

    const updateInterval = setInterval(deferredUsageUpdate, 10000);
    const finalCleanup = () => { clearInterval(updateInterval); deferredUsageUpdate(); };
    webSocket.addEventListener('close', finalCleanup, { once: true });
    webSocket.addEventListener('error', finalCleanup, { once: true });

    const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };

    readableWebSocketStream
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            sessionUsage += chunk.byteLength;

            if (udpStreamWriter) {
              return udpStreamWriter.write(chunk);
            }

            if (remoteSocketWrapper.value) {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              await writer.write(chunk);
              writer.releaseLock();
              return;
            }

            const {
              user,
              hasError,
              message,
              addressType,
              portRemote = 443,
              addressRemote = '',
              rawDataIndex,
              ProtocolVersion = new Uint8Array([0, 0]),
              isUDP,
            } = await ProcessProtocolHeader(chunk, env, ctx);

            if (hasError || !user) {
              controller.error(new Error('Authentication failed'));
              return;
            }

            userUUID = user.uuid;

            if (isExpired(user.expiration_date, user.expiration_time)) {
              controller.error(new Error('Authentication failed'));
              return;
            }

            if (user.traffic_limit && user.traffic_limit > 0) {
              const totalUsage = (user.traffic_used || 0) + sessionUsage;
              if (totalUsage >= user.traffic_limit) {
                controller.error(new Error('Authentication failed'));
                return;
              }
            }

            if (user.ip_limit && user.ip_limit > -1) {
              const ipCount = await env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?").bind(userUUID).first('count');
              if (ipCount >= user.ip_limit) {
                controller.error(new Error('IP limit exceeded'));
                return;
              }
              await env.DB.prepare("INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)").bind(userUUID, clientIp).run();
            }

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
            const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isUDP) {
              if (portRemote === 53) {
                const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => { sessionUsage += bytes; });
                udpStreamWriter = dnsPipeline.write;
                await udpStreamWriter(rawClientData);
              } else {
                controller.error(new Error('Authentication failed'));
              }
              return;
            }

            HandleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, config, (bytes) => { sessionUsage += bytes; });
          },
          close() { log('readableWebSocketStream closed'); finalCleanup(); },
          abort(err) { log('readableWebSocketStream aborted', err); finalCleanup(); },
        }),
      )
      .catch(err => {
        console.error('Pipeline failed:', err);
        safeCloseWebSocket(webSocket);
        finalCleanup();
      });

    return new Response(null, { status: 101, webSocket: client });
  } catch (e) {
    console.error('ProtocolOverWSHandler error:', e.message);
    if (webSocket) safeCloseWebSocket(webSocket);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  try {
    if (protocolBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };
  
    const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
    const version = dataView.getUint8(0);

    let uuid;
    try {
      uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
    } catch (e) {
      return { hasError: true, message: 'invalid UUID format' };
    }

    const userData = await getUserData(env, uuid, ctx);
    if (!userData) return { hasError: true, message: 'invalid user' };

    const payloadStart = 17;
    if (protocolBuffer.byteLength < payloadStart + 1) return { hasError: true, message: 'invalid data length' };

    const optLength = dataView.getUint8(payloadStart);
    const commandIndex = payloadStart + 1 + optLength;
    
    if (protocolBuffer.byteLength < commandIndex + 1) return { hasError: true, message: 'invalid data length (command)' };
    
    const command = dataView.getUint8(commandIndex);
    if (command !== 1 && command !== 2) return { hasError: true, message: `command ${command} not supported` };

    const portIndex = commandIndex + 1;
    if (protocolBuffer.byteLength < portIndex + 2) return { hasError: true, message: 'invalid data length (port)' };
    
    const portRemote = dataView.getUint16(portIndex, false);

    const addressTypeIndex = portIndex + 2;
    if (protocolBuffer.byteLength < addressTypeIndex + 1) return { hasError: true, message: 'invalid data length (address type)' };
    
    const addressType = dataView.getUint8(addressTypeIndex);

    let addressValue, addressLength, addressValueIndex;

    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) return { hasError: true, message: 'invalid data length (ipv4)' };
        addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        break;
      case 2:
        if (protocolBuffer.byteLength < addressTypeIndex + 2) return { hasError: true, message: 'invalid data length (domain length)' };
        addressLength = dataView.getUint8(addressTypeIndex + 1);
        addressValueIndex = addressTypeIndex + 2;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) return { hasError: true, message: 'invalid data length (domain)' };
        addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 3:
        addressLength = 16;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) return { hasError: true, message: 'invalid data length (ipv6)' };
        addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2, false).toString(16)).join(':');
        break;
      default:
        return { hasError: true, message: `invalid addressType: ${addressType}` };
    }

    const rawDataIndex = addressValueIndex + addressLength;
    if (protocolBuffer.byteLength < rawDataIndex) return { hasError: true, message: 'invalid data length (raw data)' };

    return {
      user: userData,
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex,
      ProtocolVersion: new Uint8Array([version]),
      isUDP: command === 2,
    };
  } catch (e) {
    console.error('ProcessProtocolHeader error:', e.message);
    return { hasError: true, message: 'protocol processing error' };
  }
}

async function HandleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log, config, trafficCallback) {
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay || socks) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(config.proxyIP || addressRemote, config.proxyPort || portRemote, false);

    tcpSocket.closed.catch(error => console.log('retry tcpSocket closed error', error)).finally(() => safeCloseWebSocket(webSocket));
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => { safeCloseWebSocket(webSocketServer); controller.close(); });
      webSocketServer.addEventListener('error', (err) => { log('webSocketServer has error'); controller.error(err); });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) {},
    cancel(reason) { log(`ReadableStream canceled: ${reason}`); safeCloseWebSocket(webSocketServer); },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
            controller.error('webSocket not open');
            return;
          }
          hasIncomingData = true;
          if (protocolResponseHeader) {
            webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
            protocolResponseHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() { log(`remoteSocket closed, hasIncomingData: ${hasIncomingData}`); },
        abort(reason) { console.error('remoteSocket abort', reason); },
      }),
    )
    .catch((error) => { console.error('remoteSocket pipeTo error', error); safeCloseWebSocket(webSocket); });
  return hasIncomingData;
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) view[i] = binaryStr.charCodeAt(i);
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === CONST.WS_READY_STATE_OPEN || socket.readyState === CONST.WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) break;
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              let responseChunk;
              if (isHeaderSent) {
                responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) trafficCallback(responseChunk.byteLength);
              webSocket.send(responseChunk);
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      }),
    )
    .catch(e => log('DNS stream error: ' + e));

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

function parseIPv6(ipv6) {
  const buffer = new ArrayBuffer(16);
  const view = new DataView(buffer);
  const parts = ipv6.split('::');
  let left = parts[0] ? parts[0].split(':') : [];
  let right = parts[1] ? parts[1].split(':') : [];
  if (left.length === 1 && left[0] === '') left = [];
  if (right.length === 1 && right[0] === '') right = [];
  const missing = 8 - (left.length + right.length);
  const expansion = [];
  if (missing > 0) for (let i = 0; i < missing; i++) expansion.push('0000');
  const hextets = [...left, ...expansion, ...right];
  for (let i = 0; i < 8; i++) {
    const val = parseInt(hextets[i] || '0', 16);
    view.setUint16(i * 2, val, false);
  }
  return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  let socket, reader, writer, success = false;

  try {
    socket = connect({ hostname, port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    const encoder = new TextEncoder();

    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read()).value;
    if (!res || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 handshake failed');

    if (res[1] === 0x02) {
      if (!username || !password) throw new Error('SOCKS5 requires credentials');
      const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
      await writer.write(authRequest);
      res = (await reader.read()).value;
      if (!res || res[0] !== 0x01 || res[1] !== 0x00) throw new Error('SOCKS5 authentication failed');
    }

    let dstAddr;
    switch (addressType) {
      case 1: dstAddr = new Uint8Array([1, ...addressRemote.split('.').map(Number)]); break;
      case 2: dstAddr = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]); break;
      case 3: const ipv6Bytes = parseIPv6(addressRemote); dstAddr = new Uint8Array(1 + 16); dstAddr[0] = 4; dstAddr.set(ipv6Bytes, 1); break;
      default: throw new Error(`Invalid address type: ${addressType}`);
    }

    const socksRequest = new Uint8Array([5, 1, 0, ...dstAddr, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    res = (await reader.read()).value;
    if (!res || res[1] !== 0x00) throw new Error('SOCKS5 connection failed');

    log(`SOCKS5 connected to ${addressRemote}:${portRemote}`);
    success = true;
    return socket;
  } catch (err) {
    log(`socks5Connect Error: ${err.message}`, err);
    throw err;
  } finally {
    if (writer) writer.releaseLock();
    if (reader) reader.releaseLock();
    if (!success && socket) socket.abort();
  }
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') throw new Error('Invalid SOCKS5 address format');
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');
  if (lastColonIndex === -1) throw new Error('Invalid SOCKS5 address: missing port');
  let hostname;
  if (hostPart.startsWith('[')) {
    const closingBracketIndex = hostPart.lastIndexOf(']');
    if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) throw new Error('Invalid IPv6 SOCKS5 address format');
    hostname = hostPart.substring(1, closingBracketIndex);
  } else {
    hostname = hostPart.substring(0, lastColonIndex);
  }
  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  if (!hostname || isNaN(port)) throw new Error('Invalid SOCKS5 address');
  let username, password;
  if (authPart) [username, password] = authPart.split(':');
  return { username, password, hostname, port };
}

// ============================================================================
// HEALTH CHECK SYSTEM
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
    return;
  }
  
  const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map(ip => ip.trim()) : Config.proxyIPs;
  const healthStmts = [];
  
  for (const ipPort of proxyIps) {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      const response = await fetch(`https://${host}:${port}`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (response.ok) { latency = Date.now() - start; isHealthy = 1; }
    } catch (e) {
      console.error(`Health check failed for ${ipPort}: ${e.message}`);
    }
    
    healthStmts.push(env.DB.prepare("INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)").bind(ipPort, isHealthy, latency, Date.now()));
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('Proxy health check completed.');
  } catch (e) {
    console.error(`performHealthCheck batch error: ${e.message}`);
  }
}

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      let cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(`Configuration Error: ${err.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service temporarily unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      if (url.pathname.startsWith(`/${adminPrefix}/`)) {
        return await handleAdminRequest(request, env, ctx, adminPrefix);
      }

      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      if (url.pathname === '/health-check' && request.method === 'GET') {
        await performHealthCheck(env, ctx);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Health check performed', { status: 200, headers });
      }

      if (url.pathname.startsWith('/api/user/')) {
        const uuid = url.pathname.substring('/api/user/'.length);
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        if (request.method !== 'GET') return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers });
        if (!isValidUUID(uuid)) return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) return new Response(JSON.stringify({ error: 'Authentication failed' }), { status: 403, headers });
        return new Response(JSON.stringify({ traffic_used: userData.traffic_used || 0, traffic_limit: userData.traffic_limit, expiration_date: userData.expiration_date, expiration_time: userData.expiration_time }), { status: 200, headers });
      }

      if (url.pathname === '/favicon.ico') {
        return new Response(null, { status: 301, headers: { Location: 'https://www.google.com/favicon.ico' } });
      }

      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured properly', { status: 503, headers });
        }
        
        const hostHeaders = env.HOST_HEADERS ? env.HOST_HEADERS.split(',').map(h => h.trim()) : ['speed.cloudflare.com'];
        const evasionHost = pick(hostHeaders);
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', evasionHost);
        const newRequest = new Request(request, { headers: newHeaders });
        
        const requestConfig = {
          userID: cfg.userID,
          proxyIP: cfg.proxyIP,
          proxyPort: cfg.proxyPort,
          socks5Address: cfg.socks5.address,
          socks5Relay: cfg.socks5.relayMode,
          enableSocks: cfg.socks5.enabled,
          parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
          scamalytics: cfg.scamalytics,
        };
        
        const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig, env, ctx);
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        return new Response(wsResponse.body, { status: wsResponse.status, webSocket: wsResponse.webSocket, headers });
      }

      const handleSubscription = async (core) => {
        const rateLimitKey = `user_path_rate:${clientIp}`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const uuid = url.pathname.substring(`/${core}/`.length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData || isExpired(userData.expiration_date, userData.expiration_time) || (userData.traffic_limit && userData.traffic_limit > 0 && (userData.traffic_used || 0) >= userData.traffic_limit)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        return await handleIpSubscription(core, uuid, url.hostname);
      };

      if (url.pathname.startsWith('/xray/')) return await handleSubscription('xray');
      if (url.pathname.startsWith('/sb/')) return await handleSubscription('sb');

      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const rateLimitKey = `user_path_rate:${clientIp}`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const userData = await getUserData(env, path, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Authentication failed', { status: 403, headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      if (env.ROOT_PROXY_URL) {
        try {
          const proxyUrl = new URL(env.ROOT_PROXY_URL);
          const targetUrl = new URL(request.url);
          targetUrl.hostname = proxyUrl.hostname;
          targetUrl.protocol = proxyUrl.protocol;
          if (proxyUrl.port) targetUrl.port = proxyUrl.port;
          
          const newRequest = new Request(targetUrl.toString(), { method: request.method, headers: request.headers, body: request.body, redirect: 'manual' });
          newRequest.headers.set('Host', proxyUrl.hostname);
          newRequest.headers.set('X-Forwarded-For', clientIp);
          newRequest.headers.set('X-Real-IP', clientIp);
          
          const response = await fetch(newRequest);
          const mutableHeaders = new Headers(response.headers);
          mutableHeaders.delete('content-security-policy-report-only');
          mutableHeaders.set('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
          mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
          
          return new Response(response.body, { status: response.status, statusText: response.statusText, headers: mutableHeaders });
        } catch (e) {
          console.error(`Reverse Proxy Error: ${e.message}`);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(`Proxy error: ${e.message}`, { status: 502, headers });
        }
      }

      const masqueradeHtml = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`;
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers });
    } catch (e) {
      console.error('Fetch handler error:', e.message);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Internal Server Error', { status: 500, headers });
    }
  },
}

'use strict';

const dgram  = require('dgram');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── Paths ────────────────────────────────────────────────────────────────────
const DATA_DIR   = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ─── Network config ───────────────────────────────────────────────────────────
let SMARTGATE_IP   = '192.168.1.100'; // ← change to your SmartGate IP
let SMARTGATE_PORT = 6000;
const SERVER_PORT  = 3003;
const LISTEN_IP    = '0.0.0.0';

// ─── Protocol constants ───────────────────────────────────────────────────────
const SMARTCLOUD_BUF = Buffer.from('SMARTCLOUD', 'ascii');
const SYNC_BUF       = Buffer.from([0xAA, 0xAA]);
const SMARTCLOUD_STR = Buffer.from('SMARTCLOUD', 'ascii'); // for UDP listener search

// Cached prefix — rebuilt only when SMARTGATE_IP changes
let cachedPrefix = null;
function buildPrefix() {
    if (!cachedPrefix) {
        const parts = SMARTGATE_IP.split('.').map(Number);
        cachedPrefix = Buffer.concat([Buffer.from(parts), SMARTCLOUD_BUF, SYNC_BUF]);
    }
    return cachedPrefix;
}
function invalidatePrefix() { cachedPrefix = null; }

const SENDER_SUBNET = 0x01;
const SENDER_DEVICE = 0x32;         // 50
const DEVICE_TYPE   = [0x01, 0x19]; // 0x0119

// ─── CRC16-XMODEM ─────────────────────────────────────────────────────────────
function crc16(buf) {
    let crc = 0x0000;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] << 8;
        for (let j = 0; j < 8; j++) {
            crc = (crc & 0x8000) ? (((crc << 1) ^ 0x1021) & 0xFFFF) : ((crc << 1) & 0xFFFF);
        }
    }
    return crc;
}

// ─── Packet builder ───────────────────────────────────────────────────────────
function buildDimmerPacket(targetSubnet, targetDevice, channel, level) {
    const hdlNoCrc = Buffer.from([
        0x0F,
        SENDER_SUBNET,
        SENDER_DEVICE,
        DEVICE_TYPE[0],
        DEVICE_TYPE[1],
        0x00, 0x31,
        targetSubnet,
        targetDevice,
        channel,
        level,
        0x00, 0x00,
    ]);
    const c = crc16(hdlNoCrc);
    const hdl = Buffer.concat([hdlNoCrc, Buffer.from([(c >> 8) & 0xFF, c & 0xFF])]);
    return Buffer.concat([buildPrefix(), hdl]);
}

// ─── UDP sender ───────────────────────────────────────────────────────────────
const udpSocket = dgram.createSocket('udp4');
udpSocket.bind(() => { udpSocket.setBroadcast(true); });

function sendPacket(buf) {
    return new Promise((resolve, reject) => {
        udpSocket.send(buf, 0, buf.length, SMARTGATE_PORT, SMARTGATE_IP, (err) => {
            if (err) reject(err); else resolve();
        });
    });
}

// ─── Activity log (JSON file, no native dependencies) ────────────────────────
const ACTIVITY_FILE = path.join(DATA_DIR, 'activity.json');
const ACTIVITY_MAX  = 500;
let activityLog = [];

function loadActivity() {
    ensureDataDir();
    try {
        if (fs.existsSync(ACTIVITY_FILE))
            activityLog = JSON.parse(fs.readFileSync(ACTIVITY_FILE, 'utf8'));
    } catch { activityLog = []; }
}

function saveActivity() {
    try { fs.writeFileSync(ACTIVITY_FILE, JSON.stringify(activityLog)); } catch {}
}

// Debounced activity save — coalesces rapid writes into one disk operation
let activitySaveTimer = null;
function scheduleActivitySave() {
    if (activitySaveTimer) return;
    activitySaveTimer = setTimeout(() => { activitySaveTimer = null; saveActivity(); }, 500);
}

function logActivity(type, description, details) {
    const now = Date.now();
    activityLog.unshift({ id: now, ts: now, type, description, details: details || null });
    if (activityLog.length > ACTIVITY_MAX) activityLog.length = ACTIVITY_MAX;
    scheduleActivitySave();
}

// ─── Log rotation ─────────────────────────────────────────────────────────────
// stdout/stderr are redirected to server.log in append mode (restart.sh uses >>),
// so truncating the file in place is safe: O_APPEND writers continue at the new
// end. Previous contents are kept once in server.log.old.
const LOG_FILE     = path.join(__dirname, 'server.log');
const LOG_MAX_SIZE = 5 * 1024 * 1024; // 5 MB

function rotateLogIfNeeded() {
    try {
        const st = fs.statSync(LOG_FILE);
        if (st.size < LOG_MAX_SIZE) return;
        fs.copyFileSync(LOG_FILE, LOG_FILE + '.old');
        fs.truncateSync(LOG_FILE, 0);
        console.log(`[Log] Rotated server.log (was ${(st.size / 1048576).toFixed(1)} MB)`);
    } catch { /* no log file (e.g. running in a terminal) — nothing to rotate */ }
}
rotateLogIfNeeded();
setInterval(rotateLogIfNeeded, 6 * 3600 * 1000);

// ─── Authentication — PIN + long-lived device tokens ─────────────────────────
// data/auth.json: { pinHash, salt, tokens: { <token>: { label, created, lastSeen } } }
// Devices enroll once with the PIN and get a token that lives until revoked.
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
let auth = { pinHash: null, salt: null, tokens: {} };

function loadAuth() {
    try {
        if (fs.existsSync(AUTH_FILE)) auth = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    } catch { auth = { pinHash: null, salt: null, tokens: {} }; }
    if (!auth.tokens) auth.tokens = {};
}

function saveAuth() {
    try { fs.writeFileSync(AUTH_FILE, JSON.stringify(auth)); } catch {}
}

function hashPin(pin, salt) {
    return crypto.scryptSync(String(pin), Buffer.from(salt, 'hex'), 32).toString('hex');
}

function verifyPin(pin) {
    if (!auth.pinHash || !auth.salt) return false;
    const h = Buffer.from(hashPin(pin, auth.salt), 'hex');
    const stored = Buffer.from(auth.pinHash, 'hex');
    return h.length === stored.length && crypto.timingSafeEqual(h, stored);
}

function issueToken(label) {
    const token = crypto.randomBytes(32).toString('hex');
    auth.tokens[token] = { label: String(label || 'Unknown device').slice(0, 60), created: Date.now(), lastSeen: Date.now() };
    saveAuth();
    return token;
}

// lastSeen updates are debounced to at most one disk write per minute
let authSaveTimer = null;
function touchToken(token) {
    const t = auth.tokens[token];
    if (!t) return;
    t.lastSeen = Date.now();
    if (!authSaveTimer)
        authSaveTimer = setTimeout(() => { authSaveTimer = null; saveAuth(); }, 60000);
}

function getReqToken(req, urlObj) {
    const h = req.headers['authorization'];
    if (h && h.startsWith('Bearer ')) return h.slice(7);
    return urlObj.searchParams.get('token'); // EventSource can't set headers
}

// Brute-force lockout: quadratic backoff after failed PIN attempts
let pinFails = { count: 0, lockedUntil: 0 };

// ─── Ad-hoc countdown timers ─────────────────────────────────────────────────
// Key: "subnet.device.channel"  Value: { expiresAt: ms epoch, minutes }
// Persisted so a server restart doesn't leave a light on past its timer.
const TIMERS_FILE = path.join(DATA_DIR, 'timers.json');
let timers = {};

function loadTimers() {
    try {
        if (fs.existsSync(TIMERS_FILE))
            timers = JSON.parse(fs.readFileSync(TIMERS_FILE, 'utf8'));
    } catch { timers = {}; }
}

function saveTimers() {
    try { fs.writeFileSync(TIMERS_FILE, JSON.stringify(timers)); } catch {}
}

function cancelTimer(k) {
    if (!timers[k]) return false;
    delete timers[k];
    saveTimers();
    broadcastEvent({ type: 'timer', key: k, timer: null });
    return true;
}

async function checkTimers() {
    const now = Date.now();
    for (const k of Object.keys(timers)) {
        const t = timers[k];
        if (t.expiresAt > now) continue;
        delete timers[k];
        saveTimers();
        broadcastEvent({ type: 'timer', key: k, timer: null });
        const [subnet, device, channel] = k.split('.').map(Number);
        try {
            await lightCmd(subnet, device, channel, 0, true);
            logActivity('timer', `Timer expired — OFF: ${deviceName(subnet, device, channel)}`,
                { subnet, device, channel, minutes: t.minutes });
            console.log(`[Timer] Expired (${t.minutes} min) — turned off ${k}`);
        } catch (e) {
            console.error(`[Timer] Failed to turn off ${k}:`, e.message);
        }
    }
}
setInterval(checkTimers, 10000);

// ─── Data layer ───────────────────────────────────────────────────────────────
const DB_FILES = ['floors', 'rooms', 'devices', 'scenes', 'schedules', 'settings'];

let db = { floors: [], rooms: [], devices: [], scenes: [], schedules: [], settings: {} };

function ensureDataDir() {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadDb() {
    ensureDataDir();
    for (const name of DB_FILES) {
        const file = path.join(DATA_DIR, `${name}.json`);
        if (fs.existsSync(file)) {
            try {
                const raw = fs.readFileSync(file, 'utf8');
                db[name] = JSON.parse(raw);
            } catch (e) {
                console.error(`Failed to parse ${name}.json:`, e.message);
                db[name] = name === 'settings' ? {} : [];
            }
        } else {
            // Seed defaults
            if (name === 'floors') {
                db.floors = [{ id: 'default-floor-1', name: 'Ground Floor' }];
            } else if (name === 'rooms') {
                db.rooms = [{
                    id: 'default-room-1', name: 'Living Room', icon: '🛋️', color: '#7c3aed',
                    floorId: 'default-floor-1',
                    lights: [{ id: 'default-light-1', name: 'Main Light', subnet: 1, device: 7, channel: 9, type: 'relay' }]
                }];
            } else if (name === 'devices') {
                db.devices = [{ id: 'default-device-1', name: 'Dimmer 1.7', subnet: 1, device: 7 }];
            } else if (name === 'settings') {
                db.settings = {
                    latitude: 40.7128, longitude: -74.006,
                    timezone: 'America/New_York',
                    gatewayIp: '192.168.1.100', gatewayPort: 6000,
                    mode: 'home', homeSceneId: null, awaySceneId: null
                };
            } else {
                db[name] = [];
            }
            saveDb(name);
        }
    }
    // Clean up any corrupted floorId values (e.g. the string "undefined"/"null")
    const BAD_IDS = new Set(['undefined', 'null', '', '0']);
    db.rooms = db.rooms.map(r => ({
        ...r,
        floorId: (r.floorId && !BAD_IDS.has(r.floorId)) ? r.floorId : null,
    }));

    // Ensure mode field exists in settings (Feature 3)
    if (!db.settings.mode) db.settings.mode = 'home';

    // Sync gateway config from settings
    if (db.settings.gatewayIp)   { SMARTGATE_IP   = db.settings.gatewayIp;   invalidatePrefix(); }
    if (db.settings.gatewayPort)   SMARTGATE_PORT = db.settings.gatewayPort;
}

function saveDb(name) {
    ensureDataDir();
    const file = path.join(DATA_DIR, `${name}.json`);
    fs.writeFileSync(file, JSON.stringify(db[name], null, 2), 'utf8');
}

// ─── In-memory light state ────────────────────────────────────────────────────
// Key: "subnet.device.channel"  Value: 0 or 100
const lightState = {};
const LIGHT_STATE_FILE = path.join(DATA_DIR, 'lightstate.json');

function lightKey(subnet, device, channel) {
    return `${subnet}.${device}.${channel}`;
}

function deviceName(subnet, device, channel) {
    for (const room of db.rooms) {
        const l = (room.lights || []).find(l =>
            l.subnet == subnet && l.device == device && l.channel == channel);
        if (l) return `${room.name} / ${l.name}`;
    }
    return `${subnet}.${device} ch${channel}`;
}

function saveLightState() {
    try { fs.writeFileSync(LIGHT_STATE_FILE, JSON.stringify(lightState)); } catch (e) {}
}

// ─── "On too long" alerts ──────────────────────────────────────────────────────
// Not persisted to disk — on a restart, lights already on just restart their
// clock from boot time, which is an acceptable simplification for this feature.
const lightOnSince = {};      // key -> ms epoch when this light last turned on
const longOnAlerted = {};     // key -> true once alerted for the CURRENT on-session

function noteLightTransition(k, prevLevel, newLevel) {
    if (newLevel > 0 && !(prevLevel > 0)) {
        lightOnSince[k] = Date.now();
    } else if (newLevel === 0) {
        delete lightOnSince[k];
        delete longOnAlerted[k];
    }
}

function checkLongOnAlerts() {
    const hours = Number(db.settings.longOnAlertHours) || 0;
    if (!hours) return;
    const thresholdMs = hours * 3600000;
    const now = Date.now();
    for (const room of db.rooms) {
        for (const light of (room.lights || [])) {
            if (light.excludeLongOnAlert) continue;
            const k = lightKey(light.subnet, light.device, light.channel);
            if (!(lightState[k] > 0) || longOnAlerted[k]) continue;
            const since = lightOnSince[k];
            if (!since || now - since < thresholdMs) continue;
            longOnAlerted[k] = true;
            const hoursOn = ((now - since) / 3600000).toFixed(1);
            const devName = deviceName(light.subnet, light.device, light.channel);
            logActivity('longOn', `⏳ On for ${hoursOn}h: ${devName}`,
                { subnet: light.subnet, device: light.device, channel: light.channel, hours: hoursOn });
            broadcastEvent({ type: 'longOnAlert', key: k, devName, hours: hoursOn });
        }
    }
}
setInterval(checkLongOnAlerts, 30000);

function initLightState() {
    // Load persisted state from last run
    try {
        if (fs.existsSync(LIGHT_STATE_FILE)) {
            const saved = JSON.parse(fs.readFileSync(LIGHT_STATE_FILE, 'utf8'));
            Object.assign(lightState, saved);
            console.log(`[State] Restored ${Object.keys(saved).length} light states from disk`);
        }
    } catch (e) {}

    // Ensure all known lights have an entry (default 0 if never seen)
    for (const room of db.rooms) {
        for (const light of (room.lights || [])) {
            const k = lightKey(light.subnet, light.device, light.channel);
            if (lightState[k] === undefined) lightState[k] = 0;
            // Lights already on at boot start their "on too long" clock now
            if (lightState[k] > 0) lightOnSince[k] = Date.now();
        }
    }
}

// Persist lightState every 60 seconds
setInterval(saveLightState, 60000);

// ─── SSE (Server-Sent Events) — real-time push to browser clients ────────────
const sseClients = new Set();

function broadcastEvent(event) {
    if (sseClients.size === 0) return;
    const msg = `data: ${JSON.stringify(event)}\n\n`;
    for (const client of sseClients) {
        try { client.write(msg); } catch { sseClients.delete(client); }
    }
}

// ─── Light command ────────────────────────────────────────────────────────────
async function lightCmd(subnet, device, channel, level, skipLog) {
    const pkt = buildDimmerPacket(Number(subnet), Number(device), Number(channel), Number(level));
    await sendPacket(pkt);
    const k = lightKey(subnet, device, channel);
    const prevLevel = lightState[k];
    const changed = prevLevel !== level;
    lightState[k] = level;
    if (changed) { saveLightState(); noteLightTransition(k, prevLevel, level); }
    if (level === 0) cancelTimer(k); // manual off cancels any countdown
    broadcastEvent({ type: 'lightState', key: k, level });
    if (!skipLog) {
        let devName = `${subnet}.${device} ch${channel}`;
        for (const room of db.rooms) {
            const l = (room.lights || []).find(l => l.subnet == subnet && l.device == device && l.channel == channel);
            if (l) { devName = `${room.name} / ${l.name}`; break; }
        }
        logActivity('device', `${level > 0 ? 'ON' : 'OFF'}: ${devName}`, { subnet, device, channel, level });
    }
}

// ─── Shared state update (used by UDP listener for both 0x0032 and 0x03CD) ───
function updateLightState(subnet, device, channel, level, logChange) {
    const k = lightKey(subnet, device, channel);
    const prev = lightState[k];
    lightState[k] = level;
    if (prev !== level) {
        saveLightState();
        noteLightTransition(k, prev, level);
        broadcastEvent({ type: 'lightState', key: k, level });
        if (level === 0) cancelTimer(k); // switched off externally (e.g. wall panel)
    }
    if (logChange && prev !== level) {
        let devName = `${subnet}.${device} ch${channel}`;
        for (const room of db.rooms) {
            const l = (room.lights || []).find(l =>
                l.subnet == subnet && l.device == device && l.channel == channel);
            if (l) { devName = `${room.name} / ${l.name}`; break; }
        }
        console.log(`[UDP] State: ${devName} = ${level > 0 ? 'ON' : 'OFF'} (${level})`);
        logActivity('device', `${level > 0 ? 'ON' : 'OFF'} (external): ${devName}`,
            { subnet, device, channel, level });
    }
}

// ─── UDP Listener ─────────────────────────────────────────────────────────────
const SMARTCLOUD_PREFIX = 'SMARTCLOUD'; // kept for legacy reference

// Build a 0x0033 "Read Status of Channels" packet — EMPTY payload (0 content bytes).
// Device responds with 0x0034: [channel_count, ch1_level, ch2_level, ...]
// This is fully read-only — does NOT change any device state.
function buildReadStatusPacket(targetSubnet, targetDevice) {
    const hdlNoCrc = Buffer.from([
        0x0B,             // length = 11 (no content bytes)
        SENDER_SUBNET, SENDER_DEVICE,
        DEVICE_TYPE[0], DEVICE_TYPE[1],
        0x00, 0x33,       // opcode: Read Status of Channels
        targetSubnet, targetDevice,
        // NO content bytes — empty payload per spec
    ]);
    const c = crc16(hdlNoCrc);
    return Buffer.concat([buildPrefix(), hdlNoCrc, Buffer.from([(c >> 8) & 0xFF, c & 0xFF])]);
}

// Send 0x0033 to each unique device — read-only state query.
// Each device responds with 0x0034 containing all its channel levels.
async function queryDeviceStates() {
    const deviceMap = new Map(); // "subnet.device" -> {subnet, device}
    for (const room of db.rooms) {
        for (const light of (room.lights || [])) {
            const key = `${light.subnet}.${light.device}`;
            if (!deviceMap.has(key)) deviceMap.set(key, light);
        }
    }
    let count = 0;
    for (const [, light] of deviceMap) {
        try {
            await sendPacket(buildReadStatusPacket(Number(light.subnet), Number(light.device)));
            count++;
            await new Promise(r => setTimeout(r, 200)); // 200ms between devices on startup query
        } catch (e) { /* ignore */ }
    }
    if (count > 0) console.log(`[State] Sent 0x0033 read queries to ${count} devices`);
}

function startUdpListener() {
    const listener = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    // Error handler must be registered before bind
    listener.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.warn('[UDP Listener] Port 6000 already in use — live state updates disabled');
        } else {
            console.warn('[UDP Listener] Error:', err.message);
        }
        try { listener.close(); } catch (e) {}
    });

    listener.on('message', (msg) => {
        try {
            // SMARTCLOUD_STR is a module-level constant — not recreated per message
            let offset = -1;
            for (let i = 0; i <= msg.length - SMARTCLOUD_STR.length; i++) {
                if (msg.slice(i, i + SMARTCLOUD_STR.length).equals(SMARTCLOUD_STR)) {
                    offset = i + SMARTCLOUD_STR.length + 2; // +2 skips 0xAA 0xAA
                    break;
                }
            }
            if (offset < 0 || msg.length < offset + 12) return;

            const opcode = (msg[offset + 5] << 8) | msg[offset + 6];

            if (opcode === 0x0032) {
                // [channel, 0xF8=success/0xF5=fail, level, ...]
                const subnet  = msg[offset + 1];
                const device  = msg[offset + 2];
                const channel = msg[offset + 9];  // content[0]
                const success = msg[offset + 10]; // content[1]: 0xF8=ok, 0xF5=fail
                const level   = msg[offset + 11]; // content[2]
                if (success === 0xF5) {
                    // Command failed — log it and broadcast alert
                    let devName = `${subnet}.${device} ch${channel}`;
                    for (const room of db.rooms) {
                        const l = (room.lights || []).find(l =>
                            l.subnet == subnet && l.device == device && l.channel == channel);
                        if (l) { devName = `${room.name} / ${l.name}`; break; }
                    }
                    console.warn(`[UDP] Command FAILED for ${devName}`);
                    logActivity('device', `FAILED: ${devName}`, { subnet, device, channel, success: false });
                    broadcastEvent({ type: 'commandFailed', key: lightKey(subnet, device, channel), devName });
                } else {
                    updateLightState(subnet, device, channel, level, true);
                }
            }

            // 0x0002: Scene activated from a physical wall panel
            if (opcode === 0x0002) {
                const subnet  = msg[offset + 1];
                const device  = msg[offset + 2];
                const area    = msg[offset + 9];  // content[0]
                const sceneNo = msg[offset + 10]; // content[1]
                const devName = `device ${subnet}.${device}`;
                console.log(`[UDP] Wall panel scene: area=${area} scene=${sceneNo} from ${devName}`);
                logActivity('scene', `Wall panel activated area ${area} scene ${sceneNo}`,
                    { subnet, device, area, sceneNo, source: 'wall_panel' });
                broadcastEvent({ type: 'wallPanelScene', subnet, device, area, sceneNo });
            }

            if (opcode === 0x0034) {
                // Response to 0x0033 read query: [channel_count, ch1_level, ch2_level, ...]
                const subnet = msg[offset + 1];
                const device = msg[offset + 2];
                const hdlLen = msg[offset + 0];
                const contentStart = offset + 9;
                const contentLen   = hdlLen - 11;
                if (contentLen >= 1) {
                    const chCount = msg[contentStart]; // first byte = channel count
                    for (let i = 0; i < chCount && i < contentLen - 1; i++) {
                        const level = msg[contentStart + 1 + i];
                        if (level <= 100) updateLightState(subnet, device, i + 1, level, false);
                    }
                    console.log(`[UDP] 0x0034: read ${chCount} channels for device ${subnet}.${device}`);
                }
            }

            if (opcode === 0x03CD) {
                // Comprehensive channel status — triggered by 0x0031/0x0033 to a device
                // Header format (confirmed): [01][senderSub][senderDev][typeHi][typeLo][10]
                // Then 16 bytes of channel levels: [ch1_level][ch2_level]...[ch16_level]
                const subnet = msg[offset + 1];
                const device = msg[offset + 2];
                const hdlLen = msg[offset + 0];
                const contentLen = hdlLen - 11; // already excludes CRC
                if (contentLen >= 7) {
                    // Skip 6-byte header, take channel level bytes
                    const channelData = msg.slice(offset + 9 + 6, offset + 9 + contentLen);
                    let updated = 0;
                    for (let i = 0; i < channelData.length; i++) {
                        const level = channelData[i];
                        if (level <= 100) {
                            updateLightState(subnet, device, i + 1, level, false);
                            updated++;
                        }
                    }
                    if (updated > 0) console.log(`[UDP] 0x03CD: synced ${updated} channels for device ${subnet}.${device}`);
                }
            }
        } catch (e) { /* ignore malformed packets */ }
    });

    // bind callback has NO error parameter — errors fire the 'error' event above
    listener.bind(6000, '0.0.0.0', () => {
        listener.setBroadcast(true);
        console.log('[UDP Listener] Bound to port 6000 — listening for SmartGate broadcasts');
        // Query all device states 2s after binding so listener is ready to capture responses
        setTimeout(queryDeviceStates, 2000);
    });
}

// ─── Sunrise/Sunset (Spencer algorithm, no npm) ──────────────────────────────
function sunTimes(date, lat, lon) {
    const rad = Math.PI / 180;
    const dayOfYear = Math.floor((date - new Date(date.getFullYear(), 0, 0)) / 86400000);
    const B = (360 / 365) * (dayOfYear - 81) * rad;
    const EoT = 9.87 * Math.sin(2 * B) - 7.53 * Math.cos(B) - 1.5 * Math.sin(B); // minutes
    const decl = 23.45 * Math.sin(B) * rad;
    const latRad = lat * rad;
    const cosHa = -Math.tan(latRad) * Math.tan(decl);
    if (cosHa < -1) return { sunrise: null, sunset: null }; // polar day
    if (cosHa >  1) return { sunrise: null, sunset: null }; // polar night
    const ha = Math.acos(cosHa) / rad; // hours-angle in degrees
    const solarNoon = 12 - (lon / 15) - (EoT / 60);
    const sunrise = solarNoon - ha / 15;
    const sunset  = solarNoon + ha / 15;
    return { sunrise, sunset }; // decimal hours UTC
}

function decimalHoursToHM(h) {
    const total = Math.round(h * 60);
    return { h: Math.floor(total / 60) % 24, m: total % 60 };
}

// ─── Scheduler ────────────────────────────────────────────────────────────────
const lastFiredMinute = {};

// Cache sun times per calendar date — only recalculated once per day
let sunCache = { date: null, sunrise: null, sunset: null };
function getCachedSunTimes(now) {
    const dateStr = now.toDateString();
    if (sunCache.date !== dateStr) {
        const lat = db.settings.latitude || 40.7128;
        const lon = db.settings.longitude || -74.006;
        const t = sunTimes(now, lat, lon);
        sunCache = { date: dateStr, sunrise: t.sunrise, sunset: t.sunset };
    }
    return sunCache;
}

setInterval(checkSchedules, 30000);

// Wall-clock "now" in the home's configured timezone — schedule times are
// entered as home wall-clock, and the NAS's own timezone may differ.
function nowInTimezone(tz) {
    try {
        const parts = new Intl.DateTimeFormat('en-US', {
            timeZone: tz, hour12: false, weekday: 'short', hour: '2-digit', minute: '2-digit',
        }).formatToParts(new Date());
        const get = t => parts.find(p => p.type === t)?.value;
        const days = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
        const hour = Number(get('hour')) % 24; // some ICU builds emit "24" at midnight
        return { minuteOfDay: hour * 60 + Number(get('minute')), day: days[get('weekday')] };
    } catch {
        const now = new Date(); // bad/missing timezone — fall back to server local
        return { minuteOfDay: now.getHours() * 60 + now.getMinutes(), day: now.getDay() };
    }
}

function tzOffsetMinutes(tz) {
    try {
        const now = new Date();
        const utc = new Date(now.toLocaleString('en-US', { timeZone: 'UTC' }));
        const loc = new Date(now.toLocaleString('en-US', { timeZone: tz }));
        return Math.round((loc - utc) / 60000);
    } catch { return -new Date().getTimezoneOffset(); }
}

async function checkSchedules() {
    const now = new Date();
    const tz = db.settings.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
    const { minuteOfDay: nowMinute, day } = nowInTimezone(tz);

    for (const sched of db.schedules) {
        if (!sched.enabled) continue;
        if (sched.days && sched.days.length > 0 && !sched.days.includes(day)) continue;

        let targetMinute = null;

        if (sched.triggerType === 'time' && sched.time) {
            const [hh, mm] = sched.time.split(':').map(Number);
            targetMinute = hh * 60 + mm;
        } else if (sched.triggerType === 'sunrise' || sched.triggerType === 'sunset') {
            const cached = getCachedSunTimes(now);
            const base = sched.triggerType === 'sunrise' ? cached.sunrise : cached.sunset;
            if (base == null) continue;
            const offsetMins = sched.offset || 0;
            const hm = decimalHoursToHM(base + offsetMins / 60);
            // Sun times are UTC — shift into the home timezone for comparison
            targetMinute = ((hm.h * 60 + hm.m + tzOffsetMinutes(tz)) + 1440) % 1440;
        }

        if (targetMinute === null) continue;
        if (nowMinute !== targetMinute) continue;

        // Key includes the date so the same schedule can fire on different days
        const firedKey = `${now.toDateString()}:${nowMinute}`;
        if (lastFiredMinute[sched.id] === firedKey) continue;
        lastFiredMinute[sched.id] = firedKey;

        try {
            if (sched.actionType === 'scene' && sched.sceneId) {
                await activateScene(sched.sceneId);
                const scene = db.scenes.find(s => s.id === sched.sceneId);
                logActivity('schedule', `Schedule fired: "${sched.name}"`, { sceneId: sched.sceneId, sceneName: scene?.name });
            } else if (sched.actionType === 'allOff') {
                await allOff();
                logActivity('schedule', `Schedule fired: "${sched.name}" — All Off`, { scheduleId: sched.id });
            }
            console.log(`[Scheduler] Fired schedule "${sched.name}" at minute ${nowMinute}`);
        } catch (e) {
            console.error(`[Scheduler] Error firing schedule "${sched.name}":`, e.message);
        }
    }
}

// Timing between commands: no official minimum in S-BUS spec.
// RS-485 bus at 9600 baud transmits ~30 bytes in ~25ms. 100ms is a safe margin.
const CMD_DELAY_SAME_DEVICE = 100; // ms — multiple channels on same physical module
const CMD_DELAY_DIFF_DEVICE =  50; // ms — commands to different physical modules

function cmdDelay(prevSubnet, prevDevice, curSubnet, curDevice) {
    if (prevSubnet === curSubnet && prevDevice === curDevice)
        return CMD_DELAY_SAME_DEVICE;
    return CMD_DELAY_DIFF_DEVICE;
}

async function activateScene(sceneId) {
    const scene = db.scenes.find(s => s.id === sceneId);
    if (!scene) return;
    // Expand floor/room/device actions into individual light commands
    const cmds = [];
    for (const action of (scene.actions || [])) {
        if (action.type === 'floor') {
            const rooms = db.rooms.filter(r => r.floorId === action.floorId);
            for (const room of rooms)
                for (const l of (room.lights || []))
                    cmds.push({ subnet: l.subnet, device: l.device, channel: l.channel, level: action.level });
        } else if (action.type === 'room') {
            const room = db.rooms.find(r => r.id === action.roomId);
            if (room)
                for (const l of (room.lights || []))
                    cmds.push({ subnet: l.subnet, device: l.device, channel: l.channel, level: action.level });
        } else {
            cmds.push(action);
        }
    }
    let prevSubnet = null, prevDevice = null;
    for (const cmd of cmds) {
        if (prevSubnet !== null) {
            await new Promise(r => setTimeout(r, cmdDelay(prevSubnet, prevDevice, cmd.subnet, cmd.device)));
        }
        await lightCmd(cmd.subnet, cmd.device, cmd.channel, cmd.level, true);
        prevSubnet = cmd.subnet;
        prevDevice = cmd.device;
    }
}

async function allOff() {
    // Use channel 0xFF to turn off ALL channels on each device in one command
    const devices = new Map();
    for (const room of db.rooms)
        for (const light of (room.lights || []))
            devices.set(`${light.subnet}.${light.device}`, { subnet: light.subnet, device: light.device });

    let prev = null;
    for (const [, d] of devices) {
        if (prev) await new Promise(r => setTimeout(r, CMD_DELAY_DIFF_DEVICE));
        await sendPacket(buildDimmerPacket(Number(d.subnet), Number(d.device), 0xFF, 0));
        // Update all known channels for this device
        for (const room of db.rooms)
            for (const light of (room.lights || []))
                if (light.subnet == d.subnet && light.device == d.device) {
                    const k = lightKey(light.subnet, light.device, light.channel);
                    noteLightTransition(k, lightState[k], 0);
                    lightState[k] = 0;
                    cancelTimer(k);
                    broadcastEvent({ type: 'lightState', key: k, level: 0 });
                }
        prev = d;
    }
    saveLightState();
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function parseBody(req) {
    return new Promise((resolve) => {
        let raw = '';
        req.on('data', chunk => { raw += chunk; });
        req.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve({}); } });
    });
}

function reply(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Access-Control-Allow-Origin': '*',
    });
    res.end(body);
}

function newId() {
    return crypto.randomBytes(6).toString('hex');
}

// ─── Static file server ───────────────────────────────────────────────────────
const MIME = {
    '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
    '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

function serveStatic(req, res, urlPath) {
    let filePath = path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath);
    // Security: prevent path traversal
    if (!filePath.startsWith(PUBLIC_DIR)) {
        res.writeHead(403); res.end('Forbidden'); return;
    }
    if (!fs.existsSync(filePath)) {
        filePath = path.join(PUBLIC_DIR, 'index.html');
    }
    const ext = path.extname(filePath);
    const mime = MIME[ext] || 'application/octet-stream';
    try {
        const data = fs.readFileSync(filePath);
        res.writeHead(200, { 'Content-Type': mime, 'Content-Length': data.length });
        res.end(data);
    } catch (e) {
        res.writeHead(500); res.end('Internal Server Error');
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
    const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const p = urlObj.pathname;
    const method = req.method;

    // OPTIONS preflight
    if (method === 'OPTIONS') {
        res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE', 'Access-Control-Allow-Headers': 'Content-Type' });
        res.end(); return;
    }

    // ── API routes ────────────────────────────────────────────────────────────
    if (p.startsWith('/api/')) {

        // ── AUTH: open endpoints (no token required) ──────────────────────────
        if (method === 'GET' && p === '/api/auth/status') {
            return reply(res, 200, { setup: !!auth.pinHash });
        }
        if (method === 'POST' && (p === '/api/auth/setup' || p === '/api/auth/login')) {
            const body = await parseBody(req);
            const pin = String(body.pin || '');
            const label = body.device;
            if (p === '/api/auth/setup') {
                if (auth.pinHash) return reply(res, 403, { error: 'Already set up — use login' });
                if (pin.length < 4) return reply(res, 400, { error: 'PIN must be at least 4 characters' });
                auth.salt = crypto.randomBytes(16).toString('hex');
                auth.pinHash = hashPin(pin, auth.salt);
                const token = issueToken(label);
                logActivity('auth', `Security enabled — device enrolled: ${auth.tokens[token].label}`, { label });
                console.log('[Auth] PIN configured, first device enrolled');
                return reply(res, 200, { ok: true, token });
            }
            // login
            const now = Date.now();
            if (now < pinFails.lockedUntil)
                return reply(res, 429, { error: `Too many attempts — wait ${Math.ceil((pinFails.lockedUntil - now) / 1000)}s` });
            if (!verifyPin(pin)) {
                pinFails.count++;
                pinFails.lockedUntil = now + Math.min(pinFails.count * pinFails.count, 60) * 1000;
                logActivity('auth', `Failed login attempt`, { label });
                return reply(res, 401, { error: 'Wrong PIN' });
            }
            pinFails = { count: 0, lockedUntil: 0 };
            const token = issueToken(label);
            logActivity('auth', `Device enrolled: ${auth.tokens[token].label}`, { label });
            return reply(res, 200, { ok: true, token });
        }

        // ── AUTH GATE: everything below requires a valid device token ─────────
        let reqToken = null;
        if (!(method === 'GET' && p === '/api/health')) {
            reqToken = getReqToken(req, urlObj);
            if (!auth.pinHash || !reqToken || !auth.tokens[reqToken])
                return reply(res, 401, { error: 'Unauthorized' });
            touchToken(reqToken);
        }

        // ── AUTH: device management (authenticated) ───────────────────────────
        if (method === 'GET' && p === '/api/auth/devices') {
            const list = Object.entries(auth.tokens).map(([tok, t]) => ({
                id: tok.slice(0, 8), label: t.label, created: t.created,
                lastSeen: t.lastSeen, current: tok === reqToken,
            })).sort((a, b) => b.lastSeen - a.lastSeen);
            return reply(res, 200, list);
        }
        const authDevMatch = p.match(/^\/api\/auth\/devices\/([^/]+)$/);
        if (authDevMatch && method === 'DELETE') {
            const tok = Object.keys(auth.tokens).find(t => t.slice(0, 8) === authDevMatch[1]);
            if (!tok) return reply(res, 404, { error: 'Not found' });
            const label = auth.tokens[tok].label;
            delete auth.tokens[tok];
            saveAuth();
            logActivity('auth', `Device revoked: ${label}`, { label });
            return reply(res, 200, { ok: true, wasCurrent: tok === reqToken });
        }

        // GET /api/events — SSE stream for real-time state updates
        if (method === 'GET' && p === '/api/events') {
            res.writeHead(200, {
                'Content-Type':  'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection':    'keep-alive',
                'Access-Control-Allow-Origin': '*',
            });
            // Send current state immediately on connect
            res.write(`data: ${JSON.stringify({ type: 'init', lightState, timers })}\n\n`);
            sseClients.add(res);
            // Keepalive comment every 30s to prevent proxy timeouts
            const hb = setInterval(() => {
                try { res.write(': keepalive\n\n'); } catch { clearInterval(hb); sseClients.delete(res); }
            }, 30000);
            req.on('close', () => { clearInterval(hb); sseClients.delete(res); });
            return; // keep connection open
        }

        // GET /api/health
        if (method === 'GET' && p === '/api/health') {
            return reply(res, 200, { ok: true, uptime: process.uptime() });
        }

        // GET /api/state
        if (method === 'GET' && p === '/api/state') {
            return reply(res, 200, lightState);
        }

        // POST /api/refresh — query all devices for current state
        if (method === 'POST' && p === '/api/refresh') {
            queryDeviceStates();
            return reply(res, 200, { ok: true, message: 'State query sent' });
        }

        // POST /api/light
        if (method === 'POST' && p === '/api/light') {
            const body = await parseBody(req);
            const { subnet = 1, device, channel, level } = body;
            if (device == null || channel == null || level == null)
                return reply(res, 400, { error: 'Required: device, channel, level' });
            if (level < 0 || level > 100)
                return reply(res, 400, { error: 'level must be 0-100' });
            try {
                await lightCmd(Number(subnet), Number(device), Number(channel), Number(level));
                return reply(res, 200, { ok: true, key: lightKey(subnet, device, channel), level });
            } catch (err) {
                return reply(res, 500, { ok: false, error: err.message });
            }
        }

        // ── TIMERS (ad-hoc auto-off countdowns) ───────────────────────────────
        if (method === 'GET' && p === '/api/timers') {
            return reply(res, 200, timers);
        }
        if (method === 'POST' && p === '/api/timer') {
            const body = await parseBody(req);
            const { subnet = 1, device, channel, minutes } = body;
            const mins = Number(minutes);
            if (device == null || channel == null || !mins || mins < 1 || mins > 1440)
                return reply(res, 400, { error: 'Required: device, channel, minutes (1-1440)' });
            const k = lightKey(subnet, device, channel);
            try {
                // Setting a timer on an OFF light turns it on ("on for N minutes")
                if (!lightState[k])
                    await lightCmd(Number(subnet), Number(device), Number(channel), 100);
                timers[k] = { expiresAt: Date.now() + mins * 60000, minutes: mins };
                saveTimers();
                broadcastEvent({ type: 'timer', key: k, timer: timers[k] });
                logActivity('timer', `Timer set (${mins} min): ${deviceName(subnet, device, channel)}`,
                    { subnet, device, channel, minutes: mins });
                return reply(res, 200, { ok: true, key: k, timer: timers[k] });
            } catch (err) {
                return reply(res, 500, { ok: false, error: err.message });
            }
        }
        const timerMatch = p.match(/^\/api\/timers\/([^/]+)$/);
        if (timerMatch && method === 'DELETE') {
            const k = timerMatch[1];
            if (!cancelTimer(k)) return reply(res, 404, { error: 'No timer for ' + k });
            const [ts, td, tc] = k.split('.');
            logActivity('timer', `Timer cancelled: ${deviceName(ts, td, tc)}`, { key: k });
            return reply(res, 200, { ok: true });
        }

        // ── MODE (Feature 3) ──────────────────────────────────────────────────
        if (p === '/api/mode') {
            if (method === 'GET') {
                return reply(res, 200, {
                    mode: db.settings.mode || 'home',
                    homeSceneId: db.settings.homeSceneId || null,
                    awaySceneId: db.settings.awaySceneId || null,
                });
            }
            if (method === 'POST') {
                const body = await parseBody(req);
                const newMode = body.mode === 'away' ? 'away' : 'home';
                const prevMode = db.settings.mode || 'home';
                db.settings.mode = newMode;
                saveDb('settings');
                logActivity('mode', `Mode changed to ${newMode}`, { from: prevMode, to: newMode });
                // Activate corresponding scene if configured
                const sceneId = newMode === 'away' ? db.settings.awaySceneId : db.settings.homeSceneId;
                if (sceneId) {
                    try {
                        await activateScene(sceneId);
                        const scene = db.scenes.find(s => s.id === sceneId);
                        logActivity('scene', `Scene activated (${newMode} mode): ${scene?.name || sceneId}`, { sceneId });
                    } catch (e) {
                        console.error('[Mode] Failed to activate scene:', e.message);
                    }
                }
                return reply(res, 200, { mode: newMode, ok: true });
            }
        }

        // ── ACTIVITY ──────────────────────────────────────────────────────────
        if (method === 'GET' && p === '/api/activity') {
            const limit = Math.min(parseInt(urlObj.searchParams.get('limit') || '50', 10), 500);
            return reply(res, 200, activityLog.slice(0, limit));
        }

        // ── FLOORS ────────────────────────────────────────────────────────────
        if (p === '/api/floors') {
            if (method === 'GET') return reply(res, 200, db.floors);
            if (method === 'POST') {
                const body = await parseBody(req);
                const floor = { id: newId(), name: body.name || 'New Floor' };
                db.floors.push(floor);
                saveDb('floors');
                return reply(res, 201, floor);
            }
        }
        const floorMatch = p.match(/^\/api\/floors\/([^/]+)$/);
        if (floorMatch) {
            const id = floorMatch[1];
            if (method === 'PUT') {
                const body = await parseBody(req);
                const idx = db.floors.findIndex(f => f.id === id);
                if (idx < 0) return reply(res, 404, { error: 'not found' });
                db.floors[idx] = { ...db.floors[idx], ...body };
                saveDb('floors');
                return reply(res, 200, db.floors[idx]);
            }
            if (method === 'DELETE') {
                db.floors = db.floors.filter(f => f.id !== id);
                saveDb('floors');
                return reply(res, 200, { ok: true });
            }
        }

        // ── FLOOR ALL-OFF (Feature 10) ────────────────────────────────────────
        const floorAllOff = p.match(/^\/api\/floor\/([^/]+)\/alloff$/);
        if (floorAllOff && method === 'POST') {
            const floorId = floorAllOff[1];
            const floor = db.floors.find(f => f.id === floorId);
            if (!floor) return reply(res, 404, { error: 'Floor not found' });
            const floorRooms = db.rooms.filter(r => r.floorId === floorId);
            // Use 0xFF to turn off all channels per device in one command
            const floorDevices = new Map();
            for (const room of floorRooms)
                for (const light of (room.lights || []))
                    floorDevices.set(`${light.subnet}.${light.device}`, { subnet: light.subnet, device: light.device });

            let count = 0, prev = null;
            for (const [, d] of floorDevices) {
                try {
                    if (prev) await new Promise(r => setTimeout(r, CMD_DELAY_DIFF_DEVICE));
                    await sendPacket(buildDimmerPacket(Number(d.subnet), Number(d.device), 0xFF, 0));
                    for (const room of floorRooms)
                        for (const light of (room.lights || []))
                            if (light.subnet == d.subnet && light.device == d.device) {
                                const k = lightKey(light.subnet, light.device, light.channel);
                                noteLightTransition(k, lightState[k], 0);
                                lightState[k] = 0;
                                cancelTimer(k);
                                broadcastEvent({ type: 'lightState', key: k, level: 0 });
                            }
                    prev = d; count++;
                } catch (e) { console.error('[FloorAllOff]', e.message); }
            }
            saveLightState();
            logActivity('device', `All Off: floor "${floor.name}" (${count} device${count === 1 ? '' : 's'})`, { floorId, floorName: floor.name, count });
            return reply(res, 200, { ok: true, floor: floor.name, count });
        }

        // ── ROOMS ─────────────────────────────────────────────────────────────
        if (p === '/api/rooms') {
            if (method === 'GET') return reply(res, 200, db.rooms);
            if (method === 'POST') {
                const body = await parseBody(req);
                const room = { id: newId(), name: body.name || 'New Room', icon: body.icon || '💡', color: body.color || '#7c3aed', lights: [] };
                db.rooms.push(room);
                saveDb('rooms');
                return reply(res, 201, room);
            }
        }
        const roomMatch = p.match(/^\/api\/rooms\/([^/]+)$/);
        if (roomMatch) {
            const id = roomMatch[1];
            const idx = db.rooms.findIndex(r => r.id === id);
            if (method === 'GET') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                return reply(res, 200, db.rooms[idx]);
            }
            if (method === 'PUT') {
                const body = await parseBody(req);
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.rooms[idx] = { ...db.rooms[idx], ...body, id };
                saveDb('rooms');
                initLightState();
                return reply(res, 200, db.rooms[idx]);
            }
            if (method === 'DELETE') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.rooms.splice(idx, 1);
                saveDb('rooms');
                return reply(res, 200, { ok: true });
            }
        }

        // ── DEVICES ───────────────────────────────────────────────────────────
        if (p === '/api/devices') {
            if (method === 'GET') return reply(res, 200, db.devices);
            if (method === 'POST') {
                const body = await parseBody(req);
                const dev = { id: newId(), name: body.name || 'New Device', subnet: Number(body.subnet) || 1, device: Number(body.device) || 0 };
                db.devices.push(dev);
                saveDb('devices');
                return reply(res, 201, dev);
            }
        }
        const devMatch = p.match(/^\/api\/devices\/([^/]+)$/);
        if (devMatch) {
            const id = devMatch[1];
            const idx = db.devices.findIndex(d => d.id === id);
            if (method === 'GET') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                return reply(res, 200, db.devices[idx]);
            }
            if (method === 'PUT') {
                const body = await parseBody(req);
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.devices[idx] = { ...db.devices[idx], ...body, id };
                saveDb('devices');
                return reply(res, 200, db.devices[idx]);
            }
            if (method === 'DELETE') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.devices.splice(idx, 1);
                saveDb('devices');
                return reply(res, 200, { ok: true });
            }
        }

        // ── SCENES ────────────────────────────────────────────────────────────
        if (p === '/api/scenes') {
            if (method === 'GET') return reply(res, 200, db.scenes);
            if (method === 'POST') {
                const body = await parseBody(req);
                const scene = { id: newId(), name: body.name || 'New Scene', icon: body.icon || '✨', actions: body.actions || [] };
                db.scenes.push(scene);
                saveDb('scenes');
                return reply(res, 201, scene);
            }
        }
        const sceneActivate = p.match(/^\/api\/scenes\/([^/]+)\/activate$/);
        if (sceneActivate && method === 'POST') {
            const id = sceneActivate[1];
            const scene = db.scenes.find(s => s.id === id);
            if (!scene) return reply(res, 404, { error: 'Scene not found' });
            try {
                await activateScene(id);
                logActivity('scene', `Scene activated: "${scene.name}"`, { sceneId: id });
                return reply(res, 200, { ok: true, activated: id });
            } catch (err) {
                return reply(res, 500, { ok: false, error: err.message });
            }
        }
        const sceneMatch = p.match(/^\/api\/scenes\/([^/]+)$/);
        if (sceneMatch) {
            const id = sceneMatch[1];
            const idx = db.scenes.findIndex(s => s.id === id);
            if (method === 'GET') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                return reply(res, 200, db.scenes[idx]);
            }
            if (method === 'PUT') {
                const body = await parseBody(req);
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.scenes[idx] = { ...db.scenes[idx], ...body, id };
                saveDb('scenes');
                return reply(res, 200, db.scenes[idx]);
            }
            if (method === 'DELETE') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.scenes.splice(idx, 1);
                saveDb('scenes');
                return reply(res, 200, { ok: true });
            }
        }

        // ── SCHEDULES ─────────────────────────────────────────────────────────
        if (p === '/api/schedules') {
            if (method === 'GET') return reply(res, 200, db.schedules);
            if (method === 'POST') {
                const body = await parseBody(req);
                const sched = {
                    id: newId(), name: body.name || 'New Schedule', enabled: body.enabled !== false,
                    triggerType: body.triggerType || 'time', time: body.time || '07:00',
                    offset: body.offset || 0, days: body.days || [0,1,2,3,4,5,6],
                    actionType: body.actionType || 'scene', sceneId: body.sceneId || null,
                };
                if (sched.actionType === 'scene' && !sched.sceneId)
                    return reply(res, 400, { error: 'A scene schedule needs a sceneId' });
                db.schedules.push(sched);
                saveDb('schedules');
                return reply(res, 201, sched);
            }
        }
        const schedMatch = p.match(/^\/api\/schedules\/([^/]+)$/);
        if (schedMatch) {
            const id = schedMatch[1];
            const idx = db.schedules.findIndex(s => s.id === id);
            if (method === 'GET') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                return reply(res, 200, db.schedules[idx]);
            }
            if (method === 'PUT') {
                const body = await parseBody(req);
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                const merged = { ...db.schedules[idx], ...body, id };
                if (merged.actionType === 'scene' && !merged.sceneId)
                    return reply(res, 400, { error: 'A scene schedule needs a sceneId' });
                db.schedules[idx] = merged;
                saveDb('schedules');
                return reply(res, 200, db.schedules[idx]);
            }
            if (method === 'DELETE') {
                if (idx === -1) return reply(res, 404, { error: 'Not found' });
                db.schedules.splice(idx, 1);
                saveDb('schedules');
                return reply(res, 200, { ok: true });
            }
        }

        // ── SETTINGS ──────────────────────────────────────────────────────────
        if (p === '/api/settings') {
            if (method === 'GET') return reply(res, 200, db.settings);
            if (method === 'PUT') {
                const body = await parseBody(req);
                db.settings = { ...db.settings, ...body };
                if (db.settings.gatewayIp)   { SMARTGATE_IP   = db.settings.gatewayIp; invalidatePrefix(); }
                if (db.settings.gatewayPort)   SMARTGATE_PORT = db.settings.gatewayPort;
                saveDb('settings');
                return reply(res, 200, db.settings);
            }
        }

        // Legacy endpoints kept for compatibility
        if (method === 'GET' && (p === '/api/on' || p === '/api/off')) {
            const level = p === '/api/on' ? 100 : 0;
            try { await lightCmd(1, 7, 9, level); return reply(res, 200, { ok: true }); }
            catch (err) { return reply(res, 500, { ok: false, error: err.message }); }
        }

        return reply(res, 404, { error: 'API endpoint not found' });
    }

    // ── Static files ──────────────────────────────────────────────────────────
    serveStatic(req, res, urlObj.pathname);
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
loadDb();
loadActivity();
loadAuth();
loadTimers();
initLightState();
startUdpListener();

// Refresh device states every 5 minutes in case something changed externally
setInterval(queryDeviceStates, 5 * 60 * 1000);

server.listen(SERVER_PORT, LISTEN_IP, () => {
    console.log(`Smart-Bus G4 server on http://localhost:${SERVER_PORT}`);
    console.log(`SmartGate: ${SMARTGATE_IP}:${SMARTGATE_PORT}`);
    console.log(`Sender: ${SENDER_SUBNET}.${SENDER_DEVICE}  DeviceType: 0x${((DEVICE_TYPE[0]<<8)|DEVICE_TYPE[1]).toString(16).toUpperCase()}`);
    console.log(`Data dir: ${DATA_DIR}`);
    console.log(`Public dir: ${PUBLIC_DIR}`);
});

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
const SERVER_PORT  = 3002;
const LISTEN_IP    = '0.0.0.0';

// ─── Protocol constants ───────────────────────────────────────────────────────
// PREFIX is rebuilt dynamically so it stays in sync when settings change the IP
function buildPrefix() {
    const parts = SMARTGATE_IP.split('.').map(Number);
    return Buffer.concat([
        Buffer.from(parts),
        Buffer.from('SMARTCLOUD', 'ascii'),
        Buffer.from([0xAA, 0xAA]),
    ]);
}

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

// ─── Data layer ───────────────────────────────────────────────────────────────
const DB_FILES = ['rooms', 'devices', 'scenes', 'schedules', 'settings'];

let db = { rooms: [], devices: [], scenes: [], schedules: [], settings: {} };

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
            if (name === 'rooms') {
                db.rooms = [{
                    id: 'default-room-1', name: 'Living Room', icon: '🛋️', color: '#7c3aed',
                    lights: [{ id: 'default-light-1', name: 'Main Light', subnet: 1, device: 7, channel: 9, type: 'relay' }]
                }];
            } else if (name === 'devices') {
                db.devices = [{ id: 'default-device-1', name: 'Dimmer 1.7', subnet: 1, device: 7 }];
            } else if (name === 'settings') {
                db.settings = { latitude: 40.7128, longitude: -74.006, timezone: 'America/New_York', gatewayIp: '192.168.1.100', gatewayPort: 6000 };
            } else {
                db[name] = [];
            }
            saveDb(name);
        }
    }
    // Sync gateway config from settings
    if (db.settings.gatewayIp)   SMARTGATE_IP   = db.settings.gatewayIp;
    if (db.settings.gatewayPort) SMARTGATE_PORT = db.settings.gatewayPort;
}

function saveDb(name) {
    ensureDataDir();
    const file = path.join(DATA_DIR, `${name}.json`);
    fs.writeFileSync(file, JSON.stringify(db[name], null, 2), 'utf8');
}

// ─── In-memory light state ────────────────────────────────────────────────────
// Key: "subnet.device.channel"  Value: 0 or 100
const lightState = {};

function lightKey(subnet, device, channel) {
    return `${subnet}.${device}.${channel}`;
}

function initLightState() {
    for (const room of db.rooms) {
        for (const light of (room.lights || [])) {
            const k = lightKey(light.subnet, light.device, light.channel);
            if (lightState[k] === undefined) lightState[k] = 0;
        }
    }
}

// ─── Light command ────────────────────────────────────────────────────────────
async function lightCmd(subnet, device, channel, level) {
    const pkt = buildDimmerPacket(Number(subnet), Number(device), Number(channel), Number(level));
    await sendPacket(pkt);
    lightState[lightKey(subnet, device, channel)] = level;
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
const lastFiredMinute = {}; // scheduleId -> minute-of-day when last fired

setInterval(checkSchedules, 30000);

async function checkSchedules() {
    const now = new Date();
    const nowMinute = now.getHours() * 60 + now.getMinutes();
    const day = now.getDay(); // 0=Sun

    for (const sched of db.schedules) {
        if (!sched.enabled) continue;
        if (sched.days && sched.days.length > 0 && !sched.days.includes(day)) continue;

        let targetMinute = null;

        if (sched.triggerType === 'time' && sched.time) {
            const [hh, mm] = sched.time.split(':').map(Number);
            targetMinute = hh * 60 + mm;
        } else if (sched.triggerType === 'sunrise' || sched.triggerType === 'sunset') {
            const lat = db.settings.latitude || 40.7128;
            const lon = db.settings.longitude || -74.006;
            const times = sunTimes(now, lat, lon);
            const base = sched.triggerType === 'sunrise' ? times.sunrise : times.sunset;
            if (base == null) continue;
            const offsetMins = sched.offset || 0;
            const hm = decimalHoursToHM(base + offsetMins / 60);
            // Convert UTC to local: use timezone offset
            const utcOffset = -now.getTimezoneOffset(); // minutes
            targetMinute = ((hm.h * 60 + hm.m + utcOffset) + 1440) % 1440;
        }

        if (targetMinute === null) continue;
        if (nowMinute !== targetMinute) continue;
        if (lastFiredMinute[sched.id] === nowMinute) continue;

        lastFiredMinute[sched.id] = nowMinute;

        try {
            if (sched.actionType === 'scene' && sched.sceneId) {
                await activateScene(sched.sceneId);
            } else if (sched.actionType === 'allOff') {
                await allOff();
            }
            console.log(`[Scheduler] Fired schedule "${sched.name}" at minute ${nowMinute}`);
        } catch (e) {
            console.error(`[Scheduler] Error firing schedule "${sched.name}":`, e.message);
        }
    }
}

async function activateScene(sceneId) {
    const scene = db.scenes.find(s => s.id === sceneId);
    if (!scene) return;
    for (const action of (scene.actions || [])) {
        await lightCmd(action.subnet, action.device, action.channel, action.level);
        await new Promise(r => setTimeout(r, 60));
    }
}

async function allOff() {
    for (const room of db.rooms) {
        for (const light of (room.lights || [])) {
            await lightCmd(light.subnet, light.device, light.channel, 0);
            await new Promise(r => setTimeout(r, 60));
        }
    }
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

        // GET /api/health
        if (method === 'GET' && p === '/api/health') {
            return reply(res, 200, { ok: true, uptime: process.uptime() });
        }

        // GET /api/state
        if (method === 'GET' && p === '/api/state') {
            return reply(res, 200, lightState);
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
                db.schedules[idx] = { ...db.schedules[idx], ...body, id };
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
                if (db.settings.gatewayIp)   SMARTGATE_IP   = db.settings.gatewayIp;
                if (db.settings.gatewayPort) SMARTGATE_PORT = db.settings.gatewayPort;
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
initLightState();

server.listen(SERVER_PORT, LISTEN_IP, () => {
    console.log(`Smart-Bus G4 server on http://localhost:${SERVER_PORT}`);
    console.log(`SmartGate: ${SMARTGATE_IP}:${SMARTGATE_PORT}`);
    console.log(`Sender: ${SENDER_SUBNET}.${SENDER_DEVICE}  DeviceType: 0x${((DEVICE_TYPE[0]<<8)|DEVICE_TYPE[1]).toString(16).toUpperCase()}`);
    console.log(`Data dir: ${DATA_DIR}`);
    console.log(`Public dir: ${PUBLIC_DIR}`);
});

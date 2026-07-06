'use strict';
// Long probe — 10 minutes, logs to file, captures all opcodes
// Also tests: send 0x0031 to already-ON device — does it respond with current level?

const dgram = require('dgram');
const fs    = require('fs');

const SMARTGATE_IP   = '192.168.86.166';
const SMARTGATE_PORT = 6000;
const LOG_FILE = '/tmp/probe_long.log';

function crc16(buf) {
    let crc = 0;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] << 8;
        for (let j = 0; j < 8; j++)
            crc = (crc & 0x8000) ? (((crc << 1) ^ 0x1021) & 0xFFFF) : ((crc << 1) & 0xFFFF);
    }
    return crc;
}

const PREFIX = Buffer.concat([
    Buffer.from([192, 168, 86, 166]),
    Buffer.from('SMARTCLOUD', 'ascii'),
    Buffer.from([0xAA, 0xAA]),
]);

function buildCmd(targetSubnet, targetDevice, opcode, content) {
    const len = 9 + content.length + 2;
    const body = Buffer.from([len, 0x01, 0x32, 0x01, 0x19,
        (opcode>>8)&0xFF, opcode&0xFF, targetSubnet, targetDevice]);
    const full = Buffer.concat([body, Buffer.from(content)]);
    const c = crc16(full);
    return Buffer.concat([PREFIX, full, Buffer.from([(c>>8)&0xFF, c&0xFF])]);
}

function parsePacket(msg) {
    const SC = Buffer.from('SMARTCLOUD', 'ascii');
    let off = -1;
    for (let i = 0; i <= msg.length - SC.length; i++) {
        if (msg.slice(i, i + SC.length).equals(SC)) { off = i + SC.length + 2; break; }
    }
    if (off < 0 || msg.length < off + 9) return null;
    const hdl = msg.slice(off);
    return {
        subnet: hdl[1], device: hdl[2],
        type:   (hdl[3]<<8)|hdl[4],
        opcode: (hdl[5]<<8)|hdl[6],
        tSub:   hdl[7], tDev: hdl[8],
        content: hdl.slice(9, Math.max(0, hdl[0]-2)),
        raw: hdl.slice(0, hdl[0]).toString('hex'),
    };
}

function hex(buf) { return [...buf].map(b=>b.toString(16).padStart(2,'0')).join(' '); }
function ts() { return new Date().toTimeString().slice(0,8); }

function log(msg) {
    const line = msg + '\n';
    process.stdout.write(line);
    fs.appendFileSync(LOG_FILE, line);
}

fs.writeFileSync(LOG_FILE, `=== LONG PROBE START ${new Date().toISOString()} ===\n`);
log('Logging all non-heartbeat opcodes for 10 minutes...');
log('Devices currently ON: 1.7 ch9, 1.7 ch13, 1.181 ch5, 1.181 ch8, 1.149 ch2, 1.45 ch7');

const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
const opcodeCounts = {};

udp.on('message', (msg) => {
    const p = parsePacket(msg);
    if (!p) return;
    const op = '0x' + p.opcode.toString(16).toUpperCase().padStart(4,'0');
    opcodeCounts[op] = (opcodeCounts[op] || 0) + 1;
    const ct = hex(p.content);
    const key = `${p.subnet}.${p.device}`;

    // Log EVERYTHING except routine heartbeats (E3E7/E3E8 with all-zero content)
    const isRoutineHeartbeat = (p.opcode === 0xE3E7 || p.opcode === 0xE3E8)
        && p.content.every(b => b === 0 || (p.content.indexOf(b) === 0 && b === 1));

    if (!isRoutineHeartbeat) {
        log(`${ts()} ${key} op=${op} → ${p.tSub}.${p.tDev} | [${ct}]`);
    }

    // Specifically track 0x0032 and 0x0034
    if (p.opcode === 0x0032 || p.opcode === 0x0034) {
        const ch = p.content[0];
        const lv = p.content.length > 2 ? p.content[2] : p.content[1];
        log(`  >>> ${op} STATE: ${key} ch${ch} = ${lv}%`);
    }

    // Track any non-zero E3E8 content
    if (p.opcode === 0xE3E8 && p.content.some((b,i) => i > 0 && b > 0)) {
        log(`  >>> E3E8 NON-ZERO from ${key}: [${ct}]`);
    }

    // Track 0x03CD
    if (p.opcode === 0x03CD) {
        log(`  >>> 0x03CD from ${key}: [${ct}]`);
    }
});

udp.bind(6000, '0.0.0.0', () => {
    udp.setBroadcast(true);
    log('[UDP] Bound to port 6000');

    // Test: send 0x0031 to device 1.7 ch9 at level=100 (already on — does it respond?)
    setTimeout(() => {
        log('\n[TEST] Sending 0x0031 level=100 to device 1.7 ch9 (already ON)...');
        const pkt = buildCmd(1, 7, 0x0031, [9, 100, 0, 0]);
        udp.send(pkt, 0, pkt.length, SMARTGATE_PORT, SMARTGATE_IP);
    }, 3000);

    // Test: send 0x0031 to device 1.181 ch5 at level=100 (already on)
    setTimeout(() => {
        log('[TEST] Sending 0x0031 level=100 to device 1.181 ch5 (already ON)...');
        const pkt = buildCmd(1, 181, 0x0031, [5, 100, 0, 0]);
        udp.send(pkt, 0, pkt.length, SMARTGATE_PORT, SMARTGATE_IP);
    }, 5000);

    // Report opcode summary every 2 minutes
    const reportInterval = setInterval(() => {
        log(`\n[SUMMARY] Opcodes seen: ${JSON.stringify(opcodeCounts)}\n`);
    }, 120000);

    setTimeout(() => {
        clearInterval(reportInterval);
        log(`\n=== PROBE COMPLETE ===`);
        log(`Final opcode counts: ${JSON.stringify(opcodeCounts)}`);
        udp.close();
        process.exit(0);
    }, 600000); // 10 minutes
});

'use strict';
// Probe v2 — investigate 0xE3E8 content (possible channel states) and 0xF036
// Sends 0x0286 via UDP, listens for 60 seconds, logs ALL packet content

const dgram = require('dgram');

const SMARTGATE_IP   = '192.168.86.166';
const SMARTGATE_PORT = 6000;

function crc16(buf) {
    let crc = 0x0000;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] << 8;
        for (let j = 0; j < 8; j++)
            crc = (crc & 0x8000) ? (((crc << 1) ^ 0x1021) & 0xFFFF) : ((crc << 1) & 0xFFFF);
    }
    return crc;
}

function buildPrefix() {
    return Buffer.concat([
        Buffer.from([192, 168, 86, 166]),
        Buffer.from('SMARTCLOUD', 'ascii'),
        Buffer.from([0xAA, 0xAA]),
    ]);
}

function buildPacket(targetSubnet, targetDevice, opcode, content) {
    const fixed = 1 + 1 + 1 + 2 + 2 + 1 + 1; // length+subnet+device+type+opcode+target
    const length = fixed + content.length + 2;  // +2 CRC
    const hdlNoCrc = Buffer.concat([
        Buffer.from([length, 0x01, 0x32, 0x01, 0x19,
                     (opcode >> 8) & 0xFF, opcode & 0xFF,
                     targetSubnet, targetDevice]),
        Buffer.from(content),
    ]);
    const c = crc16(hdlNoCrc);
    return Buffer.concat([buildPrefix(), hdlNoCrc, Buffer.from([(c >> 8) & 0xFF, c & 0xFF])]);
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
        length:  hdl[0],
        subnet:  hdl[1],
        device:  hdl[2],
        type:    (hdl[3] << 8) | hdl[4],
        opcode:  (hdl[5] << 8) | hdl[6],
        tSubnet: hdl[7],
        tDevice: hdl[8],
        content: hdl.slice(9, Math.max(0, hdl[0] - 2)),
    };
}

function hex(buf) { return [...buf].map(b => b.toString(16).padStart(2,'0')).join(' '); }
function ts() { return new Date().toTimeString().slice(0,8); }

// Track state per device from E3E8 content
const deviceStates = {}; // "subnet.device" -> channel array

const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });

udp.on('message', (msg) => {
    const p = parsePacket(msg);
    if (!p) return;
    const op = '0x' + p.opcode.toString(16).toUpperCase().padStart(4,'0');
    const ct = hex(p.content);
    const key = `${p.subnet}.${p.device}`;

    // Log everything — full content
    console.log(`${ts()} ${key} [type=0x${p.type.toString(16).toUpperCase().padStart(4,'0')}] op=${op} → ${p.tSubnet}.${p.tDevice} | [${ct}]`);

    // 0xE3E8: SmartGate heartbeat poll — content might be channel states
    if (p.opcode === 0xE3E8 && p.content.length >= 16) {
        const channels = [...p.content.slice(1, 17)]; // skip first byte, take 16
        const onChannels = channels.map((v,i) => v > 0 ? `ch${i+1}=${v}` : null).filter(Boolean);
        if (onChannels.length > 0) {
            console.log(`  *** E3E8 CHANNEL DATA for device ${p.tSubnet}.${p.tDevice}: ${onChannels.join(', ')}`);
        } else {
            console.log(`  *** E3E8 CHANNEL DATA for device ${p.tSubnet}.${p.tDevice}: all zero`);
        }
        deviceStates[`${p.tSubnet}.${p.tDevice}`] = channels;
    }

    // 0xF036: unknown opcode — log full detail
    if (p.opcode === 0xF036) {
        console.log(`  *** F036 from ${key}: content=[${ct}] — investigate this`);
    }

    // 0x0032 / 0x0034: known channel state responses
    if (p.opcode === 0x0032 || p.opcode === 0x0034) {
        const ch = p.content[0];
        const lv = p.content[2] !== undefined ? p.content[2] : p.content[1];
        console.log(`  *** ${op} STATE: device ${key} ch${ch} = ${lv}%`);
    }
});

udp.bind(6000, '0.0.0.0', () => {
    udp.setBroadcast(true);
    console.log(`[UDP] Listening on port 6000 for 60 seconds...\n`);

    // Send 0x0286 broadcast via UDP after 1s
    setTimeout(() => {
        const pkt = buildPacket(0x01, 0xFF, 0x0286, []);
        udp.send(pkt, 0, pkt.length, SMARTGATE_PORT, SMARTGATE_IP, () => {
            console.log(`[UDP] Sent 0x0286 broadcast query → 1.255`);
        });
    }, 1000);

    // Also send 0x0286 directly to the SmartGate (1.149)
    setTimeout(() => {
        const pkt = buildPacket(0x01, 0x95, 0x0286, []);
        udp.send(pkt, 0, pkt.length, SMARTGATE_PORT, SMARTGATE_IP, () => {
            console.log(`[UDP] Sent 0x0286 query → SmartGate 1.149`);
        });
    }, 2000);

    // Send 0xE3E7 heartbeat FROM us TO SmartGate — pretend to be a device
    // This may trigger SmartGate to poll us back with 0xE3E8 that contains state
    setTimeout(() => {
        const pkt = buildPacket(0x01, 0x95, 0xE3E7, [0x01]);
        udp.send(pkt, 0, pkt.length, SMARTGATE_PORT, SMARTGATE_IP, () => {
            console.log(`[UDP] Sent 0xE3E7 heartbeat → SmartGate 1.149`);
        });
    }, 3000);
});

setTimeout(() => {
    console.log('\n=== PROBE COMPLETE ===');
    console.log('Device states from E3E8:', JSON.stringify(deviceStates, null, 2));
    udp.close();
    process.exit(0);
}, 60000);

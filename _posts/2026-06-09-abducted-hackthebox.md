---
title: Abducted Write-up
date: 2026-06-09
categories: [HackTheBox, Write-up]
tags: [write-up, tutorial, HackTheBox]
author: Mohamad Helmi
description: "Abducted HackTheBox machine write-up"
---

# Abducted — HackTheBox Write-up

## Intro

Abducted is a medium-difficulty Linux machine themed around a file and print server for a professional services firm. The attack path kicks off with a CVE in the Samba print subsystem, followed by digging out a reused password from an rclone config, and finally abusing share permissions to land user access. Pretty fun chain overall — let's get into it.

---

## Enumeration

Starting off with `rustscan`, we get 3 open ports:

```txt
PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
139/tcp open  netbios-ssn syn-ack Samba smbd 4
445/tcp open  netbios-ssn syn-ack Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 22 (SSH), 139 and 445 (Samba). Looks like a file/print server. Let's go for low-hanging fruit and enumerate the SMB shares with anonymous login.

![shares](/assets/img/posts/2026-06-09-abducted-hackthebox/shares_enum.png)

The `transfer` and `projects` shares reject anonymous access, but `HP-Reception` allows guest printing — that's interesting. We also grab the server version from the SMB negotiation.

Next, we use `rpcclient` for an anonymous RPC connection to pull more info:

![samba version](/assets/img/posts/2026-06-09-abducted-hackthebox/smb_version.png)

A couple of things stand out:
- OS version **6.1** — that's Windows 7 / Server 2008 R2 territory. Old and likely vulnerable.
- Print services are active.

With that, we identify the relevant CVE: [CVE-2026-4480](https://www.samba.org/samba/security/CVE-2026-4480.html). The Samba print subsystem passes the client-supplied print job name directly into the print command without sanitizing it — meaning we can inject commands through the job name itself.

---

## Exploitation

We use the PoC from [here](https://github.com/TheCyberGeek/CVE-2026-4480-PoC) to trigger the vulnerability and catch a reverse shell as `nobody`.

![reverse shell](/assets/img/posts/2026-06-09-abducted-hackthebox/revshell.png)

From here we start poking around the host. We find an rclone config sitting in `/opt/offsite-backup`:

```bash
nobody@abducted:/var/spool/samba$ cat /opt/offsite-backup/rclone.conf 
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

The password here isn't actually encrypted — rclone only "obscures" it using a reversible encoding. rclone itself can decode it:

```bash
nobody@abducted:/var/spool/samba$ rclone obscure --reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

We try this password against other accounts on the system, and it turns out `scott` reused it. Login succeeds and we grab the user flag.

![user flag](/assets/img/posts/2026-06-09-abducted-hackthebox/user_flag.png)

---

## Key Takeaways

- **Print subsystem CVEs are no joke** — if Samba exposes guest printing without sanitizing input, a single crafted job name is enough to get a shell.
- **rclone "obscure" is not encryption** — passwords stored in rclone configs are trivially reversible using rclone's own tooling. Never treat them as secure.
- **Password reuse remains a real problem** — even with just a service account password, it's always worth trying it across other accounts.
- **Anonymous enumeration goes a long way** — SMB shares and RPC alone gave us enough info to identify the attack surface and find the right CVE.
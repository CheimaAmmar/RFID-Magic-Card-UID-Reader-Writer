# RFID Magic Card UID Reader & Writer

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red.svg)
![Status](https://img.shields.io/badge/status-experimental%20prototype-orange.svg)

> An **experimental prototype** for security research: reading and rewriting UIDs
> on MIFARE Classic "magic" cards using the MFRC522 RFID reader. Built for
> authorized security testing, access-control assessment, and RFID education.
>
> **This tool demonstrates why UID-only access control is broken.**
> See [Defending Against This Attack](#defending-against-this-attack) for the
> countermeasures analysis.

---

## Introduction

Most RFID cards store their **UID (Unique Identifier)** in a factory-locked
memory block (Block 0), making them impossible to clone at the UID level with
normal tools.

**Magic cards** are Chinese clones (often called *CUID* or *Gen1/Gen2* cards)
with an unlocked Block 0 or a hidden backdoor command, allowing the UID to be
rewritten. This tool detects the card generation and uses the appropriate
method to read or rewrite the UID — with **verified** results only: success is
never reported without an exact UID re-read match.

**Intended audience:** penetration testers, security researchers, and educators
working on **cards they own or are authorized to test**.

---

## Features

| Feature | Description |
|---------|-------------|
| UID Reading | Detects and reads any MIFARE Classic card |
| UID Writing | Supports Gen1 (backdoor) and Gen2 (direct write) cards |
| Card Type Identification | Probes the Gen1 backdoor (`0x40`/`0x43`) and reports the card type before any write |
| Configurable Key Brute-Force | Tries up to `MAX_KEY_ATTEMPTS` common authentication keys (default: 7) |
| `StopCrypto1()` After Every Attempt | Crypto-1 session is always terminated after each key try, success or failure |
| Write Verification | Re-reads the UID after writing; success is reported **only on exact match** |
| Enforced Write Guard | `REAL_WRITE_ENABLED` is checked inside every write function — in read-only mode no write command is ever sent |
| BCC Validation | Recomputes the XOR Block Check Character; target UID is validated before use |
| Memory Dump | Sector 0 dump for hex analysis |
| Library Bug Tolerance | Known `mfrc522` `IndexError` bugs handled without false success reports |
| Clean GPIO Exit | `GPIO.cleanup()` on normal exit, interrupt, or crash |
| Debounce | The same card is not re-processed while it stays on the reader |

---

## Requirements

### Hardware
- Raspberry Pi (any model with SPI) or compatible Linux SBC
- MFRC522 RFID reader module (13.56 MHz)
- Magic / UID-writable MIFARE Classic 1K cards (Gen1 or Gen2)

### Software
```bash
sudo apt update
sudo apt install python3-pip
pip3 install mfrc522 spidev RPi.GPIO
```

Enable SPI on the Raspberry Pi:
```bash
sudo raspi-config
# → Interface Options → SPI → Enable
```

### Wiring

| MFRC522 Pin | Raspberry Pi Pin | GPIO |
|-------------|------------------|------|
| SDA (SS)    | Pin 24           | GPIO 8  |
| SCK         | Pin 23           | GPIO 11 |
| MOSI        | Pin 19           | GPIO 10 |
| MISO        | Pin 21           | GPIO 9  |
| RST         | Pin 15           | GPIO 22 |
| 3.3V        | Pin 1            | —    |
| GND         | Pin 6            | —    |

>  The MFRC522 is a **3.3V device**. Never connect it to 5V.

---

## Usage

### 1. Configure the tool

Edit the configuration section at the top of `rfid_magic_writer.py`:

```python
TARGET_UID = [0xDE, 0xAD, 0xBE, 0xEF]  # The UID you want to write (4 bytes)
REAL_WRITE_ENABLED = False              # True = enable actual writes (ENFORCED)
MAX_KEY_ATTEMPTS = 7                    # Max authentication key tries per card
VERBOSE = True                          # Debug output
```

>  **The script ships in read-only mode by default** (`REAL_WRITE_ENABLED =
> False`). Set it to `True` only when testing your own magic cards.

### 2. Run the tool

```bash
sudo python3 rfid_magic_writer.py
```

> `sudo` is required for raw SPI/GPIO access.

### 3. Place a card on the reader

The tool will:
1. Detect the card and display its current UID
2. Identify the card generation (Gen1 backdoor probe / Gen2 / standard)
3. If writes are enabled, send the target UID using the detected method
4. **Verify** by re-reading the card — success is reported only on exact match
5. Dump Sector 0 for confirmation

### Example Output

```
============================================================
  RFID MAGIC CARD UID READER & WRITER
============================================================
[*] MFRC522 firmware: v2.0
[*] Target UID BCC: 0x1A (valid)
[*] Place a card on the reader...

[+] Card detected!
[*] Current UID: 17 28 21 49 (4 bytes)
[*] Testing card type...
[+] Card type: Gen1 Magic Card (backdoor unlocked)
[*] Attempting Gen1 backdoor write...
[+] Backdoor unlocked!
[+] Block 0 written (Gen1) — verification pending
[*] Verifying write...
[*] UID after write: DE AD BE EF
[✓] UID write VERIFIED — Success!
```

---

## Magic Card Generations

| Generation | Write Method | Notes |
|------------|--------------|-------|
| **Gen1** | Backdoor `0x40` (7 bits) + `0x43` (8 bits) | Replies `0x0A` ACK; detected automatically |
| **Gen2** | Direct write to Block 0, no authentication | Most common today (CUID) |
| **Gen3** | Password-protected write | Not supported by this tool |
| **Gen4** | Advanced multi-password protection | Not supported by this tool |

> **Note:** Standard (non-magic) cards have factory-locked UIDs and **cannot**
> be modified. The tool detects this and fails safely.

---

## The Real Lesson: UID-Only Access Control Is Broken

If your access-control system works like this:

> *"If the UID read is in my list of authorized badges → open the door."*

...then **this tool can defeat it in seconds.** An attacker only needs to read
a valid badge's UID once and program it onto a $1 magic card. The UID is an
**identifier, not a proof of possession**. NXP explicitly documents this
UID-presentation threat in
[AN12653](https://www.nxp.com/docs/en/application-note/AN12653.pdf).

This script is included precisely to demonstrate this attack against test
systems you own.

---

## Defending Against This Attack (Analysis)

>  **Scope note:** this repository contains an **analysis of
> countermeasures**, not a deployed protection system. The script does not
> implement AES authentication, key diversification, badge revocation, or
> alerting — it is the attack-side demonstration used to justify the
> recommendations below.

### 1. The Real Fix — Cryptographic Authentication, Not UID Matching

Replace UID checking with cards that perform **mutual cryptographic
authentication**:

| Recommended Card | Why |
|------------------|-----|
| **MIFARE DESFire EV3 (AES-128)** | Modern mutual auth, protected sessions ([product page](https://www.nxp.com/products/MF3DHx3)) |
| **MIFARE Plus (AES mode)** | Drop-in security upgrade for Classic-based systems |

At every presentation, the reader and the card exchange random nonces and prove
knowledge of a shared secret key. A copied UID does not possess the key and
cannot complete the exchange — even with a perfectly cloned UID, the door stays
closed.

>  Buying DESFire cards is **not enough by itself** — your reader software
> must actually perform and verify the authentication protocol before granting
> access. Use the card's standard protocol, never invent your own scheme.

Note: a cheap RC522 cannot talk to DESFire. Use a Proxmark3 for testing, or a
PN532/ACR122U-based setup with a DESFire library.

### 2. Interim Mitigation — If You're Stuck with MIFARE Classic + RC522

These measures **reduce** exposure but do **not** fix Crypto-1's fundamental
weaknesses:

- Replace default keys with **unique, random keys per sector — ideally per
  card** (key diversification).
- Configure sector access bits correctly (deny read/write of key A).
- **Require successful authentication before reading any data used to authorize
  access.** On auth failure → deny access, no fallback to UID checking.

With per-card diversified keys, this tool's common key list fails and brute-
forcing via the RC522 becomes impractical. But the UID can still be copied, and
Crypto-1 remains broken. Treat this as a temporary measure only.

### 3. Key Management & Compromised Badge Handling (Recommendations)

- **Diversify keys**: unique key per card, derived (AES-CMAC) from a master
  secret stored in a secure element/TPM — never plaintext on an SD card.
- **Revocation**: maintain an updatable allowlist so a lost/compromised badge
  can be removed within minutes.
- **Logging & alerting**: journal every access *and every authentication
  failure*; alert on unusual patterns (rapid retries, off-hours access).

### 4. Common Mitigations That Do NOT Work

| Mitigation | Why it fails |
|------------|--------------|
| Hashing the UID with SHA-256 | The cloned UID produces the same hash — security by obscurity, not authentication. |
| Using a non-rewritable-UID card | An attacker can present your UID from any other medium (magic card, smartphone emulator, Proxmark). |
| Storing a fixed code on the card, even encrypted | A static code read once and replayed is a static password, not authentication. |
| Checking only card type | An emulator can spoof ATQA/ATS. Type alone proves nothing. |

**Bottom line:** only a challenge–response protocol where the card proves
knowledge of a secret key stops UID cloning.

---

## Tool-Level Safety Features

These protections apply to the *tool itself* (not to your access-control
system):

1. **Write Guard (enforced)** — every write function checks
   `REAL_WRITE_ENABLED` first; in read-only mode **no write command is ever
   transmitted**.
2. **Card Type Detection** — probes the Gen1 backdoor and verifies the `0x0A`
   ACK before any write.
3. **BCC Validation** — the target UID is validated and its XOR BCC computed
   before any write is attempted.
4. **Write Verification** — success is **only** reported after an exact UID
   re-read match. `IndexError` library bugs never produce false positives.
5. **Key Rotation Limit** — at most `MAX_KEY_ATTEMPTS` authentication tries per
   card, with `StopCrypto1()` cleanup after **each** attempt.
6. **Clean GPIO Exit** — `GPIO.cleanup()` on normal exit, interrupt, or crash.
7. **Debounce** — the same card isn't re-processed while it stays on the reader.

---

## Legal & Ethical Notice

This tool is provided for **authorized security testing, research, and
education only**. Cloning or modifying RFID cards you do not own — or accessing
systems without permission — is illegal in most jurisdictions. The authors
assume no liability for misuse.

---

## Troubleshooting

| Problem | Likely Cause / Fix |
|---------|--------------------|
| `Gen1 backdoor failed` | Card is standard (not magic) or Gen3/Gen4. |
| `Authentication failed — all N keys tried` | Keys are customized (that's good protection!). |
| `IndexError` on write | Known library bug — the tool **does not assume success**; check the verification output. |
| `UID write NOT verified` | Card may be Gen3/Gen4 or standard. Try another magic card. |
| No card detected | Check SPI is enabled, wiring, and 3.3V power. |
| Permission denied | Run with `sudo`. |

---

## References

- [NXP AN12653 — MIFARE security recommendations](https://www.nxp.com/docs/en/application-note/AN12653.pdf)
- [MIFARE DESFire EV3 product page](https://www.nxp.com/products/MF3DHx3)
- [NXP Community — when to change MIFARE Classic keys](https://community.nxp.com/t5/NFC/When-to-change-keys-for-MiFare-Classic-Cards/m-p/1525649)
- [NXP MIFARE Classic lifecycle statement](https://www.nxp.com/products/rfid-nfc/mifare-hf/mifare-classic:MC_41863)

---

## Project Structure

```
rfid-magic-writer/
├── rfid_magic_writer.py   
└── README.md
```

## Credits

- [MFRC522 Python library](https://github.com/pimylifeup/MFRC522-python)
- [miguelbalboa/rfid (Arduino)](https://github.com/miguelbalboa/rfid)


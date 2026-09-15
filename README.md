#  RFID Magic Card UID Reader & Writer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)

> A professional-grade Python tool for reading and rewriting UIDs on MIFARE Classic
> "magic" cards using the MFRC522 RFID reader. Built for authorized security
> research, access-control testing, and RFID education.
>
>  **This tool doubles as a demonstration of why UID-only access control is
> broken.** See [🛡️ Defending Against This Attack](#️-defending-against-this-attack)
> for real countermeasures.

---

##  Introduction

Most RFID cards store their **UID (Unique Identifier)** in a factory-locked memory
block (Block 0). This makes them impossible to clone at the UID level with normal
tools.

**Magic cards** are Chinese clones (often called *CUID* or *Gen1/Gen2* cards) with
an unlocked Block 0 or a hidden backdoor command, allowing the UID to be rewritten.
This tool detects the card generation and uses the appropriate method to read or
rewrite the UID safely — with verification at every step.

**Intended audience:** penetration testers, security researchers, and educators
working on **cards they own or are authorized to test**.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
|  UID Reading | Detects and reads any MIFARE Classic / NTAG card |
|  UID Writing | Supports Gen1 (backdoor) and Gen2 (direct write) cards |
|  Auto-Detection | Automatically identifies magic vs. standard cards |
|  Key Brute-Force | Tries 7 common authentication keys automatically |
|  Write Verification | Re-reads the UID after writing to confirm success |
|  Memory Dump | Full sector dump for analysis (hex view) |
|  Error Protection | Robust exception handling, GPIO cleanup, safe exits |
|  Verbose Logging | Leveled logs for easy debugging |
|  Write Guard | `REAL_WRITE_ENABLED` is enforced before every write attempt |

---

##  Requirements

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

###  Wiring

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

##  Usage

### 1. Configure the target UID

Edit the top of `rfid_magic_writer.py`:

```python
TARGET_UID = [0xDE, 0xAD, 0xBE, 0xEF]  # The UID you want to write
REAL_WRITE_ENABLED = True               # False = read-only demo mode (ENFORCED)
VERBOSE = True                          # Debug output
```

### 2. Run the tool

```bash
sudo python3 rfid_magic_writer.py
```

> `sudo` is required for raw SPI/GPIO access.

### 3. Place a card on the reader

The tool will:
1. Detect the card and display its current UID
2. Identify the card generation (Gen1 / Gen2 / standard)
3. Write the target UID using the correct method
4. Verify the write by re-reading the card
5. Dump Sector 0 for confirmation

### Example Output

```
============================================================
  RFID MAGIC CARD UID READER & WRITER
============================================================
[*] MFRC522 firmware: v2.0
[*] Place a card on the reader...

[+] Card detected!
[*] Current UID: 17 28 21 49
[*] Testing card type...
[+] Card type: Gen1 Magic Card (backdoor unlocked)
[*] Attempting UID write...
[+] Backdoor unlocked!
[+] Block 0 written successfully!

[*] Verifying write...
[*] UID after write: DE AD BE EF
[✓] UID write VERIFIED - Success!
```

---

##  Magic Card Generations

| Generation | Write Method | Notes |
|------------|--------------|-------|
| **Gen1** | Backdoor `0x40` (7 bits) + `0x43` (8 bits) | Original magic cards, replies `0x0A` ACK |
| **Gen2** | Direct write to Block 0, no authentication | Most common today (CUID) |
| **Gen3** | Password-protected write | Requires unlocking password |
| **Gen4** | Advanced multi-password protection | Rare, needs specific tools |

> **Note:** Standard (non-magic) cards have factory-locked UIDs and **cannot**
> be modified. The tool detects this and fails safely.

---

##  The Real Lesson: UID-Only Access Control Is Broken

If your access-control system works like this:

> *"If the UID read is in my list of authorized badges → open the door."*

...then **this tool can defeat it in seconds.** An attacker only needs to
read a valid badge's UID once (from a wallet, a pocket, or over the air) and
program it onto a $1 magic card. The UID is an **identifier, not a proof of
possession** — knowing the number doesn't prove you hold the original card.
NXP explicitly documents this UID-presentation threat in
[AN12653](https://www.nxp.com/docs/en/application-note/AN12653.pdf).

This script is included in the project precisely to demonstrate this attack
against test systems you own.

---

##  Defending Against This Attack

### 1.  The Real Fix — Cryptographic Authentication, Not UID Matching

Replace UID checking with cards that perform **mutual cryptographic
authentication**:

| Recommended Card | Why |
|------------------|-----|
| **MIFARE DESFire EV3 (AES-128)** | Modern mutual auth, protected sessions, NXP's recommended solution ([product page](https://www.nxp.com/products/MF3DHx3)) |
| **MIFARE Plus (AES mode)** | Drop-in security upgrade for Classic-based systems |

**How it works:** at every presentation, the reader and the card exchange random
nonces and prove knowledge of a shared secret key (e.g., AES-128). A copied UID
does **not** possess the key and cannot complete the exchange — even with a
perfectly cloned UID, the door stays closed.

>  Buying DESFire cards is **not enough by itself**. Your reader software must
> actually perform and verify the authentication protocol before granting access.
> Use the card's standard protocol — never invent your own scheme.

Note: a cheap RC522 cannot talk to DESFire. You'll need a reader supporting
ISO 14443-4 / DESFire (e.g., a Proxmark3 for testing, or a commercial reader
like an ACS ACR122U, iDynamo-compatible readers, or a proper PN532-based setup
with a DESFire library).

### 2. 🔧 Interim Mitigation — If You're Stuck with MIFARE Classic + RC522

These measures **reduce** exposure but **do not fix** MIFARE Classic's
fundamental weaknesses (see [Crypto-1 attacks](#common-mitigations-that-do-not-work)):

- Replace default keys (`FF FF FF FF FF FF ...`) with **unique, random keys per
  sector — and ideally per card** (key diversification).
- Configure sector access bits correctly (deny read/write of key A).
- **Require successful authentication before reading any data used to authorize
  access.** On auth failure → **deny access, with no fallback to UID checking.**

With per-card diversified keys, this tool's list of 7 common keys will fail —
a key brute-force with the RC522 becomes impractical. But **the UID can still be
copied**, and Classic's Crypto-1 cipher remains broken. Treat this as a
temporary measure only. NXP's own position: use DESFire or Plus for anything
security-relevant ([Classic lifecycle info](https://www.nxp.com/products/rfid-nfc/mifare-hf/mifare-classic:MC_41863)).

### 3.  Key Management & Compromised Badge Handling

- **Diversify keys**: use a unique key per card, derived (AES-CMAC) from a master
  secret stored securely on the reader — ideally in a **secure element / TPM**,
  never in plaintext on the Pi's SD card.
- **Revocation**: keep an allowlist you can update so a lost/compromised badge
  can be removed within minutes.
- **Logging & alerting**: journal every access *and every authentication
  failure*; alert on unusual patterns (rapid retries, access outside hours).
- Diversification limits blast radius: one compromised card no longer
  compromises the whole system ([AN12653](https://www.nxp.com/docs/en/application-note/AN12653.pdf)).

### 4.  Common Mitigations That Do **NOT** Work

| Mitigation | Why it fails |
|------------|--------------|
| Hashing the UID with SHA-256 | The same cloned UID produces the same hash. It's security by obscurity, not authentication. |
| Using a card with a non-rewritable UID | An attacker doesn't need to *rewrite* a card — they can present your UID from any other medium (magic card, smartphone emulator, Proxmark). |
| Storing a fixed code on the card, even encrypted | If that static code is read once and replayed as-is, it is reusable — a static password, not authentication. |
| Checking only card *type* (e.g., "must be a DESFire") | An emulator can spoof any ATS/ATQA. Type alone is not proof of the secret key. |

**Bottom line:** only a challenge–response protocol where the card proves
knowledge of a secret key stops UID cloning.

---

##  Protection & Safety Features (Tool Level)

These protections apply to the *tool itself* (not to your access-control system):

1. **Card Type Detection** — probes the Gen1 backdoor and verifies the `0x0A`
   ACK before any write.
2. **Write Guard (enforced)** — every write function checks
   `REAL_WRITE_ENABLED` first; in read-only mode no write command is ever sent.
3. **BCC Validation** — recomputes the XOR Block Check Character so written
   UIDs are structurally valid.
4. **Write Verification** — re-reads the UID after writing and only reports
   success on an exact match.
5. **Key Rotation Limit** — at most `max_key_attempts` authentication tries per
   card, with `StopCrypto1()` cleanup after each attempt.
6. **Library Bug Tolerance** — known `mfrc522` `IndexError` bugs handled.
7. **Clean GPIO Exit** — `GPIO.cleanup()` on normal exit, interrupt, or crash.
8. **Debounce** — the same card isn't re-processed while it stays on the reader.

---

##  Legal & Ethical Notice

This tool is provided for **authorized security testing, research, and education
only**. Cloning or modifying RFID cards you do not own — or accessing systems
without permission — is illegal in most jurisdictions (e.g., computer fraud and
access-control laws). The authors assume no liability for misuse.

---

##  Troubleshooting

| Problem | Likely Cause / Fix |
|---------|--------------------|
| `AUTH ERROR` | Card is standard (not magic), or keys are customized (good!). |
| `IndexError` on write | Known library bug — check verification output. |
| No card detected | Check SPI is enabled, wiring, and 3.3V power. |
| UID not verified | Card may be Gen3/Gen4 or standard. Try another card. |
| Permission denied | Run with `sudo`. |

---

##  References

- [NXP AN12653 — MIFARE security recommendations](https://www.nxp.com/docs/en/application-note/AN12653.pdf)
- [MIFARE DESFire EV3 product page](https://www.nxp.com/products/MF3DHx3)
- [NXP Community — when to change MIFARE Classic keys](https://community.nxp.com/t5/NFC/When-to-change-keys-for-MiFare-Classic-Cards/m-p/1525649)
- [NXP MIFARE Classic lifecycle statement](https://www.nxp.com/products/rfid-nfc/mifare-hf/mifare-classic:MC_41863)

---

##  Project Structure

```
rfid-magic-writer/
├── rfid_magic_writer.py   # Main tool (write guard enforced)
├── rfid_protection.py     # Protection & safety module
├── README.md
└── LICENSE
```

##  License

MIT — free to use and modify. See [LICENSE](LICENSE).

##  Credits

- [MFRC522 Python library](https://github.com/pimylifeup/MFRC522-python)
- [miguelbalboa/rfid (Arduino)](https://github.com/miguelbalboa/rfid)
- The Proxmark3 community for magic-card research

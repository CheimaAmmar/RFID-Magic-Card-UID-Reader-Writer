#  RFID Magic Card UID Reader & Writer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)

> A professional-grade Python tool for reading and rewriting UIDs on MIFARE Classic
> "magic" cards using the MFRC522 RFID reader. Built for authorized security
> research, access-control testing, and RFID education.

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

##  Features

| Feature | Description |
|---------|-------------|
|  UID Reading | Detects and reads any MIFARE Classic / NTAG card |
|  UID Writing | Supports Gen1 (backdoor) and Gen2 (direct write) cards |
|  Auto-Detection | Automatically identifies magic vs. standard cards |
|  Key Brute-Force | Tries 7 common authentication keys automatically |
|  Write Verification | Re-reads the UID after writing to confirm success |
|  Memory Dump | Full sector dump for analysis (hex view) |
|  Error Protection | Robust exception handling, GPIO cleanup, safe exits |
|  Verbose Logging | Colorful, leveled logs for easy debugging |

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

### 🔌 Wiring

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
REAL_WRITE_ENABLED = True               # False = read-only demo mode
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

## 🧬 Magic Card Generations

| Generation | Write Method | Notes |
|------------|--------------|-------|
| **Gen1** | Backdoor `0x40` (7 bits) + `0x43` (8 bits) | Original magic cards, replies `0x0A` ACK |
| **Gen2** | Direct write to Block 0, no authentication | Most common today (CUID) |
| **Gen3** | Password-protected write | Requires unlocking password |
| **Gen4** | Advanced multi-password protection | Rare, needs specific tools |

> **Note:** Standard (non-magic) cards have factory-locked UIDs and **cannot**
> be modified. The tool detects this and fails safely.

---

##  Protection & Safety Features

The tool includes multiple layers of protection:

1. **Card Type Detection** — Never attempts a write on a standard (locked) card;
   it first probes the Gen1 backdoor and verifies the `0x0A` ACK.
2. **BCC Validation** — Automatically recomputes the XOR Block Check Character so
   the written UID is always structurally valid.
3. **Write Verification** — After every write, the UID is re-read and compared
   against the target before declaring success.
4. **Read-Only Mode** — Set `REAL_WRITE_ENABLED = False` to safely demo the tool
   without modifying any card.
5. **Key Rotation** — 7 common keys are tried in order; no partial auth state is
   left behind (`StopCrypto1()` after each attempt).
6. **Library Bug Tolerance** — Known `mfrc522` `IndexError` bugs are caught and
   handled gracefully.
7. **Clean GPIO Exit** — `GPIO.cleanup()` runs on exit, interrupt, or crash, so
   the pins are never left in a bad state.
8. **Debounce / Duplicate Read Protection** — The same card isn't re-processed
   while it stays on the reader.

---

##  Legal & Ethical Notice

This tool is provided for **authorized security testing, research, and education
only**. Cloning or modifying RFID cards you do not own — or accessing systems
without permission — is illegal in most jurisdictions. The authors assume no
liability for misuse.

---

##  Troubleshooting

| Problem | Likely Cause / Fix |
|---------|--------------------|
| `AUTH ERROR` | Card is standard (not magic). Use a magic card. |
| `IndexError` on write | Known library bug — check verification output. |
| No card detected | Check SPI is enabled, wiring, and 3.3V power. |
| UID not verified | Card may be Gen3/Gen4 or standard. Try another card. |
| Permission denied | Run with `sudo`. |

---

##  Project Structure

```
rfid-magic-writer/
├── rfid_magic_writer.py   # Main tool
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

       

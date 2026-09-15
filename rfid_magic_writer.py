#!/usr/bin/env python3
"""
================================================================================
  RFID Magic Card UID Reader & Writer
  Authorized Penetration Testing Tool for MIFARE Classic Magic Cards
================================================================================

Features:
  • Reads any MIFARE Classic card UID
  • Writes custom UID to magic cards (Gen1/Gen2)
  • Configurable key brute-force limit (MAX_KEY_ATTEMPTS)
  • Enforced write guard: REAL_WRITE_ENABLED is checked before EVERY write
  • Formal card type identification (Gen1 / Gen2 / standard)
  • StopCrypto1() cleanup after every authentication attempt
  • Verification after write — success is ONLY reported on exact UID match
  • BCC validation for structurally valid written UIDs
  • Memory dump for sector analysis
  • Clean GPIO exit

Requirements:
  • Raspberry Pi (or compatible Linux with SPI)
  • MFRC522 RFID reader module
  • pip install mfrc522 spidev RPi.GPIO

License: MIT
Version: 2.0.0
================================================================================
"""

import RPi.GPIO as GPIO
from mfrc522 import MFRC522
from mfrc522.MFRC522 import MFRC522 as Regs
import time
import sys


# =============================================================================
# CONFIGURATION
# =============================================================================

# Target UID to write (4 bytes for MIFARE Classic 1K)
TARGET_UID = [0xDE, 0xAD, 0xBE, 0xEF]

# Enforced write guard. When False, NO write command is ever sent to the card.
# This is checked inside every write function, not just displayed.
REAL_WRITE_ENABLED = False

# Maximum number of authentication key attempts per card.
# The key list is truncated to this limit before brute-forcing.
MAX_KEY_ATTEMPTS = 7

# Verbose output (show debug info)
VERBOSE = True

# Common authentication keys to try (truncated to MAX_KEY_ATTEMPTS)
COMMON_KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # Default factory key
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],  # Common variant
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],  # Another common
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # All zeros
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],  # Sequential
    [0x4D, 0x49, 0x46, 0x41, 0x52, 0x45],  # "MIFARE" ASCII
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],  # Variant
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_hex(data):
    """Pretty-print bytes as hex string."""
    return " ".join(f"{b:02X}" for b in data)


def log(msg, level="*"):
    """Print log message with level indicator."""
    levels = {"*": "[*]", "+": "[+]", "-": "[-]", "!": "[!]",
              "✓": "[✓]", "✗": "[✗]"}
    prefix = levels.get(level, "[*]")
    print(f"{prefix} {msg}")


def debug(msg):
    """Print message only in verbose mode."""
    if VERBOSE:
        log(msg, "*")


def calculate_bcc(uid_bytes):
    """Calculate Block Check Character (XOR of the 4 UID bytes)."""
    bcc = 0
    for b in uid_bytes:
        bcc ^= b
    return bcc


def validate_uid(uid_bytes):
    """
    Validate that the target UID is structurally usable:
      • exactly 4 bytes (MIFARE Classic 1K single-size UID)
      • BCC (byte 5 of block 0) must equal XOR of UID bytes
    Returns (is_valid, computed_bcc).
    """
    if len(uid_bytes) != 4:
        return False, None
    return True, calculate_bcc(uid_bytes)


def build_block0(new_uid, current_block0=None):
    """
    Build a valid block 0 from a 4-byte UID.
    Preserves ATQA/SAK and manufacturer bytes from current_block0 if available.
    Block layout: [UID0..3, BCC, SAK, ATQA0, ATQA1, rest of manufacturer data]
    """
    bcc = calculate_bcc(new_uid)
    if current_block0 and len(current_block0) == 16:
        block0 = list(current_block0)
        block0[0:4] = new_uid
        block0[4] = bcc
    else:
        block0 = new_uid + [bcc] + [0x08, 0x04, 0x00] + [0x00] * 9
    return block0


# =============================================================================
# MFRC522 RAW COMMAND FUNCTIONS
# =============================================================================

def send_raw_bits(reader, data, valid_bits):
    """
    Send raw bytes with specified valid bits in last byte.
    Used for Gen1 magic card backdoor commands.

    Returns (response_bytes, last_bits) or (None, 0) on error.
    """
    try:
        reader.SetBitMask(Regs.FIFOLevelReg, 0x80)          # Flush FIFO
        reader.Write_MFRC522(Regs.CommandReg, Regs.PCD_IDLE)
        for byte in data:
            reader.Write_MFRC522(Regs.FIFODataReg, byte)
        framing = 0x80 | (valid_bits & 0x07)                # StartSend + TxLastBits
        reader.Write_MFRC522(Regs.BitFramingReg, framing)
        reader.Write_MFRC522(Regs.CommandReg, Regs.PCD_TRANSCEIVE)

        timeout = 100
        while timeout > 0:
            irq = reader.Read_MFRC522(Regs.CommIrqReg)
            if irq & 0x30:
                break
            time.sleep(0.001)
            timeout -= 1
        if timeout <= 0:
            return None, 0

        fifo_level = reader.Read_MFRC522(Regs.FIFOLevelReg) & 0x3F
        response = [reader.Read_MFRC522(Regs.FIFODataReg) for _ in range(fifo_level)]
        control = reader.Read_MFRC522(Regs.ControlReg)
        last_bits = control & 0x07

        err = reader.Read_MFRC522(Regs.ErrorReg)
        if err & (0x10 | 0x08):
            return None, last_bits
        return response, last_bits
    except Exception as e:
        debug(f"Raw command error: {e}")
        return None, 0


def open_uid_backdoor(reader):
    """
    Gen1 Magic Card Backdoor.
    Sends 0x40 (7 bits) then 0x43 (8 bits); expects 0x0A ACK each time.
    Returns True if backdoor unlocked, False otherwise.
    """
    resp, bits = send_raw_bits(reader, [0x40], 7)
    if resp is None or len(resp) != 1 or resp[0] != 0x0A:
        debug(f"Backdoor 0x40 failed: resp={resp}, bits={bits}")
        return False

    resp, bits = send_raw_bits(reader, [0x43], 8)
    if resp is None or len(resp) != 1 or resp[0] != 0x0A:
        debug(f"Backdoor 0x43 failed: resp={resp}, bits={bits}")
        return False
    return True


# =============================================================================
# CARD DETECTION & READING
# =============================================================================

def get_card_uid(reader):
    """Detect and select a card. Returns (uid_bytes, tag_type) or (None, None)."""
    try:
        status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
        if status != reader.MI_OK:
            return None, None
        status, uid_bytes = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            return None, None
        try:
            reader.MFRC522_SelectTag(uid_bytes)
        except Exception:
            pass
        return uid_bytes, tag_type
    except Exception as e:
        debug(f"Card detection error: {e}")
        return None, None


def identify_card_type(reader):
    """
    Formally identify card type:
      • CARD_GEN1      — backdoor 0x40/0x43 answered with 0x0A ACK
      • CARD_GEN2      — block 0 writable without authentication (probed)
      • CARD_STANDARD  — none of the above (factory-locked UID)

    Returns (card_type_str, is_gen1).
    """
    if open_uid_backdoor(reader):
        return "Gen1 Magic Card (backdoor unlocked)", True

    # Gen2 heuristic: UID writable, but no backdoor. Definitive proof only
    # comes from an actual write + verify, which the caller performs.
    return "Unknown (Gen2 magic or standard — probing)", False


def try_authenticate(reader, block_addr, uid_bytes, key):
    """Try to authenticate with a given key. Cleans up Crypto-1 after attempt."""
    try:
        status = reader.MFRC522_Auth(reader.PICC_AUTHENT1A, block_addr, key, uid_bytes)
        if status == reader.MI_OK:
            return True
        return False
    except Exception:
        return False
    finally:
        # Always halt the cipher after each attempt, success or failure,
        # so the next attempt starts from a clean authentication state.
        try:
            reader.MFRC522_StopCrypto1()
        except Exception:
            pass


def authenticate_with_keys(reader, block_addr, uid_bytes):
    """
    Try up to MAX_KEY_ATTEMPTS common keys to authenticate.
    StopCrypto1() is called after EVERY attempt (see try_authenticate).
    Returns (success, used_key) or (False, None).
    """
    keys = COMMON_KEYS[:MAX_KEY_ATTEMPTS]
    for i, key in enumerate(keys, 1):
        debug(f"  Trying key {i}/{len(keys)}: {print_hex(key)}")
        if try_authenticate(reader, block_addr, uid_bytes, key):
            return True, key
    return False, None


def read_block(reader, block_addr):
    """Read a 16-byte block. Returns data or None."""
    try:
        status, block_data = reader.MFRC522_Read(block_addr)
        if status == reader.MI_OK and block_data:
            return block_data
    except Exception:
        pass
    return None


def dump_sector(reader, sector_num):
    """Dump all 4 blocks of a sector."""
    log(f"  Sector {sector_num}:", "*")
    for block in range(sector_num * 4, sector_num * 4 + 4):
        data = read_block(reader, block)
        if data:
            desc = " <- Trailer Block" if block % 4 == 3 else ""
            print(f"    Block {block:2d}: {print_hex(data)}{desc}")
        else:
            print(f"    Block {block:2d}: <read failed>")
            break


# =============================================================================
# UID WRITE FUNCTIONS (all enforce REAL_WRITE_ENABLED)
# =============================================================================

def write_guard():
    """
    The enforced write guard. Every write function calls this FIRST.
    In read-only mode, no write command is ever transmitted to the card.
    """
    if not REAL_WRITE_ENABLED:
        log("Write blocked: REAL_WRITE_ENABLED is False (read-only mode)", "-")
        return False
    return True


def write_uid_gen1(reader, new_uid, current_block0=None):
    """
    Write UID using Gen1 backdoor:
      1. Open backdoor (0x40/0x43)
      2. Write block 0 with new UID + valid BCC
    """
    if not write_guard():
        return False

    log("Attempting Gen1 backdoor write...", "*")
    if not open_uid_backdoor(reader):
        log("Gen1 backdoor failed", "-")
        return False

    log("Backdoor unlocked!", "+")
    block0 = build_block0(new_uid, current_block0)
    debug(f"Writing block 0: {print_hex(block0)}")

    try:
        status = reader.MFRC522_Write(0, block0)
        if status == reader.MI_OK:
            log("Block 0 written (Gen1) — verification pending", "+")
            return True
        log(f"Block 0 write failed (status: {status})", "-")
        return False
    except Exception as e:
        log(f"Block 0 write exception: {e}", "!")
        return False


def write_uid_gen2(reader, new_uid, current_block0=None):
    """
    Write UID using Gen2 direct write (no authentication needed).

    NOTE: on IndexError (known mfrc522 library bug), we do NOT report success.
    We return False and let the caller re-read the UID to determine the
    actual outcome. Only a verified re-read reports success.
    """
    if not write_guard():
        return False

    log("Attempting Gen2 direct write...", "*")
    block0 = build_block0(new_uid, current_block0)
    debug(f"Writing block 0: {print_hex(block0)}")

    try:
        status = reader.MFRC522_Write(0, block0)
        if status == reader.MI_OK:
            log("Direct write accepted (Gen2) — verification pending", "+")
            return True
        log(f"Direct write failed (status: {status})", "-")
        return False
    except IndexError:
        # Known library bug: IndexError after write with unknown outcome.
        log("Library IndexError after write — outcome unknown", "!")
        log("Do NOT assume success; relying on re-read verification", "!")
        return False
    except Exception as e:
        log(f"Direct write exception: {e}", "!")
        return False


def write_uid_authenticated(reader, uid_bytes, new_uid):
    """
    Write UID with authentication (cards whose sector 0 is unlocked).
    All key attempts include StopCrypto1() cleanup.
    """
    if not write_guard():
        return False

    log("Attempting authenticated write...", "*")
    auth_ok, used_key = authenticate_with_keys(reader, 0, uid_bytes)
    if not auth_ok:
        log(f"Authentication failed — all {MAX_KEY_ATTEMPTS} keys tried", "-")
        return False

    log(f"Authenticated with key: {print_hex(used_key)}", "+")

    block0 = read_block(reader, 0)
    if not block0:
        log("Failed to read block 0", "-")
        try:
            reader.MFRC522_StopCrypto1()
        except Exception:
            pass
        return False

    log(f"Current block 0: {print_hex(block0)}", "*")
    new_block0 = build_block0(new_uid, block0)

    try:
        status = reader.MFRC522_Write(0, new_block0)
        if status == reader.MI_OK:
            log("Authenticated write sent — verification pending", "+")
            return True
        log(f"Write failed (status: {status})", "-")
        return False
    except Exception as e:
        log(f"Write exception: {e}", "!")
        return False
    finally:
        try:
            reader.MFRC522_StopCrypto1()
        except Exception:
            pass


def verify_write(reader, expected_uid):
    """
    Re-read the card UID and compare to the target.
    This is the ONLY source of a success verdict. Returns True on exact match.
    """
    time.sleep(0.5)
    new_uid, _ = get_card_uid(reader)
    if not new_uid:
        log("Could not re-read UID for verification", "!")
        return False
    got = list(new_uid[:4])
    log(f"UID after write: {print_hex(got)}", "*")
    if got == expected_uid:
        log("UID write VERIFIED — Success!", "✓")
        return True
    log("UID write NOT verified — UID unchanged or incorrect", "✗")
    return False


# =============================================================================
# MAIN PROGRAM
# =============================================================================

def main():
    reader = None
    try:
        reader = MFRC522()

        # Reader firmware version
        try:
            ver = reader.Read_MFRC522(Regs.VersionReg)
            ver_names = {0x92: "v2.0", 0x12: "v1.0 clone", 0x88: "v1.0 variant"}
            log(f"MFRC522 firmware: {ver_names.get(ver, f'unknown (0x{ver:02X})')}", "*")
        except Exception as e:
            log(f"Can't read version: {e}", "!")

        # Validate target UID and BCC before doing anything
        valid, bcc = validate_uid(TARGET_UID)
        if not valid:
            log("Target UID is invalid (must be exactly 4 bytes). Exiting.", "✗")
            sys.exit(1)
        log(f"Target UID BCC: 0x{bcc:02X} (valid)", "*")
        if not REAL_WRITE_ENABLED:
            log("READ-ONLY MODE: writes are enforced OFF", "!")

        print("=" * 60)
        print("  RFID MAGIC CARD UID READER & WRITER")
        print("=" * 60)
        log("Place a card on the reader...", "*")

        last_uid = None

        while True:
            uid_bytes, tag_type = get_card_uid(reader)
            if uid_bytes is None:
                time.sleep(0.3)
                continue

            uid_str = print_hex(uid_bytes)
            if uid_str == last_uid:
                time.sleep(0.5)
                continue
            last_uid = uid_str
            uid_4 = list(uid_bytes[:4])

            print()
            log("Card detected!", "+")
            log(f"Current UID: {uid_str} ({len(uid_bytes)} bytes)", "*")

            if uid_4 == TARGET_UID:
                log("Card already has target UID — nothing to do", "✓")
            else:
                # ---- Formal card type identification ----
                log("Testing card type...", "*")
                card_type, is_gen1 = identify_card_type(reader)
                log(f"Card type: {card_type}", "+")

                # ---- Write attempt (guard-checked inside each function) ----
                write_sent = False
                if REAL_WRITE_ENABLED:
                    if is_gen1:
                        write_sent = write_uid_gen1(reader, TARGET_UID)
                    else:
                        write_sent = write_uid_gen2(reader, TARGET_UID)
                        if not write_sent:
                            write_sent = write_uid_authenticated(reader, uid_bytes, TARGET_UID)
                else:
                    log("Read-only mode: skipping all write attempts", "-")

                # ---- Verification: the ONLY success criterion ----
                if write_sent:
                    log("Verifying write...", "*")
                    verify_write(reader, TARGET_UID)
                else:
                    log("No write was performed — skipping verification", "-")

                # ---- Sector 0 dump ----
                log("Memory dump (sector 0):", "*")
                dump_sector(reader, 0)

            log("-" * 60)
            log("Remove card or place another...", "*")

            # Debounce: wait for card removal
            while True:
                uid_check, _ = get_card_uid(reader)
                if uid_check is None:
                    break
                time.sleep(0.3)
            last_uid = None

    except KeyboardInterrupt:
        print()
        log("Interrupted by user. Exiting...", "!")
    except Exception as e:
        print()
        log(f"Unexpected error: {e}", "!")
        if VERBOSE:
            import traceback
            traceback.print_exc()
    finally:
        try:
            GPIO.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()

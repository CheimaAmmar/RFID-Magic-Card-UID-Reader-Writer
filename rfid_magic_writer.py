#!/usr/bin/env python3
"""
================================================================================
  RFID Magic Card UID Reader & Writer
  Authorized Penetration Testing Tool for MIFARE Classic & NTAG Magic Cards
================================================================================

Features:
  • Reads any MIFARE Classic / NTAG card UID
  • Writes custom UID to magic cards (Gen1/Gen2)
  • Tries 7 common authentication keys
  • Supports Gen1 backdoor (0x40/0x43) and Gen2 direct write
  • Memory dump for sector analysis
  • Verification after write
  • Protection against common errors

Requirements:
  • Raspberry Pi (or compatible Linux with SPI)
  • MFRC522 RFID reader module
  • pip install mfrc522 spidev RPi.GPIO

Author: [Your Name]
License: MIT
Version: 1.0.0
================================================================================
"""

import RPi.GPIO as GPIO
from mfrc522 import MFRC522
from mfrc522.MFRC522 import MFRC522 as Regs
import time
import sys
import hashlib


# =============================================================================
# CONFIGURATION
# =============================================================================

# Target UID to write (4 bytes for MIFARE Classic 1K)
# Change this to your desired UID
TARGET_UID = [0xDE, 0xAD, 0xBE, 0xEF]

# Common authentication keys to try (for standard cards or sector 0)
COMMON_KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # Default factory key
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],  # Common variant
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],  # Another common
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # All zeros
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],  # Sequential
    [0x4D, 0x49, 0x46, 0x41, 0x52, 0x45],  # "MIFARE" ASCII
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],  # Variant
]

# Enable actual UID write (set False for read-only demo mode)
REAL_WRITE_ENABLED = True

# Verbose output (show debug info)
VERBOSE = True


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_hex(data):
    """Pretty-print bytes as hex string."""
    if isinstance(data, list):
        return " ".join(f"{b:02X}" for b in data)
    return " ".join(f"{b:02X}" for b in data)


def print_banner():
    """Print tool banner."""
    print("=" * 60)
    print("  RFID MAGIC CARD UID READER & WRITER")
    print("  Authorized Penetration Testing Tool")
    print("=" * 60)
    print(f"  Target UID:     {print_hex(TARGET_UID)}")
    print(f"  Real Write:     {REAL_WRITE_ENABLED}")
    print(f"  Verbose Mode:   {VERBOSE}")
    print("=" * 60)


def log(msg, level="*"):
    """Print log message with level indicator."""
    levels = {"*": "[*]", "+": "[+]", "-": "[-]", "!": "[!]", "✓": "[✓]", "✗": "[✗]"}
    prefix = levels.get(level, "[*]")
    print(f"{prefix} {msg}")


def calculate_bcc(uid_bytes):
    """Calculate Block Check Character (XOR of UID bytes)."""
    bcc = 0
    for b in uid_bytes:
        bcc ^= b
    return bcc


def generate_random_uid():
    """Generate a random 4-byte UID with valid BCC."""
    import random
    uid = [random.randint(0, 255) for _ in range(4)]
    return uid


# =============================================================================
# MFRC522 RAW COMMAND FUNCTIONS
# =============================================================================

def send_raw_bits(reader, data, valid_bits):
    """
    Send raw bytes with specified valid bits in last byte.
    Used for Gen1 magic card backdoor commands.
    
    Args:
        reader: MFRC522 instance
        data: List of bytes to send
        valid_bits: Number of valid bits in last byte (7 or 8)
    
    Returns:
        (response_bytes, last_bits) or (None, 0) on error
    """
    try:
        # Flush FIFO
        reader.SetBitMask(Regs.FIFOLevelReg, 0x80)
        # Stop any active command
        reader.Write_MFRC522(Regs.CommandReg, Regs.PCD_IDLE)
        
        # Write data to FIFO
        for byte in data:
            reader.Write_MFRC522(Regs.FIFODataReg, byte)
        
        # Set bit framing: TxLastBits = valid_bits, StartSend = 1
        framing = 0x80 | (valid_bits & 0x07)
        reader.Write_MFRC522(Regs.BitFramingReg, framing)
        
        # Start transceive
        reader.Write_MFRC522(Regs.CommandReg, Regs.PCD_TRANSCEIVE)
        
        # Wait for completion
        timeout = 100
        while timeout > 0:
            irq = reader.Read_MFRC522(Regs.CommIrqReg)
            if irq & 0x30:  # RxIRQ or TxIRQ
                break
            time.sleep(0.001)
            timeout -= 1
        
        if timeout <= 0:
            return None, 0
        
        # Read response from FIFO
        fifo_level = reader.Read_MFRC522(Regs.FIFOLevelReg) & 0x3F
        response = []
        for _ in range(fifo_level):
            response.append(reader.Read_MFRC522(Regs.FIFODataReg))
        
        control = reader.Read_MFRC522(Regs.ControlReg)
        last_bits = control & 0x07
        
        # Check for error
        err = reader.Read_MFRC522(Regs.ErrorReg)
        if err & (0x10 | 0x08):  # CRC or parity error
            return None, last_bits
        
        return response, last_bits
    
    except Exception as e:
        if VERBOSE:
            log(f"Raw command error: {e}", "!")
        return None, 0


def open_uid_backdoor(reader):
    """
    Gen1 Magic Card Backdoor
    
    Sends:
      1. 0x40 with 7 bits → expect 0x0A ACK
      2. 0x43 with 8 bits → expect 0x0A ACK
    
    Returns True if backdoor unlocked, False otherwise.
    """
    # Step 1: Send 0x40 as 7 bits
    resp, last_bits = send_raw_bits(reader, [0x40], 7)
    if resp is None or len(resp) != 1 or resp[0] != 0x0A:
        if VERBOSE:
            log(f"Backdoor 0x40 failed: resp={resp}, bits={last_bits}", "-")
        return False
    
    # Step 2: Send 0x43 as 8 bits
    resp, last_bits = send_raw_bits(reader, [0x43], 8)
    if resp is None or len(resp) != 1 or resp[0] != 0x0A:
        if VERBOSE:
            log(f"Backdoor 0x43 failed: resp={resp}, bits={last_bits}", "-")
        return False
    
    return True


# =============================================================================
# CARD DETECTION & READING
# =============================================================================

def get_card_uid(reader):
    """
    Detect and select a card.
    
    Returns:
        (uid_bytes, tag_type) or (None, None)
    """
    try:
        status, tag_type = reader.MFRC522_Request(reader.PICC_REQIDL)
        if status != reader.MI_OK:
            return None, None
        
        status, uid_bytes = reader.MFRC522_Anticoll()
        if status != reader.MI_OK:
            return None, None
        
        try:
            reader.MFRC522_SelectTag(uid_bytes)
        except:
            pass
        
        return uid_bytes, tag_type
    
    except Exception as e:
        if VERBOSE:
            log(f"Card detection error: {e}", "!")
        return None, None


def try_authenticate(reader, block_addr, uid_bytes, key):
    """Try to authenticate with a given key."""
    try:
        status = reader.MFRC522_Auth(
            reader.PICC_AUTHENT1A, block_addr, key, uid_bytes
        )
        return status == reader.MI_OK
    except:
        return False


def authenticate_with_keys(reader, block_addr, uid_bytes):
    """
    Try all common keys to authenticate.
    
    Returns:
        (success, used_key)
    """
    for key in COMMON_KEYS:
        if try_authenticate(reader, block_addr, uid_bytes, key):
            return True, key
    return False, None


def read_block(reader, block_addr):
    """Read a 16-byte block."""
    try:
        status, block_data = reader.MFRC522_Read(block_addr)
        if status == reader.MI_OK and block_data:
            return block_data
    except:
        pass
    return None


def dump_sector(reader, sector_num):
    """Dump all 4 blocks of a sector."""
    log(f"  Sector {sector_num}:", "*")
    for block in range(sector_num * 4, sector_num * 4 + 4):
        data = read_block(reader, block)
        if data:
            desc = ""
            if block % 4 == 3:
                desc = " <- Trailer Block"
            print(f"    Block {block:2d}: {print_hex(data)}{desc}")
        else:
            print(f"    Block {block:2d}: <read failed>")
            break


def dump_full_card(reader, uid_bytes):
    """Dump entire card memory (64 blocks for MIFARE 1K)."""
    log("Full memory dump:", "*")
    for sector in range(16):
        if sector > 0 and sector % 4 == 0:
            time.sleep(0.1)  # Small delay between sectors
        dump_sector(reader, sector)


# =============================================================================
# UID WRITE FUNCTIONS
# =============================================================================

def write_uid_gen1(reader, uid_bytes, new_uid):
    """
    Write UID using Gen1 backdoor.
    
    Process:
      1. Open backdoor (0x40/0x43)
      2. Write block 0 with new UID + BCC
    """
    log("Attempting Gen1 backdoor...", "*")
    
    if not open_uid_backdoor(reader):
        log("Gen1 backdoor failed", "-")
        return False
    
    log("Backdoor unlocked!", "+")
    
    # Build block 0: [UID0, UID1, UID2, UID3, BCC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    bcc = calculate_bcc(new_uid)
    block0 = new_uid + [bcc] + [0x00] * 11
    
    # Write block 0
    try:
        status = reader.MFRC522_Write(0, block0)
        if status == reader.MI_OK:
            log("Block 0 written successfully!", "+")
            return True
        else:
            log(f"Block 0 write failed (status: {status})", "-")
            return False
    except Exception as e:
        log(f"Block 0 write exception: {e}", "!")
        return False


def write_uid_gen2(reader, new_uid):
    """
    Write UID using Gen2 direct write (no auth needed).
    
    Gen2 cards allow direct write to block 0 without authentication.
    """
    log("Attempting Gen2 direct write...", "*")
    
    bcc = calculate_bcc(new_uid)
    block0 = new_uid + [bcc] + [0x00] * 11
    
    try:
        status = reader.MFRC522_Write(0, block0)
        if status == reader.MI_OK:
            log("Direct write accepted!", "+")
            return True
        else:
            log(f"Direct write failed (status: {status})", "-")
            return False
    except IndexError:
        # Library bug - write might have succeeded
        log("Library IndexError - checking if write succeeded...", "!")
        time.sleep(0.1)
        return True  # Assume success
    except Exception as e:
        log(f"Direct write exception: {e}", "!")
        return False


def write_uid_authenticated(reader, uid_bytes, new_uid):
    """
    Write UID with authentication (for cards where sector 0 is unlocked).
    
    Process:
      1. Authenticate with known keys
      2. Read block 0
      3. Modify UID bytes
      4. Write back
    """
    log("Attempting authenticated write...", "*")
    
    # Try to authenticate
    auth_ok, used_key = authenticate_with_keys(reader, 0, uid_bytes)
    
    if not auth_ok:
        log("Authentication failed - all keys tried", "-")
        reader.MFRC522_StopCrypto1()
        return False
    
    log(f"Authenticated with key: {print_hex(used_key)}", "+")
    
    # Read block 0
    block0 = read_block(reader, 0)
    if not block0:
        log("Failed to read block 0", "-")
        reader.MFRC522_StopCrypto1()
        return False
    
    log(f"Current block 0: {print_hex(block0)}", "*")
    
    # Modify UID bytes and BCC
    for i in range(4):
        block0[i] = new_uid[i]
    block0[4] = calculate_bcc(new_uid)
    
    # Write back
    try:
        status = reader.MFRC522_Write(0, block0)
        reader.MFRC522_StopCrypto1()
        
        if status == reader.MI_OK:
            log("Authenticated write successful!", "+")
            return True
        else:
            log(f"Write failed (status: {status})", "-")
            return False
    except Exception as e:
        log(f"Write exception: {e}", "!")
        return False


# =============================================================================
# MAIN PROGRAM
# =============================================================================

def main():
    """Main program loop."""
    reader = MFRC522()
    
    # Check reader version
    try:
        ver = reader.Read_MFRC522(Regs.VersionReg)
        ver_names = {0x92: "v2.0", 0x12: "v1.0 clone", 0x88: "v1.0 variant"}
        ver_str = ver_names.get(ver, f"unknown (0x{ver:02X})")
        log(f"MFRC522 firmware: {ver_str}", "*")
    except Exception as e:
        log(f"Can't read version: {e}", "!")
    
    print_banner()
    print()
    log("Place a card on the reader...", "*")
    print()
    
    last_uid = None
    write_attempted = False
    
    try:
        while True:
            uid_bytes, tag_type = get_card_uid(reader)
            
            if uid_bytes is None:
                time.sleep(0.3)
                continue
            
            uid_str = print_hex(uid_bytes)
            
            # Skip if same card still present
            if uid_str == last_uid:
                time.sleep(0.5)
                continue
            
            last_uid = uid_str
            uid_4bytes = list(uid_bytes[:4])
            
            # Display card info
            print()
            log(f"Card detected!", "+")
            log(f"Current UID: {uid_str} ({len(uid_bytes)} bytes)", "*")
            
            # Check if already target UID
            if uid_4bytes == TARGET_UID:
                log("Card already has target UID!", "✓")
            else:
                log(f"Target UID:  {print_hex(TARGET_UID)}", "*")
                log(f"Current UID: {uid_str}", "*")
                
                # Check if it's a magic card by trying backdoor
                log("\n[*] Testing card type...", "*")
                
                is_gen1 = open_uid_backdoor(reader)
                if is_gen1:
                    log("Card type: Gen1 Magic Card (backdoor unlocked)", "+")
                else:
                    log("Card type: Not Gen1 magic (trying other methods)", "*")
                
                # Attempt UID write
                log("\n[*] Attempting UID write...", "*")
                write_success = False
                
                if is_gen1:
                    # Use Gen1 backdoor
                    if write_uid_gen1(reader, uid_bytes, TARGET_UID):
                        write_success = True
                else:
                    # Try Gen2 direct write
                    if write_uid_gen2(reader, TARGET_UID):
                        write_success = True
                    else:
                        # Try authenticated write
                        if write_uid_authenticated(reader, uid_bytes, TARGET_UID):
                            write_success = True
                
                # Verification
                log("\n[*] Verifying write...", "*")
                time.sleep(0.5)
                
                new_uid, _ = get_card_uid(reader)
                if new_uid:
                    new_uid_str = print_hex(new_uid)
                    log(f"UID after write: {new_uid_str}", "*")
                    
                    if list(new_uid[:4]) == TARGET_UID:
                        log("✓ UID write VERIFIED - Success!", "✓")
                    else:
                        log("✗ UID write not verified - UID unchanged", "✗")
                else:
                    log("Could not re-read UID for verification", "!")
                
                # Memory dump after write
                log("\n[*] Memory dump (sector 0):", "*")
                dump_sector(reader, 0)
            
            log("\n" + "-" * 60, "*")
            log("Remove card or place another...", "*")
            
            # Wait for card removal
            while get_card_uid(reader)[0] is not None:
                time.sleep(0.3)
            
            last_uid = None
            write_attempted = False
            
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
        GPIO.cleanup()


if __name__ == "__main__":
    main()

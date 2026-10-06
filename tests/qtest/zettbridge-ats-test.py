#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real VT-d page tables + queued device invalidations, behind a Root Port.

Run: python3 tests/qtest/zettbridge-ats-test.py build/qemu-system-x86_64
The two guests' RAM is independent. No OS or synthetic cache-flush hook is used.
"""
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

BAR = 0xF0000000
VTD = 0xFED90000
ATSC = 0xE0100106
CAPACITY = 256 << 20


class Guest:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        for _ in range(200):
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.02)
        self.stream = self.sock.makefile("rwb", buffering=0)
        self.seq = self.tail = 0

    def cmd(self, value):
        self.stream.write((value + "\n").encode())
        reply = self.stream.readline().decode().strip()
        while reply.startswith("IRQ"):
            reply = self.stream.readline().decode().strip()
        assert reply.startswith("OK"), (value, reply)
        return reply[3:]

    def write(self, addr, value, width="q"):
        self.cmd(f"write{width} {addr:#x} {value:#x}")

    def read(self, addr, width="q"):
        return int(self.cmd(f"read{width} {addr:#x}"), 0)

    def config(self, bdf, offset, value):
        self.cmd(f"outl 0xcf8 {0x80000000 | (bdf << 8) | offset:#x}")
        self.cmd(f"outl 0xcfc {value:#x}")

    def setup(self):
        self.config(0, 0x60, 0xE0000001)  # ECAM, 256 MiB
        self.config(8, 0x18, 0x10100)  # Root Port: secondary/subordinate bus 1
        self.config(8, 0x20, 0xF000F000)
        self.config(8, 4, 6)
        self.config(0x100, 0x10, BAR)
        self.config(0x100, 4, 6)

    def w(self, offset, value):
        self.write(BAR + offset, value, "l")

    def w64(self, offset, value):
        self.w(offset, value & 0xFFFFFFFF)
        self.w(offset + 4, value >> 32)

    def r64(self, offset):
        return self.read(BAR + offset, "l") | (self.read(BAR + offset + 4, "l") << 32)

    def op(self, op, status=0):
        self.seq += 1
        self.w64(0x50, 1)
        self.w(0x58, self.seq)
        self.w(0x40 if op == 512 else 0x18, 1 if op == 512 else op)
        assert self.r64(0x60) == self.seq
        assert self.r64(0x68) == status, (op, self.r64(0x68), status)

    def invalidate(self, low=0x12, high=0):
        self.write(0x106000 + self.tail, low)
        self.write(0x106008 + self.tail, high)
        self.tail += 16
        self.write(VTD + 0x88, self.tail)
        assert self.read(VTD + 0x80) == self.tail, "queued invalidation completion"

    def device_invalidate(self, address, sid=0x100):
        self.invalidate(3 | (sid << 32), address)

    def mapping(self, iova, physical, perm=3):
        self.write(0x105000 + (iova >> 12) * 8, physical | perm if perm else 0)

    def iommu(self):
        self.write(0x100010, 0x101001)  # bus 1 root entry
        self.write(0x101000, 0x102005)  # endpoint 00.0, device-IOTLB translation
        self.write(0x101008, 0x102)  # DID=1, AW=48 bits
        for table, nxt in [(0x102000, 0x103000), (0x103000, 0x104000),
                           (0x104000, 0x105000)]:
            self.write(table, nxt | 3)
        self.write(VTD + 0x20, 0x100000)
        self.write(VTD + 0x18, 1 << 30, "l")  # SRTP
        self.write(VTD + 0x90, 0x106000)
        self.write(VTD + 0x18, (1 << 31) | (1 << 26), "l")  # TE + QIE
        assert self.read(VTD + 0x1C, "l") & 0x84000000 == 0x84000000
        self.write(ATSC, 0x8000, "w")
        assert self.r64(0x368) == 7

    def close(self):
        self.stream.close()
        self.sock.close()


def run(qemu, ending):
    with tempfile.TemporaryDirectory(prefix="zb-ats-") as tmp:
        out = pathlib.Path(tmp)
        processes, guests, logs = [], [], []
        try:
            for role in ["provider", "consumer"]:
                log = open(out / (role + ".log"), "w+")
                logs.append(log)
                cmd = [qemu, "-machine", "q35", "-accel", "qtest", "-m", "512M",
                       "-display", "none", "-nodefaults", "-S",
                       "-qtest", f"unix:{out / role},server=on,wait=off",
                       "-device", "pcie-root-port,id=rp,addr=1,chassis=1",
                       "-device", f"zettbridge,bus=rp,addr=0,provider={'on' if role == 'provider' else 'off'},"
                       f"ats={'on' if role == 'provider' else 'off'},socket={out / 'bridge'},capacity=256M"]
                if role == "provider":
                    cmd += ["-device", "intel-iommu,caching-mode=on,device-iotlb=on,aw-bits=48"]
                processes.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
                guest = Guest(out / role)
                guests.append(guest)
                guest.setup()
            b, a = guests
            b.iommu()
            # Non-identity IOVA mappings: this also detects double translation.
            b.mapping(0x8000, 0x200000)
            b.write(0x200000, 0x1122334455667788)
            b.write(0x201000, 0x8877665544332211)
            b.w64(0x30, 0x8000)
            b.op(0x105)
            assert b.r64(0x3A8) == 0x1122334455667788
            requests = b.r64(0x370)
            b.op(0x105)
            assert b.r64(0x370) == requests and b.r64(0x378) > 0
            # The IOMMU's own invalidation must not implicitly flush the ATC.
            b.mapping(0x8000, 0x201000)
            b.invalidate()
            b.op(0x105)
            assert b.r64(0x3A8) == 0x1122334455667788
            # Another requester and another page must not evict this entry.
            invalidations = b.r64(0x380)
            b.device_invalidate(0x8000, sid=8)
            assert b.r64(0x380) == invalidations
            b.device_invalidate(0x9000)
            b.op(0x105)
            assert b.r64(0x3A8) == 0x1122334455667788
            b.device_invalidate(0x8000)
            assert b.r64(0x388) == 0
            b.op(0x105)
            assert b.r64(0x3A8) == 0x8877665544332211
            # Unmap: stale translations must no longer authorize reads.
            b.mapping(0x8000, 0, perm=0)
            b.invalidate()
            b.device_invalidate(0x8000)
            b.op(0x105, status=6)
            assert b.r64(0x388) == 0
            b.mapping(0x8000, 0x200000)
            b.invalidate()
            # Invalidation range covers two adjacent cached pages.
            b.mapping(0x9000, 0x201000)
            for addr in [0x8000, 0x9000]:
                b.w64(0x30, addr)
                b.op(0x105)
            assert b.r64(0x388) == 2
            b.device_invalidate(0x8001)  # S=1, 8 KiB range
            assert b.r64(0x388) == 0
            # Prepare a read-only payload translation in the device cache.
            b.mapping(0x10000, 0x202000, perm=1 if ending == "permission" else 3)
            b.mapping(0x11000, 0x204000)
            b.write(0x202000, 0xDEADBEEF)
            b.w64(0x30, 0x10000)
            b.op(0x105)
            assert b.r64(0x3A8) == 0xDEADBEEF
            raw = struct.pack("<QQQQIIHH20x", 0, CAPACITY, 0x10000, 1, 1, 7, 0, 0)
            b.cmd(f"write 0x200000 0x40 0x{raw.hex()}")
            b.w64(0x30, 0x8000)
            b.w64(0x38, 1)
            b.op(512)
            a.w64(0x300, 1)
            a.w64(0x308, 2)
            a.w64(0x310, CAPACITY)
            a.op(0x100)
            b.op(1)
            if ending != "permission":
                # A single request crosses pages with non-contiguous targets.
                b.write(0x202FF8, 0xFFFFFFFFFFFFFFFF)
                b.write(0x204000, 0xFFFFFFFFFFFFFFFF)
                b.write(0x203000, 0xCCCCCCCCCCCCCCCC)
                a.w64(0x330, 4094)
                a.w64(0x338, 4)
                a.op(0x103)
                assert b.read(0x202FF8) == 0x0000FFFFFFFFFFFF
                assert b.read(0x204000) == 0xFFFFFFFFFFFF0000
                assert b.read(0x203000) == 0xCCCCCCCCCCCCCCCC
            if ending == "permission-change":
                b.mapping(0x10000, 0x202000, perm=1)
                b.invalidate()
                b.device_invalidate(0x10000)
            elif ending == "bus-master":
                b.config(0x100, 4, 2)
            if ending in ["permission", "permission-change", "bus-master"]:
                a.w64(0x330, 0)
                a.w64(0x338, 8)
                a.op(0x103, status=6)
                assert b.read(0x202000) == 0xDEADBEEF
                assert b.r64(0x48) == 6
            elif ending == "disable":
                b.write(ATSC, 0, "w")
                assert b.r64(0x368) == 1 and b.r64(0x388) == 0
                assert b.r64(0x48) == 6
                b.write(ATSC, 0x8000, "w")
                a.w64(0x330, 0)
                a.w64(0x338, 8)
                a.op(0x103, status=6)  # re-enable cannot resurrect a faulted export
            else:
                a.op(0x101)
                b.op(2)
                b.op(3)
                b.op(4)
                assert b.r64(0x388) == 0 and b.r64(0x368) == 7
                assert b.r64(0x3A0) == 1, "ATS stayed enabled through retire"
            print(f"PASS ATS {ending}: Root Port requester, non-identity translation, cache hits, "
                  "range/SID invalidation, remap and unmap")
        except BaseException:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read()[-4000:], file=sys.stderr)
            raise
        finally:
            for guest in guests:
                guest.close()
            for proc in processes:
                proc.terminate()
            for proc in processes:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    for case in ["permission", "permission-change", "bus-master", "disable", "retire"]:
        run(binary, case)

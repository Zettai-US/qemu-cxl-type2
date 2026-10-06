#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reset, unsupported ATS and hostile peer regression tests (no guest OS).

Run with the qemu-system-x86_64 binary; optional case names select a subset.
Every case owns its processes and sockets. Existing VM pairs are untouched.
"""
import importlib.util
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location(
    "ats", pathlib.Path(__file__).with_name("zettbridge-ats-test.py"))
ats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ats)


class Pair:
    def __init__(self, binary, iommu="device-iotlb=on", consumer=True):
        self.binary, self.iommu, self.consumer = binary, iommu, consumer
        self.procs, self.guests, self.logs = [], [], []

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="zb-edge-")
        self.out = pathlib.Path(self.tmp.name)
        try:
            roles = ["provider", "consumer"] if self.consumer else ["provider"]
            for role in roles:
                log = open(self.out / (role + ".log"), "w+")
                self.logs.append(log)
                enabled = "on" if role == "provider" else "off"
                model = (f"zettbridge,bus=rp,addr=0,provider={enabled},"
                         f"ats={enabled},socket={self.out / 'bridge'},"
                         "capacity=256M")
                monitor = self.out / (role + ".qmp")
                cmd = [self.binary, "-machine", "q35", "-accel", "qtest",
                       "-m", "512M",
                       "-display", "none", "-nodefaults", "-S",
                       "-qtest", f"unix:{self.out / role},server=on,wait=off",
                       "-qmp", f"unix:{monitor},server=on,wait=off",
                       "-device", "pcie-root-port,id=rp,addr=1,chassis=1",
                       "-device", model]
                if role == "provider" and self.iommu:
                    cmd += ["-device", "intel-iommu,caching-mode=on,"
                            "aw-bits=48," + self.iommu]
                self.procs.append(subprocess.Popen(
                    cmd, stdout=log, stderr=subprocess.STDOUT))
                guest = ats.Guest(self.out / role)
                self.guests.append(guest)
                guest.setup()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, typ, value, traceback):
        if typ:
            for log in self.logs:
                log.flush()
                log.seek(0)
                print(log.read()[-1800:], file=sys.stderr)
        for guest in self.guests:
            guest.close()
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for log in self.logs:
            log.close()
        self.tmp.cleanup()

    def qmp(self, role, command):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(str(self.out / (role + ".qmp")))
            with sock.makefile("rwb", buffering=0) as stream:
                json.loads(stream.readline())
                for op in ["qmp_capabilities", command]:
                    stream.write((json.dumps({"execute": op}) + "\n").encode())
                    while True:
                        response = json.loads(stream.readline())
                        if "event" not in response:
                            assert "return" in response, response
                            break
                return response["return"]

    def publish(self, attach=True):
        b = self.guests[0]
        b.iommu()
        b.mapping(0x8000, 0x200000)
        b.mapping(0x10000, 0x202000)
        raw = struct.pack("<QQQQIIHH20x", 0, ats.CAPACITY, 0x10000,
                          1, 1, 7, 0, 0)
        b.cmd(f"write 0x200000 0x40 0x{raw.hex()}")
        b.w64(0x30, 0x8000)
        b.w64(0x38, 1)
        b.op(512)
        if attach:
            a = self.guests[1]
            a.w64(0x300, 1)
            a.w64(0x308, 2)
            a.w64(0x310, ats.CAPACITY)
            a.op(0x100)
            b.op(1)


def unsupported(binary, iommu):
    with Pair(binary, iommu, consumer=False) as pair:
        b = pair.guests[0]
        b.write(ats.ATSC, 0x8000, "w")
        assert b.r64(0x48) == 6, "unsupported ATS must fault the function"
        assert b.r64(0x368) & 4 == 0, "failed notifier must not be marked live"
        assert not pair.qmp("provider", "query-status")["running"]
        # Failed registration must not be unregistered.
        b.write(ats.ATSC, 0, "w")


def reset(binary, published):
    with Pair(binary, consumer=published) as pair:
        b = pair.guests[0]
        if published:
            pair.publish()
        else:
            b.iommu()
            b.mapping(0x8000, 0x200000)
            b.w64(0x30, 0x8000)
            b.op(0x105)
            b.op(6)
        pair.qmp("provider", "system_reset")
        b.setup()
        assert b.r64(0x388) == 0
        assert b.r64(0x368) == 1
        if published:
            assert b.r64(0x48) == 6, "reset cannot revive published backing"
        else:
            b.seq = 0
            b.op(6)  # fresh driver starts command sequence at one
            assert b.r64(0x48) == 0


def disconnect(binary, attached):
    with Pair(binary) as pair:
        pair.publish(attached)
        pair.qmp("consumer", "quit")
        pair.procs[1].wait(timeout=5)
        b = pair.guests[0]
        assert b.r64(0x48) == 6, "COMMIT-to-ATTACH disconnect must fault"
        assert b.r64(0x388) == 0
        assert b.r64(0x368) == 7, "fault preserves ATS invalidation capability"


def usage(binary):
    with Pair(binary) as pair:
        pair.publish()
        b, a = pair.guests

        def report(seq=1, epoch=1, session=1, capacity=ats.CAPACITY,
                   allocated=4096, releasing=0, quarantined=0, requested=1,
                   reserved=0, status=0):
            values = [epoch, session, 2, seq, 3 << 32, capacity, allocated,
                      releasing, quarantined, requested, reserved,
                      0, 0, 0, 0, 0]
            for index, value in enumerate(values):
                a.w64(0x2000 + index * 8, value)
            a.op(0x201, status)

        report()
        b.op(8)
        assert b.r64(0x2030) == 4096
        report(allocated=8192)  # duplicate must not replace accepted snapshot
        b.op(8)
        assert b.r64(0x2030) == 4096
        report(seq=2, allocated=8192)
        assert b.r64(0x2030) == 4096, "shadow stays stable until READ_USAGE"
        b.op(8)
        assert b.r64(0x2030) == 8192
        for invalid in [dict(seq=0, status=2), dict(seq=1, status=4),
                        dict(epoch=2, status=4), dict(session=9, status=4),
                        dict(capacity=ats.CAPACITY + 1, status=2),
                        dict(allocated=(1 << 64) - 1, releasing=1, status=2),
                        dict(releasing=ats.CAPACITY, status=2),
                        dict(quarantined=ats.CAPACITY, status=2),
                        dict(requested=4097, status=2),
                        dict(reserved=1, status=2)]:
            report(**invalid)
            b.op(8)
            assert b.r64(0x2018) == 2 and b.r64(0x2030) == 8192
        report(seq=3, allocated=0, requested=0)
        b.op(8)
        assert b.r64(0x2018) == 3 and b.r64(0x2030) == 0
        assert b.r64(0x368) == 7 and b.r64(0x48) == 0


def range_and_sequence(binary):
    with Pair(binary) as pair:
        pair.publish()
        b, a = pair.guests
        b.write(0x202000, 0x1122334455667788)
        for start, length in [(0, 0), (ats.CAPACITY, 1), (ats.CAPACITY - 1, 2),
                              ((1 << 64) - 1, 2), (1, (1 << 64) - 1)]:
            a.w64(0x330, start)
            a.w64(0x338, length)
            a.op(0x103, 8)
            assert b.read(0x202000) == 0x1122334455667788
        a.w64(0x330, 0)
        a.w64(0x338, 1)
        a.op(0x103)
        b.write(0x202000, 0x1122334455667788)
        for seq in [0, a.seq - 1, a.seq]:
            a.w(0x58, seq)
            a.w(0x18, 0x103)
            assert b.read(0x202000) == 0x1122334455667788
        a.seq = 0xFFFFFFFE
        a.op(7)
        a.w(0x58, 1)
        a.w(0x18, 0x103)
        assert a.r64(0x60) == 0xFFFFFFFF
        assert b.read(0x202000) == 0x1122334455667788


def malformed(binary, published):
    with Pair(binary, consumer=False) as pair:
        b = pair.guests[0]
        if published:
            pair.publish(False)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
            peer.settimeout(5)
            peer.connect(str(pair.out / "bridge"))
            # Valid framing, invalid operation/width/address.
            for op, size, addr in [(99, 4, 0), (0, 8, 0), (0, 4, 1),
                                    (0, 4, 0x4000), (3, 65, 0), (3, 0, 0)]:
                raw = struct.pack("<IIIIQQ64x", 0x5A424D01, op, size,
                                  0, addr, 0)
                peer.sendall(raw)
                reply = peer.recv(128)
                assert len(reply) == 96
                assert struct.unpack_from("<I", reply, 12)[0] == 2
            # Reject oversized datagrams even if the receive buffer truncates.
            raw = struct.pack("<IIIIQQ64x", 0x5A424D01, 0, 4, 0, 0, 0)
            peer.sendall(raw + b"extra")
            assert peer.recv(128) == b""
        assert b.r64(0x48) == (6 if published else 0)
        assert b.r64(0x388) == 0


def invalid_stu(binary):
    with Pair(binary, consumer=False) as pair:
        b = pair.guests[0]
        b.write(ats.ATSC, 0x8001, "w")
        assert b.r64(0x48) == 6 and b.r64(0x368) & 4 == 0


def cache_collision(binary):
    with Pair(binary, consumer=False) as pair:
        b = pair.guests[0]
        b.iommu()
        for iova, target, value in [(0x8000, 0x200000, 11),
                                    (0x108000, 0x201000, 22)]:
            b.mapping(iova, target)
            b.write(target, value)
        for iova, value in [(0x8000, 11), (0x108000, 22), (0x8000, 11)]:
            b.w64(0x30, iova)
            b.op(0x105)
            assert b.r64(0x3A8) == value
        assert b.r64(0x388) == 1 and b.r64(0x370) == 3
        b.mapping(0x8000, ats.BAR)  # translation to MMIO is not payload RAM
        b.invalidate()
        b.device_invalidate(0x8000)
        b.op(0x105, 6)


CASES = {
    "ats-without-iommu": lambda b: unsupported(b, None),
    "ats-without-device-iotlb": lambda b: unsupported(b, "device-iotlb=off"),
    "ats-with-snoop-control": lambda b: unsupported(
        b, "device-iotlb=on,snoop-control=on"),
    "ats-unsupported-stu": invalid_stu,
    "ats-cache-collision-and-mmio": cache_collision,
    "reset-before-publication": lambda b: reset(b, False),
    "reset-after-publication": lambda b: reset(b, True),
    "disconnect-before-attach": lambda b: disconnect(b, False),
    "disconnect-active": lambda b: disconnect(b, True),
    "usage-invalid-and-duplicate": usage,
    "range-overflow-and-sequence-wrap": range_and_sequence,
    "malformed-before-publication": lambda b: malformed(b, False),
    "malformed-after-publication": lambda b: malformed(b, True),
}


if __name__ == "__main__":
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    failures = []
    for name in sys.argv[2:] or CASES:
        try:
            CASES[name](binary)
            print("PASS", name, flush=True)
        except Exception as exc:
            failures.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {exc}", flush=True)
    if failures:
        sys.exit(1)

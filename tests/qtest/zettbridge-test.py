#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Two-process RPU management ABI regression; no guest OS required.
Usage: python3 tests/qtest/zettbridge-test.py build/qemu-system-x86_64
"""
import os,pathlib,socket,struct,subprocess,sys,tempfile,time
QEMU=str(pathlib.Path(sys.argv[1]).resolve())
class QTest:
 def __init__(self,path):
  self.s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.s.settimeout(10)
  for _ in range(200):
   try:self.s.connect(str(path));break
   except (FileNotFoundError,ConnectionRefusedError):time.sleep(.02)
  self.f=self.s.makefile('rwb',buffering=0);self.seq=0
 def cmd(self,c):
  self.f.write((c+'\n').encode());r=self.f.readline().decode().strip()
  while r.startswith('IRQ'):r=self.f.readline().decode().strip()
  assert r.startswith('OK'),(c,r)
  return r[3:]
 def out(self,addr,v):self.cmd(f'outl {addr:#x} {v:#x}')
 def setup(self):
  for off,val in [(0x10,0xf0000000),(4,6)]:self.out(0xcf8,0x80001000+off);self.out(0xcfc,val)
 def w(self,off,v):self.cmd(f'writel {0xf0000000+off:#x} {v:#x}')
 def r(self,off):return int(self.cmd(f'readl {0xf0000000+off:#x}'),0)
 def w64(self,off,v):self.w(off,v&0xffffffff);self.w(off+4,v>>32)
 def r64(self,off):return self.r(off)|(self.r(off+4)<<32)
 def mem(self,addr,b):self.cmd(f'write {addr:#x} {len(b):#x} 0x{b.hex()}')
 def op(self,op,epoch=1,status=0):
  self.seq+=1;self.w64(0x50,epoch);self.w(0x58,self.seq)
  self.w(0x40 if op==512 else 0x90 if op==513 else 0x18,1 if op in [512,513] else op)
  assert self.r(0x60)==self.seq
  assert self.r(0x68)==status,(op,self.r(0x68),status)
  assert self.r64(0xc8)==epoch
 def close(self):self.f.close();self.s.close()
def extent(dpa,length,dma,epoch=1,flags=7,tier=0):
 return struct.pack('<QQQQIIHH20x',dpa,length,dma,epoch,1,flags,tier,0)
with tempfile.TemporaryDirectory(prefix='zb-qtest-') as tmp:
 d=pathlib.Path(tmp);ps=[];qs=[];logs=[]
 try:
  for role in ['provider','consumer']:
   log=open(d/(role+'.log'),'w');logs.append(log)
   cmd=[QEMU,'-machine','q35','-accel','qtest','-m','512M','-display','none','-nodefaults','-S',
        '-qtest',f'unix:{d/role},server=on,wait=off','-device',
        f'zettbridge,id=rpu,addr=2,provider={"on" if role=="provider" else "off"},socket={d/"bridge"},capacity=256M']
   ps.append(subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT))
   q=QTest(d/role);qs.append(q);q.setup()
  b,a=qs
  assert a.r(0)==b.r(0)==0x5a520002
  assert b.r(8)==31 and b.r64(0x80)==4096
  assert a.r64(0x360)==b.r64(0x360)==256<<20
  a.w64(0x360,8<<30);b.w64(0x360,8<<30)
  assert a.r64(0x360)==b.r64(0x360)==256<<20 # capacity is read-only
  # Split staging, permission isolation and atomic reject without table switch.
  a.op(512,status=8)
  b.w64(0x30,0x100000);b.w64(0x38,2)
  b.mem(0x100000,extent(0,4096,0x1000000)+extent(8192,(256<<20)-4096,0x1001000))
  b.op(512,status=3);assert b.r64(0x20)==0 and b.r64(0x28)==0
  for bad in [extent(0,256<<20,0x1000000,flags=15),extent(0,256<<20,0x1000000,tier=2),extent(0,256<<20,(1<<64)-4096)]:
   b.w64(0x38,1);b.mem(0x100000,bad);b.op(512,status=3)
  # Two adjacent extents remain distinct DMA segments.
  b.w64(0x38,2)
  b.mem(0x100000,extent(0,4096,0x1000000)+extent(4096,(256<<20)-4096,0x1100000))
  b.op(0x102);b.op(512);assert b.r64(0x28)==256<<20
  a.w64(0x300,0x1234);a.w64(0x308,0x5678);a.w64(0x310,256<<20)
  a.op(0x100);b.op(1);a.op(4,status=8);b.op(2,status=5)
  # Every snapshot is immutable until explicitly refreshed.
  a.op(6);snap=a.r64(0x1008);assert snap==256<<20
  # Publish a full record, then read the latched provider shadow.
  def usage(seq,allocated=4096,requested=1):
   raw=struct.pack('<QQQQIIQQQQQ48x',1,0x1234,0x5678,seq,0,3,256<<20,allocated,0,0,requested)
   a.w(0x98,0)
   for i in range(0,128,4):a.w(0x2000+i,int.from_bytes(raw[i:i+4],'little'))
  usage(1);a.op(513);b.w(0x98,0);b.op(8);assert b.r64(0x2030)==4096
  usage(2,8192);a.op(513);assert b.r64(0x2030)==4096
  b.op(8);assert b.r64(0x2030)==8192
  usage(3,1,2);a.op(513,status=2);b.op(8);assert b.r64(0x2030)==8192
  usage(2,8192);a.op(513) # idempotent report
  usage(1);a.op(513,status=4)
  # Out-of-band query cannot clobber the sequential completion bank.
  seq=a.seq;a.w(0xa0,seq);a.w64(0xa8,1);a.w(0xb0,7);a.w(0xb8,1)
  assert a.r(0xc0)==7 and a.r(0x1110)==2 and a.r(0x1114)==4 and a.r(0x60)==seq
  a.w(0xa0,seq-1);a.w(0xb0,8);a.w(0xb8,1);assert a.r(0x1110)==0
  a.op(7);b.op(0x104);a.op(0x101);b.op(2);b.op(3);b.op(4)
  assert b.r64(0x28)==0 and a.r64(0x1008)==snap
  b.op(1,status=1);a.op(0x100,status=8)
  print('PASS: two QEMU banks, invalid tables, permissions, usage, snapshot, query, barrier, retire')
 finally:
  for q in qs:q.close()
  for pr in ps:
   pr.terminate()
  for pr in ps:
   try:pr.wait(timeout=5)
   except subprocess.TimeoutExpired:pr.kill();pr.wait()
  for f in logs:f.close()

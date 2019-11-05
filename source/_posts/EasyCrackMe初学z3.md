---
title: EasyCrackMe初学z3
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:29:45
tags:
keywords:
description:
photos:
---
TokyoWesterns的题目实在有意思，只能水水热身题混混日子






先从文件的逆向开始
![图片](EasyCrackMe初学z3/wm6gfM8yYL8sWFhl.png)

一开始很明显，flag长度为39且前6位为TWCTF{最后一位是 }   s就相当于flag

![图片](EasyCrackMe初学z3/w7fLJhGb1QgRo5B9.png)

接着是一段check，稍微把变量类型修改下看起来舒服些

![图片](EasyCrackMe初学z3/Rkt6QR0OxSQ8LRXm.png)

能看出来这是对flag里[0-9][a-f]进行计次，并且要符合cont_check里的值

![图片](EasyCrackMe初学z3/OacyZQzR44I5VsGU.png)

接着是两端相似的验证，直接扔上来修改后的

![图片](EasyCrackMe初学z3/lRVEZ0GzqhkKdyY7.png)
![图片](EasyCrackMe初学z3/vklSzVTTjt0XBZfr.png)

接着就是对[s1,s2,s3,s4]进行check

![图片](EasyCrackMe初学z3/eICMa2BwsXojiHc8.png)

然后我们老样子把数据从地址中提取出来

![图片](EasyCrackMe初学z3/ghSywpTnasgH4P3p.png)

然后把上面的整理一下就变成

![图片](EasyCrackMe初学z3/Dua1OngnAikZkxjs.png)

然后就直接用z3去求这个约束

![图片](EasyCrackMe初学z3/x3qIs7IQfZMzuKqL.png)

然后下面也是个简单的判断然后对比，再把这个条件加到约束条件中

![图片](EasyCrackMe初学z3/Gh3xmiAVbRUEtgm8.png)

然后是检验ascii码之和是否为1160和flag的某些位是否为某个值

![图片](EasyCrackMe初学z3/dgzQiJyDDsULKALF.png)

这两个整理下加入z3脚本里就是

![图片](EasyCrackMe初学z3/apecfvwgVy0bcRWO.png)

接着就是最开始的统计字符出现个数的约束
这个巨蛋疼，当时不知道z3要用If函数（大写I小写f）用if弄了半天unsat

![图片](EasyCrackMe初学z3/i2wDZFfENP03EFyB.png)

最终代码

![图片](EasyCrackMe初学z3/uLnEhJLrdisOGqYm.png)
TWCTF{df2b4877e71bd91c02f8ef6004b584a5}

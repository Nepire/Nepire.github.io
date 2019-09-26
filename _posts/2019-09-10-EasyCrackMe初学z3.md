---
layout: post
title: "EasyCrackMe初学z3"
date:   2019-09-10 19:00:00
categories: WriteUp
tags: WriteUp z3 re TokyoWesterns
---

* content
{:toc}

TokyoWesterns的题目实在有意思，只能水水热身题混混日子






先从文件的逆向开始
![图片](https://uploader.shimo.im/f/wm6gfM8yYL8sWFhl.png!thumbnail)一开始很明显，flag长度为39且前6位为TWCTF{最后一位是 }   s就相当于flag

![图片](https://uploader.shimo.im/f/w7fLJhGb1QgRo5B9.png!thumbnail)
接着是一段check，稍微把变量类型修改下看起来舒服些
![图片](https://uploader.shimo.im/f/Rkt6QR0OxSQ8LRXm.png!thumbnail)
能看出来这是对flag里[0-9][a-f]进行计次，并且要符合cont_check里的值
![图片](https://uploader.shimo.im/f/OacyZQzR44I5VsGU.png!thumbnail)
接着是两端相似的验证，直接扔上来修改后的
![图片](https://uploader.shimo.im/f/lRVEZ0GzqhkKdyY7.png!thumbnail)
![图片](https://uploader.shimo.im/f/vklSzVTTjt0XBZfr.png!thumbnail)
接着就是对[s1,s2,s3,s4]进行check
![图片](https://uploader.shimo.im/f/eICMa2BwsXojiHc8.png!thumbnail)
然后我们老样子把数据从地址中提取出来
![图片](https://uploader.shimo.im/f/ghSywpTnasgH4P3p.png!thumbnail)
然后把上面的整理一下就变成
![图片](https://uploader.shimo.im/f/Dua1OngnAikZkxjs.png!thumbnail)
然后就直接用z3去求这个约束
![图片](https://uploader.shimo.im/f/x3qIs7IQfZMzuKqL.png!thumbnail)
然后下面也是个简单的判断然后对比，再把这个条件加到约束条件中
![图片](https://uploader.shimo.im/f/Gh3xmiAVbRUEtgm8.png!thumbnail)
然后是检验ascii码之和是否为1160和flag的某些位是否为某个值
![图片](https://uploader.shimo.im/f/dgzQiJyDDsULKALF.png!thumbnail)
这两个整理下加入z3脚本里就是
![图片](https://uploader.shimo.im/f/apecfvwgVy0bcRWO.png!thumbnail)
接着就是最开始的统计字符出现个数的约束
这个巨蛋疼，当时不知道z3要用If函数（大写I小写f）用if弄了半天unsat
![图片](https://uploader.shimo.im/f/i2wDZFfENP03EFyB.png!thumbnail)
最终代码
![图片](https://uploader.shimo.im/f/uLnEhJLrdisOGqYm.png!thumbnail)
TWCTF{df2b4877e71bd91c02f8ef6004b584a5}

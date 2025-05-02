# Level06

## Walkthrough

We list the files in the current home directory.

```bash
level06@OverRide:~$ ls -lA
total 17
-rw-r--r--  1 level06 level06  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level06 level06 3533 Sep 10  2016 .bashrc
-rw-r--r--+ 1 level06 level06   41 Oct 19  2016 .pass
-rw-r--r--  1 level06 level06  675 Sep 10  2016 .profile
-rwsr-s---+ 1 level07 users   7907 Sep 10  2016 level06
level06@OverRide:~$ file level06 
level06: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x459bcb819bfdde7ecfa5612c8445e7dd0831cc48, not stripped
```

The file `level06` is owned by **level07** and has the setuid bit.

We list the functions inside the executable.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080484d0  _init
0x08048510  printf
0x08048510  printf@plt
0x08048520  strcspn
0x08048520  strcspn@plt
0x08048530  fflush
0x08048530  fflush@plt
0x08048540  getchar
0x08048540  getchar@plt
0x08048550  fgets
0x08048550  fgets@plt
0x08048560  signal
0x08048560  signal@plt
0x08048570  alarm
0x08048570  alarm@plt
0x08048580  __stack_chk_fail
0x08048580  __stack_chk_fail@plt
0x08048590  puts
0x08048590  puts@plt
0x080485a0  system
0x080485a0  system@plt
0x080485b0  __gmon_start__
0x080485b0  __gmon_start__@plt
0x080485c0  __libc_start_main
0x080485c0  __libc_start_main@plt
0x080485d0  strnlen
0x080485d0  strnlen@plt
0x080485e0  __isoc99_scanf
0x080485e0  __isoc99_scanf@plt
0x080485f0  ptrace
0x080485f0  ptrace@plt
0x08048600  _start
0x08048630  __do_global_dtors_aux
0x08048690  frame_dummy
0x080486b4  clear_stdin
0x080486d7  get_unum
0x0804870f  prog_timeout
0x08048720  enable_timeout_cons
0x08048748  auth
0x08048879  main
0x08048990  __libc_csu_init
0x08048a00  __libc_csu_fini
0x08048a02  __i686.get_pc_thunk.bx
0x08048a10  __do_global_ctors_aux
0x08048a3c  _fini
```

There are 2 user-defined functions: `main()` and `auth()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048879 <+0>:     push   ebp
   0x0804887a <+1>:     mov    ebp,esp
   0x0804887c <+3>:     and    esp,0xfffffff0
   0x0804887f <+6>:     sub    esp,0x50
   0x08048882 <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048885 <+12>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048889 <+16>:    mov    eax,gs:0x14
   0x0804888f <+22>:    mov    DWORD PTR [esp+0x4c],eax
   0x08048893 <+26>:    xor    eax,eax
   0x08048895 <+28>:    push   eax
   0x08048896 <+29>:    xor    eax,eax
   0x08048898 <+31>:    je     0x804889d <main+36>
   0x0804889a <+33>:    add    esp,0x4
   0x0804889d <+36>:    pop    eax
   0x0804889e <+37>:    mov    DWORD PTR [esp],0x8048ad4
   0x080488a5 <+44>:    call   0x8048590 <puts@plt>
   0x080488aa <+49>:    mov    DWORD PTR [esp],0x8048af8
   0x080488b1 <+56>:    call   0x8048590 <puts@plt>
   0x080488b6 <+61>:    mov    DWORD PTR [esp],0x8048ad4
   0x080488bd <+68>:    call   0x8048590 <puts@plt>
   0x080488c2 <+73>:    mov    eax,0x8048b08
   0x080488c7 <+78>:    mov    DWORD PTR [esp],eax
   0x080488ca <+81>:    call   0x8048510 <printf@plt>
   0x080488cf <+86>:    mov    eax,ds:0x804a060
   0x080488d4 <+91>:    mov    DWORD PTR [esp+0x8],eax
   0x080488d8 <+95>:    mov    DWORD PTR [esp+0x4],0x20
   0x080488e0 <+103>:   lea    eax,[esp+0x2c]
   0x080488e4 <+107>:   mov    DWORD PTR [esp],eax
   0x080488e7 <+110>:   call   0x8048550 <fgets@plt>
   0x080488ec <+115>:   mov    DWORD PTR [esp],0x8048ad4
   0x080488f3 <+122>:   call   0x8048590 <puts@plt>
   0x080488f8 <+127>:   mov    DWORD PTR [esp],0x8048b1c
   0x080488ff <+134>:   call   0x8048590 <puts@plt>
   0x08048904 <+139>:   mov    DWORD PTR [esp],0x8048ad4
   0x0804890b <+146>:   call   0x8048590 <puts@plt>
   0x08048910 <+151>:   mov    eax,0x8048b40
   0x08048915 <+156>:   mov    DWORD PTR [esp],eax
   0x08048918 <+159>:   call   0x8048510 <printf@plt>
   0x0804891d <+164>:   mov    eax,0x8048a60
   0x08048922 <+169>:   lea    edx,[esp+0x28]
   0x08048926 <+173>:   mov    DWORD PTR [esp+0x4],edx
   0x0804892a <+177>:   mov    DWORD PTR [esp],eax
   0x0804892d <+180>:   call   0x80485e0 <__isoc99_scanf@plt>
   0x08048932 <+185>:   mov    eax,DWORD PTR [esp+0x28]
   0x08048936 <+189>:   mov    DWORD PTR [esp+0x4],eax
   0x0804893a <+193>:   lea    eax,[esp+0x2c]
   0x0804893e <+197>:   mov    DWORD PTR [esp],eax
   0x08048941 <+200>:   call   0x8048748 <auth>
   0x08048946 <+205>:   test   eax,eax
   0x08048948 <+207>:   jne    0x8048969 <main+240>
   0x0804894a <+209>:   mov    DWORD PTR [esp],0x8048b52
   0x08048951 <+216>:   call   0x8048590 <puts@plt>
   0x08048956 <+221>:   mov    DWORD PTR [esp],0x8048b61
   0x0804895d <+228>:   call   0x80485a0 <system@plt>
   0x08048962 <+233>:   mov    eax,0x0
   0x08048967 <+238>:   jmp    0x804896e <main+245>
   0x08048969 <+240>:   mov    eax,0x1
   0x0804896e <+245>:   mov    edx,DWORD PTR [esp+0x4c]
   0x08048972 <+249>:   xor    edx,DWORD PTR gs:0x14
   0x08048979 <+256>:   je     0x8048980 <main+263>
   0x0804897b <+258>:   call   0x8048580 <__stack_chk_fail@plt>
   0x08048980 <+263>:   leave
   0x08048981 <+264>:   ret
End of assembler dump.
```

The `main()` function:
- calls `fgets()` to read up to 32 bytes from stdin, and stores user input in `[esp + 0x2c]`
- calls `scanf()` with `%u` as first argument and stores the unsigned integer written by the user to `[esp + 0x28]`
- calls `auth()` with `[esp + 0x2c]` and `[esp + 0x28]`
- calls `system()` to execute `/bin/sh` if the returned value by `auth()` is equal to 0

```
(gdb) disas auth
Dump of assembler code for function auth:
   0x08048748 <+0>:     push   ebp
   0x08048749 <+1>:     mov    ebp,esp
   0x0804874b <+3>:     sub    esp,0x28
   0x0804874e <+6>:     mov    DWORD PTR [esp+0x4],0x8048a63
   0x08048756 <+14>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048759 <+17>:    mov    DWORD PTR [esp],eax
   0x0804875c <+20>:    call   0x8048520 <strcspn@plt>
   0x08048761 <+25>:    add    eax,DWORD PTR [ebp+0x8]
   0x08048764 <+28>:    mov    BYTE PTR [eax],0x0
   0x08048767 <+31>:    mov    DWORD PTR [esp+0x4],0x20
   0x0804876f <+39>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048772 <+42>:    mov    DWORD PTR [esp],eax
   0x08048775 <+45>:    call   0x80485d0 <strnlen@plt>
   0x0804877a <+50>:    mov    DWORD PTR [ebp-0xc],eax
   0x0804877d <+53>:    push   eax
   0x0804877e <+54>:    xor    eax,eax
   0x08048780 <+56>:    je     0x8048785 <auth+61>
   0x08048782 <+58>:    add    esp,0x4
   0x08048785 <+61>:    pop    eax
   0x08048786 <+62>:    cmp    DWORD PTR [ebp-0xc],0x5
   0x0804878a <+66>:    jg     0x8048796 <auth+78>
   0x0804878c <+68>:    mov    eax,0x1
   0x08048791 <+73>:    jmp    0x8048877 <auth+303>
   0x08048796 <+78>:    mov    DWORD PTR [esp+0xc],0x0
   0x0804879e <+86>:    mov    DWORD PTR [esp+0x8],0x1
   0x080487a6 <+94>:    mov    DWORD PTR [esp+0x4],0x0
   0x080487ae <+102>:   mov    DWORD PTR [esp],0x0
   0x080487b5 <+109>:   call   0x80485f0 <ptrace@plt>
   0x080487ba <+114>:   cmp    eax,0xffffffff
   0x080487bd <+117>:   jne    0x80487ed <auth+165>
   0x080487bf <+119>:   mov    DWORD PTR [esp],0x8048a68
   0x080487c6 <+126>:   call   0x8048590 <puts@plt>
   0x080487cb <+131>:   mov    DWORD PTR [esp],0x8048a8c
   0x080487d2 <+138>:   call   0x8048590 <puts@plt>
   0x080487d7 <+143>:   mov    DWORD PTR [esp],0x8048ab0
   0x080487de <+150>:   call   0x8048590 <puts@plt>
   0x080487e3 <+155>:   mov    eax,0x1
   0x080487e8 <+160>:   jmp    0x8048877 <auth+303>
   0x080487ed <+165>:   mov    eax,DWORD PTR [ebp+0x8]
   0x080487f0 <+168>:   add    eax,0x3
   0x080487f3 <+171>:   movzx  eax,BYTE PTR [eax]
   0x080487f6 <+174>:   movsx  eax,al
   0x080487f9 <+177>:   xor    eax,0x1337
   0x080487fe <+182>:   add    eax,0x5eeded
   0x08048803 <+187>:   mov    DWORD PTR [ebp-0x10],eax
   0x08048806 <+190>:   mov    DWORD PTR [ebp-0x14],0x0
   0x0804880d <+197>:   jmp    0x804885b <auth+275>
   0x0804880f <+199>:   mov    eax,DWORD PTR [ebp-0x14]
   0x08048812 <+202>:   add    eax,DWORD PTR [ebp+0x8]
   0x08048815 <+205>:   movzx  eax,BYTE PTR [eax]
   0x08048818 <+208>:   cmp    al,0x1f
   0x0804881a <+210>:   jg     0x8048823 <auth+219>
   0x0804881c <+212>:   mov    eax,0x1
   0x08048821 <+217>:   jmp    0x8048877 <auth+303>
   0x08048823 <+219>:   mov    eax,DWORD PTR [ebp-0x14]
   0x08048826 <+222>:   add    eax,DWORD PTR [ebp+0x8]
   0x08048829 <+225>:   movzx  eax,BYTE PTR [eax]
   0x0804882c <+228>:   movsx  eax,al
   0x0804882f <+231>:   mov    ecx,eax
   0x08048831 <+233>:   xor    ecx,DWORD PTR [ebp-0x10]
   0x08048834 <+236>:   mov    edx,0x88233b2b
   0x08048839 <+241>:   mov    eax,ecx
   0x0804883b <+243>:   mul    edx
   0x0804883d <+245>:   mov    eax,ecx
   0x0804883f <+247>:   sub    eax,edx
   0x08048841 <+249>:   shr    eax,1
   0x08048843 <+251>:   add    eax,edx
   0x08048845 <+253>:   shr    eax,0xa
   0x08048848 <+256>:   imul   eax,eax,0x539
   0x0804884e <+262>:   mov    edx,ecx
   0x08048850 <+264>:   sub    edx,eax
   0x08048852 <+266>:   mov    eax,edx
   0x08048854 <+268>:   add    DWORD PTR [ebp-0x10],eax
   0x08048857 <+271>:   add    DWORD PTR [ebp-0x14],0x1
   0x0804885b <+275>:   mov    eax,DWORD PTR [ebp-0x14]
   0x0804885e <+278>:   cmp    eax,DWORD PTR [ebp-0xc]
   0x08048861 <+281>:   jl     0x804880f <auth+199>
   0x08048863 <+283>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048866 <+286>:   cmp    eax,DWORD PTR [ebp-0x10]
   0x08048869 <+289>:   je     0x8048872 <auth+298>
   0x0804886b <+291>:   mov    eax,0x1
   0x08048870 <+296>:   jmp    0x8048877 <auth+303>
   0x08048872 <+298>:   mov    eax,0x0
   0x08048877 <+303>:   leave
   0x08048878 <+304>:   ret
End of assembler dump.
```

The `auth()` function:
- calls `strnlen()` to get the length of the first argument passed to the function, stores the result in `[ebp - 0xc]`, and ends the function while returning 1 if the previous length is not greater than 5
- calls `ptrace()` to check if the current process is being traced, and ends the function while returning 1 if it's the case
- performs a XOR operation on the 3rd byte of the first argument passed to the function, and stores the result in `[ebp - 0x10]`
- iterates on the first argument passed to the function, ends the function and returns 1 if the current byte value is not greater than 31, or performs another XOR operation on `[ebp - 0x10]`
- compares the final value of all the XOR operations stored to `[ebp - 0x10]` with the second argument passed to the function, ends the function, and returns 0 if they are equal, otherwise returns 1

We download the executable and upload it on **Dogbolt** in order to better understand the operations performed on `[ebp - 0x10]`.

[Link to the decompiled executable](https://dogbolt.org/?id=9f72fea8-183c-4bdc-9620-b88449bc2ae1#Hex-Rays=186)

```c
_BOOL4 __cdecl auth(char *s, int a2)
{
  int i; // [esp+14h] [ebp-14h]
  int v4; // [esp+18h] [ebp-10h]
  int v5; // [esp+1Ch] [ebp-Ch]

  s[strcspn(s, "\n")] = 0;
  v5 = strnlen(s, 32);
  if ( v5 <= 5 )
    return 1;
  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
  {
    puts("\x1B[32m.---------------------------.");
    puts("\x1B[31m| !! TAMPERING DETECTED !!  |");
    puts("\x1B[32m'---------------------------'");
    return 1;
  }
  else
  {
    v4 = (s[3] ^ 0x1337) + 6221293;
    for ( i = 0; i < v5; ++i )
    {
      if ( s[i] <= 31 )
        return 1;
      v4 += (v4 ^ (unsigned int)s[i]) % 0x539;
    }
    return a2 != v4;
  }
}
```

The definition of the `auth()` function is quite similar to our GDB analysis.  

We know that to solve this level, we have to:
- write a string of more that 5 characters as first input
- write a number equal to the result of all the XOR operations performed in `auth()` as second input

But first we have to find the result of all the XOR operations. Thanks to the decompiled output, we can reproduce the code performed in the executable on our local setup and displays the result. The content of the string does not matter, as long as it respects the minimum length. We choose `"......"`.

```c
#include <stdio.h>

int main(void)
{
  char* s = "      ";
  int nb = (s[3] ^ 4919) + 6221293;
  for (int i = 0; i < 6; i++) {
    nb += (nb ^ (unsigned int)s[i]) % 1337;
  }
  printf("%d\n", nb);
  return 0;
}
```

```bash
xxx@xxx:~$ vim main.c
xxx@xxx:~$ gcc main.c && ./a.out 
6230887
```

The result from all the XOR operations is `6230887`.

To complete this level, we have to call the executable and pass `"      "` followed by `6230887`,

```bash
level06@OverRide:~$ ./level06 
***********************************
*		level06		  *
***********************************
-> Enter Login:       
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6230887
Authenticated!
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

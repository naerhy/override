# Override

> If you thought Rainfall was easy, here’s a more daunting challenge. Override is last ISO that will have you search for faults present in the protected binaries, and re-build these binaries depending on their behavior. 

## Description

Override is the final project of the cybersecurity branch, whose theme is the exploitation of ELF binaries. It is the continuation of [Snow Crash](https://github.com/naerhy/snow-crash) and [Rainfall](https://github.com/naerhy/rainfall).

It's based on the same principles as Rainfall: we have to use pretty much the same techniques (check its README for more details), but with a higher level of complexity, to exploit the executables.  
The disassembled executables were harder to understand than in the Rainfall project, but decompiler like Dogbolt make this easier.

## Usage

In order to start this project, you have to first download and install the provided ISO by 42.  
Then you need to use a virtual machine with the ISO. If using **VirtualBox**, you must set the `Attached to` setting in the `Network` tab to `Host-only Adapter`.  
Finally you can connect to the first level, using ssh. The ip is displayed on the home screen of the VM and the port is `4242`. The credentials for the first level are `level00`, for both username and password.

```
ssh level00@xxx.xxx.xxx.xxx -p 4242
```

Once logged, you will have to find a way to read the `.pass` file of the next level's user account. It is located in the home directory of each user.

```
level0@OverRide:~$ ./level00 $(exploit)
$ cat /home/users/level01/.pass
?????????????????????
$ exit
level0@OverRide:~$ su level01
Password:
level01@OverRide:~$ _
```

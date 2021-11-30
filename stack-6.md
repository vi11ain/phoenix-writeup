## Stack Six
Where does Stack Six go wrong, and what can you do with it?

## Source Code
```c
/*
 * phoenix/stack-six, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * Why do fungi have to pay double bus fares? Because they take up too
 * mushroom.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *what = GREET;

char *greet(char *who) {
  char buffer[128];
  int maxSize;

  maxSize = strlen(who);
  if (maxSize > (sizeof(buffer) - /* ensure null termination */ 1)) {
    maxSize = sizeof(buffer) - 1;
  }

  strcpy(buffer, what);
  strncpy(buffer + strlen(buffer), who, maxSize);

  return strdup(buffer);
}

int main(int argc, char **argv) {
  char *ptr;
  printf("%s\n", BANNER);

#ifdef NEWARCH
  if (argv[1]) {
    what = argv[1];
  }
#endif

  ptr = getenv("ExploitEducation");
  if (NULL == ptr) {
    // This style of comparison prevents issues where you may accidentally
    // type if(ptr = NULL) {}..

    errx(1, "Please specify an environment variable called ExploitEducation");
  }

  printf("%s\n", greet(ptr));
  return 0;
}
```

## Challenge
The aim is to `execve("/bin/sh")`

## Solution
### The Plan

### Breaking it
```console
(gdb) info variables
All defined variables:

Non-debugging symbols:
0x0000000000400918  __GNU_EH_FRAME_HDR
0x0000000000400980  __EH_FRAME_BEGIN__
0x00000000004009c8  __FRAME_END__
0x00000000006009d0  __CTOR_LIST__
0x00000000006009d8  __CTOR_END__
0x00000000006009e0  __DTOR_LIST__
0x00000000006009e8  __DTOR_END__
0x00000000006009f0  _DYNAMIC
0x0000000000600b30  _GLOBAL_OFFSET_TABLE_
0x0000000000600b88  __dso_handle
0x0000000000600b90  what
0x0000000000600b98  __TMC_END__
0x0000000000600b98  __bss_start
0x0000000000600b98  _edata
0x0000000000600ba0  completed
0x0000000000600ba8  dtor_idx
0x0000000000600bc0  object
0x0000000000600bf0  _end
(gdb) p (char*) what
$3 = 0x400850 "Welcome, I am pleased to meet you "
```

Notice `maxSize` is compared to `128` (`sizeof(buffer)`) but we actually `strcpy()` it to `buffer + strlen(buffer)`, thus we can overflow `buffer`.
```c
  maxSize = strlen(who);
  if (maxSize > (sizeof(buffer) - /* ensure null termination */ 1)) {
    maxSize = sizeof(buffer) - 1;
  }

  strcpy(buffer, what);
  strncpy(buffer + strlen(buffer), who, maxSize);

  return strdup(buffer);
```

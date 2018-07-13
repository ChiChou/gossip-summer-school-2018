#include <CoreFoundation/CFRunLoop.h>
#include <stdio.h>

#include "time.h"


int main(int argc, char *argv[])
{
    printf("size: %lu\n", sizeof(Time));

    Time time(12, 30, 0);
    time.print();

    CFRunLoopRun();  // do not quit, so you can play in frida REPL
    return 0;
}

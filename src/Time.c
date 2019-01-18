#define _POSIX_C_SOURCE 199309L

#include "Time.h"

#include <time.h>

void Time_nsleep(long nanos) {
    struct timespec req = { 0, nanos };
    nanosleep(&req, NULL);
}

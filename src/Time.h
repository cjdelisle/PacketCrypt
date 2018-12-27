#include <sys/time.h>

typedef struct {
    struct timeval tv0;
    struct timeval tv1;
} Time;

#define Time_NEXT(t) do { memcpy(&(t).tv0, &(t).tv1, sizeof(struct timeval)); } while (0)
#define Time_BEGIN(t) gettimeofday(&(t).tv0, NULL)
#define Time_END(t) gettimeofday(&(t).tv1, NULL)
#define Time_MICROS(t) ( \
    ((t).tv1.tv_sec - (t).tv0.tv_sec) * 1000000ull + (t).tv1.tv_usec - (t).tv0.tv_usec \
)

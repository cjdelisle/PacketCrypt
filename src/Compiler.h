#ifndef COMPILER_H
#define COMPILER_H

#define Compiler_likely(x)       __builtin_expect((x),1)
#define Compiler_unlikely(x)     __builtin_expect((x),0)

#endif

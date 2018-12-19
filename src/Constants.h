#ifndef CONSTANTS_H
#define CONSTANTS_H

// keep these powers of 2 because there is unsigned modulo using &
#define MEMORY_SZ 1024
#define HASH_SZ 8

#define CYCLES 10

// RandGen parameters
// How complex of a program do we want to create ?
#define BUDGET 400000

#define MIN_INSNS   20
#define MAX_INSNS 3000

#define MIN_OPS   2000
#define MAX_OPS 200000

// How much do we value various operations ?
#define MEMORY_COST  20
#define INPUT_COST    2
#define BRANCH_COST  50

#define LOOP_MIN_CYCLES 2
#define LOOP_MAX_CYCLES(scopeDepth) (7 + scopeDepth * 29)

#define SHOULD_LOOP(rand)               (((rand) % 64) < 46)
#define SHOULD_BRANCH(rand, insnCount)  (((rand) % 64 + (insnCount * 25 / MAX_INSNS)) < 50)

// How much budget remains after we enter an if sub-branch
// Technically it should be 100% because only one of the two branches will be taken
// but reducing it a bit helps make the code more compact and convoluted.
#define IF_BODY_BUDGET(budget, scopes) (((budget) * 7) / 32)

#define RANDOM_BRANCH_LIKELYHOOD 2 // 50% chance that an if statement is completely unpredictable
#define HIGHER_SCOPE_LIKELYHOOD  4 // 25% chance that an input variable will come from a higher scope
#define VAR_REUSE_LIKELYHOOD     8 // 12.5% chance that a variable used in an op is one which has been used before
#define IMMEDIATE_LIKELYHOOD     4 // 25% chance that an op uses an immediate input rather than a variable


#endif

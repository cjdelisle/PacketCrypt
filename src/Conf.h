/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef CONF_H
#define CONF_H

#include "packetcrypt/PacketCrypt.h"

// parentBlockHeight -> x -> y -> valid
//         0            1    2      3
#define Conf_PacketCrypt_ANN_WAIT_PERIOD 3

// This is a parent block height which will be used for the first 3 blocks
// because there is not yet enough chain history to fulfill the waiting period.
#define Conf_PacketCrypt_ANN_FAKE_PARENT_HEIGHT 0xfffffffc

// How many times to run the random hash program per announcement hash cycle
#define Conf_AnnHash_RANDHASH_CYCLES 4

// How many times to run memohash when creating an item for announcement hashing
#define Conf_AnnHash_MEMOHASH_CYCLES 2

// ============================================================================
// RandHash / RandGen parameters
// ============================================================================

// RandHash rules, if a program requires fewer than MIN_OPS
// or more than MAX_OPS cycles to complete, it will be deemed invalid
// and the hashing attempt is failed.
#define Conf_RandHash_MIN_OPS             0
#define Conf_RandHash_MAX_OPS         20000

// How complex of a program do we want to create ?
// Most operations have a "cost" equal to the number of inputs to the
// op. Loops multiply the cost of the operations within by the number
// of cycles of the loop. RandGen stops generating the hash program when
// the budget is exhausted.
#define Conf_RandGen_INITIAL_BUDGET   20000

// Programs which are created with fewer than MIN_INSNS or more than
// MAX_INSNS are deemed invalid and the hash attempt is failed.
#define Conf_RandGen_MIN_INSNS            0
#define Conf_RandGen_MAX_INSNS         2048
_Static_assert(sizeof(PacketCrypt_ValidateCtx_t) >= Conf_RandGen_MAX_INSNS*4, "");

// Some operations are more complicated than normal and have particular costs.
#define Conf_RandGen_MEMORY_COST         20
#define Conf_RandGen_INPUT_COST           2
#define Conf_RandGen_BRANCH_COST         50

// Loops have random numbers of cycles, these are the bounds of the random
// numbers. The max cycles become more as the scope depth grows, this helps
// stabilize the size of programs because outer loops have few cycles and thus
// spend less budget but inner loops have many more.
#define Conf_RandGen_LOOP_MIN_CYCLES      2
#define Conf_RandGen_LOOP_MAX_CYCLES(scopeDepth)     (7 + scopeDepth * 29)

// Likelyhood in a scope that a loop or branch will be created.
// Loops have a flat 23 in 32 chance while branches become less likely as the
// number of inctructions already emitted approaches the maximum. This helps
// to stabilize the size of generated programs.
#define Conf_RandGen_SHOULD_LOOP(rand) \
    (((rand) % 32) < 23)
#define Conf_RandGen_SHOULD_BRANCH(rand, insnCount) \
    (((rand) % 64 + (insnCount * 25 / Conf_RandGen_MAX_INSNS)) < 50)

// How much budget remains after we enter an if sub-scope
// Technically it should be 100% because only one of the two branches will be taken
// but reducing it a bit helps make the code more compact and convoluted.
#define Conf_RandGen_IF_BODY_BUDGET(budget, scopes)  (((budget) * 7) / 32)

// 50% chance that an if statement is completely unpredictable
#define Conf_RandGen_RANDOM_BRANCH_LIKELYHOOD 2

// 25% chance that an input variable will come from a higher scope
#define Conf_RandGen_HIGHER_SCOPE_LIKELYHOOD  4

// 12.5% chance that a variable used in an op is one which has been used before
#define Conf_RandGen_VAR_REUSE_LIKELYHOOD     8

// 25% chance that an op uses an immediate input rather than a variable
#define Conf_RandGen_IMMEDIATE_LIKELYHOOD     4


#endif

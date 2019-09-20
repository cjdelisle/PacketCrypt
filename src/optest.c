/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include <stdint.h>
#include "OpTemplate.h"

#define OpCodes_1_1
#define OpCodes_VISITOR(OP) \
    uint32_t optest11_ ## OP (uint32_t a) { return OP(a); }
#include "OpCodes.h"

#define OpCodes_2_1
#define OpCodes_VISITOR(OP) \
    uint32_t optest21_ ## OP (uint32_t a, uint32_t b) { return OP(a,b); }
#include "OpCodes.h"

#define OpCodes_2_2
#define OpCodes_VISITOR(OP) \
    uint64_t optest22_ ## OP (uint32_t a, uint32_t b) { return OP(a,b); }
#include "OpCodes.h"

#define OpCodes_4_2
#define OpCodes_VISITOR(OP) \
    uint64_t optest42_ ## OP (uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return OP(a,b,c,d); }
#include "OpCodes.h"

#define OpCodes_4_4
#define OpCodes_VISITOR(OP) \
    uint128 optest44_ ## OP (uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return OP(a,b,c,d); }
#include "OpCodes.h"


#include "Hash.h"
#include "Conf.h"
#include "RandGen.h"
#include "RandHash.h"
#include "packetcrypt/PacketCrypt.h"
#include "CryptoCycle.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

int main() {
    uint32_t* progbuf = calloc(sizeof(uint32_t), Conf_RandGen_MAX_INSNS);
    uint32_t* item = calloc(sizeof(uint32_t), RandHash_INOUT_SZ);
    CryptoCycle_State_t* pcState = calloc(sizeof(CryptoCycle_State_t), 1);
    assert(progbuf && item && pcState);
    Buf32_t buf = { .ints = {0} };
    uint64_t seed0 = 0;
    seed0 <<= 16; seed0 |= rand();
    seed0 <<= 16; seed0 |= rand();
    seed0 <<= 16; seed0 |= rand();
    seed0 <<= 16; seed0 |= rand();
    Buf32_t seed = { .longs = { seed0 } };

    printf("This test will search for differences between OpTemplate.h and OpTemplate2.h\n");
    printf("It's sort of a fuzz test, don't wait for it to end...\n");
    printf("RandomSeed = %016llx\n", (unsigned long long) seed0);

    for (int i = 0; i < 0x7fffffff; i++) {
        if ((i & 0xffff) == 0) { printf("i = %08x\n", i); }
        Hash_expand(buf.bytes, 32, seed.bytes, i);
        int ret = RandGen_generate(progbuf, &buf);
        if (ret < 0) { continue; }
        if (RandHash_interpret(progbuf, pcState, item, ret, sizeof(uint32_t) * RandHash_INOUT_SZ, 4)) {
            continue;
        }
    }
}

#ifndef PACKETCRYPT_H
#define PACKETCRYPT_H

#include "CryptoCycle.h"
#include "Buf.h"

#include <stdbool.h>

typedef union {
    CryptoCycle_Header_t hdr;
    Buf_TYPES(2048);
    Buf16_t sixteens[128];
    Buf32_t thirtytwos[64];
    Buf64_t sixtyfours[32];
} PacketCrypt_State_t;
_Static_assert(sizeof(PacketCrypt_State_t) == 2048, "");

typedef union {
    Buf_TYPES(1024);
    Buf16_t sixteens[64];
    Buf32_t thirtytwos[32];
    Buf64_t sixtyfours[16];
} PacketCrypt_Item_t;
_Static_assert(sizeof(PacketCrypt_Item_t) == 1024, "");

void PacketCrypt_init(PacketCrypt_State_t* state, Buf32_t* seed, uint64_t nonce);

bool PacketCrypt_update(PacketCrypt_State_t* state, PacketCrypt_Item_t* item, int randHashCycles);

void PacketCrypt_final(PacketCrypt_State_t* state);

static inline uint32_t PacketCrypt_getNum(PacketCrypt_State_t* state) {
    return state->sixteens[1].shorts[0];
}

#endif

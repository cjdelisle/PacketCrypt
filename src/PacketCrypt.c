#include "PacketCrypt.h"
#include "Hash.h"
#include "CryptoCycle.h"
#include "RandHash.h"

#include <stdint.h>
#include <assert.h>
#include <string.h>

void PacketCrypt_init(
    PacketCrypt_State_t* restrict state,
    Buf32_t* restrict seed,
    uint64_t nonce)
{
    Hash_expand(state->bytes, sizeof(PacketCrypt_State_t), seed->bytes, 0);
    state->hdr.nonce = nonce;
    CryptoCycle_makeFuzzable(&state->hdr);
    CryptoCycle_crypt(&state->hdr);
    assert(!CryptoCycle_isFailed(&state->hdr));
}

bool PacketCrypt_update(
    PacketCrypt_State_t* restrict state,
    PacketCrypt_Item_t* restrict item,
    int randHashCycles)
{
    if (randHashCycles) {
        #ifdef NO_RANDHASH
            assert(0);
        #else
        uint32_t progbuf[2048];
        RandHash_Program_t rhp = { .insns = progbuf, .len = 2048 };
        if (RandHash_generate(&rhp, &item->thirtytwos[31]) < 0) { return false; }
        if (RandHash_interpret(
            &rhp, &state->sixtyfours[1], item->ints, sizeof *item, randHashCycles))
        {
            return false;
        }
        #endif
    }

    memcpy(state->sixteens[2].bytes, item, sizeof *item);
    CryptoCycle_makeFuzzable(&state->hdr);
    CryptoCycle_crypt(&state->hdr);
    assert(!CryptoCycle_isFailed(&state->hdr));
    return true;
}

void PacketCrypt_final(PacketCrypt_State_t* restrict state) {
    memcpy(state->bytes, state->sixteens[12].bytes, 16);
}

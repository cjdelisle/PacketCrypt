#ifndef VALIDATE_H
#define VALIDATE_H

#include "packetcrypt/PacketCrypt.h"

enum {
    Validate_checkAnn_OK =                  0,
    Validate_checkAnn_INVAL =               1,
    Validate_checkAnn_INVAL_ITEM4 =         2,
    Validate_checkAnn_INSUF_POW =           3
};
int Validate_checkAnn(
    uint8_t annHashOut[32],
    const PacketCrypt_Announce_t* pcAnn,
    const uint8_t* parentBlockHash,
    PacketCrypt_ValidateCtx_t* vctx);

enum {
    Validate_checkBlock_OK =               0,
    Validate_checkBlock_RUNT =             (1<<8),
    Validate_checkBlock_ANN_INVALID_ =     (2<<8),
    Validate_checkBlock_ANN_INSUF_POW_ =   (3<<8),
    Validate_checkBlock_PCP_INVAL =        (4<<8),
    Validate_checkBlock_PCP_MISMATCH =     (5<<8),
    Validate_checkBlock_INSUF_POW =        (6<<8),
    Validate_checkBlock_BAD_COINBASE =     (7<<8),
    Validate_checkBlock_SHARE_OK =         (8<<8)
};
#define Validate_checkBlock_ANN_INVALID(x) (Validate_checkBlock_ANN_INVALID_ | (x))
#define Validate_checkBlock_ANN_INSUF_POW(x) (Validate_checkBlock_ANN_INSUF_POW_ | (x))

int Validate_checkBlock(const PacketCrypt_HeaderAndProof_t* hap,
                        uint32_t blockHeight,
                        uint32_t shareTarget,
                        const PacketCrypt_Coinbase_t* coinbaseCommitment,
                        const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
                        uint8_t workHashOut[static 32],
                        PacketCrypt_ValidateCtx_t* vctx);

#endif

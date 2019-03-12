#ifndef VALIDATE_H
#define VALIDATE_H

#include "packetcrypt/PacketCrypt.h"

#define Validate_checkAnn_OK                  0
#define Validate_checkAnn_INVAL               1
#define Validate_checkAnn_INVAL_ITEM4         2
#define Validate_checkAnn_INSUF_POW           3
int Validate_checkAnn(
    const PacketCrypt_Announce_t* pcAnn,
    const uint8_t* parentBlockHash,
    PacketCrypt_ValidateCtx_t* vctx);

#define Validate_checkBlock_OK                0
#define Validate_checkBlock_RUNT             (1<<8)
#define Validate_checkBlock_ANN_INVALID(i)   ((2<<8) | (i))
#define Validate_checkBlock_ANN_INSUF_POW(i) ((3<<8) | (i))
#define Validate_checkBlock_PCP_INVAL        (4<<8)
#define Validate_checkBlock_PCP_MISMATCH     (5<<8)
#define Validate_checkBlock_INSUF_POW        (6<<8)
#define Validate_checkBlock_BAD_COINBASE     (7<<8)
int Validate_checkBlock(const PacketCrypt_HeaderAndProof_t* hap,
                        uint32_t blockHeight,
                        const PacketCrypt_Coinbase_t* coinbaseCommitment,
                        const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
                        PacketCrypt_ValidateCtx_t* vctx);

#endif

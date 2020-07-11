/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#ifndef VALIDATE_H
#define VALIDATE_H

#include "packetcrypt/PacketCrypt.h"
#include "config.h"

enum {
    Validate_checkAnn_OK =                  0,
    Validate_checkAnn_INVAL =               1,
    Validate_checkAnn_INVAL_ITEM4 =         2,
    Validate_checkAnn_INSUF_POW =           3,
    Validate_checkAnn_SOFT_NONCE_HIGH =     4
};

char* Validate_checkAnn_outToString(int code);

int Validate_checkAnn(
    uint8_t annHashOut[32],
    const PacketCrypt_Announce_t* pcAnn,
    const uint8_t* parentBlockHash,
    PacketCrypt_ValidateCtx_t* vctx);

enum {
    Validate_checkBlock_OK =                    0,
    Validate_checkBlock_SHARE_OK =              1<<8,
    Validate_checkBlock_ANN_INVALID_ =          2<<8,
    Validate_checkBlock_ANN_INSUF_POW_ =        3<<8,
    Validate_checkBlock_ANN_SIG_INVALID_ =      4<<8,
    Validate_checkBlock_ANN_CONTENT_INVALID_ =  5<<8,
    Validate_checkBlock_PCP_INVAL =             6<<8,
    Validate_checkBlock_PCP_MISMATCH =          7<<8,
    Validate_checkBlock_INSUF_POW =             8<<8,
    Validate_checkBlock_BAD_COINBASE =          9<<8,
};
#define Validate_checkBlock_ANN_INVALID(x) (Validate_checkBlock_ANN_INVALID_ | (x))
#define Validate_checkBlock_ANN_INSUF_POW(x) (Validate_checkBlock_ANN_INSUF_POW_ | (x))
#define Validate_checkBlock_ANN_SIG_INVALID(x) (Validate_checkBlock_ANN_SIG_INVALID_ | (x))
#define Validate_checkBlock_ANN_CONTENT_INVALID(x) (Validate_checkBlock_ANN_CONTENT_INVALID_ | (x))

char* Validate_checkBlock_outToString(int code);

int Validate_checkBlock(const PacketCrypt_HeaderAndProof_t* hap,
                        uint32_t hapLen,
                        uint32_t blockHeight,
                        uint32_t shareTarget,
                        const PacketCrypt_Coinbase_t* coinbaseCommitment,
                        const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
                        uint8_t workHashOut[static 32],
                        PacketCrypt_ValidateCtx_t* vctx);

#endif

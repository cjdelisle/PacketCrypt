#ifndef ANNOUNCE_H
#define ANNOUNCE_H

#define Announce_MERKLE_DEPTH 13

#define AnnMerkle_DEPTH Announce_MERKLE_DEPTH
#define AnnMerkle_NAME Announce_Merkle
#include "AnnMerkle.h"
_Static_assert(sizeof(Announce_Merkle_Branch) == (Announce_MERKLE_DEPTH+1)*64, "");

/**
 * Announcement header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |    version    |                   soft_nonce                  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                          hard_nonce                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |                          work_bits                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                     parent_block_height                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                                                               |
 *    +                         content_type                          +
 * 20 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +                                                               +
 * 32 |                                                               |
 *    +                                                               +
 * 36 |                                                               |
 *    +                         content_hash                          +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +                                                               +
 * 48 |                                                               |
 *    +                                                               +
 * 52 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * Announcement:
 *
 * [ Header 0:56 ][ AnnMerkle proof 56:952 ][ Item 4 Prefix 952:1024 ]
 */
typedef struct {
    uint8_t version;
    uint8_t softNonce[3];
    uint32_t hardNonce;
    uint32_t workBits;
    uint32_t parentBlockHeight;

    uint64_t contentType;
    uint8_t contentHash[32];
} Announce_Header_t;
_Static_assert(sizeof(Announce_Header_t) == 56, "");

#define ITEM4_PREFIX_SZ (1024 - sizeof(Announce_Header_t) - sizeof(Announce_Merkle_Branch))
typedef struct {
    Announce_Header_t hdr;
    Announce_Merkle_Branch merkleProof;
    uint8_t item4Prefix[ITEM4_PREFIX_SZ];
} Announce_t;
_Static_assert(sizeof(Announce_t) == 1024, "");


#endif

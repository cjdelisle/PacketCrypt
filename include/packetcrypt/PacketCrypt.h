/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 *
 * This is a Library Header File, it is intended to be included in other projects without
 * affecting the license of those projects.
 */
#ifndef PACKETCRYPT_H
#define PACKETCRYPT_H

#include <stdint.h>

#define PacketCrypt_NUM_ANNS 4

/**
 * Block header, this is taken directly from bitcoin and should be
 * bit-for-bit compatible.
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                           version                             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                                                               |
 *    +                                                               +
 *  8 |                                                               |
 *    +                                                               +
 * 12 |                                                               |
 *    +                                                               +
 * 16 |                                                               |
 *    +                         hashPrevBlock                         +
 * 20 |                                                               |
 *    +                                                               +
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +                                                               +
 * 32 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 36 |                                                               |
 *    +                                                               +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +                                                               +
 * 48 |                                                               |
 *    +                        hashMerkleRoot                         +
 * 52 |                                                               |
 *    +                                                               +
 * 56 |                                                               |
 *    +                                                               +
 * 60 |                                                               |
 *    +                                                               +
 * 64 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 68 |                          timeSeconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 72 |                           workBits                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 76 |                             nonce                             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 80
 */
typedef struct {
    uint32_t version;
    uint32_t hashPrevBlock[8];
    uint32_t hashMerkleRoot[8];
    uint32_t timeSeconds;
    uint32_t workBits;
    uint32_t nonce;
} PacketCrypt_BlockHeader_t;
_Static_assert(sizeof(PacketCrypt_BlockHeader_t) == 80, "");

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
 * 16 |                         content_type                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 20 |                        content_length                         |
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
 * 56 |                                                               |
 *    +                                                               +
 * 60 |                                                               |
 *    +                                                               +
 * 64 |                                                               |
 *    +                                                               +
 * 68 |                                                               |
 *    +                          signing_key                          +
 * 72 |                                                               |
 *    +                                                               +
 * 76 |                                                               |
 *    +                                                               +
 * 80 |                                                               |
 *    +                                                               +
 * 84 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 88
 *
 * version: Always zero for now
 * soft_nonce: Nonce which is not dependent on the content of the announcement, can be changed
 *     without regenerating dataset.
 * hard_nonce: Additional nonce, rolling this nonce requires regenerating dataset.
 * work_bits: Difficulty of announcement in bitcoin nBits format
 * parent_block_height: The height of the most recent known block,
 *   it's hash is committed in the announcement hashing process.
 * content_type: An arbitrary field for informing about the content of the announcement
 * content_hash: announcement content merkle root, opaque for our purposes
 * signing_key: is non-zero, the final announcement in the block must be immediately followed by
 *   an ed25519 signature which is validatable using this pubkey.
 * content_length: the size of the content
 *
 * Announcement:
 *
 * [ Header 0:88 ][ Item 4 Prefix 88:128 ][ AnnMerkle proof 128:1024 ]
 */
typedef struct {
    uint8_t version;
    uint8_t softNonce[3];
    uint32_t hardNonce;
    uint32_t workBits;
    uint32_t parentBlockHeight;

    uint32_t contentType;
    uint32_t contentLength;
    uint8_t contentHash[32];

    uint8_t signingKey[32];
} PacketCrypt_AnnounceHdr_t;
_Static_assert(sizeof(PacketCrypt_AnnounceHdr_t) == 88, "");

static inline uint32_t PacketCrypt_AnnounceHdr_softNonce(const PacketCrypt_AnnounceHdr_t* hdr) {
    return (hdr->softNonce[2] << 16) | (hdr->softNonce[1] << 8) | hdr->softNonce[0];
}

typedef struct {
    PacketCrypt_AnnounceHdr_t hdr;
    uint64_t proof[117];
} PacketCrypt_Announce_t;
_Static_assert(sizeof(PacketCrypt_Announce_t) == 1024, "");

typedef struct {
    PacketCrypt_BlockHeader_t blockHeader;
    uint32_t _pad;
    uint32_t nonce2;
    PacketCrypt_Announce_t announcements[PacketCrypt_NUM_ANNS];
    uint8_t proof[8]; // this is a flexible length buffer
} PacketCrypt_HeaderAndProof_t;
_Static_assert(sizeof(PacketCrypt_HeaderAndProof_t) ==
    sizeof(PacketCrypt_BlockHeader_t) +
    4 +
    4 +
    sizeof(PacketCrypt_Announce_t) * PacketCrypt_NUM_ANNS +
    8, "");
#define PacketCrypt_HeaderAndProof_SIZEOF(proofLen) ( sizeof(PacketCrypt_HeaderAndProof_t) - 8 + (proofLen) )

#define PacketCrypt_Coinbase_MAGIC 0x0211f909
typedef struct {
    uint32_t magic;

    // The target representing the least work of any of the announcements in the set
    uint32_t annLeastWorkTarget;

    uint8_t merkleRoot[32];
    uint64_t numAnns;
} PacketCrypt_Coinbase_t;
_Static_assert(sizeof(PacketCrypt_Coinbase_t) == 48, "");

typedef struct {
    uint64_t ptr;
    uint64_t size;
} PacketCrypt_Find_t;
_Static_assert(sizeof(PacketCrypt_Find_t) == 16, "");

typedef struct {
    uint32_t progbuf[2048];
    int progLen;
} PacketCrypt_ValidateCtx_t;
_Static_assert(sizeof(PacketCrypt_ValidateCtx_t) == 2049*4, "");

#endif

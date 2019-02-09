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
} PacketCrypt_AnnounceHdr_t;
_Static_assert(sizeof(PacketCrypt_AnnounceHdr_t) == 56, "");

typedef struct {
    PacketCrypt_AnnounceHdr_t hdr;
    uint64_t proof[121];
} PacketCrypt_Announce_t;
_Static_assert(sizeof(PacketCrypt_Announce_t) == 1024, "");

typedef struct {
    PacketCrypt_BlockHeader_t blockHeader;
    uint32_t nonce2;
    uint32_t proofLen;
    PacketCrypt_Announce_t announcements[PacketCrypt_NUM_ANNS];
    uint8_t proof[];
} PacketCrypt_HeaderAndProof_t;
_Static_assert(sizeof(PacketCrypt_HeaderAndProof_t) ==
    sizeof(PacketCrypt_BlockHeader_t) +
    4 +
    4 +
    sizeof(PacketCrypt_Announce_t) * PacketCrypt_NUM_ANNS, "");

typedef struct {
    uint8_t merkleRoot[32];
    uint64_t numAnns;

    // The target representing the least work of any of the announcements in the set
    uint32_t annLeastWorkTarget;
} PacketCrypt_Coinbase_t;
_Static_assert(sizeof(PacketCrypt_Coinbase_t) == 32+8+4+4, "");

typedef struct {
    uint64_t ptr;
    uint64_t size;
} PacketCrypt_Find_t;
_Static_assert(sizeof(PacketCrypt_Find_t) == 16, "");

#endif

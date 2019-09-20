/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef CRYPTOCYCLE_H
#define CRYPTOCYCLE_H

#include "Buf.h"
#include "Conf.h"

#include <stdint.h>
#include <stdbool.h>

/*
 * Crypto query header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                                                               |
 *    +                                                               +
 *  4 |                            nonce                              |
 *    +                                                               +
 *  8 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |     unused    | add |D|  tzc  |      len    |T|   version   |F|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                                                               |
 *    +                                                               +
 * 20 |                                                               |
 *    +                                                               +
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +                        encryption_key                         +
 * 32 |                                                               |
 *    +                                                               +
 * 36 |                                                               |
 *    +                                                               +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 48
 *
 * Crypto reply header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                                                               |
 *    +                                                               +
 *  4 |                            nonce                              |
 *    +                                                               +
 *  8 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 | unused|  azc  | add |D|  tzc  |      len    |T|   version   |F|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                                                               |
 *    +                                                               +
 * 20 |                                                               |
 *    +                    poly1305_authenticator                     +
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 32 |                                                               |
 *    +                                                               +
 * 36 |                                                               |
 *    +                           key_half                            +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 48
 *
 * nonce: This is the nonce which will be used by chacha20
 *
 * unused: This is for future use, in version 0 it will be returned
 *         untouched.
 *
 * add: The size of the "additional data" which should be associated with
 *      the message for authentication purposes but not encrypted or
 *      decrypted. This is measured in 16 byte units.
 *
 * D: If set, the algorithm will attempt to decrypt rather than encrypt.
 *    Technically this means Poly1305 will simply be performed before
 *    encryption instead of after. BEWARE: You MUST check that the Poly1305
 *    authenticator matches the one sent to you. To prevent side-channel
 *    attacks, do this using a constant time verification function such as
 *    crypto_verify16().
 *
 *    ****************************************************************
 *    * THIS ALGORITHM WILL HAPPILY DECRYPT MESSAGES WHICH HAVE BEEN *
 *    * TAMPERED WITH, YOU MUST CHECK.                               *
 *    ****************************************************************
 *
 * tzc:  Trailing Zero Count -- the number of zero bytes which are padding
 *       the end of the message. The actual length of the message is
 *       len*16 - tzc. When decrypting, this is ignored completely.
 *
 * len:  The length of the message to encrypt, excluding header and AEAD
 *       additional content. This is measured in 16 byte units. Because
 *       the sum of length, additional and the header exceeds the buffer
 *       size of 2048, len is reduced to make them fit and the T flag is
 *       set.
 *       The algorithm does the following:
 *           real_length = MIN(header.len, 128 - 3 - header.add)
 *           header.T = real_len != header.len
 *           header.len = real_len
 *
 * T: Set by the algorithm len was decreased in order that length +
 *    additional + header size all fit inside of a 2048 byte buffer.
 *    If no truncation of the length took place, this is cleared.
 *    Its value as set by the user is ignored.
 *
 * version: The version of the algorithm to use, currently there is only
 *          one version (zero) and so the algorithm will set the fail flag
 *          if ver is non-zero.
 *
 * F: This is the fail flag, if it is set by the user then the algorithm
 *    will do nothing, if version is unrecognized then the algorithm will
 *    set the fail flag and return the data without any processing.
 *
 * pad: This is meant to align the key to a 16 byte memory boundry, it may
 *      be used in future versions but in version 0 it is ignored and
 *      returned untouched.
 *
 * encryption_key: In a query message, this is the key to use for
 *                 symmetrical encryption.
 *
 * poly1305_authenticator: In a reply message, this is the Poly1305
 *                         authenticator. If you are decrypting, you MUST
 *                         compare this to the authenticator you received.
 *
 * key_half: In a reply message, this is the low 16 bytes of the encryption key.
 */
typedef struct {
    uint8_t nonce[12];

    /**
     * The value of data in little endian is:
     *     0               1               2               3
     *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  8 |   version   |F|      len    |T| add |D|  tzc  |unused |  azc  |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     * We byte-swap it to little and then use it that way.
     */
    uint32_t data;

    uint8_t key_high_or_auth[16];
    uint8_t key_low[16];
} CryptoCycle_Header_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define CryptoCycle_LE(x) ((uint32_t)(x))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define CryptoCycle_LE(x) __builtin_bswap32(((uint32_t)(x)))
#else
    #error "cannot detect the byte order of the machine"
#endif

#define CryptoCycle_SETTER_GETTER(begin, count, setter, getter) \
    static inline int CryptoCycle_ ## getter (CryptoCycle_Header_t* restrict hdr) {             \
        return (CryptoCycle_LE(hdr->data)>>begin) & ((1u<<count)-1);                            \
    }                                                                                           \
    static inline void CryptoCycle_ ## setter \
        (CryptoCycle_Header_t* restrict hdr, uint32_t val) { \
        val &= (1u<<count) - 1;                                                                 \
        hdr->data = CryptoCycle_LE(                                                             \
            (CryptoCycle_LE(hdr->data) & (~(((1u<<count)-1)<<begin))) | (((uint32_t)val)<<begin)\
        );                                                                                      \
    }

CryptoCycle_SETTER_GETTER( 0, 4, setAdditionalZeros, getAdditionalZeros)
CryptoCycle_SETTER_GETTER( 8, 4, setTrailingZeros, getTrailingZeros)
CryptoCycle_SETTER_GETTER(12, 1, setDecrypt, isDecrypt)
CryptoCycle_SETTER_GETTER(13, 3, setAddLen, getAddLen)
CryptoCycle_SETTER_GETTER(16, 1, setTruncated, isTruncated)
CryptoCycle_SETTER_GETTER(17, 7, setLength, getLength)
CryptoCycle_SETTER_GETTER(24, 1, setFailed, isFailed)
CryptoCycle_SETTER_GETTER(25, 7, setVersion, getVersion)

void CryptoCycle_makeFuzzable(CryptoCycle_Header_t* restrict hdr);

void CryptoCycle_crypt(CryptoCycle_Header_t* restrict msg);

typedef union {
    CryptoCycle_Header_t hdr;
    Buf_TYPES(2048);
    Buf16_t sixteens[128];
    Buf32_t thirtytwos[64];
    Buf64_t sixtyfours[32];
} CryptoCycle_State_t;
_Static_assert(sizeof(CryptoCycle_State_t) == 2048, "");

typedef union {
    Buf_TYPES(1024);
    Buf16_t sixteens[64];
    Buf32_t thirtytwos[32];
    Buf64_t sixtyfours[16];
} CryptoCycle_Item_t;
_Static_assert(sizeof(CryptoCycle_Item_t) == 1024, "");

static inline uint64_t CryptoCycle_getItemNo(CryptoCycle_State_t* state) {
    return state->sixteens[1].longs[0];
}

void CryptoCycle_init(CryptoCycle_State_t* state, const Buf32_t* seed, uint64_t nonce);

bool CryptoCycle_update(
    CryptoCycle_State_t* restrict state,
    CryptoCycle_Item_t* restrict item,
    const uint8_t* restrict contentProof,
    int randHashCycles,
    PacketCrypt_ValidateCtx_t* ctx);

void CryptoCycle_smul(CryptoCycle_State_t* state);
void CryptoCycle_final(CryptoCycle_State_t* state);

#endif

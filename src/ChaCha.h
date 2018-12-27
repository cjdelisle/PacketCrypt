#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>

/*
 * Crypto query header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                                                               |
 *    +                            nonce                              +
 *  4 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |     unused    | add |D| unusd |      len    |T|   version   |F|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                             pad                               |
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
 *    +                            nonce                              +
 *  4 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |     unused    | add |D| unusd |      len    |T|   version   |F|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                             pad                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 26 |                                                               |
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
 *    +                        encrypted_key                          +
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
 * unusd: Also unused, returned untouched.
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
 * encrypted_key: In a reply message, this is the low 16 bytes of the
 *                encryption key which are themselves encrypted using the
 *                key and an initialization constant of 2.
 */
typedef struct {
    uint64_t nonce;

    /**
     * The value of data in little endian is:
     *     0               1               2               3
     *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  8 |   version   |F|      len    |T| add |D|         unused        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * We byte-swap it to little and then use it that way.
     */
    uint32_t data;

    uint32_t pad;
    uint8_t key_high_or_auth[16];
    uint8_t key_low[16];
} ChaCha_Header_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define ChaCha_LE(x) ((uint32_t)(x))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define ChaCha_LE(x) __builtin_bswap32(((uint32_t)(x)))
#else
    #error "cannot detect the byte order of the machine"
#endif

#define ChaCha_SETTER_GETTER(begin, count, setter, getter) \
    static inline int ChaCha_ ## getter (ChaCha_Header_t* hdr) {                                \
        return (ChaCha_LE(hdr->data)>>begin) & ((1u<<count)-1);                         \
    }                                                                                           \
    static inline void ChaCha_ ## setter (ChaCha_Header_t* hdr, uint32_t val) {                 \
        val &= (1u<<count) - 1;                                                                 \
        hdr->data = ChaCha_LE(                                                                  \
            (ChaCha_LE(hdr->data) & (~(((1u<<count)-1)<<begin))) | (((uint32_t)val)<<begin)   \
        );                                                                                      \
    }

ChaCha_SETTER_GETTER(12, 1, setDecrypt, isDecrypt)
ChaCha_SETTER_GETTER(13, 3, setAddLen, getAddLen)
ChaCha_SETTER_GETTER(16, 1, setTruncated, isTruncated)
ChaCha_SETTER_GETTER(17, 7, setLength, getLength)
ChaCha_SETTER_GETTER(24, 1, setFailed, isFailed)
ChaCha_SETTER_GETTER(25, 7, setVersion, getVersion)

#include <assert.h>

static inline void ChaCha_makeFuzzable(ChaCha_Header_t* hdr)
{
    hdr->data = *((uint32_t*)hdr->key_high_or_auth);

    ChaCha_setVersion(hdr, 0);
    ChaCha_setFailed(hdr, 0);

    assert(ChaCha_isFailed(hdr) == 0);
    assert(ChaCha_getVersion(hdr) == 0);

    // Length must be at least 32 blocks (512 bytes) long
    ChaCha_setLength(hdr, ChaCha_getLength(hdr) | 32);
}

void ChaCha_crypt(ChaCha_Header_t* msg);

#endif

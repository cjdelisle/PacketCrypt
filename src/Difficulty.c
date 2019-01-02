#include "Difficulty.h"

#include <assert.h>
#include <stdbool.h>

#ifdef __APPLE__
// Apple ships with openssl and then complains when you use it
// because they'd rather you use their framework instead
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/bn.h>

static void bnSetCompact(BIGNUM* bn, uint32_t nCompact)
{
    unsigned int nSize = nCompact >> 24;
    bool fNegative     =(nCompact & 0x00800000) != 0;
    unsigned int nWord = nCompact & 0x007fffff;
    if (nSize <= 3)
    {
        nWord >>= 8*(3-nSize);
        assert(BN_set_word(bn, nWord));
    }
    else
    {
        assert(BN_set_word(bn, nWord));
        assert(BN_lshift(bn, bn, 8*(nSize-3)));
    }
    BN_set_negative(bn, fNegative);
}

static uint32_t bnGetCompact(const BIGNUM* bn)
{
    unsigned int nSize = BN_num_bytes(bn);
    unsigned int nCompact = 0;
    if (nSize <= 3)
        nCompact = BN_get_word(bn) << 8*(3-nSize);
    else
    {
        //CBigNum x;
        BIGNUM x;
        BN_init(&x);
        assert(BN_rshift(&x, bn, 8*(nSize-3)));
        nCompact = BN_get_word(&x);
        BN_free(&x);
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000)
    {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= nSize << 24;
    nCompact |= (BN_is_negative(bn) ? 0x00800000 : 0);
    return nCompact;
}

static inline void bn256(BIGNUM* out) {
    BN_one(out);
    assert(BN_lshift(out, out, 256));
}

// work = 2**256 / (target + 1)
static inline void bnWorkForDiff(BN_CTX* ctx, BIGNUM* workOut, /*const*/ BIGNUM* diff) {
    // workOut = 2**256
    bn256(workOut);
    // diff++
    assert(BN_add(diff, diff, BN_value_one()));
    // workOut /= diff
    assert(BN_div(workOut, NULL, workOut, diff, ctx));
    // diff--
    assert(BN_sub(diff, diff, BN_value_one()));
}

// diffOut = (2**256 - work) / work
static inline void bnDiffForWork(BN_CTX* ctx, BIGNUM* diffOut, const BIGNUM* work)
{
    // diffOut = 2**256
    bn256(diffOut);

    // if work is zero then diff is maximum difficulty
    if (BN_is_zero(work)) { return; }

    // diffOut -= work
    assert(BN_sub(diffOut, diffOut, work));
    // diffOut /= work
    assert(BN_div(diffOut, NULL, diffOut, work, ctx));
}

static void setuint64(BIGNUM* out, uint64_t n)
{
    unsigned char pch[sizeof(n) + 6];
    unsigned char* p = pch + 4;
    bool fLeadingZeroes = true;
    for (int i = 0; i < 8; i++)
    {
        unsigned char c = (n >> 56) & 0xff;
        n <<= 8;
        if (fLeadingZeroes)
        {
            if (c == 0)
                continue;
            if (c & 0x80)
                *p++ = 0;
            fLeadingZeroes = false;
        }
        *p++ = c;
    }
    unsigned int nSize = p - (pch + 4);
    pch[0] = (nSize >> 24) & 0xff;
    pch[1] = (nSize >> 16) & 0xff;
    pch[2] = (nSize >> 8) & 0xff;
    pch[3] = (nSize) & 0xff;
    assert(BN_mpi2bn(pch, p - pch, out) == out);
}

static inline void getEffectiveWork(
    BN_CTX* ctx,
    BIGNUM* workOut,
    const BIGNUM* blockWork,
    const BIGNUM* annWork,
    uint64_t annCount)
{
    assert(BN_copy(workOut, blockWork) == workOut);

    // workOut = workOut**3
    assert(BN_sqr(workOut, workOut, ctx));
    assert(BN_mul(workOut, workOut, blockWork, ctx));
    // workOut /= annWork
    assert(BN_div(workOut, NULL, workOut, annWork, ctx));

    BIGNUM bnAnnCount;
    BN_init(&bnAnnCount);
    setuint64(&bnAnnCount, annCount);

    // workOut /= annCount
    assert(BN_div(workOut, NULL, workOut, &bnAnnCount, ctx));

    BN_free(&bnAnnCount);
}

uint32_t Difficulty_getEffectiveDifficulty(uint32_t blockTar, uint32_t annTar, uint64_t annCount)
{
    BN_CTX* ctx = BN_CTX_new();
    assert(ctx);

    BIGNUM x; BN_init(&x);
    BIGNUM bnBlockWork; BN_init(&bnBlockWork);
    BIGNUM bnAnnWork; BN_init(&bnAnnWork);

    bnSetCompact(&x, blockTar);
    bnWorkForDiff(ctx, &bnBlockWork, &x);

    bnSetCompact(&x, annTar);
    bnWorkForDiff(ctx, &bnAnnWork, &x);

    getEffectiveWork(ctx, &x, &bnBlockWork, &bnAnnWork, annCount);

    bnDiffForWork(ctx, &bnBlockWork, &x);
    uint32_t res = bnGetCompact(&bnBlockWork);

    BN_free(&x);
    BN_free(&bnBlockWork);
    BN_free(&bnAnnWork);
    BN_CTX_free(ctx);

    return res > 0x207fffff ? 0x207fffff : res;
}

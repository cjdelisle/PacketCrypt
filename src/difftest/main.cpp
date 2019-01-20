extern "C" {
#include "src/Difficulty.h"
}
#include "bignum.h"

#include <stdint.h>
#include <assert.h>

#include <chrono>
#include <random>

static CBigNum expand(uint32_t num) {
    CBigNum out;
    out.SetCompact(num);
    return out;
}

static CBigNum TWO_256 = CBigNum(1) << 256;

// work = 2**256 / (target + 1)
static inline CBigNum workForDiff(const CBigNum& target) {
    CBigNum out(TWO_256);
    CBigNum x(target);
    x += 1;
    out /= x;
    return out;
}

// target = (2**256 - work) / work
static inline CBigNum diffForWork(const CBigNum& work) {
    CBigNum out(TWO_256);
    if (work > 0) {
        out -= work;
        out /= work;
    }
    return out;
}

static inline uint32_t compact(const CBigNum& num) {
    uint32_t out = num.GetCompact();
    return (out > 0x207fffff) ? 0x207fffff : out;
}

// From difficulty, ann difficulty and ann count
// global_work = work * ann_work * ann_count
// work = (global_work**3) / ann_work / ann_count
static inline CBigNum getEffectiveWork(
    const CBigNum& blockWork, const CBigNum& annWork, uint64_t annCount)
{
    CBigNum out(blockWork);
    out *= blockWork;
    out *= blockWork;
    out /= annWork;
    out /= annCount;
    return out;
}

// total**3 = block_work_performed * ann_work * ann_count
static inline void checkEffectiveWork(
    const CBigNum& specifiedWork,
    const CBigNum& effectiveWork,
    const CBigNum& annWork,
    uint64_t annCount)
{
    CBigNum swCubed(specifiedWork);
    swCubed *= specifiedWork;
    swCubed *= specifiedWork;

    CBigNum x(effectiveWork);
    x *= annWork;
    x *= annCount;

    int swCubedCompact = compact(swCubed);
    int xCompact = compact(x);
    if (swCubedCompact - xCompact > 1 || xCompact - swCubedCompact > 1) {
        if (effectiveWork < 0xffffffff && specifiedWork < annWork * annCount) {
            // rounding error
            return;
        }
        printf("\n");
        printf("annCount           %08lx\n", (unsigned long)annCount);
        printf("specifiedWork      %s\n", specifiedWork.GetHex().c_str());
        printf("effectiveWork      %s\n", effectiveWork.GetHex().c_str());
        printf("annWork            %s\n", annWork.GetHex().c_str());
        printf("swCubed            %s\n", swCubed.GetHex().c_str());
        printf("x                  %s\n", x.GetHex().c_str());
        printf("%08x %08x\n", swCubed.GetCompact(), x.GetCompact());
        assert(0);
    }
}

static uint32_t getEffectiveDifficulty(uint32_t blockTar, uint32_t annTar, uint64_t annCount)
{
    CBigNum blockWork = workForDiff(expand(blockTar));
    CBigNum annWork = workForDiff(expand(annTar));
    CBigNum globalWork = getEffectiveWork(blockWork, annWork, annCount);
    checkEffectiveWork(blockWork, globalWork, annWork, annCount);
    CBigNum globalDiff = diffForWork(globalWork);
    return compact(globalDiff);
}

static uint32_t randCompact(std::default_random_engine& gen) {
    uint32_t x = gen();
    if ((x >> 24) != 0x20) { x &= 0x1f7fffff; }
    x &= 0xff7fffff;
    return x;
}

int main() {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine gen(seed);

    // Test that two ways of calculating difficulty agree
    for (int i = 0; i < 10000;) {
        uint32_t blockTar = randCompact(gen);
        uint32_t annTar = randCompact(gen);
        uint32_t annCount = randCompact(gen) & 0xffffff;

        uint32_t x = getEffectiveDifficulty(blockTar, annTar, annCount);
        uint32_t y = Difficulty_getEffectiveTarget(blockTar, annTar, annCount);

        if (x != y) {
            printf("blockTar %08x\n", blockTar);
            printf("annTar   %08x\n", annTar);
            printf("annCount %u\n", annCount);
            printf("x %08x\n", x);
            printf("y %08x\n", y);
            //printf("z %08x\n", blockWork.GetCompact());
            assert(0);
        }
        //printf("x %08x\n", x);
        if (y != 0x207fffff && y != 0) { i++; }
    }
}

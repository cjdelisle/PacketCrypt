#include "BlkMerkle.h"
#include "Hash.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

static int mkSize(int itemCount) {
    int size = 0;
    while (itemCount > 1) {
        itemCount += (itemCount & 1);
        size += itemCount;
        itemCount >>= 1;
    }
    // root
    size++;
    return sizeof(BlkMerkle_t) + sizeof(BlkMerkle_Entry_t) * size;
}

BlkMerkle_t* BlkMerkle_alloc(int itemCount) {
    int size = mkSize(itemCount);
    BlkMerkle_t* out = malloc(size);
    assert(out);
    out->itemCount = itemCount;
    out->size = size;
    return out;
}

void BlkMerkle_free(BlkMerkle_t* bm) {
    free(bm);
}

static void compute(int hashCount, BlkMerkle_Entry_t* base, char* top) {
    if (hashCount & 1) {
        Buf_OBJSET(&base[hashCount].hash, 0);
        hashCount++;
    }
    BlkMerkle_Entry_t* out = &base[hashCount];
    for (int i = 0, o = 0; i < hashCount; i += 2, o++) {
        assert((char*)(&out[o]) < top);
        Hash_compress32(out[o].hash.bytes, base[i].hash.bytes, (sizeof base[i]) * 2);
        out[o].range = base[i].range + base[i+1].range;
    }
    if (hashCount > 2) {
        compute(hashCount >> 1, out, top);
    } else {
        // sanity check
        assert((char*)&out[1] == top);
    }
}

/*
 * Strategy:
 * 1. Scan and number the entries
 * 2. Sort the entries
 * 3. Remove duplicates
 * 4. Compute first layer -> range = item[1].longs[0] - item[0].longs[0]
 * 5. Compute rest
 */

static int comparitor(const void* negIfFirst, const void* posIfFirst) {
    const BlkMerkle_Entry_t* nif = negIfFirst;
    const BlkMerkle_Entry_t* pif = posIfFirst;
    return (nif->hash.longs[0] < pif->hash.longs[0]) ? -1 :
        (nif->hash.longs[0] > pif->hash.longs[0]) ? 1 : 0;
}

void BlkMerkle_compute(BlkMerkle_t* bm) {
    // number the items so we can find them later
    for (int i = 0; i < bm->itemCount; i++) { bm->entries[i].range = i; }
    // sort
    qsort(bm->entries, bm->itemCount, sizeof(BlkMerkle_Entry_t), comparitor);
    int o = 0;
    // Remove duplicates
    for (int i = 1; i < bm->itemCount; i++) {
        if (bm->entries[i].hash.longs[0] == bm->entries[o].hash.longs[0]) { continue; }
        o++;
        if (i > o) { Buf_OBJCPY(&bm->entries[o], &bm->entries[i]); }
    }
    // hashes beginning with 0xffffffffffffffff are not accepted either
    while (o > 0 && bm->entries[o - 1].hash.longs[0] == ~((uint64_t)0)) { o--; }

    bm->itemCount = o;
    bm->size = mkSize(o);

    int hashCount = bm->itemCount;

    // create 2 pad entries so that we don't need to worry about the end of the range
    // if we have an even number of items, we'll use one (for the range) and if we have
    // an odd number of items, we'll use one as a pad and the other for the range.
    Buf_OBJSET(&bm->entries[hashCount], 0xff);
    Buf_OBJSET(&bm->entries[hashCount+1], 0xff);
    hashCount += (hashCount & 1);

    Buf64_t b;
    o = hashCount;
    for (int i = 0; i < hashCount; i += 2, o++) {
        Buf_OBJCPY(&b.thirtytwos[0], &bm->entries[i].hash);
        Buf_OBJCPY(&b.thirtytwos[1], &bm->entries[i+1].hash);
        Hash_compress32(bm->entries[o].hash.bytes, b.bytes, sizeof b);
        bm->entries[o].range = bm->entries[i+2].hash.longs[0] - bm->entries[i].hash.longs[0];
    }
    compute(hashCount / 2, &bm->entries[hashCount], ((char*)&bm[bm->size]));
}

Buf32_t* BlkMerkle_getRoot(BlkMerkle_t* bm) {
    return (Buf32_t*) &((char*)bm)[bm->size - 32];
}


#define LOG2LL(X) ((unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1))
#define LOG2L(X) ((unsigned) (8*sizeof (unsigned long) - __builtin_clzl((X)) - 1))
#define LOG2(X) _Generic(X, unsigned long long: LOG2LL(X), unsigned long: LOG2L(X) )
static inline int maxLog2(uint64_t x) {
    assert(x);
	return ((x & (x - 1)) != 0) + LOG2(x);
}
/*
static uint64_t treeWidth(uint64_t entryCount, int height) {

}
func (m *merkleBlock) calcTreeWidth(height uint32) uint32 {
	return (m.numTx + (1 << height) - 1) >> height
}

func (m *merkleBlock) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < m.numTx; i++ {
		isParent |= m.matchedBits[i]
	}
	m.bits = append(m.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		m.finalHashes = append(m.finalHashes, m.calcHash(height, pos))
		return
	}

	// At this point, the node is an internal node and it is the parent of
	// of an included leaf node.

	// Descend into the left child and process its sub-tree.
	m.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < m.calcTreeWidth(height-1) {
		m.traverseAndBuild(height-1, pos*2+1)
	}
}*/

BlkMerkle_Proof_t* BlkMerkle_mkProof(BlkMerkle_t* bm, int entryCount, uint64_t* entryIndexes)
{
    int height = maxLog2(bm->itemCount);

    uint64_t x = 2;
    x <<= height;

    uint8_t* flags = malloc(x);
    assert(flags);

    for (int i = 0; i < entryCount; i++) {
        assert(entryIndexes[i] < x);
        flags[entryIndexes[i]] = 1;
    }

    // TODO
    return NULL;
}

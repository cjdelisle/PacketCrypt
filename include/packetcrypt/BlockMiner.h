#ifndef BLOCKMINER_H
#define BLOCKMINER_H

#include "packetcrypt/PacketCrypt.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct BlockMiner_s BlockMiner_t;

typedef struct BlockMiner_Stats_s {
    // Announcements which were in the miner from the previous cycle and seem to still be valid.
    uint64_t oldGood;

    // Announcements which were dropped because they are nolonger valid.
    uint64_t oldExpired;

    // Announcements which were replaced because there are new ones with more effective work.
    uint64_t oldReplaced;

    // New announcements which seem to be good.
    uint64_t newGood;

    // New announcements which are not valid (either expired or not yet mature)
    uint64_t newExpired;

    // New announcements which were not added because they are not better than existing ones.
    uint64_t newNotEnough;

    // Number of announcements finally computed after deduplication.
    uint64_t finalCount;
} BlockMiner_Stats_t;

// This is the result which is written out to the file descriptor.
typedef struct BlockMiner_Share_s {
    PacketCrypt_Coinbase_t coinbase;
    PacketCrypt_HeaderAndProof_t hap;
} BlockMiner_Share_t;
#define BlockMiner_Share_SIZEOF(proofLen) \
    (sizeof(PacketCrypt_Coinbase_t) + PacketCrypt_HeaderAndProof_SIZEOF(proofLen))
_Static_assert(BlockMiner_Share_SIZEOF(8) == sizeof(BlockMiner_Share_t), "");

/**
 * Create a new block miner, you must provide the maximum number of announcements which this
 * miner can hold. As announcements of higher value are added using addAnns, less valuable
 * announcements will be discarded.
 *
 * If beDeterministic is true, the block miner will not try to update the time on the block
 * header.
 *
 * If sendPtr is true, the POINTER to the BlockMiner_Share_t will be written
 * to the provided fileNo rather than the data and the caller is expected to free() that
 * pointer when they are done with it.
 */
BlockMiner_t* BlockMiner_create(
    uint64_t maxAnns, int threads, int fileNo, bool beDeterministic, bool sendPtr);

/**
 * Stops and the block miner and then frees the relevant resources.
 */
void BlockMiner_free(BlockMiner_t* bm);

/**
 * Add one or more announcements to a block miner, if the number of announcements goes over
 * maxAnns, the least valuable announcements will be deleted.
 * You cannot add announcements while the miner is locked but you can once it begins mining.
 */
#define BlockMiner_addAnns_LOCKED 1
int BlockMiner_addAnns(BlockMiner_t* bm, PacketCrypt_Announce_t* anns, uint64_t count, int noCopy);

/**
 * Prepare the miner for mining a block, this call outputs a coinbase commitment to your location
 * of choice, this commitment must be in the coinbase and the validators will check for it.
 * Once the miner is locked, no new announcements can be added but mining can commence.
 *
 * If the miner is currently mining, this will stop it so the following pattern is ok:
 *
 * onAnnouncementDiscovered((ann) => {
 *     BlockMiner_addAnns(bm, [ann], 1);
 * });
 * onBlockDiscovered((block) => {
 *     blockchain.acceptBlock(block);
 *     PacketCrypt_Coinbase_t coinbase;
 *     height = blockchain.getNextHeight();
 *     diff = blockchain.getNextTarget();
 *     if ((err = BlockMiner_lockForMining(bm, &coinbase, height, diff))) {
 *         return handleError(err);
 *     }
 *     blockchain.setCoinbaseCommitment(&coinbase);
 *     block = blockchain.getBlockTemplate();
 *     if ((err = BlockMiner_start(bm, block.header))) { return handleError(err); }
 * })
 *
 * commitOut is a PacketCrypt_Coinbase_t which will be filled in
 * nextBlockHeight the height of the block to be mined
 * nextBlockTarget the work nBits for the block to be mined
 */
#define BlockMiner_lockForMining_OK      0
#define BlockMiner_lockForMining_NO_ANNS 1
int BlockMiner_lockForMining(
    BlockMiner_t* bm,
    BlockMiner_Stats_t* statsOut,
    PacketCrypt_Coinbase_t* commitOut,
    uint32_t nextBlockHeight,
    uint32_t nextBlockTarget);

/**
 * Begin mining a block, the miner must be locked for mining before this can happen.
 * In practice, the caller must call BlockMiner_lockForMining() and then place the Coinbase_t
 * output in the coinbase, then hash up the transactions to create the BlockHeader which they
 * create here.
 */
#define BlockMiner_start_OK             0
#define BlockMiner_start_NOT_LOCKED     1
#define BlockMiner_start_ALREADY_MINING 2
int BlockMiner_start(BlockMiner_t* ctx, PacketCrypt_BlockHeader_t* blockHeader);

/**
 * If a block is currently being mined, stop mining, in any case unlock the miner.
 * After a block is discovered, it's up to the caller to stop the miner
 */
#define BlockMiner_stop_OK          0
#define BlockMiner_stop_NOT_LOCKED  1
int BlockMiner_stop(BlockMiner_t* bm);

#endif

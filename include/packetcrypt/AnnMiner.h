#ifndef ANNMINER_H
#define ANNMINER_H

#include "packetcrypt/PacketCrypt.h"

typedef struct AnnMiner_s AnnMiner_t;

/**
 * Create a new announcement miner and allocate threads.
 */
AnnMiner_t* AnnMiner_create(int threads, int outFile);

/**
 * Begin mining announcements with a particular hash and content type.
 * If the miner is currently mining, it will stop and begin mining the new parameters.
 * Every time an announcement is found, every time an announcement is found, it will
 * be written to fileNo
 */
void AnnMiner_start(
    AnnMiner_t* ctx,
    uint8_t contentHash[32],
    uint64_t contentType,
    uint32_t difficulty,
    uint32_t parentBlockHeight,
    uint8_t parentBlockHash[32]);

/**
 * Stops the announcement miner.
 */
void AnnMiner_stop(AnnMiner_t* miner);

/**
 * Stops the announcement miner (if necessary) and frees relevant resources.
 */
void AnnMiner_free(AnnMiner_t* miner);

/**
 * Get the number of hashes per second at which the miner is currently mining.
 */
#define AnnMiner_getHashesPerSecond_NOT_MINING -1
int64_t AnnMiner_getHashesPerSecond(AnnMiner_t* miner);

#endif

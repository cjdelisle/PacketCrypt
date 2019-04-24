#ifndef ANNMINER_H
#define ANNMINER_H

#include "packetcrypt/PacketCrypt.h"

typedef struct AnnMiner_s AnnMiner_t;

/**
 * Create a new announcement miner and allocate threads.
 * threads is the number of threads to use
 * outfiles is a list of output file descriptors
 * numOutfiles is the number of output file descriptors in outFiles
 * if sendPtr is non-zero, then write a PacketCrypt_Find_t, otherwise write the content
 */
AnnMiner_t* AnnMiner_create(int threads, int* outFiles, int numOutFiles, int sendPtr);

/**
 * Begin mining announcements with a particular hash and content type.
 * If the miner is currently mining, it will stop and begin mining the new parameters.
 * Every time an announcement is found, every time an announcement is found, it will
 * be written to fileNo
 *
 * @param ctx the annMiner,
 * @param headerTemplate a template for the announcement header, no part of this will
 *      be altered except for the softNonce (which will be completely overwritten) and
 *      the hardNonce which will be incremented
 */
void AnnMiner_start(
    AnnMiner_t* ctx,
    PacketCrypt_AnnounceHdr_t* headerTemplate,
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

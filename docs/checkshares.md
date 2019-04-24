# checkshares - PacketCrypt pool block share verifier core

**NOTE**: You probably don't want to use this directly, the
[pool](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pool.md) server is much easier
to use and runs this in the background.

checkshares is a binary for validating shares mined by PacketCrypt miners.

Usage: `checkshares OPTIONS <indir> <outdir> <blkdir> <statedir>`

* `--threads <n>` (optional): Allocate *n* threads for processing, default is 1
* **indir** is the directory which will be periodically scanned for new files containing
work shares. The format of these files is documented below. Files which do not have a filename
prefix `share_` will be ignored.
* **outdir** is the directory where results from announcement verification will be placed, result
files will have the same names as the input files in **indir** so they can be easily identified,
the format of results is documented below.
* **blkdir** is the directory where shares are written if the hash is low enough that the share
constitutes a block find. The format is the same as a share except with a few fields updated.
* **statedir** is the directory which is used to store deduplication state.

The process of `checkshares` is as follows:

1. Scan **indir** for share files, upon finding one...
2. Check that the length is at least as long as the minimum size of the contained data, plus check
that the length of the file is sane given **work_length**. If this fails then fail with
Output_INVALID_LEN.
3. Perform a blake2b hash of the BlockMiner_Share_t component of the file and compare this, modulo
`hash_mod` to `hash_num`. If they are not the same then fail with `Output_WRONG_HANDLER`.
4. Copy the `nonce` and
[hashMerkleRoot](https://github.com/cjdelisle/PacketCrypt/blob/master/include/packetcrypt/PacketCrypt.h#L8)
fields from the block header contained inside of the **share** to the header which is part of the
**work**.
5. Compare the block headers from the **share** and the **work**, if they are different then fail
with `Output_HEADER_MISMATCH`.
6. Search for the coinbase commitment pattern in **work**, if it's not found then fail with
`Output_BAD_WORK`.
7. Copy the coinbase commitment from **share** to the coinbase commitment locaiton in **work**.
8. Sha256 verify the merkle branch from the coinbase transaction to the coinbase merkle root in
**work**, if it doesn't match the hashMerkleRoot declared in **share** then fail with
`Output_MERKLE_ROOT_MISMATCH`.
9. Call
[Validate_checkBlock()](https://github.com/cjdelisle/PacketCrypt/blob/master/include/packetcrypt/Validate.h#L32)
and if this fails then return `Output_CHECK_FAIL` ORed with the return code shifted left by 8 bits.
10. Check if the another share has been submitted with the same hash, if it has then fail with
`Output_DUPLICATE`.
11. If the share hash is good enough to become a block, the share file (modified as explained above)
is written out to the **blkdir**.
12. output `Output_ACCEPT`


## Share file format
Share files are somewhat complex and so are not fully documented here, they contain a standard
header, 4 announcement parent block hashes (needed to validate the 4 announcements) plus the
work which was created by the pool and the share that was created by the block miner.

### Share file header

```
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                           version                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |    hash_num   |    hash_mod   |           work_length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8
```

* **version**: This should always be zero.
* **hash_num**: Used to allow multiple validator/deduplicators to validate shared in parallel by
segmenting them by hash (so that there can be no duplicates across segments). When validating, the
first byte of the hash is taken modulo **hash_mod** and compared to **hash_num**. If it is not a
match then the announcement is invalid.
* **hash_mod**: Used with **hash_num** to allow multiple workers to validate announcements. If this
is zero then it is set internally to 1 and so everything will match a hashNum of 0.
* **work_length**: Used to find the boundry between the **work** section of the file and the
**share** section as both PoolProto_Work_t and BlockMiner_Share_t are variable length.

### Share file content
* **header** `8 bytes` defined above
* **announcement_parent_hashes** `128 bytes` the block hashes of the 4 blocks which are the
parent_block_height for each of the 4 announcements in the share.
* **payto** `64 bytes` these bytes will be faithfully reproduced to the output file but otherwise are
of no interest to checkshares, they can be used for indicating who should get paid for the work done.
* **work** `work_length bytes` a
[PoolProto_Work_t](https://github.com/cjdelisle/PacketCrypt/blob/master/src/PoolProto.h#L7)
which contains the work as defined by the pool master.
* **share** `(rest of the file)` a
[BlockMiner_Share_t](https://github.com/cjdelisle/PacketCrypt/blob/master/include/packetcrypt/BlockMiner.h#L35)
which contains the share as created by the miner.

## Output format

The output file format is simply 4 bytes which indicate the result of verifying the share.
The lower 8 bits of the result are parsed as the output enum and the upper 24 bits are to be parsed
as *additional information*. Possible values are:

* Output_CHECK_FAIL = 0: The call to `Validate_checkBlock` has failed, *additional information*
contains the result from `Validate_checkBlock`.
* Output_INVALID_LEN = 1: The size of the file is insane, early bailout to prevent buffer overflow,
no *additional information*
* Output_WRONG_HANDLER = 2: The hash of the **share** component does not match **hash_num** modulo
**hash_mod**, the share is meant for another validator. No *additional information*.
* Output_HEADER_MISMATCH = 3: The block header in the **share** does not match the block header in
the **work**. No *additional information*.
* Output_BAD_WORK = 4: No coinbase commitment pattern could be found in the coinbase section of the
**work**. No *additional information*.
* Output_MERKLE_ROOT_MISMATCH = 5: Hashing the coinbase with the commitment doesn't yield the same
hash that was given in the **share** block header. No *additional information*.
* Output_DUPLICATE = 6: The block share is valid, but another share with the same hash has been
seen before. No *additional information*.
* Output_ACCEPT = 7: The block share was accepted. No *additional information*.

## Notes

To shut down `checkshares` cleanly, send it a single SIGINT signal, this will cause it to shutdown
after writing out deduplication state to disk. If it is killed or crashes, this state will be lost
and some duplicate shares may be accepted.

Stale shares are not checked here, however since the caller should be sending the most recent
**work** with the shares from the miners, stale shares will fail anyway with
`Output_HEADER_MISMATCH`.

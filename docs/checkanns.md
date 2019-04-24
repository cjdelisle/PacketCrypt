# checkanns - PacketCrypt pool announcement verifier core

**NOTE**: You probably don't want to use this directly, the
[pool](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pool.md) server is much easier
to use and runs this in the background.

checkanns is a tool which streamlines validation of announcements for usage in a pool context.

Usage: `checkanns [--threads <n>] <indir> <outdir> <anndir> <statedir> <tempdir>`

* `--threads <n>` (optional): Allocate *n* threads for processing, default is 1
* **indir** is the directory which will be periodically scanned for new files containing
announcements. The format of these files is documented below. Files which do not have a filename
prefix `annshare_` will be ignored.
* **outdir** is the directory where results from announcement verification will be placed, result
files will have the same names as the input files in **indir** so they can be easily identified,
the format of results is documented below.
* **anndir** is the directory where announcements are written. These are simply in the format of
a sequence of announcements in a file.
* **statedir** is the directory which is used to store deduplication state.
* **tempdir** is a directory which is used to store results until they are finished writing, then
they are copied to **outdir**.

The process of `checkanns` is as follows:

1. Scan **indir** for announcement files, upon finding one...
2. Verify announcements in announcement file
3. Deduplicate announcements in announcement file, preferring announcements with highest work/age.
4. Write a file in **outdir** telling how many announcements were accepted and how many were
rejected as invalid vs. how many were rejected as duplicates.
5. Delete the file in **indir**.
6. If there is are least `OUT_ANN_CAP` announcements accepted or if 15 seconds has elapsed, create
a new file in **statedir** containing the deduplication table entries for the `OUT_ANN_CAP` new
announcements, then create a file in **anndir** containing the announcements themselves.

## Indir file format

Files created in indir must contain a fixed format header followed by a sequence of one or more
announcements, the header format is as follows:

```
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                           version                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |    hash_num   |   hash_mod    |            unused             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                                                               |
   +                                                               +
12 |                                                               |
   +                                                               +
16 |                                                               |
   +                                                               +
20 |                                                               |
   +                         content_hash                          +
24 |                                                               |
   +                                                               +
28 |                                                               |
   +                                                               +
32 |                                                               |
   +                                                               +
36 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
40 |                                                               |
   +                                                               +
44 |                                                               |
   +                                                               +
48 |                                                               |
   +                                                               +
52 |                                                               |
   +                      parent_block_hash                        +
56 |                                                               |
   +                                                               +
60 |                                                               |
   +                                                               +
68 |                                                               |
   +                                                               +
72 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
76 |                        min_ann_target                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
80 |                      parent_block_height                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
84 |                        announcements....
   +
80
```

* **version**: 4 bytes which indicates the version of the file, this exists for future versions
which contain announcements that need different verification. Right now this must always be zero.
* **hash_num**: Used to allow multiple validator/deduplicators to validate announcements in
parallel by segmenting them by hash (so that there can be no duplicates across segments). When
validating, the first byte of the hash is taken modulo **hash_mod** and compared to **hash_num**.
If it is not a match then the announcement is invalid.
* **hash_mod**: Used with **hash_num** to allow multiple workers to validate announcements. If this
is zero then it is set internally to 1 and so everything will match a hashNum of 0.
* **ignored**: This is ignored.
* **content_hash**: 32 byte blake2b hash of the content. The content for all announcements in one
file must be the same.
* **parent_block_hash**: This is the sha256 hash of the most recent block at the time that the
announcements to validate were created. All announcements in one announcement file must have
the same parent block.
* **min_ann_target**: This is the minimum target for announcements in this group, announcements
with a target with less work (numerically higher) will be considered invalid.
* **parent_block_height**: This is the block height of the parent block for announcements in this
group, any announcement which has a parent_block_height not equal to this number is considered
invalid.
* **announcements**: This is a list of one or more 1024 byte announcement headers.

To avoid a partial read, always create the file elsewhere and then move it into the **indir**
after it is completed. Files in **outdir** will have the same name as files in **indir** but
use care to make sure the filename is unique because failure to create a file in **outdir**
will cause `checkanns` to abort. You may delete files in **outdir** at your leasure.


## Outdir file format

The output file is a status contiaining the number of accepted announcements, the number of
announcements that are considered duplicates and the number of announcements

```
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                        accepted_count                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |                        duplicate_count                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                        invalid_count                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **accepted_count**: Number of announcements which were accepted.
* **duplicate_count**: Number of announcements which were rejected as duplicated.
* **invalid_count**: Number of announcements which were rejected as invalid.


## Anndir and Statedir
Anndir contains a sequence of 1MB files, each one containing announcements which can be
downloaded by miners. Each file in the **anndir** will be named `ann_<n>.bin` where n is
an auto-incrementing number. While these files contain deduplicated announcements, they
still must be deduplicated again on the miner because new announcements are allowed to
override old ones of lesser effective work.

`checkanns` will attempt to keep track of the next number of announcement file to create
but if it attempts to create a new one and one with that name already exists, it advances
it's number and tries the next one. This is to allow multi-process `checkanns` to cooperate.

After opening the announcement file, `checkanns` will attempt to open a state file with the
name `state_<n>.bin` in the **statedir**. If this file exists or if opening or writing to it
or the ann file fails for any other reason, `checkanns` will abort.

**NOTE:** You may delete old announcements in the **anndir** but when you do so, *you must*
also delete the corrisponding state file at the same time. Deleting one of these and not the
other can lead to announcements being thrown away or accepted by the deduplicator or may even
cause it to abort.


## Notes

To shut down `checkanns` cleanly, send it a single SIGINT signal, this will cause it to shutdown
after processing the next batch of announcements and to write out (short) announcement/state
files from what is residing in memory. If it is killed or crashes, some announcements will
be lost.

Finally, if at any time the files in **statedir** do not match one-for-one with the files in
**anndir**, files should be deleted in order to make them match.

# pcann - the PacketCrypt announcement miner core

**NOTE**: You probably don't want to use this directly, there is a more friendly wrapper called
[annmine](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/annmine.md) which uses this.

pcann arguments:

* `--threads <n>` (optional): Allocate *n* threads for processing, default is 1
* `--test` (optional): If this flag is passed, pcann will not require input from stdin and
will mine bogus announcements.
* `--out <dir>` (required): Filename of file which will contain mined announcements. If `--out` is
passed more than once, announcements will be split up by hash and sent to file by the modulo of the
first byte of the hash. This exists to support checkanns cluster mode.

Upon starting up, unless `--test` is specified, pcann will wait for a message to stdin in order to
give it the work it needs to use for mining announcements. The structure of an the work which must
be written to stdin is as follows:

```
    0               1               2               3
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |    version    |                   soft_nonce                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |                          hard_nonce                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                          work_bits                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                     parent_block_height                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                                                               |
   +                         content_type                          +
20 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 |                                                               |
   +                                                               +
28 |                                                               |
   +                                                               +
32 |                                                               |
   +                                                               +
36 |                                                               |
   +                         content_hash                          +
40 |                                                               |
   +                                                               +
44 |                                                               |
   +                                                               +
48 |                                                               |
   +                                                               +
52 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
56 |                                                               |
   +                                                               +
60 |                                                               |
   +                                                               +
64 |                                                               |
   +                                                               +
68 |                                                               |
   +                       parent_block_hash                       +
72 |                                                               |
   +                                                               +
76 |                                                               |
   +                                                               +
80 |                                                               |
   +                                                               +
84 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The first 56 bytes of the request message is an announcement header which will be used
as a template for mining announcements. The only fields which will be touched are soft_nonce
and hard_nonce which will be updated to scan for nonces.

* **soft_nonce** will be completely replaced
* **hard_nonce** will be rolled whenever soft_nonce is exhausted, you can get an estimate
of how many times **hard_nonce** will be rolled by examining the hashrate and estimating
when 2 to the power of 24 hashes will be computed. For example a 2.5 GHz Intel Core i7 which
gets less than 7000 hashes per second will take an estimated 2300 seconds to roll **hard_nonce**.
However when this happens, it will be printed to stderr `AnnMiner: Updating hard_nonce`.
With this in mind, you can assign hard_nonce to make sure all of your miners work on a
different part of the nonce space.

When you submit a request to the miner, the miner re-opens the output files in order that
you can move the original files elsewhere and have it create new ones.

If you submit exactly the same request a second time to the miner, the miner will not reset
it's nonces, it will continue searching where it was, but it will re-open the output files.

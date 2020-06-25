# PacketCrypt

Bandwidth-hard proof of work.
[![Build Status](https://travis-ci.org/cjdelisle/PacketCrypt.svg?branch=master)](https://travis-ci.org/cjdelisle/PacketCrypt)

## Abstract

Since the invention of blockchains, there has been research into how to make the proof of work
do something useful. Unfortunately, it has been remarkably difficult to make the work useful
without allowing miners to influence the nature of the work problem to their own advantage,
destroying the fairness of the algorithm.

PacketCrypt takes a different approach, while the work done in PacketCrypt is itself useless,
PacketCrypt is designed to encourage investment into the design and deployment of hardware
which is useful for other purposes.

PacketCrypt encourages development of hardware solutions for high speed encryption and
decryption of messages about the size of an internet packet. It also uses randomized code in
order to encourage CPU mining as well as next generation CPU design research. Perhaps most
significantly, PacketCrypt encourages cooperation between many mining devices, allowing
*bandwidth* to be expended in lieu of processor effort.

## Install

PacketCrypt is meant to be used in-tree. To set it up, you need to build the C code, then
install the nodejs dependencies.

### Ubuntu

Make sure you have the universe repository enabled

    sudo add-apt-repository universe

Install the required tools

    sudo apt install pkg-config libsodium-dev autoconf-archive git libssl-dev

Clone the source code

    git clone https://github.com/cjdelisle/PacketCrypt

Do the build process

    cd PacketCrypt
    ./autogen.sh
    ./configure
    make
    npm install

### Alpine linux

First make sure you have the [community](https://wiki.alpinelinux.org/wiki/Enable_Community_Repository)
repository enabled

    sudo apk update
    sudo apk add nodejs npm autoconf automake autoconf-archive build-base git libsodium-dev openssl-dev
    ./autogen.sh
    ./configure
    make
    npm install

### Apple OSX

Make sure you have [homebrew](https://brew.sh/) installed first, then:

    brew install libsodium pkg-config autoconf-archive openssl
    ./autogen.sh
    export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:`echo /usr/local/Cellar/libsodium/*/lib/pkgconfig`"
    export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:`echo /usr/local/Cellar/openssl*/*/lib/pkgconfig/`"
    ./configure
    make
    npm install

## Mining

Once you've built the relevant code, you can begin mining *announcements* in the
[gridfinity](https://gridfinity.com) mining pool using:

    node ./annmine.js http://pool.gridfinity.com/master

To mine blocks, use:

    node ./blkmine.js http://pool.gridfinity.com/master

You'll probably want to specify the payment address and other flags, you can just type

    node ./annmine.js
    node ./blkmine.js

to see the arguments which you can pass to these utilities or visit
[annmine](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/annmine.md) and
[blkmine](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/blkmine.md).

**NOTE:** Because of a [bug in pcblk](https://github.com/cjdelisle/PacketCrypt/issues/3) it is
best to stop and restart the block miner periodically (for example every 10 minutes).

For information about running a pool, see
[pool](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pool.md).

## How it works

PacketCrypt uses two distinct stages, the first stage mines a 1 KiB proof known as an
*announcement*. The second stage, which is used to mine a block, gets a difficulty advantage
based on the number of valid announcements which the miner can prove they had in memory at
the time of mining. The default behavior of nodes in the network is to *forward* announcements,
and announcements contain a payload hash, making them a dual use entity which can also be used
for broadcasting messages across the network as well as for mining.

The block miner's job is first to collect or create a set of announcements, they then commit
the merkle root of their set in the coinbase. They also commit the set size and minimum amount
of work done on any announcement in that set. Mining consists of performing a sequence of 4
encryption and memory accesses to announcements in the set. The hash of the work done on the
block must be less than the effectiveTarget, where the effectiveTarget is defined as:

        target_for_work( work_for_target(block_header.nBits)**3 / minimum_announcement_work / announcement_count )
          where:
            work_for_target(t) = 2**256 / (t + 1)
            target_for_work(w) = (2**256 - w) / w

If this work meets the target specified in the bitcoin block header, the block is valid and the
miner sends a proof containing the 4 announcements which were accessed in the winning cycle as
well as the merkle branches necessary to prove that they were included in the committed hash.

Though this proof is probabilistic only, faking the `announcement_count` or otherwise faking the
announcements is not better than simply mining a smaller announcement set.

### The Mining Algorithm

The core mining algorithm of PacketCrypt is a 4 cycle encryption and memory lookup loop over
a 2 KiB buffer. Each cycle, a 1 KiB item (announcement) is selected and copied over a portion of
the encrypted data before the data is encrypted again.

```go
const zero [16]byte
func PacketCryptCycle(announcements [][1024]byte, seed [32]byte, nonce uint32) [32]byte {
  var state [2048]byte
  chacha20.XORKeyStream(state, state, zero, seed)
  writeUInt32LE(state[0:4], nonce)
  CryptoCycle(state)
  for i := 0; i < 4; i++ {
      itemNo := readUInt32LE(state[16:20]) % len(announcements)
      copy(state[32:1056], announcements[itemNo])
      CryptoCycle(state)
  }
  return concat(state[192:208], state[16:32])
}
```

#### CryptoCycle
In order to understand how the mining algorithm works and why it makes use of the particular
offsets when copying data, its important to understand exactly what CryptoCycle does. CryptoCycle
is based on an implementation of chacha20/poly1305 as standardized by the IETF in
[RFC-7539](https://tools.ietf.org/html/rfc7539). Effort was made to ensure that building a device
for performing CryptoCycle is *not significantly easier than building a device which can encrypt
internet packets*.

Because encrypting internet traffic requires being able to encrypt messages of differing lengths
with or without [associated data](https://en.wikipedia.org/wiki/Authenticated_encryption),
CryptoCycle treats the first 16 bytes of the buffer as a header with certain parameters about the
encryption to be performed. The header specifies the length of the content to encrypt and
additional data to authenticate as well as a flag to indicate whether the algorithm is in
encryption or decryption mode. Decryption is slightly different, with the poly1305 authentication
occuring *before* the chacha20 instead of after.

When attempting to "decrypt" random data with a random key, it's clear that the authentication
check will almost certainly fail, so this algorithm requires the caller to verify the
authenticator manually with an inexpensive constant-time `memcmp()` operation.

##### Crypto Request Layout
The following is the data structure which represents a request to encrypt or decrypt data:

```
     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  0 |                                                               |
    +                            nonce                              +
  4 |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  8 |     unused    | add |D| unusd |     len     |T|   version   |F|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 12 |                             pad                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 16 |                                                               |
    +                                                               +
 20 |                                                               |
    +                                                               +
 24 |                                                               |
    +                                                               +
 28 |                                                               |
    +                        encryption_key                         +
 32 |                                                               |
    +                                                               +
 36 |                                                               |
    +                                                               +
 40 |                                                               |
    +                                                               +
 44 |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 48 |                                                               |
    +                          content...
 52 |
```

The meaning of the fields are as follows:

* `nonce` the encryption nonce, as per the IETF chacha20/poly1305 standard
* `add` the length of the additional data in 16 byte elements
* `D` if this bit is set, the message is being decrypted (order of chacha20/poly1305 is reversed)
* `len` the length of the data to encrypt (in 16 byte units)
* `T` (truncated) this field is ignored in the request but is set if the sum of `len` and `add`
is greater than 2048
* `version` this is always set to zero and exists for possible future use
* `F` this must be cleared by the caller
* `pad` / `unused` these are unused and ignored
* `encryption_key` this is the key used for the chacha20 encryption
* `content` the first `add * 16` bytes of this is additional authenticated data, it is unaltered
but included in the Poly1305 authenticator calculation as per RFC-7539. The `len * 16` bytes
following the end of the authenticated data is the data to be encrypted. If the sum of is greater
than 2048 bytes, the `len` is decreased by the algorithm and the `T` flag is set.

##### Crypto Reply Layout
The reply is much like the request:

```
     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  0 |                                                               |
    +                            nonce                              +
  4 |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  8 |     unused    | add |D| unusd |      len    |T|   version   |F|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 12 |                             pad                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 26 |                                                               |
    +                                                               +
 20 |                                                               |
    +                    poly1305_authenticator                     +
 24 |                                                               |
    +                                                               +
 28 |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 32 |                                                               |
    +                                                               +
 36 |                                                               |
    +                   key_and_authenticated_data                  +
 40 |                                                               |
    +
 44 |
    +

... 16 + (16 * add) bytes long ...
                                                                    +
                                                                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ?? |                                                               |
    +                       encrypted_content...
 ?? |
 ```

The fields which are *updated by the algorithm* are as follows:

* `len` this is *potentially updated* if the length of the message plus length of additional data
is greater than 2048.
* `T` (truncated) this flag is set if `len` has been updated, otherwise it is cleared.
* `F` (failed) this flag is set if there is a failure, during mining this should never happen
(see: Crypto Request Preparation)
* `poly1305_authenticator` this is the resulting authenticator from encryption/decryption, if the
caller is intending to encrypt data, they should send this along with their encrypted message, if
they are intending to decrypt data, they should compare this value to the poly1305 authenticator
using a constant-time implementation of `memcmp()`.
* `key_and_authenticated_data` this is bytes 32 to 48 of the encryption key plus the additional
authenticated data which are untouched.
* `encrypted_content` this is the content as it was before, but encrypted

##### Crypto Request Preparation
There are a few changes which are made to the data input before it is sent to the CryptoCycle core.

1. bytes 8 to 12 are set to the value of bytes 16 to 20, this is to make sure that the length of
the encrypted data and additional authenticated data are randomized each cycle.
2. `version` and `F` are set to zero because an unexpected version or `F` flag set will cause the
algorithm to give up. In the reference implementation, if the `F` flag is ever set, it's an
assertion failure.
3. `len` is OR'd with 32 to make sure that no encryption cycle will ever happen on less than 32
16-byte elements (512 bytes). This is important to make sure that the miner cannot *search* for
hashes where the length is zero, thus avoiding the need to encrypt anything at all.

You can see the real code which does this in
[CryptoCycle_makeFuzzable()](https://github.com/cjdelisle/PacketCrypt/blob/master/src/CryptoCycle.h#L177).

#### General Considerations
As you will note from the pseudocode above, the miner copies the 1 KiB announcement over bytes
32 to 1056 of the buffer, this is so the first 16 bytes of the announcement content will be mixed
with the Poly1305 authenticator from the previous cycle to form the next cycle's encryption key.

You will also note that the output of the algorithm is taken from bytes 192 to 208 followed by
bytes 16 to 32. Bytes 192 to 208 were chosen because they fall beyond the maximum size of
additional authenticated data but within the minimum size of encrypted data, meaning they will
always be encrypted. Bytes 16 to 32 are of course the Poly1305 authenticator. As Bitcoin's
difficulty metric considers the hash as a *little endian* number, the last byte of the hash is
most significant, this is why algorithm places the Poly1305 authenticator at the end of the output.

### Announcement Mining
Each announcement contains a commitment of the block height (`parent_block_height`) as well as the
most recent block hash at the time when the announcement was created. An announcement "matures" and
becomes usable for mining a block when the block height is `parent_block_height + 2`, this gives
announcement miners a bit of time to mine their announcements and then gives block miners time to
receive them. After this height, the work value of an announcement (for the purposes of
`minimum_announcement_work`) is divided by the number of blocks since it's maturity.

Announcement mining itself follows a similar pattern to block mining, reusing many of the same
algorithmic primitives but with a few special tweaks.

First, as there are no Announcements to collect, the miner generates 16384 1 KiB data elements
using [RandMemoHash](http://www.hashcash.org/papers/memohash.pdf). These items are generated using
the hash of the announcement header with the `soft_nonce` field blanked.

Secondly, because the verifier can re-generate the 1 KiB data items, the prover need not attach
the items for verification, nor even the merkle branches except for the last item. This helps
control the size of the resulting announcement which must be precisely 1KiB.

Third, in order to encourage CPU mining and also encourage research into advanced CPU designs, the
announcement mining process also involves the execution of randomly generated programs.

The announcement header is as follows:

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
 56
```

* `version` is always zero and exists for future usage
* `soft_nonce` is the only part of the announcement header which is not used when creating the
table of data items
* `work_bits` is the difficulty target for the announcement hashing, represented in the Bitcoin
standard format
* `parent_block_height` is the height of the most recent block at the time that the announcement
was hashed, the hash of this block must be committed when making the table of data items for this
announcement
* `content_type` is a value which is opaque to the mining algorithm, it represents the meaning of
the announcement (if any)
* `content_hash` is the hash of the announcement, for announcements which were created purely for
the purpose of creating blocks, miners are encouraged to set both `content_type` and `content_hash`
to all zeros

#### Announcement Design Objectives
There are a number of design objectives which went into the design of the announcement:

* Multi-use: An announcement which is mined for the purpose of broadcasting a message to the network
should not be significantly less useful to a block miner than an announcement which was mined
for the purpose of helping the block miner mine a block.
* Bandwidth-hardness: The exchange of announcements in order to get a discount on the proof of work
necessary to mine a block must be a *bandwidth hard* activity. This implies announcements should be
difficult to compress and also that miners should be incentivised to prefer many announcements
rather than few.
* CPU-favoritism: Announcements are intended not only to serve as proof of work but also to allow
communication, so announcement mining is designed to favor commodity hardware such as PCs and
phones.
* CPU-evolution: Finally, the announcement mining algorithm is intended to provide a basis for
thinking about next generation CPU designs.

##### Irreducability
For the multi-use and the bandwidth-hardness objectives, it is desirable that an announcement miner
cannot cause their announcements to be compressable to significantly less than 1 KiB in size. The
announcement *payload* is separated from the 1 KiB announcement itself so that the only parts of
the announcement which an announcement miner can really control are the `content_type` and
`content_hash`. A block miner who has no interest in using casually crafted announcements can omit
these 40 bytes from the memory locations where they store announcements, but these 40 bytes are
about all.

The content of the announcement is the 56 byte header plus a Merkle branch 13 hashes long and a
Merkle root needed to validate the announcement. The Merkle tree used for announcement hashing uses
64 byte Blake2b hashes which creates a total of 896 bytes of hashes which cannot be omitted without
requiring the recipient to regenerate the 16384 data items used to create the announcement. The 56
byte header plus the 896 byte Merkle branch and root is 952 bytes, so the final 72 bytes comes
from the 4th data item. While the 4th data item is probably the easiest thing to recreate, it is
only 7% of the announcement data and while it can be omitted from the data sent by the
announcement miner to the block miner, the work required to redo the RandMemoHash cycle for
recreating the data is far too much for the miner to omit it from memory.

Announcement layout:

```
[ header (56 bytes) ][ merkle branch (832 bytes) ][ merkle root (64 bytes) ][ 4th item prefix (72 bytes) ]
```

##### Reusability
With casual announcement miners and "professional" announcement miners both participating in the
network, one might expect the typical `minimum_announcement_work` to skyrocket as professionals
generate almost all of the announcements needed for block mining. This is mitigated by the fact
that announcements are *reusable* for mining multiple blocks - but at a degrading value. So if
you receive 100 announcements per block period and they're worth 100 CPU-units each, you can start
out by mining a block with `minimum_announcement_work` of 100, then next cycle you can double your
announement count by halving `minimum_announcment_work`, keeping the same total effort but now
being able to also include more casually mined announcements which have a lower amount of work
done on them.

##### CPU-favoritism
The announcment mining algorithm uses a couple of tricks to favor CPU mining over GPU and to
frustrate ASIC design efforts. However, the announcement mining algorithm is not designed to use
every circuit on current generation CPUs, instead it is designed to try to match general purpose
computing workloads to encourage research on the next generation of CPUs.

To this end, the announcement mining algorithm creates random programs which must be executed
before each encryption cycle. The random programs are generated from the result of the previous
cycle, which depend in part on the previous random program.

The programs use a stack of 32 bit elements and an instruction set of about 100 instructions.
There are branches (both predictable and unpredictable) and loops. Programs are normally
interpreted but they can be output as C language code which looks like the following:

```c
char* RANDHASH_SEED = "2";
#include "prelude.h"
BEGIN
LOOP(loop_1, 3) { // 0x00300042 @ 0
  OP1(l_1_1, MEMORY(loop_1, 0x000044d8, 9, 11)); // 0x89b13641 @ 1
  OP1(l_1_2, MEMORY(loop_1, 0x000044d8, 9, 8)); // 0x89b13041 @ 2
  OP1(l_1_3, MEMORY(loop_1, 0x000044d8, 9, 11)); // 0x89b13641 @ 3
  OP1(l_1_4, IN(7)); // 0x27a9e440 @ 4
  OP1(l_1_5, ROTL32(l_1_4, l_1_2)); // 0x0020081d @ 5
  OP1(l_1_6, CLZ8(l_1_5)); // 0x00000a04 @ 6
  LOOP(loop_2, 22) { // 0x01600042 @ 7
    OP1(l_2_1, MEMORY(loop_2, 0x00003293, 3, 2)); // 0x65266441 @ 8
    OP1(l_2_2, MEMORY(loop_2, 0x00003293, 3, 3)); // 0x65266641 @ 9
    OP1(l_2_3, MEMORY(loop_2, 0x00003293, 3, 7)); // 0x65266e41 @ 10
    OP1(l_2_4, XOR(l_2_2, l_2_3)); // 0x00a01223 @ 11
    OP1(l_2_5, IN(3)); // 0xa4b0b740 @ 12
    OP2(l_2_6, l_2_7, MULU8C(l_1_6, l_2_5)); // 0x00c00c30 @ 13
    OP1(l_2_8, CTZ16(l_2_4)); // 0x00001608 @ 14
    LOOP(loop_3, 2) { // 0x00200042 @ 15
      OP1(l_3_1, MEMORY(loop_3, 0x0000504d, 12, 11)); // 0xa09b9741 @ 16
      OP1(l_3_2, MEMORY(loop_3, 0x0000504d, 12, 4)); // 0xa09b8941 @ 17
      OP1(l_3_3, IN(7)); // 0xde8ab140 @ 18
      OP1(l_3_4, IN(5)); // 0x9755cf40 @ 19
      OP1(l_3_5, IN(7)); // 0xddd89640 @ 20
      OP1(l_3_6, SHRL8(l_3_2, 0x000000cd)); // 0x0cd42415 @ 21
      OP2(l_3_7, l_3_8, MULSU16C(l_3_6, l_3_5)); // 0x01502c2e @ 22
      OP4(l_3_9, l_3_10, l_3_11, l_3_12, SUB64C(l_2_6, l_2_7, l_3_3, l_3_4)); // 0x01401c3c @ 23
      OP4(l_3_13, l_3_14, l_3_15, l_3_16, ADD64C(l_2_5, l_2_6, 0x000001c9, 0x00000000)); // 0x1c941a3b @ 24
      IF_LIKELY(l_1_6) { // 0x00200c43 @ 25
        OP1(l_4_1, IN(0)); // 0xec830e40 @ 27
        OP1(l_4_2, IN(7)); // 0x1b765740 @ 28
        OUT2(l_4_1, l_4_2);
      } // 0x00000046 @ 29
      else { // 0x00000545 @ 30
        OP1(l_4_1, OR(l_3_7, l_2_1)); // 0x00802e22 @ 31
        OP1(l_4_2, SHRL16(l_4_1, l_2_8)); // 0x00f04416 @ 32
        OP1(l_4_3, AND(l_4_2, l_4_2)); // 0x02304621 @ 33
        OP2(l_4_4, l_4_5, ROTR64(l_4_1, l_4_2, 0x000006fb, 0x00000000)); // 0x6fb44639 @ 34
        OUT4(l_4_1, l_4_2, l_4_3, l_4_4);
        OUT(l_4_5);
      } // 0x00000046 @ 35
      OP1(l_3_17, IN(3)); // 0x74322a40 @ 36
      OP1(l_3_18, CLZ8(l_2_8)); // 0x00001e04 @ 37
      OP1(l_3_19, IN(7)); // 0xa78a6d40 @ 38
      OP1(l_3_20, POPCNT8(l_3_8)); // 0x00003001 @ 39
      OP1(l_3_21, SUB32(l_1_3, l_3_9)); // 0x01900611 @ 40
      OP1(l_3_22, CLZ16(l_3_10)); // 0x00003405 @ 41
      OP2(l_3_23, l_3_24, MUL64(l_2_2, l_2_3, l_2_3, l_2_4)); // 0x00b0143a @ 42
      OP1(l_3_25, BSWAP32(l_3_14)); // 0x00003c0b @ 43
      OP1(l_3_26, IN(7)); // 0xad2a6540 @ 44
      IF_RANDOM(l_3_17) { // 0x00204244 @ 45
        OP1(l_4_1, IN(0)); // 0x1c035640 @ 47
        OP1(l_4_2, ADD32(l_2_1, l_4_1)); // 0x02c0100e @ 48
        OP2(l_4_3, l_4_4, MUL64(l_3_11, l_3_12, l_4_1, l_4_2)); // 0x02d0383a @ 49
        OP1(l_4_5, POPCNT32(l_4_3)); // 0x00005c03 @ 50
        OP2(l_4_6, l_4_7, MUL64(l_3_15, l_3_16, 0x000004bf, 0x00000000)); // 0x4bf4403a @ 51
        OP1(l_4_8, IN(5)); // 0xa0d7a540 @ 52
        IF_LIKELY(l_4_8) { // 0x00206643 @ 53
          OP1(l_5_1, IN(6)); // 0x80fe1a40 @ 55
          OP1(l_5_2, CLZ16(l_4_2)); // 0x00005a05 @ 56
          OP1(l_5_3, IN(7)); // 0x085f7e40 @ 57
          OP1(l_5_4, CLZ16(l_5_1)); // 0x00006a05 @ 58
          OP1(l_5_5, POPCNT32(l_5_2)); // 0x00006c03 @ 59
          OP2(l_5_6, l_5_7, ADD8C(l_4_4, l_4_6)); // 0x03105e24 @ 60
          OP2(l_5_8, l_5_9, ADD8C(l_5_3, l_4_5)); // 0x03006e24 @ 61
          OP2(l_5_10, l_5_11, MUL16C(l_5_4, 0xfffffb57)); // 0xb574702b @ 62
          OP2(l_5_12, l_5_13, ADD64(l_5_7, l_5_8, l_5_9, l_5_10)); // 0x03e07833 @ 63
          OP1(l_5_14, POPCNT32(l_5_5)); // 0x00007203 @ 64
          OP4(l_5_15, l_5_16, l_5_17, l_5_18, MULU64C(l_4_6, l_4_7, l_4_7, l_4_8)); // 0x0330643f @ 65
          OP1(l_5_19, IN(7)); // 0x3f4ebe40 @ 66
          OP1(l_5_20, CTZ8(l_3_1)); // 0x00002207 @ 67
          OP1(l_5_21, CLZ16(l_4_3)); // 0x00005c05 @ 68
          OP2(l_5_22, l_5_23, MULSU16C(l_5_19, l_4_8)); // 0x03308e2e @ 69
          OP2(l_5_24, l_5_25, SHRA64(l_4_6, l_4_7, 0xfffffd66, 0xffffffff)); // 0xd6646437 @ 70
          OP2(l_5_26, l_5_27, MULSU8C(l_5_1, l_5_6)); // 0x03a06a2d @ 71
          OP1(l_5_28, POPCNT16(l_5_20)); // 0x00009002 @ 72
          OP2(l_5_29, l_5_30, ROTR64(l_4_1, l_4_2, l_5_12, l_5_13)); // 0x04105a39 @ 73
          OP1(l_5_31, SHRL32(l_5_24, l_5_25)); // 0x04d09817 @ 74
          OP4(l_5_32, l_5_33, l_5_34, l_5_35, MULU64C(l_5_14, l_5_15, 0x0000053d, 0x00000000)); // 0x53d4863f @ 75
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT8(l_5_17, l_5_18, l_5_19, l_5_20, l_5_21, l_5_22, l_5_23, l_5_24);
          OUT8(l_5_25, l_5_26, l_5_27, l_5_28, l_5_29, l_5_30, l_5_31, l_5_32);
          OUT2(l_5_33, l_5_34);
          OUT(l_5_35);
        } // 0x00000046 @ 76
        else { // 0x00000c45 @ 77
          OP4(l_5_1, l_5_2, l_5_3, l_5_4, ADD64C(l_4_7, l_4_8, 0x00000707, 0x00000000)); // 0x7074663b @ 78
          OP1(l_5_5, ADD16(l_5_1, l_5_2)); // 0x03606a0d @ 79
          OP2(l_5_6, l_5_7, ADD8C(l_2_4, l_5_4)); // 0x03801624 @ 80
          OP1(l_5_8, CTZ8(l_5_6)); // 0x00007407 @ 81
          OP2(l_5_9, l_5_10, MUL64(l_5_4, l_5_5, l_4_6, l_4_7)); // 0x0320723a @ 82
          OP1(l_5_11, ROTL32(l_5_10, l_5_7)); // 0x03b07c1d @ 83
          OP1(l_5_12, CTZ32(l_4_1)); // 0x00005809 @ 84
          OP2(l_5_13, l_5_14, SHRA64(l_5_11, l_5_12, 0x000002f7, 0x00000000)); // 0x2f748037 @ 85
          OP4(l_5_15, l_5_16, l_5_17, l_5_18, SUB64C(l_5_13, l_5_14, l_5_1, l_5_2)); // 0x0360843c @ 86
          OP2(l_5_19, l_5_20, SHLL64(l_5_8, l_5_9, 0x0000058c, 0x00000000)); // 0x58c47a35 @ 87
          OP2(l_5_21, l_5_22, ADD16C(l_5_17, l_5_15)); // 0x04308a25 @ 88
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT4(l_5_17, l_5_18, l_5_19, l_5_20);
          OUT2(l_5_21, l_5_22);
        } // 0x00000046 @ 89
        OP1(l_4_9, IN(7)); // 0x78dea840 @ 90
        OP2(l_4_10, l_4_11, SHRL64(l_3_11, l_3_12, 0x0000021a, 0x00000000)); // 0x21a43836 @ 91
        OP1(l_4_12, IN(3)); // 0xae2c7c40 @ 92
        OP2(l_4_13, l_4_14, SUB32C(l_4_12, l_4_9)); // 0x03406e29 @ 93
        OP4(l_4_15, l_4_16, l_4_17, l_4_18, MULU64C(l_3_18, l_3_19, l_4_13, l_4_14)); // 0x0390463f @ 94
        OP1(l_4_19, POPCNT32(l_4_15)); // 0x00007403 @ 95
        OP1(l_4_20, POPCNT8(l_4_16)); // 0x00007601 @ 96
        IF_LIKELY(l_4_10) { // 0x00206a43 @ 97
          OP2(l_5_1, l_5_2, MULU8C(l_4_11, 0xfffff9c4)); // 0x9c446c30 @ 99
          OP4(l_5_3, l_5_4, l_5_5, l_5_6, MULU64C(l_5_1, l_5_2, 0xfffffcfe, 0xffffffff)); // 0xcfe4843f @ 100
          OP2(l_5_7, l_5_8, MULSU32C(l_5_3, l_5_4)); // 0x0440862f @ 101
          IF_LIKELY(l_4_9) { // 0x00206843 @ 102
            OP1(l_6_1, IN(0)); // 0xc9853140 @ 104
            OP1(l_6_2, IN(7)); // 0xfddeb140 @ 105
            OP1(l_6_3, CTZ32(l_6_1)); // 0x00009409 @ 106
            OUT2(l_6_1, l_6_2);
            OUT(l_6_3);
          } // 0x00000046 @ 107
          else { // 0x00000445 @ 108
            OP1(l_6_1, IN(7)); // 0x88de6140 @ 109
            OP1(l_6_2, BSWAP16(l_6_1)); // 0x0000940a @ 110
            OP1(l_6_3, IN(1)); // 0x2690f740 @ 111
            OUT2(l_6_1, l_6_2);
            OUT(l_6_3);
          } // 0x00000046 @ 112
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
        } // 0x00000046 @ 113
        else { // 0x00001245 @ 114
          OP1(l_5_1, IN(6)); // 0xc17bf440 @ 115
          OP1(l_5_2, IN(1)); // 0xeb173e40 @ 116
          OP1(l_5_3, POPCNT32(l_5_2)); // 0x00008403 @ 117
          OP1(l_5_4, SHLL32(l_5_3, l_3_13)); // 0x01d08614 @ 118
          OP1(l_5_5, POPCNT32(l_5_4)); // 0x00008803 @ 119
          OP1(l_5_6, AND(l_5_1, l_4_16)); // 0x03b08221 @ 120
          OP2(l_5_7, l_5_8, ROTL64(l_4_4, l_4_5, l_5_5, l_5_6)); // 0x04606038 @ 121
          OP2(l_5_9, l_5_10, SHRL64(l_5_6, l_5_7, l_5_2, l_5_3)); // 0x04308e36 @ 122
          OP4(l_5_11, l_5_12, l_5_13, l_5_14, MUL64C(l_5_7, l_5_8, l_5_5, l_5_6)); // 0x0460903d @ 123
          OP1(l_5_15, BSWAP32(l_5_9)); // 0x0000920b @ 124
          IF_LIKELY(l_4_19) { // 0x00207c43 @ 125
            OP1(l_6_1, CLZ32(l_5_15)); // 0x00009e06 @ 127
            OUT(l_6_1);
          } // 0x00000046 @ 128
          else { // 0x00000245 @ 129
            OP1(l_6_1, POPCNT16(l_5_10)); // 0x00009402 @ 130
            OUT(l_6_1);
          } // 0x00000046 @ 131
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT4(l_5_9, l_5_10, l_5_11, l_5_12);
          OUT2(l_5_13, l_5_14);
          OUT(l_5_15);
        } // 0x00000046 @ 132
        OUT8(l_4_1, l_4_2, l_4_3, l_4_4, l_4_5, l_4_6, l_4_7, l_4_8);
        OUT8(l_4_9, l_4_10, l_4_11, l_4_12, l_4_13, l_4_14, l_4_15, l_4_16);
        OUT4(l_4_17, l_4_18, l_4_19, l_4_20);
      } // 0x00000046 @ 133
      else { // 0x00003a45 @ 134
        OP1(l_4_1, IN(7)); // 0xfdf5a340 @ 135
        OP1(l_4_2, CTZ8(l_4_1)); // 0x00005807 @ 136
        OP2(l_4_3, l_4_4, SHLL64(l_4_1, l_4_2, l_4_1, l_4_2)); // 0x02d05a35 @ 137
        OP4(l_4_5, l_4_6, l_4_7, l_4_8, MULSU64C(l_4_3, l_4_4, l_3_20, l_3_21)); // 0x02505e3e @ 138
        OP1(l_4_9, POPCNT16(l_4_6)); // 0x00006202 @ 139
        IF_LIKELY(l_4_2) { // 0x00205a43 @ 140
          OP1(l_5_1, IN(7)); // 0x90ee1140 @ 142
          OP1(l_5_2, SHRA16(l_5_1, l_4_9)); // 0x03406c19 @ 143
          OP1(l_5_3, POPCNT32(l_5_2)); // 0x00006e03 @ 144
          OP2(l_5_4, l_5_5, ADD64(l_5_1, l_5_2, l_5_1, l_5_2)); // 0x03706e33 @ 145
          OP1(l_5_6, SHRL32(l_5_3, l_5_4)); // 0x03907017 @ 146
          OP2(l_5_7, l_5_8, SUB16C(l_5_5, l_5_6)); // 0x03b07428 @ 147
          OP2(l_5_9, l_5_10, ROTL64(l_5_2, l_5_3, 0x00000081, 0x00000000)); // 0x08147038 @ 148
          OP2(l_5_11, l_5_12, MULSU16C(l_2_8, 0xfffffc67)); // 0xc6741e2e @ 149
          IF_LIKELY(l_5_8) { // 0x00207a43 @ 150
            OP1(l_6_1, IN(1)); // 0x1f93bb40 @ 152
            OP1(l_6_2, IN(3)); // 0x67312f40 @ 153
            OP1(l_6_3, CLZ32(l_6_1)); // 0x00008606 @ 154
            OP1(l_6_4, SHLL32(l_6_2, l_6_2)); // 0x04408814 @ 155
            OUT4(l_6_1, l_6_2, l_6_3, l_6_4);
          } // 0x00000046 @ 156
          else { // 0x00000545 @ 157
            OP1(l_6_1, IN(7)); // 0x35739940 @ 158
            OP1(l_6_2, IN(6)); // 0xf2e47d40 @ 159
            OP1(l_6_3, CTZ16(l_3_22)); // 0x00004c08 @ 160
            OP1(l_6_4, IN(7)); // 0x489fdd40 @ 161
            OUT4(l_6_1, l_6_2, l_6_3, l_6_4);
          } // 0x00000046 @ 162
          OP1(l_5_13, IN(5)); // 0xa7d11a40 @ 163
          OP2(l_5_14, l_5_15, ROTR64(l_5_12, l_5_13, l_5_9, l_5_10)); // 0x03f08439 @ 164
          OP2(l_5_16, l_5_17, SHRL64(l_5_13, l_5_14, l_4_2, l_4_3)); // 0x02e08636 @ 165
          OP1(l_5_18, CTZ16(l_5_2)); // 0x00006e08 @ 166
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT2(l_5_17, l_5_18);
        } // 0x00000046 @ 167
        else { // 0x00000f45 @ 168
          OP4(l_5_1, l_5_2, l_5_3, l_5_4, SUB64C(l_4_7, l_4_8, l_2_7, l_2_8)); // 0x00f0663c @ 169
          OP1(l_5_5, CTZ8(l_5_2)); // 0x00006e07 @ 170
          OP1(l_5_6, AND(l_5_5, l_5_2)); // 0x03707421 @ 171
          OP2(l_5_7, l_5_8, SHLL64(l_5_3, l_5_4, l_5_1, l_5_2)); // 0x03707235 @ 172
          OP4(l_5_9, l_5_10, l_5_11, l_5_12, MUL64C(l_5_6, l_5_7, l_5_6, l_5_7)); // 0x03c0783d @ 173
          OP1(l_5_13, SUB32(l_5_10, l_4_5)); // 0x03007e11 @ 174
          OP4(l_5_14, l_5_15, l_5_16, l_5_17, MULU64C(l_5_8, l_5_9, 0xfffffa37, 0xffffffff)); // 0xa3747c3f @ 175
          OP1(l_5_18, SHRL8(l_5_11, 0xfffffb72)); // 0xb7248015 @ 176
          OP1(l_5_19, SHLL32(l_5_12, l_2_8)); // 0x00f08214 @ 177
          IF_RANDOM(l_5_18) { // 0x00208e44 @ 178
          } // 0x00000046 @ 180
          else { // 0x00000145 @ 181
          } // 0x00000046 @ 182
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT2(l_5_17, l_5_18);
          OUT(l_5_19);
        } // 0x00000046 @ 183
        LOOP(loop_5, 11) { // 0x00b00042 @ 184
          OP1(l_5_1, MEMORY(loop_5, 0x00003f06, 10, 4)); // 0x7e0d4841 @ 185
          OP1(l_5_2, MEMORY(loop_5, 0x00003f06, 10, 5)); // 0x7e0d4a41 @ 186
          OP1(l_5_3, IN(1)); // 0xe412cf40 @ 187
          OP2(l_5_4, l_5_5, ADD32C(l_2_2, l_5_1)); // 0x03601226 @ 188
          OP1(l_5_6, POPCNT8(l_5_3)); // 0x00007001 @ 189
          OP1(l_5_7, CLZ32(l_5_2)); // 0x00006e06 @ 190
          OUT4(l_5_1, l_5_2, l_5_3, l_5_4);
          OUT2(l_5_5, l_5_6);
          OUT(l_5_7);
        } // 0x00000046 @ 191
        OUT8(l_4_1, l_4_2, l_4_3, l_4_4, l_4_5, l_4_6, l_4_7, l_4_8);
        OUT(l_4_9);
      } // 0x00000046 @ 192
      LOOP(loop_4, 85) { // 0x05500042 @ 193
        OP1(l_4_1, MEMORY(loop_4, 0x00004afd, 4, 11)); // 0x95fa9741 @ 194
        OP1(l_4_2, ADD8(l_4_1, l_4_1)); // 0x02c0580c @ 195
        OP2(l_4_3, l_4_4, SUB8C(l_4_2, l_4_2)); // 0x02d05a27 @ 196
        OUT4(l_4_1, l_4_2, l_4_3, l_4_4);
      } // 0x00000046 @ 197
      OUT8(l_3_1, l_3_2, l_3_3, l_3_4, l_3_5, l_3_6, l_3_7, l_3_8);
      OUT8(l_3_9, l_3_10, l_3_11, l_3_12, l_3_13, l_3_14, l_3_15, l_3_16);
      OUT8(l_3_17, l_3_18, l_3_19, l_3_20, l_3_21, l_3_22, l_3_23, l_3_24);
      OUT2(l_3_25, l_3_26);
    } // 0x00000046 @ 198
    OUT8(l_2_1, l_2_2, l_2_3, l_2_4, l_2_5, l_2_6, l_2_7, l_2_8);
  } // 0x00000046 @ 199
  OUT4(l_1_1, l_1_2, l_1_3, l_1_4);
  OUT2(l_1_5, l_1_6);
} // 0x00000046 @ 200
END
```

###### Instructions
Arithmatic instructions have 4 variants for treating 8 bit, 16 bit, 32 bit and 64 bit numbers.
If ADD8 for instance will add each 8 bit section of argument one to each 8 bit section of
argument 2. Arithmatic instructions also have a variant which returns two outputs, a value
and a "carry", for addition, carry is a 1 if the number rolls over when adding, for
multiplication is is the high bits of the result.

* One argument instructions, one output
    * POPCNT count the number of bits which are set in the input value
        * POPCNT8
        * POPCNT16
        * POPCNT32
    * CLZ count the number of leading zeros in the input value
        * CLZ8
        * CLZ16
        * CLZ32
    * CLZ count the number of *trailing* zeros in the input
        * CTZ8
        * CTZ16
        * CTZ32
    * BSWAP16 swap the high and low bytes of each 16 bit half of the value
    * BSWAP32 swap value from big endian to little endian or the reverse
* Two argument instructions, one output
    * ADD add without carry (number rolls over)
        * ADD8
        * ADD16
        * ADD32
    * SUB subtract without carry
        * SUB8
        * SUB16
        * SUB32
    * SHLL shift left logical (unsigned)
        * SHLL8
        * SHLL16
        * SHLL32
    * SHRL shift right logical (unsigned)
        * SHRL8
        * SHRL16
        * SHRL32
    * SHRA shift right arithmatic (signed, extends the sign bit)
        * SHRA8
        * SHRA16
        * SHRA32
    * ROTL rotate left
        * ROTL8
        * ROTL16
        * ROTL32
    * MUL multiply without carry
        * MUL8
        * MUL16
        * MUL32
    * AND logical AND
    * OR logical OR
    * XOR logical XOR
* Two argument instructions with 2 outputs
    * ADDC add values and output the result and a carry value
        * ADD8C
        * ADD16C
        * ADD32C
    * SUBC subtract and carry
        * SUB8C
        * SUB16C
        * SUB32C
    * MULC multiply signed*signed and carry
        * MUL8C
        * MUL16C
        * MUL32C
    * MULSUC multiply signed*unsigned and carry
        * MULSU8C
        * MULSU16C
        * MULSU32C
    * MULUC multiply unsigned*unsigned and carry
        * MULU8C
        * MULU16C
        * MULU32C
* 64 bit instructions with one 64 bit output
    * ADD64
    * SUB64
    * SHLL64
    * SHRL64
    * SHRA64
    * ROTL64
    * ROTR64
    * MUL64
* 64 bit instructions with two 64 bit outputs
    * ADD64C
    * SUB64C
    * MUL64C
    * MULSU64C
    * MULU64C
* Control instructions
    * IN reads a word from the input hash
    * MEMORY reads a value from memory, this is used with LOOP to stream memory
    * LOOP repeat a set of instructions n times
    * IF_LIKELY branch with a 87.5% chance that it will be taken
    * IF_RANDOM branch with a 50% chance that it will be taken
    * JMP unconditional jump (used with IF to implement the "else" block)
    * END end a scope (LOOP, IF)

## License

You may use this software under the terms of the
[LGPL-2.1](https://www.gnu.org/licenses/lgpl-2.1-standalone.html)
OR at your option, the
[LGPL-3.0](https://www.gnu.org/licenses/lgpl-3.0-standalone.html).
It is intended that you may embed this software in products, regardless of the licenses
which those products use, however any changes to the internals of this codebase (for
example to improve performance) should be made open source.

# blkmine - the PacketCrypt block miner

This is the miner which you'll want to use to mine blocks.
The miner uses
[pcann](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcblk.md)
internally to do the mining but uses nodejs code to handle the uploads
and downloads to/from the mining pool.

When you start up blkmine, the only thing you *need* is a path to a mining pool server,
but you have 5 optional arguments which you can pass:

* **paymentAddr**: This is a string which will be submitted to the pool with your work,
technically it can be anything that your pool is able to understand. If you do not specify
one then `bc1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4st4nj3u` and you will receive
a warning when starting up annmine.
* **threads**: This is the number of threads to dedicate to mining, it's an optional argument
but it is recommended that you pass it because the default number is 1.
* **maxAnns**: Maximum number of announcements to place in memory for mining, increasing this
number lower the amount of hashes per second which is needed to find a block, however it will
also use more memory. Each announcement requires 1024 bytes so the amount of memory used is
roughly **maxAnns** kilobytes. The default value is about a million, which corrisponds to
roughly 1GB of memory.
* **minerId**: This is a 32 bit unsigned number which is used in the block header nonce. If there
are multiple miners mining the exact same set of announcements, this will prevent them from finding
duplicate shares. By default blkmine uses a random number.
* **corePath**: This is the path to the `pcann` executable, the default value is `./bin/pcann`
which is ok if you're using annmine in the PacketCrypt git repository.
* **dir**: This is a path to a directory which annmine will use for temporary files.
If this directory doesn't exist then it will be created but make sure the user which
annmine is running under is able to create it. You can safely delete this directory any
time that annmine is not running.

## Example

```
$ node ./blkmine.js --threads 4 --paymentAddr bc1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4st4nj3u http://my.favorite.mining.pool/
```

## FAQ

### What is effective hashrate ?

Because of the way PacketCrypt calculates difficulty, your likelyhood of winning a share is
not directly corrulated to your hashes per second, therefore blkmine logs both your real hashrate
and your *effective hashrate*.

Your *effective hashrate* is your real hashrate times the number of announcements which you have
in memory, times the work of the least valuable announcement which you have. Effective hashrate
is the best predictor of your chance of winning a share.

        pcblk: 8565h real hashrate - 300Mh effective hashrate


### What does the BlockMiner_lockForMining log line mean ?

When you are mining, you will periodically see a log line such as the following:

        pcblk: BlockMiner_lockForMining(): ng: 8809 ne: 0 nne: 0 og: 0 oe: 0 or: 0 finalCount: 8763 minTarget: 203fffff

Each number explains something about the announcements which you have collected for mining:

* **ng**: "new good" this is the number of announcements which the block miner didn't know about
until this block and they seem to be valid.
* **ne**: "new expired" this is the number of announcements which the block miner didn't know about
until this block, but they do not have enough work to be usable for mining. Since announcements age
out over time, they might have been good before but they have since *expired*.
* **nne**: "new not enough" these are new announcements which are usable but were not included because
they did not fit within the space specified in **maxAnns**. Since announcements are sorted by work and
the highest work announcements are selected, these are the ones with "not enough" work.
* **og**: "old good" these are announcements which the block miner knew about since before and which are
still good enough to continue mining with (they have not expired).
* **oe**: "old expired" this is the number of announcements which the miner already knew about and which
are nolonger usable for mining a block, they have *expired*.
* **or**: "old replaced" this is the number of announcements which were replaced in order to fit within
the number of announcements specified in **maxAnns**. Whether old announcements are displaced (increasing
**or**) or new announcements are dropped (increasing **nne** depends on which ones have higher value).
* **finalCount**: This is the number of announcements which have finally been accepted by the block miner.
This number is **ng** plus **og** deduplicated. Since PacketCrypt considers 2 announcements to be "duplicates"
if only 64 bits of the hashes collide, you can expect to see significant duplicates.


### The miner is not using as much memory as I allocated, what's wrong ?

The memory needs to be populated with valid announcements which are downloaded from your pool, this will
take time so you may not populate the amount of memory which you specify for a while.

# pool - the PacketCrypt mining pool coordinator

Pool consists of everything needed to support miners of PacketCrypt announcements as well as blocks.

## How it works

In order to take advantage of commodity high performance caching web servers, pool operates entirely
on top of http. There are 3 component classes: **Master**, **AnnHandler**, **BlkHandler**, and
**PayMaker**. There can only be one **Master** and **PayMaker** but there can be as many **AnnHandler**
and **BlkHandler** nodes as you want.

## Master

The **Master** must have a connection to pktd in order to get the block headers and transactions for
making a work object. As there is only one **Master**, scalability requires that it must not do much
work. Miners can only make `GET` requests to the **Master** for work items which are the same for
everyone, and thus cachable.

### Http Endpoints

* `GET /config.json`: get global configuration for the pool (honor cache headers)
* `GET /work_<n>.bin`: get a work entry (can cache forever)
* `GET /work_<n+1>.bin`: longpoll (can cache forever once it returns an HTTP 200)
* `GET /blkinfo_<hash>.json`: Get information about a block based on it's hash (can cache forever)

## AnnHandler

This node processes announcements which are posted to it by the announcement miner and then makes the
announcements available for block miners to download. You can run as many of them as you want, but
note that every announcement miner will post files to all of them so there will be additional network
traffic.

**NOTE**: The AnnHandler is located in [packetcrypt_rs](https://github.com/cjdelisle/packetcrypt_rs)
repository.

### Http Endpoints

* `POST /submit`: upload an announcement (don't cache)
* `GET /anns/index.json`: number of the highest numbered ann file (honor cache headers)
* `GET /anns/anns_<name>.bin`: batches of announcements, name is in index (can cache forever)


## BlkHandler
Like **AnnHandler**, the **BlkHandler** processes shares from block miners. When **BlkHandler**
discovers a share which it thinks is good enough for a valid block, it will submit it as a block.
The **BlkHandler** connects to a pktd instance in order to verify shares and to submit blocks.

### Http Endpoints

* `POST /submit`: upload a share

## PayMaker
The **PayMaker** also connects to the pktd instance and it tells the pktd instance which addresses
should be paid by the next block template. The **PayMaker** takes http posts from the **AnnHandler**
and the **BlkHandler** and with information about announcements and block shares which were recently
found by the miners.

### Http Endpoints

* `POST /events`: Upload a log of announcements or blocks which were found (protected by http
password because anyone who can post to this can make the pool pay them arbitrary amounts of PKT)
* `GET /stats`: Get some basic stats about memory usage on the **PayMaker**
* `GET /whotopay`: Get information about the miners and who will get what percentage of the next block

## Configuring the pool
Every part of the pool is configured in the same file so there is only one section on configuration.
The configuration is inside of pool.js, you might want to copy this to another filename so you can
pull the git repository without overwriting it.

* **masterUrl**: Every component of the pool needs to know the URL of the master in order to get the
updated configuration from it. This should be the public URL which clients will use.
* **rootWorkdir**: This is the location where the particular worker (**Master**, **PayMaker** or
**BlkHandler**) will store it's data, it can be different for each node in the pool.
* **annHandlers**: These need to be specified in the pool so that the miners know where to find them,
but they need to be configured separately using [packetcrypt_rs](https://github.com/cjdelisle/packetcrypt_rs).
* **blkHandlers**: These are arrays of block handlers in the
pool, this is used both on the **Master** and on the **BlkHandler** nodes themselves.
  * **url**: This is the public URL of the **BlkHandler** node, used by the
  **Master** to direct miners to the appropriate **BlkHandler** nodes and also
  used by the individual nodes to identify themselves in the **Master** configuration.
  * **port**: This is the port which will be bound internally by the **BlkHandler** node
  * **root**: The global config, so that it is accessible to the **AnnHandler** code, leave this
  alone.
* **master**: This is the configuration for the master node
  * **port**: The port number to bind internally
  * **rpc**: Configuration for connecting to btcd, see [bitcoin-rpc](https://www.npmjs.com/package/bitcoind-rpc)
  * **annMinWork** and **shareMinWork**: These are the minimum amounts of work to makes a valid
  announcement and share respectively, this is read on the **Master** node only, you can change
  this and restart the **Master** and all other nodes and miners will live update.
  * **config**: A reference to the global config, leave this alone.

## Starting a pool

First, you'll need to follow the [install process](https://github.com/cjdelisle/PacketCrypt/#install)
then once you have successfully installed the executables, you can start launching processes:

Then edit pool.js and setup your configuration, this is where you'll decide how many **AnnHandler**
and **BlkHandler** nodes you should run. Note that AnnHandler is part of packetcrypt_rs and needs
to be launched separately.

Launch the master:

        node ./pool.js --master

Launch the **BlkHandler** nodes, specify `--blk0` for the first **BlkHandler**, `--blk1` for the
second, and so forth.

        node ./pool.js --blk0

The **PayMaker** and **BlkHandler** nodes will connect back to the **Master** (using the public
URL) and will begin accepting requests from miners.

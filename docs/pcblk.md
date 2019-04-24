# pcblk - the PacketCrypt block miner core

**NOTE**: You probably don't want to use this directly, there is a more friendly wrapper called
[blkmine](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/blkmine.md) which uses this.

pcblk arguments:

* **maxanns** (optional): Limit the number of announcements which will be processed, some memory is allocated
spontaniously so it's difficult to make strong statements about total memory consumption but memory usage should
target nearly this many kilobytes.
* **threads** (optional): Allocate *n* threads for processing, default is 1
* **minerId**: This is a 32 bit unsigned number which is used in the block header nonce. If there
are multiple miners mining the exact same set of announcements, this will prevent them from finding
duplicate shares. Default is 0.
* `<wrkdir>` (required): Directory to scan for work inputs and to place results

Most of the interaction with pcblk is done by writing and reading files.
When you launch pcblk, it takes 1 mandatory argument, a work directory, this must be a path which pcblk can write to.

Inside of the work directory, pcann will search for numbered subdirectories, and inside of these numbered
subdirectories shall be files containing announcements. The names of the subdirectories must be an incrementing
number but the names of the announcement files can be anything.

```
* workdir/
  * 512/
    * ann1.bin
    * ann2.xxx
  * 513/
    * ann1.bin
    * ...
```

Pcann uses the numberes of the numbered directories to know which directories have already been examined so they
must be in numbered order, for example creating a directory called 56879302 will cause all numbers below 56879302
to be ignored forever.

After loading announcements, pcblk look for a file called `workdir/work.bin`, if this file is found, it will be
read and deleted and it's content will be interpreted as a work job coming from the mining pool
(see [js/Protocol.js](https://github.com/cjdelisle/PacketCrypt/blob/master/js/Protocol.js) for the description of
this data structure.

At this point, if there are elligable announcements in the workdir numbered folders, pcblk will begin mining.

When pcblk finds a share (difficulty defined by `work.bin`) it will write this to a file called `shares_0.bin`
in the workdir. If the caller would like to submit the shares with minimal chance of a race condition, they can
signal pcblk with a SIGHUP and it will open a new file called `shares_1.bin` the first time, `shares_2.bin` the
second time and so on. When a new `shares_<n>.bin` file is created, it is created write-only, it is chmod'd
to read/write only after it becomes safe to upload the old file.

**CAUTION**: If `shares_<n>.bin` files are already existing when pcblk attempts to create them, it will crash.
It is the caller's responsibility to delete them after they have been handled.

**NOTE**: pcblk will only scan an announcements directory once, if it contains announcements which are too *new*
to be included in the next block, they will be discarded and not scanned again. It is the caller's responsibilty
to only place announcement directories in pcblk's workdir *after* the announcements are elligable for inclusion
in the next block. However, pcblk will not discard announcements *while* mining, it will only do so when it is
preparing to mine a new block, so you can supply it with announcements which are too new for the block which is
currently being mined, as long as they are ok for the next work that pcblk will receive.

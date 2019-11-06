# annmine - the PacketCrypt announcement miner

This is the miner which you'll want to use to mine announcements.
The miner uses
[pcann](https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcann.md)
internally to do the mining but uses nodejs code to handle the uploads
and downloads to/from the mining pool.

When you start up annmine, the only thing you *need* is a path to a mining pool server,
but you have 4 optional arguments which you can pass:

* **paymentAddr**: This is a string which will be submitted to the pool with your work,
technically it can be anything that your pool is able to understand. If you do not specify
one then
[pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2](https://pkt-cash.github.io/www.pkt.cash/steward/)
and you will receive a warning when starting up annmine.
* **threads**: This is the number of threads to dedicate to mining, it's an optional argument
but it is recommended that you pass it because the default number is 1.
* **minerId**: This is a 32 bit unsigned number which is used in the announcement hard_nonce.
If there are multiple miners searching for announcements with the same content, this will
prevent them from finding duplicate shares. By default annmine uses a random number.
* **corePath**: This is the path to the `pcann` executable, the default value is `./bin/pcann`
which is ok if you're using annmine in the PacketCrypt git repository.
* **dir**: This is a path to a directory which annmine will use for temporary files.
If this directory doesn't exist then it will be created but make sure the user which
annmine is running under is able to create it. You can safely delete this directory any
time that annmine is not running.
* **contentType**: An integer for the type of content, to the PoW this is opaque but it can
be used for communicating through announcements.
* **content**: A string representation of the content for the announcement.
* **contentFile**: A path to a file which contains the content to be packaged with the
announcement. Mutually exclusive with `--content`
* **randContent**: Generate random content for each announcement that is mined, this exists
for testing of the announcement content handling. Mutually exclusive with `--content` and
`--contentFile`.

## Example:
Mining with 4 threads and a 10Mb/s bandwidth limit.

```
$ node ./annmine.js --threads 4 --maxKbps 100000 --paymentAddr pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2 http://my.favorite.mining.pool/
```

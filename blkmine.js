/*@flow*/
const Spawn = require('child_process').spawn;
const Fs = require('fs');
const nThen = require('nthen');
const Blake2b = require('blake2b');
const Minimist = require('minimist');

const Pool = require('./js/PoolClient.js');
const Util = require('./js/Util.js');

const DEFAULT_MAX_ANNS = 1024*1024;

/*::
import type { FSWatcher } from 'fs';
import type { ChildProcess } from 'child_process';
import type { ClientRequest, IncomingMessage } from 'http';
import type { PoolClient_t } from './js/PoolClient.js';
import type { Protocol_PcConfigJson_t } from './js/Protocol.js';
import type { Util_Mutex_t } from './js/Util.js';
import type { Config_Miner_t } from './js/Config.js'

type Context_t = {
    config: Config_Miner_t,
    miner: void|ChildProcess,
    pool: PoolClient_t,
    masterConf: Protocol_PcConfigJson_t,
    shareFileMutex: Util_Mutex_t,
    uploadReqs: Array<ClientRequest>,
    resultQueue: Array<string>,
    handledShares: { [string]:boolean }
};
*/

const getAnnFileParentNum = (filePath, _cb) => {
    const cb = Util.once(_cb);
    const stream = Fs.createReadStream(filePath, { end: 16 });
    const data = [];
    stream.on('data', (d) => { data.push(d); });
    stream.on('end', () => {
        const buf = Buffer.concat(data);
        if (buf.length < 16) { return void cb(new Error("Could not read file [" + filePath + "]")); }
        const blockNo = buf.readUInt32LE(12);
        console.log("Got announcements with parent block number [" + blockNo + "]");
        cb(undefined, blockNo);
    });
    stream.on('error', (err) => {
        cb(err);
    });
};

/*::
type DownloadAnnResult_t = {
    annPath: string,
    wrkPath: string,
};
type DownloadAnnError_t = Error | {statusCode:number} | {code:string,annPath:string};
*/

const downloadAnnFile = (
    wrkdir /*:string*/,
    serverUrl /*:string*/,
    serverId /*:string*/,
    fileNo /*:number*/,
    cb /*:(?DownloadAnnError_t, ?DownloadAnnResult_t)=>true|void*/
) => {
    const url = serverUrl + '/anns/anns_' + fileNo + '.bin';
    const fileSuffix = '_' + serverId + '_' + fileNo + '.bin';
    const annPath = wrkdir + '/anndir/anns' + fileSuffix;
    nThen((w) => {
        Fs.stat(annPath, w((err, st) => {
            if (err && err.code === 'ENOENT') { return; }
            if (err) { throw err; }
            w.abort();
            return void cb({ code: 'EEXIST', annPath: annPath });
        }));
    }).nThen((_) => {
        console.log("Get announcements [" + url + "] -> [" + annPath + "]");
        let wrkPath;
        Util.httpGetStream(url, (err, res) => {
            if (!res) {
                if (!err) { err = new Error("unknown error"); }
                return cb(err);
            }
            let parentBlockNum;
            nThen((w) => {
                res.pipe(Fs.createWriteStream(annPath)).on('finish', w());
            }).nThen((w) => {
                getAnnFileParentNum(annPath, w((err, pbn) => {
                    if (typeof(pbn) === 'undefined') {
                        // filesystem error, we probably want to bail out...
                        throw err;
                    }
                    parentBlockNum = pbn;
                }));
            }).nThen((w) => {
                wrkPath = wrkdir + '/wrkdir/anns_' + parentBlockNum + fileSuffix;
                Fs.link(annPath, wrkPath, w((err) => {
                    if (err) { throw err; }
                }));
            }).nThen((w) => {
                cb(undefined, {
                    annPath: annPath,
                    wrkPath: wrkPath
                });
            });
        });
    });
};

/*
if (searchBackward && err.statusCode === 404) {
    console.log("Backward search on server [" + server + "] complete");
    return;
}
console.log("Unable to get ann file at [" + url + "] [" + String(err) + "]");
return true;
*/

const getAnnFileNum = (
    server /*:string*/,
    then /*:(annFileNum:number)=>void*/
) => {
    const url = server + '/anns/index.json';
    Util.httpGetStr(url, (err, res) => {
        if (!res) {
            console.log("Unable to contact AnnHandler at [" + url + "] [" + String(err) + "]");
            return true;
        }
        let num = NaN;
        try {
            const obj = JSON.parse(res);
            num = Number(obj.highestAnnFile);
        } catch (e) { }
        if (isNaN(num)) {
            console.log("in response from [" + url + "] could not parse [" + res + "]");
            return true;
        }
        if (num < 0) {
            console.log("Ann server doesn't have any anns yet, trying again in 10 seconds");
            return void setTimeout(() => { getAnnFileNum(server, then); }, 10000);
        }
        then(num);
    });
};

const deleteWorkAndShares = (config /*:Config_Miner_t*/, _cb) => {
    const cb = Util.once(_cb);
    let files;
    nThen((w) => {
        Fs.readdir(config.dir + '/wrkdir', w((err, f) => {
            if (err) {
                w.abort();
                return void cb(err);
            }
            files = f;
        }));
    }).nThen((w) => {
        let nt = nThen;
        files.forEach((f) => {
            if (!/^shares_[0-9]+\.bin$/.test(f) && !/^work\.bin$/.test(f)) { return; }
            nt = nt((w) => {
                Fs.unlink(config.dir + '/wrkdir/' + f, w((err) => {
                    if (err) {
                        w.abort();
                        return void cb(err);
                    }
                }));
            }).nThen;
        });
        nt(w());
    }).nThen((w) => {
        cb();
    });
};

const onNewWork = (ctx /*:Context_t*/, work, done) => {
    nThen((w) => {
        // Kill all uploads because they're all stale shares now
        ctx.uploadReqs.forEach((req) => { req.abort(); });
        ctx.uploadReqs.length = 0;

        // Delete share/work files because there is no chance of them being useful
        deleteWorkAndShares(ctx.config, w((err) => {
            if (err && err.code !== 'ENOENT') {
                throw err;
            }
        }));
    }).nThen((w) => {
        console.log("Writing work.bin");
        Fs.writeFile(ctx.config.dir + '/wrkdir/_work.bin', work.binary, w((err) => {
            if (err) { throw err; }
            Fs.rename(
                ctx.config.dir + '/wrkdir/_work.bin',
                ctx.config.dir + '/wrkdir/work.bin',
                w((err) =>
            {
                if (err) { throw err; }
            }));
        }));
    }).nThen((_w) => {
        if (!ctx.miner) { return; }
        ctx.miner.kill('SIGHUP');
        done();
    });
};

/*
typedef struct {
    uint32_t magic;

    // The target representing the least work of any of the announcements in the set
    uint32_t annLeastWorkTarget;

    uint8_t merkleRoot[32];
    uint64_t numAnns;
} PacketCrypt_Coinbase_t;
_Static_assert(sizeof(PacketCrypt_Coinbase_t) == 32+8+4+4, "");
typedef struct {
    PacketCrypt_BlockHeader_t blockHeader;
    uint32_t nonce2;
    uint32_t proofLen; <-- offset 48+84
    PacketCrypt_Announce_t announcements[PacketCrypt_NUM_ANNS]; <-- length without proof: 48+88+1024*4
    uint8_t proof[];
} PacketCrypt_HeaderAndProof_t;
*/

// In case more than one share are in the same file, we need to split them.
const splitShares = (buf /*:Buffer*/) /*:Array<Buffer>*/ => {
    // First we need to get the length of an individual header-and-proof from the buf,
    // then we slice off the first <len> bytes and then repeat.
    if (buf.length === 0) { return []; }
    const proofLen = buf.readUInt32LE(48+84);
    const shareLen = 48 + 88 + (1024 * 4) + proofLen;
    if (buf.length < shareLen) {
        console.log("WARNING: short share entry of length [" + buf.length + "]");
        return [];
    }
    if (buf.length === shareLen) { return [ buf ]; }
    const out = [ buf.slice(0, shareLen) ];
    const more = splitShares(buf.slice(shareLen));
    more.forEach((x) => { out.push(x); });
    return out;
};

const checkResultLoop = (ctx /*:Context_t*/) => {
    const again = () => {
        if (!ctx.resultQueue.length) { return void setTimeout(again, 5000); }
        const url = ctx.resultQueue.shift();
        Util.httpGetStr(url, (err, res) => {
            if (!res) {
                if (!err) {
                    console.error("Empty result from pool, retrying");
                    return true;
                }
                const e /*:any*/ = err;
                // 404s are normal because we're polling waiting for the file to exist
                if (typeof(e.statusCode) !== 'number' || e.statusCode !== 404) {
                    console.error("Got error from pool [" + JSON.stringify(e) + "]");
                }
                return true;
            }
            try {
                const obj = JSON.parse(res);
                if (obj.result !== 'Output_ACCEPT') {
                    console.log("SHARE REJECTED: [" + res + "]");
                } else {
                    console.log("SHARE: [" + res + "]");
                    if (obj.payTo !== ctx.config.paymentAddr) {
                        console.log("WARNING: pool is paying [" + obj.payTo + "] but configured " +
                            "payment address is [" + ctx.config.paymentAddr + "]");
                    }
                }
            } catch (e) {
                console.log("WARNING: unable to parse json: [" + res + "]");
            }
            again();
        });
    };
    again();
};

const httpRes = (ctx /*:Context_t*/, res /*:IncomingMessage*/) => {
    const data = [];
    res.on('data', (d) => { data.push(d.toString('utf8')); });
    res.on('end', () => {
        if (res.statusCode !== 200) {
            if (res.statusCode === 400) {
                console.error("Pool replied with error 400 " + data.join('') + ", stopping");
                process.exit(100);
            }
            console.error("WARNING: Pool replied with [" + res.statusMessage +
                "] [" + data.join('') + "]");
            return;
        }
        const d = data.join('');
        let result;
        try {
            const o = JSON.parse(d);
            result = o.result;
            if (o.error.length > 0) {
                console.error("WARNING: Pool error [" + JSON.stringify(o.error) + "]");
                // we do not proceed
                return;
            }
            if (o.warn.length > 0) {
                console.error("WARNING: Pool is warning us [" + JSON.stringify(o.warn) + "]");
            }
            result = o.result;
        } catch (e) {
            console.error("WARNING: Pool reply is invalid [" + d + "]");
            return;
        }
        if (typeof(result) !== 'string') {
            console.error("WARNING: Pool replied without a result [" + d + "]");
            return;
        }
        console.error("Upload complete [" + data.join('') + "]");
        ctx.resultQueue.push(result);
    });
};

const uploadFile = (ctx /*:Context_t*/, filePath /*:string*/, cb /*:()=>void*/) => {
    let fileBuf;
    nThen((w) => {
        //console.log("uploadShares2 " + filePath);
        Fs.readFile(filePath, w((err, ret) => {
            if (err) {
                // could be ENOENT if the file was deleted in the mean time because
                // new work arrived.
                if (err.code === 'ENOENT') {
                    console.log("Shares [" + filePath + "] disappeared");
                    return;
                }
                throw err;
            }
            if (ret.length > 0) {
                console.log("Uploading shares [" + filePath + "]");
                fileBuf = ret;
            }
        }));
    }).nThen((w) => {
        if (!fileBuf) { return; }
        if (ctx.miner) { ctx.miner.kill('SIGHUP'); }
        ctx.handledShares[filePath] = true;
        splitShares(fileBuf).forEach((share, i) => {
            const hash = Blake2b(64).update(share).digest(Buffer.alloc(64));
            const handlerNum = hash.readUInt16LE(0) % ctx.masterConf.submitBlockUrls.length;
            const url = ctx.masterConf.submitBlockUrls[handlerNum];
            //console.log(share.toString('hex'));
            console.log("Uploading share [" + filePath + "] [" + i + "] to [" + url + "]");
            const req = Util.httpPost(url, {
                'Content-Type': 'application/octet-stream',
                'x-pc-payto': ctx.config.paymentAddr
            }, (res) => {
                httpRes(ctx, res);
            });
            ctx.uploadReqs.push(req);
            req.end(share);
        });
    }).nThen((w) => {
        cb();
    });
};

const checkShares = (ctx /*:Context_t*/) => {
    ctx.shareFileMutex((done) => {
        let files;
        let nums;
        nThen((w) => {
            Fs.readdir(ctx.config.dir + '/wrkdir', w((err, f) => {
                if (err) { throw err; }
                files = f;
            }));
        }).nThen((w) => {
            nums = files.map((f) => {
                let num = NaN;
                f.replace(/^shares_([0-9]+)\.bin$/, (all, n) => {
                    num = Number(n);
                    return '';
                });
                return num;
            }).filter((n) => (!isNaN(n)));
            nums.sort((x,y) => ( (x > y) ? -1 : (x === y) ? 0 : 1 ));

            let nt = nThen;
            nums.forEach((n, i) => {
                const filePath = ctx.config.dir + '/wrkdir/shares_' + n + '.bin';
                nt = nt((w) => {
                    if (i > 0 && ctx.handledShares[filePath]) {
                        Fs.unlink(filePath, w((err) => {
                            if (err && err.code !== 'ENOENT') {
                                console.log("WARNING: failed to delete file [" + filePath + "]");
                                return;
                            }
                            delete ctx.handledShares[filePath];
                        }));
                        return;
                    }
                    Fs.stat(filePath, w((err, ret) => {
                        // file was deleted, new work
                        if (err && err.code === 'ENOENT') { return; }
                        if (err) { throw err; }
                        if ((ret.mode & 0600) !== 0600) {
                            // If the file is non-readable, this indicates that we're
                            // in a race window between an open and a dup2
                        } else if (ret.size > 0) {
                            uploadFile(ctx, filePath, w());
                        } else if (i > 0) {
                            ctx.handledShares[filePath] = true;
                        }
                    }));
                }).nThen;
            });
            nt(w());
        }).nThen((_) => {
            done();
        });
    });
};

const deleteUselessAnns = (config, height, done) => {
    Util.deleteUselessAnns(config.dir + '/anndir', height, (f, done2) => {
        console.log("Deleted expired announcements [" + f + "]");
        const path = config.dir + '/anndir/' + f;
        Fs.unlink(path, (err) => {
            done2();
            if (!err) { return; }
            console.log("Failed to delete [" + path + "] [" + err.message + "]");
        });
    }, done);
};

const mkLinks = (config, done) => {
    Fs.readdir(config.dir + '/anndir', (err, files) => {
        if (err) { throw err; }
        let nt = nThen;
        files.forEach((f) => {
            nt = nt((w) => {
                Fs.link(
                    config.dir + '/anndir/' + f,
                    config.dir + '/wrkdir/' + f,
                    w((err) =>
                {
                    if (err && err.code !== 'EEXIST') { throw err; }
                }));
            }).nThen;
        });
        nt(() => {
            done();
        });
    });
};

const mkMiner = (ctx) => {
    const args = [
        '--threads', String(ctx.config.threads || 1),
        '--maxanns', String(ctx.config.maxAnns || 1024*1024),
        '--minerId', String(ctx.config.minerId),
        ctx.config.dir + '/wrkdir'
    ];
    console.log(ctx.config.corePath + ' ' + args.join(' '));
    const miner = Spawn(ctx.config.corePath, args, {
        stdio: [ 'pipe', 1, 2 ]
    });
    miner.on('close', (num, sig) => {
        console.log("pcblk died [" + num + "] [" + sig + "], restarting in 5 seconds");
        nThen((w) => {
            setTimeout(w(), 5000);
        }).nThen((w) => {
            deleteWorkAndShares(ctx.config, w());
        }).nThen((w) => {
            mkLinks(ctx.config, w());
            if (ctx.work && ctx.pool.connected) { onNewWork(ctx, ctx.work, w()); }
        }).nThen((w) => {
            mkMiner(ctx);
        });
    });
    ctx.miner = miner;
};

const downloadOldAnns = (config, masterConf, done) => {
    let nt = nThen;
    console.log("Downloading announcements to fill memory");

    const serverCurrentNum = [];
    masterConf.downloadAnnUrls.forEach((server, i) => {
        nt = nt((w) => {
            getAnnFileNum(server, w((num) => {
                serverCurrentNum[i] = { server: server, currentAnnNum: num };
            }));
        }).nThen;
    });
    // we need to cycle around between AnnHandlers because if we only get
    // announcements from one, we will get worse quality (older) announcements
    // and then possibly fill up our memory limit while there are newer announcements
    // which are skipped because they're on other AnnHandlers.

    // When these are equal, we quit because we have enough announcements
    let totalLen = 0;
    const maxLen = (config.maxAnns || DEFAULT_MAX_ANNS) * 1024;

    // This is deincremented as each server nolonger has any more announcements for us
    let activeServers;
    const again = (i) => {
        if (!activeServers) {
            console.log("No more announcements available on any server, done");
            return void done();
        }
        if (totalLen >= maxLen) {
            console.log("Downloaded enough announcements to fill available memory, done");
            return void done();
        }
        if (i > serverCurrentNum.length) { i = 0; }
        if (!serverCurrentNum[i]) { return void again(i + 1); }
        const as = serverCurrentNum[i];
        downloadAnnFile(config.dir, as.server, String(i), as.currentAnnNum, (err, res) => {
            if (res) {
                return void Fs.stat(res.annPath, (err, st) => {
                    if (err) { throw err; }
                    totalLen += st.size;
                    as.currentAnnNum--;
                    return void again(i + 1);
                });
            }
            if (err && err.code === 'EEXIST') {
                // We already have this file, search for the previous...
                as.currentAnnNum--;
                return void again(i + 1);
            }
            if (err && err.statusCode === 404) {
                console.log("Reached the end of useful announcements on [" + as.server + "]");
                serverCurrentNum[i] = undefined;
                activeServers--;
                return void again(i + 1);
            }
            console.log("Requesting ann file [" + as.currentAnnNum + "] from [" + as.server + "]" +
                "got [" + JSON.stringify(err || null) + "] retrying...");
            return true;
        });
    };

    nt((_) => {
        activeServers = serverCurrentNum.length;
        again(0);
    });
};

const pollAnnHandlers = (ctx) => {
    const again = (server, i, num) => {
        downloadAnnFile(ctx.config.dir, server, String(i), num, (err, res) => {
            if (res) {
                return void again(server, i, num + 1);
            }
            if (err && err.code === 'EEXIST' && err.annPath) {
                // Lets just continue looking for newer files
                return void again(server, i, num + 1);
                // const path = String(err.annPath);
                // throw new Error("Failed to download ann file to [" + path +
                //     "] file already exists, please delete it and restart");
            }
            console.log("Requesting ann file [" + num + "] from [" + server + "]" +
                "got [" + JSON.stringify(err || null) + "] retrying...");
            return true;
        });
    };
    ctx.masterConf.downloadAnnUrls.forEach((server, i) => {
        getAnnFileNum(server, (num) => { again(server, i, num+1); });
    });
};

const launch = (config /*:Config_Miner_t*/) => {
    if (config.paymentAddr.length > 64) {
        throw new Error("Illegal payment address (over 64 bytes long)");
    }
    const pool = Pool.create(config.poolUrl);
    let masterConf;
    nThen((w) => {
        pool.getMasterConf(w((conf) => { masterConf = conf; }));
        Util.checkMkdir(config.dir + '/wrkdir', w());
        Util.checkMkdir(config.dir + '/anndir', w());
        Util.clearDir(config.dir + '/wrkdir', w());
    }).nThen((w) => {
        mkLinks(config, w());
        pool.onWork(Util.once(w((work) => {
            deleteUselessAnns(config, work.height, w(()=>{}));
        })));
    }).nThen((w) => {
        downloadOldAnns(config, masterConf, w());
    }).nThen((_) => {
        const ctx = {
            config: config,
            miner: undefined,
            pool: pool,
            masterConf: masterConf,
            shareFileMutex: Util.createMutex(),
            work: undefined,
            uploadReqs: [],
            resultQueue: [],
            handledShares: {}
        };
        mkMiner(ctx);
        console.log("Got [" + masterConf.downloadAnnUrls.length + "] AnnHandlers");
        pollAnnHandlers(ctx);
        pool.onWork((work) => {
            ctx.work = work;
            onNewWork(ctx, work, ()=>{});
            deleteUselessAnns(config, work.height, ()=>{});
        });
        setInterval(() => { checkShares(ctx); }, 100);
        checkResultLoop(ctx);
    });
};

const usage = () => {
    console.log("Usage: node blkmine.js OPTIONS <poolurl>\n" +
        "    OPTIONS:\n" +
        "        --paymentAddr # the bitcoin address to request payment from the pool\n" +
        "                      # when submitting shares\n" +
        "        --threads     # number of threads to use for mining\n" +
        "        --maxAnns     # maximum number of announcements to use\n" +
        "                      # more announcements gives you better chance of a share\n" +
        "                      # but it increases your memory consumption\n" +
        "                      # default is 1 million (roughly 1GB of memory needed)\n" +
        "        --minerId     # the number of the miner in order to avoid duplicates\n" +
        "                      # when multiple miners are mining the exact same set of\n" +
        "                      # announcements.\n" +
        "        --corePath    # if specified, this will be the path to the core engine\n" +
        "                      # default is ./bin/pcblk\n" +
        "        --dir         # the directory to use for storing announcements and state\n" +
        "                      # default is ./datastore/blkmine\n" +
        "    <poolurl>         # the URL of the mining pool to connect to\n" +
        "\n" +
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/blkmine.md\n" +
        "    for more information");
    return 100;
};

const DEFAULT_PAYMENT_ADDR = "bc1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4st4nj3u";

const main = (argv) => {
    const defaultConf = {
        corePath: './bin/pcblk',
        dir: './datastore/blkmine',
        paymentAddr: DEFAULT_PAYMENT_ADDR,
        maxAnns: DEFAULT_MAX_ANNS,
        threads: 1,
        minerId: Math.floor(Math.random()*(1<<30)*2)
    };
    const a = Minimist(argv.slice(2));
    if (!/http(s)?:\/\/.*/.test(a._[0])) { process.exit(usage()); }
    const conf = {
        corePath: a.corePath || defaultConf.corePath,
        dir: a.dir || defaultConf.dir,
        paymentAddr: a.paymentAddr || defaultConf.paymentAddr,
        poolUrl: a._[0],
        maxAnns: a.maxAnns || defaultConf.maxAnns,
        threads: a.threads || defaultConf.threads,
        minerId: a.minerId || defaultConf.minerId
    };
    if (!a.paymentAddr) {
        console.log("WARNING: You have not specified a paymentAddr\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    launch(Object.freeze(conf));
};
main(process.argv);

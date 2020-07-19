/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Spawn = require('child_process').spawn;
const Fork = require('child_process').fork;
const Fs = require('fs');
const nThen = require('nthen');
const Minimist = require('minimist');
const Saferphore /*:any*/ = require('saferphore'); // flow doesn't like how saferphore exports

const Pool = require('./js/PoolClient.js');
const Util = require('./js/Util.js');
const Protocol = require('./js/Protocol.js');

const DEFAULT_MAX_ANNS = 1024*1024;

/*::
import type { FSWatcher } from 'fs';
import type { ChildProcess } from 'child_process';
import type { ClientRequest, IncomingMessage } from 'http';
import type { PoolClient_t } from './js/PoolClient.js';
import type { Protocol_PcConfigJson_t } from './js/Protocol.js';
import type { Util_Mutex_t } from './js/Util.js';
import type { Config_BlkMiner_t } from './js/Config.js'

const _flow_typeof_saferphore = Saferphore.create(1);
type Saferphore_t = typeof _flow_typeof_saferphore;

type Context_t = {
    config: Config_BlkMiner_t,
    miner: void|ChildProcess,
    pool: PoolClient_t,
    lock: Saferphore_t,
    lock2: Saferphore_t,
    newWorkLock: Saferphore_t,
    minerLastSignaled: number,
    stats: {
        [string]: {
            downloaded: number,
            downloading: number,
            todo: number,
        },
    }
};
*/

const debug = (...args) => {
    console.error('blkmine:', ...args);
};



const getAnnFileNum = (
    server /*:string*/,
    then /*:(number, ?Array<string>)=>void*/
) => {
    const url = server + '/anns/index.json';
    Util.httpGetStr(url, (err, res) => {
        if (!res) {
            debug("Unable to contact AnnHandler at [" + url + "] [" + String(err) + "]");
            return true;
        }
        let num = NaN;
        let urls;
        try {
            const obj = JSON.parse(res);
            num = Number(obj.highestAnnFile);
            const files = obj.files;
            if (files) { urls = files.map((u) => server + '/anns/' + u); }
        } catch (e) { }
        if (isNaN(num)) {
            debug("in response from [" + url + "] could not parse [" + res + "]");
            return true;
        }
        if (num < 0) {
            debug("Ann server doesn't have any anns yet, trying again in 10 seconds");
            return void setTimeout(() => { getAnnFileNum(server, then); }, 10000);
        }
        then(num, urls);
    });
};

const deleteWorkAndShares = (config /*:Config_BlkMiner_t*/, _cb) => {
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

const sigMiner = (ctx /*:Context_t*/) => {
    const now = +new Date();
    const diff = now - ctx.minerLastSignaled;
    if (diff < 1000) { return false; }
    const b = Buffer.from("01000000", "hex");
    if (ctx.miner) { ctx.miner.stdin.write(b); }
    return true;
};

const onNewWork = (ctx /*:Context_t*/, work, done) => {
    ctx.newWorkLock.take((ra) => {
        done = ra(done);
        nThen((w) => {
            debug("Writing work.bin");
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
        }).nThen((w) => {
            if (!ctx.miner) { return; }
            // It's important that if there's new work, the miner does woken up...
            const s = () => {
                if (!sigMiner(ctx)) { setTimeout(w(s), 50); }
            };
            s();
        }).nThen((_) => {
            done();
        });
    });
};

/*
typedef struct BlockMiner_Share_s {
    uint32_t length;
    uint32_t _pad;
    PacketCrypt_Coinbase_t coinbase;
    PacketCrypt_HeaderAndProof_t hap;
} BlockMiner_Share_t;

typedef struct {
    uint32_t magic;

    // The target representing the least work of any of the announcements in the set
    uint32_t annLeastWorkTarget;

    uint8_t merkleRoot[32];
    uint64_t numAnns;
} PacketCrypt_Coinbase_t;
_Static_assert(sizeof(PacketCrypt_Coinbase_t) == 48, "");
typedef struct {
    PacketCrypt_BlockHeader_t blockHeader;
    uint32_t _pad;
    uint32_t nonce2; <-- offset 8+48+80+4
    PacketCrypt_Announce_t announcements[PacketCrypt_NUM_ANNS]; <-- length without proof: 8+48+80+4+4+1024*4
    uint8_t proof[];
} PacketCrypt_HeaderAndProof_t;
*/

// In case more than one share are in the same file, we need to split them.
const splitShares = (buf /*:Buffer*/) /*:Array<Buffer>*/ => {
    // First we need to get the length of an individual header-and-proof from the buf,
    // then we slice off the first <len> bytes and then repeat.
    if (buf.length === 0) { return []; }
    const shareLen = buf.readUInt32LE(0);
    const out = [ buf.slice(8, shareLen) ];
    const more = splitShares(buf.slice(shareLen));
    more.forEach((x) => { out.push(x); });
    return out;
};

/*::
type Share_t = {
    contentProofIdx: number,
    toSubmit: {
        coinbase_commit: string,
        header_and_proof: string,
    }
};
*/

// This converts the format of the share which is output from pcblk to the
// format expected by BlkHandler
const convertShare = (
    buf /*:Buffer*/,
    version /*:number*/
) /*:Share_t*/ => {
    const coinbase = buf.slice(0, Protocol.COINBASE_COMMIT_LEN).toString('hex');
    buf = buf.slice(Protocol.COINBASE_COMMIT_LEN);
    const header = buf.slice(0, 80);
    const proof = buf.slice(84);

    const versionBuf = Util.mkVarInt(version);
    const submission = [
        header,
        Util.mkVarInt(Protocol.PC_PCP_TYPE),
        Util.mkVarInt(proof.length),
        proof,
        Util.mkVarInt(Protocol.PC_VERSION_TYPE),
        Util.mkVarInt(versionBuf.length),
        versionBuf
    ];

    return {
        contentProofIdx: Util.getShareId(header, proof).readUInt32LE(0),
        toSubmit: {
            coinbase_commit: coinbase,
            header_and_proof: Buffer.concat(submission).toString('hex'),
        }
    };
};

const httpRes = (ctx /*:Context_t*/, res /*:IncomingMessage*/) => {
    const data = [];
    res.on('data', (d) => { data.push(d.toString('utf8')); });
    res.on('end', () => {
        if (res.statusCode !== 200) {
            // if (res.statusCode === 400) {
            //     debug("Pool replied with error 400 " + data.join('') + ", stopping");
            //     process.exit(100);
            // }
            debug("WARNING: Pool replied with [" + res.statusMessage +
                "] [" + data.join('') + "]");
            return;
        }
        const d = data.join('');
        let result;
        try {
            const o = JSON.parse(d);
            result = o.result;
            if (o.error.length > 0) {
                debug("WARNING: Pool error [" + JSON.stringify(o.error) + "]");
                // we do not proceed
                return;
            }
            if (o.warn.length > 0) {
                debug("WARNING: Pool is warning us [" + JSON.stringify(o.warn) + "]");
            }
            result = o.result;
        } catch (e) {
            debug("WARNING: Pool reply is invalid [" + d + "]");
            return;
        }
        debug("Pool responded [" + JSON.stringify(result) + "]");
    });
};

const uploadFile = (ctx /*:Context_t*/, filePath /*:string*/, cb /*:()=>void*/) => {
    let fileBuf;
    nThen((w) => {
        //debug("uploadShares2 " + filePath);
        Fs.readFile(filePath, w((err, ret) => {
            if (err) {
                // could be ENOENT if the file was deleted in the mean time because
                // new work arrived.
                if (err.code === 'ENOENT') {
                    debug("Shares [" + filePath + "] disappeared");
                    return;
                }
                throw err;
            }
            if (ret.length > 0) {
                //debug("Uploading shares [" + filePath + "]");
                fileBuf = ret;
            }
        }));
    }).nThen((w) => {
        if (!fileBuf) { return; }
        Fs.unlink(filePath, w((err) => {
            if (err) {
                debug("WARNING: failed to delete file [" + filePath + "] [" +
                    String(err.code) + "]");
                return;
            }
        }));
    }).nThen((_) => {
        if (!fileBuf) { return; }
        splitShares(fileBuf).forEach((share, i) => {
            if (!ctx.pool.work) {
                debug("Dropping share because we have no work");
                return;
            }
            const work = ctx.pool.work;
            const shr = convertShare(share, ctx.config.version);
            const sharePrevHash = share.slice(Protocol.COINBASE_COMMIT_LEN + 4).slice(0,32);
            const currentWorkPrevHash = work.header.slice(4,36);
            if (currentWorkPrevHash.compare(sharePrevHash)) {
                debug("Dropping stale share");
                return;
            }
            const handlerNum = shr.contentProofIdx % ctx.pool.config.submitBlockUrls.length;
            const url = ctx.pool.config.submitBlockUrls[handlerNum];
            debug("Uploading share [" + filePath + "] [" + i + "] to [" + url + "]");
            const req = Util.httpPost(url, {
                'Content-Type': 'application/json',
                'x-pc-payto': ctx.config.paymentAddr,
                'x-pc-sver': Protocol.SOFT_VERSION,
            }, (res) => {
                httpRes(ctx, res);
            });
            req.end(JSON.stringify(shr.toSubmit));
            req.on('error', (err) => {
                debug("Failed to upload share [" + err + "]");
            });
        });
        cb();
    });
};

const checkShares = (ctx /*:Context_t*/, done) => {
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
        // Put the list into decending order, biggest number first
        nums.sort((x,y) => ( (x > y) ? -1 : (x === y) ? 0 : 1 ));

        let nt = nThen;
        nums.forEach((n, i) => {
            const filePath = ctx.config.dir + '/wrkdir/shares_' + n + '.bin';
            nt = nt((w) => {
                Fs.stat(filePath, w((err, ret) => {
                    // file was deleted, new work
                    if (err && err.code === 'ENOENT') { return; }
                    if (err) { throw err; }
                    if (i === 0) {
                        if (ret.size > 0) {
                            // The most recent file has content so lets just sig the
                            // miner so that it will make a new file and then we'll
                            // submit the content of this one on the next go around.
                            sigMiner(ctx);
                        }
                    } else if (ret.size > 0) {
                        // we have content in a file which we can upload now
                        uploadFile(ctx, filePath, w());
                    } else {
                        // Size of the file is zero and it's not the biggest number
                        // file in the list, this means it's a stray share which stopped
                        // being used when the miner was signaled because there was new
                        // work, delete it.
                        Fs.unlink(filePath, w((err) => {
                            if (err && err.code !== 'ENOENT') {
                                debug("WARNING: failed to delete file [" + filePath + "]");
                                return;
                            }
                        }));
                    }
                }));
            }).nThen;
        });
        nt(w());
    }).nThen((_) => {
        done();
    });
};

const rankForDeletion = (fileNames, height) => {
    // anns_454982_4_10949021.bin
    // anns_4_10947406.bin
    const byBlk = {};
    const last = [];
    for (const fn of fileNames) {
        if (!/^anns_/.test(fn)) { continue; }
        const blkNum = fn.replace(/^anns_([0-9]+)_[0-9]+_[0-9]+\.bin$/, (_, blkNum) => blkNum);
        if (Number(blkNum) > (height - 3)) {
            // never consider for deletion any file which is not yet usable
            continue;
        }
        if (blkNum === fn) {
            last.push(fn);
            continue;
        }
        const blkList = byBlk[blkNum];
        if (!blkList) {
            byBlk[blkNum] = [ fn ];
        } else {
            blkList.push(fn);
        }
    }
    const out = [];
    Object.keys(byBlk).sort().reverse().forEach((k) => out.push(...byBlk[k]));
    out.push(...last);
    return out;
};

const deleteUselessAnns = (config, height, done) => {
    debug("Deleting expired announcements");
    Fs.readdir(config.dir + '/anndir', (err, files) => {
        if (err) { throw err; }
        const ranked = rankForDeletion(files, height);
        let nt = nThen;
        ranked.slice(Math.floor(config.maxAnns * 1.25 / 1024)).forEach((f) => {
            const path = config.dir + '/anndir/' + f;
            const wrkpath = config.dir + '/anndir/' + f;
            const trashpath = config.dir + '/trash/' + f;
            nt = nt((w) => {
                Fs.rename(path, trashpath, w((err) => {
                    if (err && err.code !== 'ENOENT') {
                        debug("Failed to move [" + path + "] to trash [" + err.message + "]");
                    }
                }));
                Fs.rename(wrkpath, trashpath + '.wrkdir', w((err) => {
                    if (err && err.code !== 'ENOENT') {
                        debug("Failed to move [" + wrkpath + "] to trash [" + err.message + "]");
                    }
                    // ENOENT are very likely here if the file has been deleted
                }));
            }).nThen;
        });
        nt(() => {
            debug("Deleting expired announcements complete");
            done();
        });
    });
};

const mkLinks = (config, done) => {
    const sema = Saferphore.create(8);
    debug("mkLinks() getting list of files");
    let files;
    nThen((w) => {
        Fs.readdir(config.dir + '/anndir', w((err, fls) => {
            if (err) { throw err; }
            debug("mkLinks() processing [" + fls.length + "] files");
            files = fls;
        }));
    }).nThen((w) => {
        files.forEach((f, i) => {
            sema.take((ra) => {
                Fs.link(
                    config.dir + '/anndir/' + f,
                    config.dir + '/wrkdir/' + f,
                    w(ra((err) =>
                {
                    if (!err) {
                        return;
                    }
                    if (err.code === 'EEXIST') {
                        return;
                    }
                    if (err.code === 'ENOENT') {
                        // this is a race against deleteUselessAnns
                        //debug("Failed to link [" + f + "] because file is missing");
                        return;
                    }
                    throw err;
                })));
            });
        });
    }).nThen((_) => {
        debug("mkLinks() complete");
        done();
    });
};

const mkMiner = (ctx) => {
    const args = [
        '--threads', String(ctx.config.threads || 1),
        '--maxanns', String(ctx.config.maxAnns || 1024*1024),
        '--minerId', String(ctx.config.minerId),
    ];
    if (ctx.config.slowStart) {
        args.push('--slowStart');
    }
    args.push(ctx.config.dir + '/wrkdir');
    debug(ctx.config.corePath + ' ' + args.join(' '));
    const miner = Spawn(ctx.config.corePath, args, {
        stdio: [ 'pipe', 1, 2 ]
    });
    miner.on('close', (num, sig) => {
        debug("pcblk died [" + num + "] [" + sig + "], restarting in 1 second");
        ctx.miner = undefined;
        setTimeout(() => {
            ctx.lock.take((returnAfter) => {
                debug("Enter pkblk died");
                nThen((w) => {
                    debug("Delete work and shares");
                    deleteWorkAndShares(ctx.config, w());
                }).nThen((w) => {
                    debug("Hard linking ann files");
                    mkLinks(ctx.config, w());
                }).nThen((w) => {
                    debug("onNewWork");
                    if (ctx.pool.work && ctx.pool.connected) { onNewWork(ctx, ctx.pool.work, w()); }
                }).nThen((w) => {
                    mkMiner(ctx);
                    debug("Exit pkblk died");
                    returnAfter()();
                });
            });
        }, 1000);
    });
    miner.stdin.on('error', (e) => {
        debug("error from pcblk [" + e + "]");
    });
    ctx.miner = miner;
};

/*::
type DownloadAnnError_t = Error | {statusCode:number} | {code:string,annPath:string};
*/
const downloadAnnFile = (
    currentHeight /*:number*/,
    config /*:Config_BlkMiner_t*/,
    url /*:string*/,
    serverId /*:number*/,
    fileNo /*:number*/,
    _cb /*:(?DownloadAnnError_t)=>void*/
) => {
    const wrkdir = config.dir;
    let timedout = false;
    const to = setTimeout(() => {
        debug("Request for " + url + " in flight for 5 minutes, cancelling.");
        timedout = true;
        _cb({ code: 'TIMEOUT', annPath: url });
        _cb = (_x)=> { throw new Error(); };
    }, 300000);
    const cb = (x) => {
        if (timedout) {
            debug("Request for " + url + " finally returned, too late");
            return;
        }
        clearTimeout(to);
        _cb(x);
        _cb = (_x)=> { throw new Error(); };
    };

    let annBin;
    let wrkPath;
    let annPath;
    nThen((w) => {
        // debug("Get announcements [" + url + "] -> [" + annPath + "]");
        Util.httpGetBin(url, w((err, res) => {
            if (!res || res.length < 1024 || res.length % 1024) {
                if (!err) { err = new Error("unknown error"); }
                w.abort();
                return void cb(err);
            }
            annBin = res;
        }));
    }).nThen((w) => {
        if (!annBin) { return; }
        let fileName = url.replace(/^.*\/([^\/]+)$/, (_, x) => x);
        if (/^anns_[0-9]+_[0-9]+_[0-9]+.bin$/.test(fileName)) {
            // The file coming from the server already contains everything it needs
            // just use the url as it is.
        } else {
            // Old url format, anns_<number>.bin, need to extract the block number
            // from the work and also add the server number.
            const parentBlockNum = annBin.readUInt32LE(12);
            const annWorkBits = annBin.readUInt32LE(8);
            if (Util.isWorkUselessExponential(annWorkBits, currentHeight - parentBlockNum)) {
                w.abort();
                return void cb({ code: 'USELESS', annPath: url });
            }
            fileName = 'anns_' + parentBlockNum + '_' + serverId + '_' + fileNo + '.bin';
        }
        annPath = wrkdir + '/anndir/' + fileName;
        wrkPath = wrkdir + '/wrkdir/' + fileName;
    }).nThen((w) => {
        if (!annBin) { return; }
        Fs.writeFile(annPath, annBin, w((err) => {
            if (err) {
                w.abort();
                return void cb(err);
            }
        }));
    }).nThen((w) => {
        if (!annBin) { return; }
        Fs.link(annPath, wrkPath, w((err) => {
            if (err && err.code === 'EEXIST') {
                // Just ignore if the file already exists
                return;
            }
            if (err) { throw err; }
        }));
    }).nThen((_) => {
        if (!annBin) { return; }
        cb();
    });
};

const connsPerAh = 20;
const pollAnnHandler = (ctx /*:Context_t*/, serverNum /*:number*/) => {

    let topFile;
    const filesTodo = [];
    const filesInProgress = [];
    let downloaded = 0;

    const again = () => {
        if (!topFile || filesInProgress.length > connsPerAh) { return setTimeout(again, 5000); }
        if (!ctx.pool.work) { return setTimeout(again, 1000); }
        const work = ctx.pool.work;
        const cycle = () => {
            const curHeight = work.height;
            const url = filesTodo.pop();
            filesInProgress.push(url);
            const fileNo = url.replace(/^.*\/anns_([0-9]+).bin$/, (_, a) => a);
            //debug("Getting file " + url);
            downloadAnnFile(curHeight, ctx.config, url, Number(fileNo), serverNum, (err, res) => {
                downloaded++;
                // return the connection
                const idx = filesInProgress.indexOf(url);
                if (idx === -1) {
                    console.error("Spooky file disappeared " + url);
                } else {
                    filesInProgress.splice(idx, 1);
                }
                if (!err) {
                } else if ((err /*:any*/).statusCode === 404 || (err /*:any*/).code === 'USELESS') {
                    // File is either missing or not usable, don't re-download
                } else {
                    // We'll come back around and try later if it's a slow day
                    filesTodo.unshift(url);
                }
                again();
            });
        };
        while (filesInProgress.length < connsPerAh && filesTodo.length) { cycle(); }
    };

    const serverUrl = ctx.pool.config.downloadAnnUrls[serverNum];
    const getTop = () => {
        getAnnFileNum(serverUrl, (num, urls) => {
            let n = 0;
            let newFiles = false;
            if (topFile) {
                const topNum = topFile.replace(/^.*_([0-9]+).bin$/, (_, num) => num);
                if (topFile === topNum) { throw new Error("Unexpected filename " + topFile); }
                n = Number(topNum);
                if (isNaN(n) || Math.floor(n) !== n || n < 0) {
                    throw new Error("Unexpected filename " + topFile);
                }
            }
            if (urls) {
                for (const url of urls) {
                    const num = Number(url.replace(/^.*_([0-9]+).bin$/, (_, num) => num));
                    if (isNaN(num)) {
                        debug("Unexpeced file from server [" + url + "]");
                    } else if (num <= n) {
                        // already got it
                    } else {
                        newFiles = true;
                        filesTodo.push(url);
                    }
                }
            } else {
                if (num - n > 300) { n = num - 300; }
                for (; n <= num; n++) {
                    filesTodo.push(serverUrl + '/anns/anns_' + n + '.bin');
                    newFiles = true;
                }
            }
            if (newFiles) {
                topFile = filesTodo[filesTodo.length - 1];
            }
            while (filesTodo.length > 500) { filesTodo.shift(); }
            setTimeout(getTop, 2000);
            again();
            ctx.stats[serverUrl] = {
                downloaded,
                downloading: filesInProgress.length,
                todo: filesTodo.length,
            };
            // debug(`[${serverUrl}] downloaded [${String(downloaded)}] ` +
            //     `downloading [${filesInProgress.length}] todo [${filesTodo.length}]`);
        });
    };
    getTop();
};

const pollAnnHandlers = (ctx) => {
    for (let i = 0; i < ctx.pool.config.downloadAnnUrls.length; i++) {
        pollAnnHandler(ctx, i);
    }
};

const launchDeleter = (trashDir, retryCount) => {
    // We need stdin to be a pipe to the parent process, the deleter will
    // exit when that pipe closes.
    const deleter = Fork('./js/FileDeleter.js', {
        stdio: ['pipe', 1, 2, 'ipc']
    });
    deleter.send({ directory: trashDir, prefix: 'anns_' });
    deleter.on('close', () => {
        if (retryCount > 10) {
            throw new Error("Tried restarting the deleter 10 times, aborting");
        }
        launchDeleter(trashDir, retryCount + 1);
    });
};

const launch = (config /*:Config_BlkMiner_t*/) => {
    if (!Util.isValidPayTo(config.paymentAddr)) {
        debug('Payment address [' + config.paymentAddr +
            '] is not a valid pkt address');
        process.exit(100);
    }
    const pool = Pool.create(config.poolUrl);
    nThen((w) => {
        pool.getMasterConf(w());
        Util.checkMkdir(config.dir + '/wrkdir', w());
        Util.checkMkdir(config.dir + '/anndir', w());
        Util.checkMkdir(config.dir + '/trash', w());
        Util.clearDir(config.dir + '/wrkdir', w());
    }).nThen((w) => {
        launchDeleter(config.dir + '/trash', 0);
        console.log('Deleting expired announcements');
        if (!pool.work) { throw new Error(); }
        deleteUselessAnns(config, pool.work.height, w());
    }).nThen((w) => {
        console.log('Hardlinking announcements to workdir');
        mkLinks(config, w());
    }).nThen((_) => {
        const ctx /*:Context_t*/ = {
            config: config,
            miner: undefined,
            pool: pool,
            lock: Saferphore.create(1),
            lock2: Saferphore.create(1),
            newWorkLock: Saferphore.create(1),
            minerLastSignaled: +new Date(),
            stats: {},
        };
        mkMiner(ctx);
        debug("Got [" + pool.config.downloadAnnUrls.length + "] AnnHandlers");
        pollAnnHandlers(ctx);
        pool.onWork((work) => {
            onNewWork(ctx, work, ()=>{});
            ctx.lock2.take((r) => {
                deleteUselessAnns(config, work.height, r());
            });
        });
        setInterval(() => {
            ctx.lock.take((returnAfter) => {
                //debug("Enter checkShares");
                checkShares(ctx, returnAfter(() => {
                    //debug("Exit checkShares");
                }));
            });
        }, 500);

        let totalDownloaded = 0;
        setInterval(() => {
            let downloaded = 0;
            const downloading = [];
            const todo = [];
            for (let i = 0; i < ctx.pool.config.downloadAnnUrls.length; i++) {
                const sx = ctx.stats[ctx.pool.config.downloadAnnUrls[i]];
                if (!sx) {
                    downloading.push('unknown');
                    todo.push('unknown');
                    continue;
                }
                downloaded += sx.downloaded;
                downloading.push(sx.downloading);
                todo.push(sx.todo);
            }
            downloaded -= totalDownloaded;
            debug(`STATS: downloaded [${String(downloaded)}] ` +
                `getting [${downloading.join(',')}] queued [${todo.join(',')}]`);
            totalDownloaded += downloaded;
        }, 10000);
    });
};

const MAGIC1 = "See: https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcblk.md";
const MAGIC2 = "PacketCrypt Block Miner: Protocol Version ";
const getMinerVersion = (cfg, cb) => {
    const miner = Spawn(cfg.corePath, []);
    let data = '';
    miner.stderr.on('data', (d) => { data += d; });
    miner.on('close', () => {
        if (data.indexOf(MAGIC2) === -1) {
            if (data.indexOf(MAGIC1) === -1) {
                debug("pcblk not present or not working, if you are running the miner");
                debug("from outside of the PacketCrypt directory, make sure you pass --corePath");
                process.exit(100);
            } else {
                debug("pcblk is out of date, you may need to recompile");
                process.exit(100);
            }
        } else if (data.indexOf(MAGIC2 + '2\n') > -1) {
            debug("PacketCrypt Block Miner: Protocol Version 2");
            cb(2);
        } else if (data.indexOf(MAGIC2 + '1\n') > -1) {
            debug("PacketCrypt Block Miner: Protocol Version 1");
            cb(1);
        } else {
            debug("pcblk unknown protocol version");
            process.exit(100);
        }
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
        "        --slowStart   # wait 10 seconds when starting pcblk to allow time for gdb\n" +
        "                      # to be attached.\n" +
        "    <poolurl>         # the URL of the mining pool to connect to\n" +
        "\n" +
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/blkmine.md\n" +
        "    for more information");
    return 100;
};

const DEFAULT_PAYMENT_ADDR = "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2";

const main = (argv) => {
    const defaultConf = {
        corePath: './bin/pcblk',
        dir: './datastore/blkmine',
        paymentAddr: DEFAULT_PAYMENT_ADDR,
        maxAnns: DEFAULT_MAX_ANNS,
        threads: 1,
        minerId: Math.floor(Math.random()*(1<<30)*2),
        slowStart: false,
        version: 1
    };
    const a = Minimist(argv.slice(2), { boolean: [ 'slowStart' ] });
    if (!/http(s)?:\/\/.*/.test(a._[0])) { process.exit(usage()); }
    const conf = {
        corePath: a.corePath || defaultConf.corePath,
        dir: a.dir || defaultConf.dir,
        paymentAddr: a.paymentAddr || defaultConf.paymentAddr,
        poolUrl: a._[0],
        maxAnns: a.maxAnns || defaultConf.maxAnns,
        threads: a.threads || defaultConf.threads,
        minerId: a.minerId || defaultConf.minerId,
        slowStart: a.slowStart === true || defaultConf.slowStart,
        version: defaultConf.version,
    };
    if (!a.paymentAddr) {
        debug("WARNING: You have not passed the --paymentAddr flag\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    getMinerVersion(conf, (version) => {
        conf.version = version;
        launch(Object.freeze(conf));
    });
};
main(process.argv);

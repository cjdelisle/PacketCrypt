/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Spawn = require('child_process').spawn;
const Fs = require('fs');
const nThen = require('nthen');
const Minimist = require('minimist');
const MerkleTree = require('merkletreejs').MerkleTree;
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
    minerLastSignaled: number
};
*/

const debug = (...args) => {
    console.error('blkmine:', ...args);
};

const getAnnFileParentNum = (filePath, _cb) => {
    const cb = Util.once(_cb);
    const again = (i) => {
        let error = (w, err) => {
            error = (_w, _e) => {};
            w.abort();
            if (i > 5) {
                cb(err);
            } else {
                setTimeout(()=> {
                    if (i > 3) {
                        debug('getAnnFileParentNum [' + String(err) +
                            '] (attempt [' + i + '])');
                    }
                    again(i+1);
                }, (i > 0) ? 5000 : 500);
            }
        };
        nThen((w) => {
            Fs.stat(filePath, w((err, st) => {
                if (err) {
                    error(w, "stat error " + String(err));
                } else if (st.size < 16) {
                    error(w, "short stat " + st.size);
                }
            }));
        }).nThen((w) => {
            const stream = Fs.createReadStream(filePath, { end: 16 });
            const data = [];
            stream.on('data', (d) => { data.push(d); });
            stream.on('end', () => {
                const buf = Buffer.concat(data);
                if (buf.length < 16) {
                    return void error(w, "short read " + buf.length);
                }
                const blockNo = buf.readUInt32LE(12);
                //debug("Got announcements with parent block number [" + blockNo + "]");
                error = (_w, _e) => {};
                cb(undefined, blockNo);
            });
            stream.on('error', (err) => { error(w, err); });
        });
    };
    again(0);
};

// returns filenames ranked worst to best
const rankAnnFiles = (fileNames) => {
    const handlers = {};
    for (const fn of fileNames) {
        if (!/^anns_/.test(fn)) { continue; }
        const h = fn.slice(0, fn.lastIndexOf('_'));
        const num = fn.replace(/^.*_([0-9]+)\.bin$/, (_, x) => x);
        const handler = handlers[h] = (handlers[h] || []);
        handler.push(num);
    }
    for (const hn in handlers) { handlers[hn].sort(); }
    const out = [];
    let cont;
    do {
        cont = false;
        for (const hn in handlers) {
            const f = handlers[hn].shift();
            if (typeof(f) === 'undefined') { continue; }
            const file = hn + '_' + f + '.bin';
            out.push(file);
            cont = true;
        }
    } while (cont);
    return out;
};

/*::
type DownloadAnnCtx_t = {
    inflight: {[string]:number};
};
type DownloadAnnResult_t = {
    annPath: string,
    wrkPath: string,
};
type DownloadAnnError_t = Error | {statusCode:number} | {code:string,annPath:string};
*/

const downloadAnnFile = (
    dac /*:DownloadAnnCtx_t*/,
    currentHeight /*:number*/,
    config /*:Config_BlkMiner_t*/,
    serverUrl /*:string*/,
    serverId /*:string*/,
    fileNo /*:number*/,
    _cb /*:(?DownloadAnnError_t, ?DownloadAnnResult_t)=>true|void*/
) => {
    const wrkdir = config.dir;
    const fileSuffix = '_' + serverId + '_' + fileNo + '.bin';
    const annPath = wrkdir + '/anndir/anns' + fileSuffix;
    const url = serverUrl + '/anns/anns_' + fileNo + '.bin';
    if (dac.inflight[url]) {
        return void _cb({ code: 'INFLIGHT_REQ', annPath });
    }
    dac.inflight[url] = 1;
    let timedout = false;
    const to = setTimeout(() => {
        debug("Request for " + url + " in flight for 5 minutes, cancelling.");
        delete dac.inflight[url];
        timedout = true;
        _cb({ code: 'TIMEOUT', annPath: annPath });
    }, 300000);
    const cb = (x, y) => {
        if (timedout) {
            debug("Request for " + url + " finally returned, too late");
            return;
        }
        if (!dac.inflight[url]) { throw new Error(url + " returned twice"); }
        delete dac.inflight[url];
        clearTimeout(to);
        _cb(x, y);
    };
    const again = () => {
        let parentBlockNum;
        let annBin;
        let wrkPath;
        nThen((w) => {
            Fs.stat(annPath, w((err, _) => {
                if (err && err.code === 'ENOENT') { return; }
                if (err) { throw err; }
                w.abort();
                return void cb({ code: 'EEXIST', annPath: annPath });
            }));
        }).nThen((w) => {
            // debug("Get announcements [" + url + "] -> [" + annPath + "]");
            Util.httpGetBin(url, w((err, res) => {
                if (!res || res.length < 1024 || res.length % 1024) {
                    if (!err) { err = new Error("unknown error"); }
                    w.abort();
                    if (cb(err)) { setTimeout(again, 5000); }
                }
                annBin = res;
            }));
        }).nThen((w) => {
            if (!annBin) { return; }
            const annParentBlockHeight = annBin.readUInt32LE(12);
            const annWorkBits = annBin.readUInt32LE(8);
            if (Util.isWorkUselessExponential(annWorkBits, currentHeight - annParentBlockHeight)) {
                w.abort();
                return void cb({ code: 'USELESS', annPath: annPath });
            }
        }).nThen((w) => {
            if (!annBin) { return; }
            if (config.version >= 2) { return; }
            let nt = nThen;
            const eachAnn = (i) => {
                if (!annBin) { throw new Error(); } // shouldn't happen
                const annContentLen = annBin.readUInt32LE(i + 20);
                if (annContentLen <= 32) { return; }
                const annContentHash = annBin.slice(i + 24, i + 56);
                nt = nt((ww) => {
                    const cfname = 'ann_' + annContentHash.toString('hex') + '.bin';
                    const curl = serverUrl + '/content/' + cfname;
                    const cpath = wrkdir + '/contentdir/' + cfname;
                    //debug("Get announcement content [" + curl + "] -> [" + cpath + "]");
                    Util.httpGetBin(curl, ww((err, res) => {
                        if (!res) {
                            if (!err) { err = new Error("unknown error"); }
                            ww.abort();
                            w.abort();
                            if (cb(err)) { setTimeout(again, 5000); }
                            return;
                        }
                        Fs.writeFile(cpath, res, (err) => {
                            if (err) {
                                ww.abort();
                                w.abort();
                                if (cb(err)) { setTimeout(again, 5000); }
                            }
                        });
                    }));
                }).nThen;
            };
            for (let i = 0; i < annBin.length; i += 1024) { eachAnn(i); }
            nt(w());
        }).nThen((w) => {
            if (!annBin) { return; }
            Fs.writeFile(annPath, annBin, w((err) => {
                if (err) {
                    w.abort();
                    if (cb(err)) { setTimeout(again, 5000); }
                }
            }));
        }).nThen((w) => {
            if (!annBin) { return; }
            getAnnFileParentNum(annPath, w((err, pbn) => {
                if (typeof(pbn) === 'undefined') {
                    debug('getAnnFileParentNum() error ' + String(err));
                    // filesystem error, we probably want to bail out...
                    throw err;
                }
                parentBlockNum = pbn;
            }));
        }).nThen((w) => {
            if (!annBin) { return; }
            wrkPath = wrkdir + '/wrkdir/anns_' + parentBlockNum + fileSuffix;
            Fs.readdir(wrkdir + '/wrkdir/', (err, files) => {
                if (err) { throw err; }
                if (files.length > config.maxAnns * 1024) {
                    console.log('Deleting old announcements');
                    const ranked = rankAnnFiles(files);
                    for (let i = 0; i < 1000; i++) {
                        //console.log('Deleting ' + ranked[i]);
                        Fs.unlink(wrkdir + '/wrkdir/' + ranked[i], (err) => {
                            if (err) {
                                //console.log('Failed to delete ' + ranked[i]);
                            }
                        });
                    }
                }
            });
            Fs.link(annPath, wrkPath, w((err) => {
                if (err && err.code === 'EEXIST') {
                    // Just ignore if the file already exists
                    return;
                }
                if (err) { throw err; }
            }));
        }).nThen((_) => {
            if (!annBin) { return; }
            if (cb(undefined, {
                annPath: annPath,
                wrkPath: wrkPath
            })) {
                setTimeout(again, 5000);
            }
        });
    };
    again();
};

/*
if (searchBackward && err.statusCode === 404) {
    debug("Backward search on server [" + server + "] complete");
    return;
}
debug("Unable to get ann file at [" + url + "] [" + String(err) + "]");
return true;
*/

const getAnnFileNum = (
    server /*:string*/,
    then /*:(annFileNum:number)=>void*/
) => {
    const url = server + '/anns/index.json';
    Util.httpGetStr(url, (err, res) => {
        if (!res) {
            debug("Unable to contact AnnHandler at [" + url + "] [" + String(err) + "]");
            return true;
        }
        let num = NaN;
        try {
            const obj = JSON.parse(res);
            num = Number(obj.highestAnnFile);
        } catch (e) { }
        if (isNaN(num)) {
            debug("in response from [" + url + "] could not parse [" + res + "]");
            return true;
        }
        if (num < 0) {
            debug("Ann server doesn't have any anns yet, trying again in 10 seconds");
            return void setTimeout(() => { getAnnFileNum(server, then); }, 10000);
        }
        then(num);
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

const mkMerkleProof = (() => {
    const split = (content, out) => {
        out = out || [];
        if (content.length <= 32) {
            const b = Buffer.alloc(32);
            content.copy(b);
            out.push(b);
            return out;
        }
        out.push(content.slice(0, 32));
        split(content.slice(32), out);
        return out;
    };

    const mkProof = (mt, arr, blockNum) => {
        const p = mt.getProof(arr[blockNum]);
        const proofList = p.map((x) => x.data);
        proofList.unshift(arr[blockNum]);
        return Buffer.concat(proofList);
    };

    const mkMerkleProof = (content /*:Buffer*/, ident /*:number*/) => {
        if (content.length <= 32) { throw new Error("Content is too short to make a tree"); }
        const arr = split(content);
        const blocknum = ident % arr.length;
        const mt = new MerkleTree(arr, Util.b2hash32);
        return mkProof(mt, arr, blocknum);
    };

    return mkMerkleProof;
})();

// This converts the format of the share which is output from pcblk to the
// format expected by BlkHandler
const convertShare = (
    buf /*:Buffer*/,
    annContents /*:Array<Buffer>*/,
    version /*:number*/
) /*:Share_t*/ => {
    const coinbase = buf.slice(0, Protocol.COINBASE_COMMIT_LEN).toString('hex');
    buf = buf.slice(Protocol.COINBASE_COMMIT_LEN);
    const header = buf.slice(0, 80);
    const proof = buf.slice(84);
    const contentProofIdx = Util.getShareId(header, proof).readUInt32LE(0);
    const contentProofs = [];
    for (let i = 0; i < 4; i++) {
        if (!annContents[i] || annContents[i].length <= 32) { continue; }
        contentProofs.push(mkMerkleProof(annContents[i], contentProofIdx));
    }

    const submission = [
        header,
        Util.mkVarInt(Protocol.PC_PCP_TYPE),
        Util.mkVarInt(proof.length),
        proof
    ];

    if (version > 1) {
        const versionBuf = Util.mkVarInt(version);
        submission.push(
            Util.mkVarInt(Protocol.PC_VERSION_TYPE),
            Util.mkVarInt(versionBuf.length),
            versionBuf
        );
    }

    if (contentProofs.length) {
        const cp = Buffer.concat(contentProofs);
        submission.push(
            Util.mkVarInt(Protocol.PC_CONTENTPROOFS_TYPE),
            Util.mkVarInt(cp.length),
            cp
        );
    }

    return {
        contentProofIdx: contentProofIdx,
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

const getAnnContent = (ctx, ann /*:Buffer*/, cb) => {
    const length = ann.readUInt32LE(Protocol.ANN_CONTENT_LENGTH_OFFSET);
    if (!length) { return void cb(); }
    if (length <= 32) {
        return void cb(undefined, ann.slice(Protocol.ANN_CONTENT_HASH_OFFSET,
            Protocol.ANN_CONTENT_HASH_OFFSET + length));
    }
    const h = ann.slice(Protocol.ANN_CONTENT_HASH_OFFSET, Protocol.ANN_CONTENT_HASH_OFFSET + 32);
    const file = ctx.config.dir + '/contentdir/ann_' + h.toString('hex') + '.bin';
    Fs.readFile(file, (err, buf) => {
        if (err) { return void cb(err); }
        if (buf.length !== length) {
            return void cb(new Error("Length of content file [" + file + "] is [" + buf.length +
                "] but the announcement defined length is [" + length + "]"));
        }
        cb(undefined, buf);
    });
};

const BLOCK_HEADER_OFFSET = 32+8+4+4;
const PROOF_OFFSET = BLOCK_HEADER_OFFSET+80+4;
const FIRST_ANN_OFFSET = PROOF_OFFSET+4;
const getAnn = (share /*:Buffer*/, num /*:number*/) => {
    const idx = FIRST_ANN_OFFSET + (num * 1024);
    return share.slice(idx, idx + 1024);
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
    }).nThen((w) => {
        if (!fileBuf) { return; }
        splitShares(fileBuf).forEach((share, i) => {
            const annContents = [];
            let failed = false;
            nThen((w) => {
                if (ctx.config.version !== 1) { return; }
                [0,1,2,3].forEach((num) => {
                    const ann = getAnn(share, num);
                    const length = ann.readUInt32LE(Protocol.ANN_CONTENT_LENGTH_OFFSET);
                    if (length <= 32) { return; }
                    getAnnContent(ctx, ann, w((err, buf) => {
                        if (failed) { return; }
                        if (!buf) {
                            debug("Unable to submit share");
                            debug(err);
                            failed = true;
                            return;
                        }
                        annContents[num] = buf;
                    }));
                });
            }).nThen((w) => {
                if (failed) { return; }
                const shr = convertShare(share, annContents, ctx.config.version);
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
                //console.log(JSON.stringify(shr.toSubmit));
            });
        });
    }).nThen((w) => {
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

const deleteUselessAnns = (config, height, done) => {
    Util.deleteUselessAnns(config.dir + '/anndir', height, (f, done2) => {
        //debug("Deleted expired announcements [" + f + "]");
        const path = config.dir + '/anndir/' + f;
        Fs.unlink(path, (err) => {
            done2();
            if (!err) { return; }
            debug("Failed to delete [" + path + "] [" + err.message + "]");
        });
    }, done);
};

const FILES_PER_BATCH = 500;
const mkLinks = (config, done) => {
    const sema = Saferphore.create(8);
    debug("mkLinks() getting list of files");
    let files;
    const more = (i) => {
        debug("mkLinks() processing files [" + i + "] to [" + (i + FILES_PER_BATCH) + "]");
        const chunk = files.slice(i, i + FILES_PER_BATCH);
        if (!chunk.length) {
            debug("mkLinks() done");
            return void done();
        }
        nThen((w) => {
            chunk.forEach((f, _i) => {
                const index = i + _i;
                sema.take((ra) => {
                    // consider each file contains about 1000 anns
                    if (index < config.maxAnns * 1024) {
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
                                debug("Failed to link [" + f + "] because file is missing");
                                return;
                            }
                            throw err;
                        })));
                    } else {
                        Fs.unlink(config.dir + '/anndir/' + f, w(ra(() => {})));
                    }
                });
            });
        }).nThen((_) => {
            more(i + FILES_PER_BATCH);
        });
    };
    nThen((w) => {
        Fs.readdir(config.dir + '/anndir', w((err, fls) => {
            if (err) { throw err; }
            debug("mkLinks() processing [" + fls.length + "] files");
            const ranked = rankAnnFiles(fls);
            ranked.reverse();
            debug("mkLinks() ranked");
            files = ranked;
        }));
    }).nThen((_) => {
        more(0);
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
    if (ctx.config.version === 1) {
        args.push(ctx.config.dir + '/contentdir');
    }
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
                    if (ctx.work && ctx.pool.connected) { onNewWork(ctx, ctx.work, w()); }
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

const downloadOldAnns = (dac, config, currentHeight, masterConf, done) => {
    let nt = nThen;
    debug("Downloading announcements to fill memory");

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
            debug("No more announcements available on any server, done");
            return void done();
        }
        if (totalLen >= maxLen) {
            debug("Downloaded enough announcements to fill available memory, done");
            return void done();
        }
        if (i > serverCurrentNum.length) { i = 0; }
        if (!serverCurrentNum[i]) { return void again(i + 1); }
        const as = serverCurrentNum[i];
        downloadAnnFile(dac, currentHeight, config, as.server, String(i), as.currentAnnNum, (err, res) => {
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
            if (err && err.code === 'USELESS') {
                debug("No more useful announcements on server [" + as.server + "]");
                serverCurrentNum[i] = undefined;
                activeServers--;
                return void again(i + 1);
            }
            if (err && err.statusCode === 404) {
                debug("Reached the end of useful announcements on [" + as.server + "]");
                serverCurrentNum[i] = undefined;
                activeServers--;
                return void again(i + 1);
            }
            debug("Requesting ann file [" + as.currentAnnNum + "] from [" + as.server + "]" +
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
    const downloadSlots = [];
    const again = (server, i, num) => {
        let completed = false;
        setTimeout(() => {
            if (completed) { return; }
            completed = true;
            again(server, i, num);
        }, 60000);
        if (!ctx.work) { return; }
        const currentHeight = ctx.work.height;
        downloadAnnFile(ctx.dac, currentHeight, ctx.config, server, String(i), num, (err, res) => {
            if (completed) { return; }
            if (res) {
                completed = true;
                return void again(server, i, num + 1);
            }
            if (err && err.code === 'EEXIST' && err.annPath) {
                // Lets just continue looking for newer files
                completed = true;
                return void again(server, i, num + 1);
                // const path = String(err.annPath);
                // throw new Error("Failed to download ann file to [" + path +
                //     "] file already exists, please delete it and restart");
            } else if (err && err.code === 'INFLIGHT_REQ') {
                // We'll silently continue trying until the other requestor finishes
                return true;
            }
            if ((err /*:any*/).statusCode === 404 || (err /*:any*/).code === 'USELESS') {
                // This might mean we are not able to download ann files fast enough
                // to keep up with the server, in this case lets just figure out where
                // the server is and update num to that number and start downloading
                // the most recent anns.
                // debug("Requesting ann file [" + num + "] from [" + server + "] " +
                //     "got a 404, re-requesting the index");
                return void getAnnFileNum(server, (num) => { again(server, i, num); });
            }
            debug("Requesting ann file [" + num + "] from [" + server + "]" +
                "got [" + JSON.stringify(err || null) + "] retrying...");
            return true;
        });
    };
    ctx.pool.config.downloadAnnUrls.forEach((server, i) => {
        getAnnFileNum(server, (num) => { again(server, i, num); });
    });
};

const launch = (config /*:Config_BlkMiner_t*/) => {
    if (!Util.isValidPayTo(config.paymentAddr)) {
        debug('Payment address [' + config.paymentAddr +
            '] is not a valid pkt address');
        process.exit(100);
    }
    const dac = { inflight: {} };
    const pool = Pool.create(config.poolUrl);
    let masterConf;
    nThen((w) => {
        pool.getMasterConf(w());
        Util.checkMkdir(config.dir + '/wrkdir', w());
        Util.checkMkdir(config.dir + '/anndir', w());
        if (config.version === 1) {
            Util.checkMkdir(config.dir + '/contentdir', w());
        }
        Util.clearDir(config.dir + '/wrkdir', w());
    }).nThen((w) => {
        console.log('Deleting expired announcements');
        if (!pool.work) { throw new Error(); }
        deleteUselessAnns(config, pool.work.height, w());
    }).nThen((w) => {
        console.log('Hardlinking announcements to workdir');
        mkLinks(config, w());
    }).nThen((w) => {
        if (!pool.work) { throw new Error(); }
        if (!config.initialDl) { return; }
        downloadOldAnns(dac, config, pool.work.height, pool.config, w());
    }).nThen((w) => {
        const ctx = {
            dac,
            config: config,
            miner: undefined,
            pool: pool,
            lock: Saferphore.create(1),
            lock2: Saferphore.create(1),
            work: undefined,
            minerLastSignaled: +new Date()
        };
        mkMiner(ctx);
        debug("Got [" + pool.config.downloadAnnUrls.length + "] AnnHandlers");
        pollAnnHandlers(ctx);
        pool.onWork((work) => {
            ctx.work = work;
            //debug("onWork");
            ctx.lock.take((returnAfter) => {
                //debug("Enter pool.onWork");
                nThen((w) => {
                    onNewWork(ctx, work, w());
                }).nThen((w) => {
                    //debug("Exit pool.onWork");
                    returnAfter()();
                });
            });
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
                debug("from outside of the PacketCryp directory, make sure you pass --corePath");
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
        "        --initialDl   # perform an initial download of anns before mining\n" +
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
    const a = Minimist(argv.slice(2), { boolean: [ 'slowStart', 'initialDl' ] });
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
        initialDl: a.initialDl || false,
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

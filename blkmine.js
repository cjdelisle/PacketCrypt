/*@flow*/
const Spawn = require('child_process').spawn;
const Fs = require('fs');
const nThen = require('nthen');
const Minimist = require('minimist');
const MerkleTree = require('merkletreejs').MerkleTree;
const Saferphore = require('saferphore');

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
import type { Config_Miner_t } from './js/Config.js'

const _flow_typeof_saferphore = Saferphore.create(1);
type Saferphore_t = typeof _flow_typeof_saferphore;

type Context_t = {
    config: Config_Miner_t,
    miner: void|ChildProcess,
    pool: PoolClient_t,
    masterConf: Protocol_PcConfigJson_t,
    lock: Saferphore_t,
    minerLastSignaled: number
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
        //console.error("Got announcements with parent block number [" + blockNo + "]");
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
    let parentBlockNum;
    let annBin;
    let wrkPath;
    nThen((w) => {
        Fs.stat(annPath, w((err, st) => {
            if (err && err.code === 'ENOENT') { return; }
            if (err) { throw err; }
            w.abort();
            return void cb({ code: 'EEXIST', annPath: annPath });
        }));
    }).nThen((w) => {
        console.error("Get announcements [" + url + "] -> [" + annPath + "]");
        Util.httpGetBin(url, w((err, res) => {
            if (!res) {
                if (!err) { err = new Error("unknown error"); }
                w.abort();
                return cb(err);
            }
            annBin = res;
        }));
    }).nThen((w) => {
        let nt = nThen;
        const eachAnn = (i) => {
            const annContentLen = annBin.readUInt32LE(i + 20);
            if (annContentLen <= 32) { return; }
            const annContentHash = annBin.slice(i + 24, i + 56);
            nt = nt((ww) => {
                const cfname = 'ann_' + annContentHash.toString('hex') + '.bin';
                const curl = serverUrl + '/content/' + cfname;
                const cpath = wrkdir + '/contentdir/' + cfname;
                //console.error("Get announcement content [" + curl + "] -> [" + cpath + "]");
                Util.httpGetBin(curl, ww((err, res) => {
                    if (!res) {
                        if (!err) { err = new Error("unknown error"); }
                        ww.abort();
                        w.abort();
                        return cb(err);
                    }
                    Fs.writeFile(cpath, res, (err) => {
                        if (err) {
                            ww.abort();
                            w.abort();
                            cb(err);
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
                cb(err);
            }
        }));
    }).nThen((w) => {
        if (!annBin) { return; }
        getAnnFileParentNum(annPath, w((err, pbn) => {
            if (typeof(pbn) === 'undefined') {
                console.error('getAnnFileParentNum() error ' + String(err));
                // filesystem error, we probably want to bail out...
                throw err;
            }
            parentBlockNum = pbn;
        }));
    }).nThen((w) => {
        if (!annBin) { return; }
        wrkPath = wrkdir + '/wrkdir/anns_' + parentBlockNum + fileSuffix;
        Fs.link(annPath, wrkPath, w((err) => {
            if (err) { throw err; }
        }));
    }).nThen((_) => {
        if (!annBin) { return; }
        cb(undefined, {
            annPath: annPath,
            wrkPath: wrkPath
        });
    });
};

/*
if (searchBackward && err.statusCode === 404) {
    console.error("Backward search on server [" + server + "] complete");
    return;
}
console.error("Unable to get ann file at [" + url + "] [" + String(err) + "]");
return true;
*/

const getAnnFileNum = (
    server /*:string*/,
    then /*:(annFileNum:number)=>void*/
) => {
    const url = server + '/anns/index.json';
    Util.httpGetStr(url, (err, res) => {
        if (!res) {
            console.error("Unable to contact AnnHandler at [" + url + "] [" + String(err) + "]");
            return true;
        }
        let num = NaN;
        try {
            const obj = JSON.parse(res);
            num = Number(obj.highestAnnFile);
        } catch (e) { }
        if (isNaN(num)) {
            console.error("in response from [" + url + "] could not parse [" + res + "]");
            return true;
        }
        if (num < 0) {
            console.error("Ann server doesn't have any anns yet, trying again in 10 seconds");
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

const sigMiner = (ctx /*:Context_t*/) => {
    const now = +new Date();
    const diff = now - ctx.minerLastSignaled;
    if (diff < 1000) { return false; }
    if (ctx.miner) { ctx.miner.kill('SIGHUP'); }
    return true;
};

const onNewWork = (ctx /*:Context_t*/, work, done) => {
    nThen((w) => {
        // Delete share/work files because there is no chance of them being useful
        deleteWorkAndShares(ctx.config, w((err) => {
            if (err && err.code !== 'ENOENT') {
                throw err;
            }
        }));
    }).nThen((w) => {
        //console.error("Writing work.bin");
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
        // It's important that if there's new work, the miner does get signaled...
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
    annContents /*:Array<Buffer>*/
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
        proof,
    ];

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
            //     console.error("Pool replied with error 400 " + data.join('') + ", stopping");
            //     process.exit(100);
            // }
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
        console.error("Pool responded [" + JSON.stringify(result) + "]");
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
        //console.error("uploadShares2 " + filePath);
        Fs.readFile(filePath, w((err, ret) => {
            if (err) {
                // could be ENOENT if the file was deleted in the mean time because
                // new work arrived.
                if (err.code === 'ENOENT') {
                    console.error("Shares [" + filePath + "] disappeared");
                    return;
                }
                throw err;
            }
            if (ret.length > 0) {
                //console.error("Uploading shares [" + filePath + "]");
                fileBuf = ret;
            }
        }));
    }).nThen((w) => {
        if (!fileBuf) { return; }
        Fs.unlink(filePath, w((err) => {
            if (err) {
                console.error("WARNING: failed to delete file [" + filePath + "] [" +
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
                [0,1,2,3].forEach((num) => {
                    const ann = getAnn(share, num);
                    const length = ann.readUInt32LE(Protocol.ANN_CONTENT_LENGTH_OFFSET);
                    if (length <= 32) { return; }
                    getAnnContent(ctx, ann, w((err, buf) => {
                        if (failed) { return; }
                        if (!buf) {
                            console.error("Unable to submit share");
                            console.error(err);
                            failed = true;
                            return;
                        }
                        annContents[num] = buf;
                    }));
                });
            }).nThen((w) => {
                if (failed) { return; }
                const shr = convertShare(share, annContents);
                const handlerNum = shr.contentProofIdx % ctx.masterConf.submitBlockUrls.length;
                const url = ctx.masterConf.submitBlockUrls[handlerNum];
                console.error("Uploading share [" + filePath + "] [" + i + "] to [" + url + "]");
                const req = Util.httpPost(url, {
                    'Content-Type': 'application/json',
                    'x-pc-payto': ctx.config.paymentAddr
                }, (res) => {
                    httpRes(ctx, res);
                });
                req.end(JSON.stringify(shr.toSubmit));
                req.on('error', (err) => {
                    console.error("Failed to upload share [" + err + "]");
                });
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
                                console.error("WARNING: failed to delete file [" + filePath + "]");
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
        console.error("Deleted expired announcements [" + f + "]");
        const path = config.dir + '/anndir/' + f;
        Fs.unlink(path, (err) => {
            done2();
            if (!err) { return; }
            console.error("Failed to delete [" + path + "] [" + err.message + "]");
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
                    if (!err) {
                        return;
                    }
                    if (err.code === 'EEXIST') {
                        return;
                    }
                    if (err.code === 'ENOENT') {
                        // this is a race against deleteUselessAnns
                        console.error("Failed to link [" + f + "] because file is missing");
                        return;
                    }
                    throw err;
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
    ];
    if (ctx.config.slowStart) {
        args.push('--slowStart');
    }
    args.push(
        ctx.config.dir + '/wrkdir',
        ctx.config.dir + '/contentdir'
    );
    console.error(ctx.config.corePath + ' ' + args.join(' '));
    const miner = Spawn(ctx.config.corePath, args, {
        stdio: [ 'pipe', 1, 2 ]
    });
    miner.on('close', (num, sig) => {
        console.error("pcblk died [" + num + "] [" + sig + "], restarting in 1 second");
        setTimeout(() => {
            ctx.lock.take((returnAfter) => {
                //console.error("Enter pkblk died");
                nThen((w) => {
                    deleteWorkAndShares(ctx.config, w());
                }).nThen((w) => {
                    mkLinks(ctx.config, w());
                    if (ctx.work && ctx.pool.connected) { onNewWork(ctx, ctx.work, w()); }
                }).nThen((w) => {
                    mkMiner(ctx);
                    //console.error("Exit pkblk died");
                    returnAfter()();
                });
            });
        }, 1000);
    });
    ctx.miner = miner;
};

const downloadOldAnns = (config, masterConf, done) => {
    let nt = nThen;
    console.error("Downloading announcements to fill memory");

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
            console.error("No more announcements available on any server, done");
            return void done();
        }
        if (totalLen >= maxLen) {
            console.error("Downloaded enough announcements to fill available memory, done");
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
                console.error("Reached the end of useful announcements on [" + as.server + "]");
                serverCurrentNum[i] = undefined;
                activeServers--;
                return void again(i + 1);
            }
            console.error("Requesting ann file [" + as.currentAnnNum + "] from [" + as.server + "]" +
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
            console.error("Requesting ann file [" + num + "] from [" + server + "]" +
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
        Util.checkMkdir(config.dir + '/contentdir', w());
        Util.clearDir(config.dir + '/wrkdir', w());
    }).nThen((w) => {
        mkLinks(config, w());
        if (!pool.work) { throw new Error(); }
        deleteUselessAnns(config, pool.work.height, w());
    }).nThen((w) => {
        downloadOldAnns(config, masterConf, w());
    }).nThen((w) => {
        const ctx = {
            config: config,
            miner: undefined,
            pool: pool,
            masterConf: masterConf,
            lock: Saferphore.create(1),
            work: undefined,
            minerLastSignaled: +new Date()
        };
        mkMiner(ctx);
        console.error("Got [" + masterConf.downloadAnnUrls.length + "] AnnHandlers");
        pollAnnHandlers(ctx);
        pool.onWork((work) => {
            ctx.work = work;
            ctx.lock.take((returnAfter) => {
                //console.error("Enter pool.onWork");
                nThen((w) => {
                    onNewWork(ctx, work, w());
                }).nThen((w) => {
                    deleteUselessAnns(config, work.height, w());
                }).nThen((w) => {
                    //console.error("Exit pool.onWork")
                    returnAfter()();
                });
            });
        });
        setInterval(() => {
            ctx.lock.take((returnAfter) => {
                //console.error("Enter checkShares");
                checkShares(ctx, returnAfter(() => {
                    //console.error("Exit checkShares");
                }));
            });
        }, 500);
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
        slowStart: false
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

        // unused, just to please flow
        randContent: false,
    };
    if (!a.paymentAddr) {
        console.error("WARNING: You have not passed the --paymentAddr flag\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    launch(Object.freeze(conf));
};
main(process.argv);

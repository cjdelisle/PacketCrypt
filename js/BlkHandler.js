/*@flow*/
/*
format of a share upload

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
const FIRST_ANN_OFFSET = (32+8+4+4)+(80+4+4);
const ANN_PARENT_HEIGHT_OFFSET = 12;
const ANN_CONTENT_HASH_OFFSET = 24;
const SHARE_MIN_LENGTH = (32+8+4+4)+(80+4+4+(1024*4));
const SHARE_MAX_LENGTH = SHARE_MIN_LENGTH * 4;

/*
typedef struct WorkJob_s {
    PacketCrypt_BlockHeader_t blkHdr;
    Buf32_t contentHash;
    uint32_t shareTarget;
    uint32_t annTarget;
    int32_t height;
    uint32_t coinbaseLen;
    uint8_t coinbaseAndMerkles[];
} PoolProto_Work_t;

typedef struct CheckShareReq_s {
    uint32_t version;
    uint8_t hashNum;
    uint8_t hashMod;
    uint16_t workLen;
    Buf32_t parentHashes[4];
    Buf64_t payTo;
    PoolProto_Work_t work;
    BlockMiner_Share_t share;
} CheckShareReq_t;
*/

// checkshare onwork:
// 0. if version is not zero, ignore file, do not delete
// 1. delete the file
// 2. chacha20 and compare to hashNum/hashMod make sure it wasn't sent to the wrong handler
// 3. compare the work block header and the block header to verify that they are the same except for:
//  * nonce, roothash
// 4. place the coinbase commit into the coinbase from the work and hash up the chain
//    verify it matches the header merkle root
// 5. int Validate_checkBlock(const PacketCrypt_HeaderAndProof_t* hap,
//    uint32_t blockHeight, (from work)
//    const PacketCrypt_Coinbase_t* coinbaseCommitment,
//    const uint8_t blockHashes[static PacketCrypt_NUM_ANNS * 32],
//    PacketCrypt_ValidateCtx_t* vctx);  TODO: hashOut so we can verify it matches target
// 6. deduplicate...
// 7. if hashOut matches header.nbits, write file content to blockfile
// 8. write a result file

const Fs = require('fs');
const Crypto = require('crypto');

const nThen = require('nthen');
const Spawn = require('child_process').spawn;
const Http = require('http');

const Util = require('./Util.js');
const PoolClient = require('./PoolClient.js');
const Protocol = require('./Protocol.js');

/*::
import type { Config_t } from './Config.js';
import type { PoolClient_t } from './PoolClient.js';
import type { Util_LongPollServer_t, Util_Mutex_t } from './Util.js';
import type { ChildProcess } from 'child_process';

export type BlkHandler_Config_t = {
    url: string,
    port: number,
    threads: number,
    root: Config_t
}
type Context_t = {
    workdir: string,
    poolClient: PoolClient_t,
    uploadBlockMutex: Util_Mutex_t,
    mut: {
        hashNum: number,
        hashMod: number,

        cfg: BlkHandler_Config_t,
        checkshares: void|ChildProcess,
        outdirLongpoll: void|Util_LongPollServer_t,
        blkdirLongpoll: void|Util_LongPollServer_t,
        ready: bool
    }
};
*/

const launchCheckshares = (ctx /*:Context_t*/) => {
    const args = [
        '--threads', String(ctx.mut.cfg.threads),
        ctx.workdir + '/indir',
        ctx.workdir + '/outdir',
        ctx.workdir + '/blkdir',
        ctx.workdir + '/statedir',
    ];
    console.log(ctx.mut.cfg.root.checksharesPath + ' ' + args.join(' '));
    const checkanns = ctx.mut.checkshares = Spawn(ctx.mut.cfg.root.checksharesPath, args, {
        stdio: ['pipe', 1, 2]
    });
    checkanns.on('close', Util.once(() => {
        console.error("checkshares has died, relaunching in 1 second");
        setTimeout(() => { launchCheckshares(ctx); }, 1000);
    }));
};

const postBlock = (ctx, blockContent) => {
    Util.httpPost(ctx.mut.cfg.root.masterUrl + '/privileged/block', {}, (res) => {
        const data = [];
        res.on('data', (d) => { data.push(d); });
        res.on('end', () => {
            const result = typeof(data[0]) === 'string' ?
                data.join('') : Buffer.concat(data).toString('utf8');
            if (res.statusCode >= 400 && res.statusCode < 500) {
                console.log("Master replied [" + res.statusCode + "] [" + result +
                    "] giving up");
                return;
            }
            if (res.statusCode !== 200) {
                console.log("Master replied [" + res.statusCode + "] [" + result +
                    "] trying again in 5 seconds");
                setTimeout(() => {
                    postBlock(ctx, blockContent);
                }, 5000);
                return;
            }
            console.log("postblock OK [" + result + "]");
        });
    }).end(blockContent);
};

const uploadBlock = (ctx, file, done) => {
    let content;
    nThen((w) => {
        Fs.readFile(file, w((err, ret) => {
            if (!err) {
                content = ret;
                return;
            }
            console.log("WARNING: failed readfile [" + file + "] [" + err.message + "]");
        }));
    }).nThen((w) => {
        if (!content) { return; }
        Fs.unlink(file, w((err) => {
            if (!err) { return; }
            console.log("WARNING: failed delete [" + file + "] [" +
                err.message + "]");
        }));
    }).nThen((_) => {
        if (!content) { return; }
        console.log("Posting block [" + file + "] to master");
        postBlock(ctx, content);
        done();
    });
};

const uploadBlocks = (ctx) => {
    ctx.uploadBlockMutex((done) => {
        let files;
        nThen((w) => {
            Fs.readdir(ctx.workdir + '/blkdir', w((err, ff) => {
                if (err) {
                    console.log("WARNING: failed readdir [" + ctx.workdir + '/blkdir' + "] [" +
                        err.message + "]");
                } else {
                    files = ff.map((f) => (ctx.workdir + '/blkdir/' + f));
                }
            }));
        }).nThen((w) => {
            if (!files) { return; }
            let nt = nThen;
            files.forEach((f) => {
                nt = nThen((w) => {
                    uploadBlock(ctx, f, w());
                }).nThen;
            });
            nt(w());
        }).nThen(done);
    });
};

// strategy:
// - 1. get current work from master
// - 2. setup a longpoll server in outdir
// - 3. setup a longpoll server in blockdir but without any actual logpoll endpoint
// 4. on blockdir longpoll update
//   * http post work to master/privileged path
// - 5. wait for shares... on share:
// -  * get 4 announcement parent block numbers, cache these
// -  * write a file containing:
// -      header: number and modulo
// -      work from master
// -      4 parent hashes
// -      coinbase and header/proof
// -  * move file to indir

const getAnnParentNum = (share /*:Buffer*/, num) => {
    return share.readUInt32LE(FIRST_ANN_OFFSET + ANN_PARENT_HEIGHT_OFFSET + (1024 * num));
};

const getAnnContentHash = (share /*:Buffer*/, num) => {
    const start = FIRST_ANN_OFFSET + (1024 * num) + ANN_CONTENT_HASH_OFFSET;
    return share.slice(start, start+32);
};

// Must be greater than or equal to zero and less than current work - 3
const parentNumInRange = (ctx, num) => {
    if (!ctx.poolClient.work) { return false; }
    if (ctx.poolClient.work.height > 3 && num > (ctx.poolClient.work.height - 3)) {
        return false;
    }
    return num >= 0;
};

const onSubmit = (ctx, req, res) => {
    if (Util.badMethod('POST', req, res)) { return; }
    const payTo = req.headers['x-pc-payto'] || '';

    let failed = false;
    const errorEnd = (code, message) => {
        if (failed) { return; }
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ result: '', error: [message], warn: [] }));
    };

    const hashes = [];
    let bytes;
    nThen((w) => {
        let len = 0;
        const data = [];
        req.on('data', (d) => {
            if (len > SHARE_MAX_LENGTH) {
                errorEnd(400, "too big");
                return;
            }
            len += d.length;
            data.push(d);
        });
        req.on('end', w(() => {
            if (failed) { return; }
            if (data.length === 0) {
                errorEnd(400, 'no content');
            } else if (typeof(data[0]) === 'string') {
                errorEnd(400, 'content not binary');
            } else if (len < SHARE_MIN_LENGTH) {
                errorEnd(400, 'runt content');
            } else {
                bytes = Buffer.concat(data);
            }
        }));
    }).nThen((w) => {
        if (failed) { return; }
        [0,1,2,3].forEach((num) => {
            const parentNum = getAnnParentNum(bytes, num);
            if (!parentNumInRange(ctx, parentNum)) {
                errorEnd(400, 'announcement parent block [' + parentNum + '] out of range');
                return;
            }
            ctx.poolClient.getWorkByNum(parentNum + 1, w((work) => {
                hashes[num] = work.lastHash;
                const chash = getAnnContentHash(bytes, num);
                if (Buffer.compare(work.contentHash, chash)) {
                    errorEnd(400, 'announcement [' + num + '] invalid content hash ' +
                        'want [' + work.contentHash.toString('hex') + '] got [' +
                        chash.toString('hex') + ']');
                    return;
                }
            }));
        });
    }).nThen((w) => {
        if (failed) { return; }
        const currentWork = ctx.poolClient.work;
        if (!currentWork) {
            errorEnd(500, 'no currentWork');
            return;
        }

        const fileName = 'share_' + currentWork.height + '_' +
            Crypto.randomBytes(16).toString('hex') + '.bin';
        const fileUploadPath = ctx.workdir + '/uploaddir/' + fileName;
        const fileInPath = ctx.workdir + '/indir/' + fileName;
        /*
        typedef struct CheckShareReq_s {
            uint32_t version;
            uint8_t hashNum;
            uint8_t hashMod;
            uint16_t workLen;
            Buf32_t parentHashes[4];
            Buf64_t payTo;
            PoolProto_Work_t work;
            BlockMiner_Share_t share;
        } CheckShareReq_t;
        */

        const share = Protocol.shareDecode(bytes);
        const shareFile = Protocol.shareFileEncode({
            version: 0,
            hashNum: ctx.mut.hashNum,
            hashMod: ctx.mut.hashMod,
            hashes: hashes,
            payTo: payTo.slice(0,64),
            work: currentWork,
            share: share
        });
        Fs.writeFile(fileUploadPath, shareFile, w((err) => {
            if (err) {
                console.error("Failed to write file [" + fileUploadPath + "] [" + err.message + "]");
                return void errorEnd(500, "failed to write file [" + err.message + "]");
            }
            Fs.rename(fileUploadPath, fileInPath, w((err) => {
                if (err) {
                    return void errorEnd(500, "failed to move file [" + err.message + "]");
                }
                const out = { warn: [], error: [], result: '' };
                out.result = ctx.mut.cfg.url + '/outdir/' + fileName;
                if (!Util.isValidPayTo(payTo)) {
                    out.warn.push("invalid payto, cannot credit work");
                }
                res.end(JSON.stringify(out));
            }));
        }));
    });
};

const getResult = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const fileName = req.url.split('/').pop();
    if (!/^share_[0-9]+_[a-f0-9]+\.bin$/.test(fileName)) {
        res.statusCode = 404;
        return void res.end();
    }
    if (!ctx.mut.outdirLongpoll) { throw new Error(); }
    ctx.mut.outdirLongpoll.onReq(req, res);
};

const onReq = (ctx, req, res) => {
    if (!ctx.mut.ready) {
        res.statusCode = 500;
        return void res.end("server not ready");
    }
    if (req.url === '/submit') { return void onSubmit(ctx, req, res); }
    if (req.url.startsWith('/outdir/')) { return void getResult(ctx, req, res); }
    res.statusCode = 404;
    return void res.end(JSON.stringify({ error: "not found" }));
};

module.exports.create = (cfg /*:BlkHandler_Config_t*/) => {
    const ctx /*:Context_t*/ = Object.freeze({
        workdir: cfg.root.rootWorkdir + '/blk_' + cfg.port,
        uploadBlockMutex: Util.createMutex(),
        mut: {
            cfg: cfg,
            checkshares: undefined,
            outdirLongpoll: undefined,
            blkdirLongpoll: undefined,
            ready: false,

            hashNum: -1,
            hashMod: -1
        },
        poolClient: PoolClient.create(cfg.root.masterUrl),
    });
    nThen((w) => {
        ctx.poolClient.getMasterConf(w((conf) => {
            const url = cfg.url + '/submit';
            if (conf.submitBlockUrls.indexOf(url) === -1) {
                console.error("ERROR: This node [" + url + "] is not authorized by the master");
                console.error("Authorized nodes include " + JSON.stringify(conf.submitBlockUrls));
                console.error("shutting down");
                process.exit(100);
            }
            ctx.mut.hashMod = conf.submitBlockUrls.length;
            ctx.mut.hashNum = conf.submitBlockUrls.indexOf(url);
        }));
        ctx.poolClient.onWork((work) => {
            Util.deleteResults(
                ctx.workdir + '/outdir',
                work.height - 10,
                /share_([0-9]*)_[0-9a-f]*\.bin/);
        });
        nThen((w) => {
            Util.checkMkdir(ctx.workdir + '/indir', w());
            Util.checkMkdir(ctx.workdir + '/outdir', w());
            Util.checkMkdir(ctx.workdir + '/blkdir', w());
            Util.checkMkdir(ctx.workdir + '/statedir', w());

            Util.checkMkdir(ctx.workdir + '/uploaddir', w());
        }).nThen((w) => {
            Util.clearDir(ctx.workdir + '/uploaddir', w());
            Util.clearDir(ctx.workdir + '/blkdir', w());
        }).nThen((_) => {
            ctx.mut.outdirLongpoll = Util.longPollServer(ctx.workdir + '/outdir');
            const lp = ctx.mut.blkdirLongpoll = Util.longPollServer(ctx.workdir + '/blkdir');
            lp.onFileUpdate((_) => { uploadBlocks(ctx); });
            setInterval(() => { uploadBlocks(ctx); }, 1000);
            launchCheckshares(ctx);
        }).nThen(w());
    }).nThen((_) => {
        ctx.mut.ready = true;
    });

    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Http = require('http');
const Crypto = require('crypto');

const nThen = require('nthen');
const Tweetnacl = require('tweetnacl');
const Sema = require('saferphore');

const Protocol = require('./Protocol.js');
const Util = require('./Util.js');
const PoolClient = require('./PoolClient.js');
const Rpc = require('./Rpc.js');

const SHARE_MAX_LENGTH = 0xffff;

/*::
import type { WriteStream } from 'fs';
import type { Config_t } from './Config.js';
import type { PoolClient_t } from './PoolClient.js';
import type { Util_LongPollServer_t, Util_Mutex_t } from './Util.js';
import type { ChildProcess } from 'child_process';
import type { Rpc_Client_t } from './Rpc.js';

export type BlkHandler_Config_t = {
    url: string,
    port: number,
    host?: string,
    maxConnections?: number,
    root: Config_t
}
type Context_t = {
    workdir: string,
    poolClient: PoolClient_t,
    rpcClient: Rpc_Client_t,
    mut: {
        lastSubmission: number,
        connections: number,
        hashNum: number,
        hashMod: number,
        logStream: ?WriteStream,
        lastBlockHash: ?string,
        cfg: BlkHandler_Config_t,
        ready: bool
    }
};
*/

// Must be greater than or equal to zero and less than current work - 3
const parentNumInRange = (ctx, num) => {
    if (!ctx.poolClient.work) { return false; }
    if (ctx.poolClient.work.height > 3 && num > (ctx.poolClient.work.height - 3)) {
        return false;
    }
    return num >= 0;
};

const COMMIT_PATTERN = Buffer.from(
    "6a3009f91102fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc" +
    "fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc", 'hex');
const COMMIT_PATTERN_OS = 2;

const isZero = (buf) => {
    for (let i = buf.length - 1; i >= 0; i--) {
        if (buf[i]) { return false; }
    }
    return true;
};

const onSubmit = (ctx, req, res) => {
    if (Util.badMethod('POST', req, res)) { return; }
    const payTo = req.headers['x-pc-payto'] || '';
    const warn = [];
    if (!Util.isValidPayTo(payTo)) {
        warn.push('Address [' + payTo +
            '] is not a valid pkt address, WORK WILL NOT BE CREDITED');
        // we're not going to clear the payTo, we'll keep it anyway so that
        // we have it in the logs just in case.
    }
    if (!req.headers['x-pc-sver']) {
        warn.push("Your miner is out of date and will stop working soon, please update");
    }

    let failed = false;
    const errorEnd = (code, message) => {
        if (failed) { return; }
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ result: '', error: [message], warn: warn }));
    };

    // Additional data which is needed with the pcp
    const signatures = [];

    const hashes = [];
    let rawUpload;
    let blockTemplate;
    let currentWork;
    let hexblock;
    let submitRet;
    let headerAndProof;
    let coinbase;
    let coinbaseCommit;
    let shareId;
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
            } else if (typeof (data[0]) === 'string') {
                errorEnd(400, 'content not binary');
            } else {
                rawUpload = Buffer.concat(data);
            }
        }));
    }).nThen((w) => {
        if (failed) { return; }

        try {
            const shareObj = JSON.parse(rawUpload.toString('utf8'));
            coinbaseCommit = Buffer.from(shareObj.coinbase_commit, 'hex');
            headerAndProof = Buffer.from(shareObj.header_and_proof, 'hex');
        } catch (e) {
            return void errorEnd(400, "Upload is not parsable as json");
        }

        const proofMarker = Util.parseVarInt(headerAndProof.slice(80));
        if (proofMarker[0] !== Protocol.PC_PCP_TYPE) {
            return void errorEnd(400, "First element after header must be Pcp");
        }
        const proofLen = Util.parseVarInt(headerAndProof.slice(81));
        const proof = headerAndProof.slice(81 + proofLen[1], 81 + proofLen[1] + proofLen[0]);
        shareId = Util.getShareId(headerAndProof.slice(0, 80), proof);

        currentWork = ctx.poolClient.work;
        if (!currentWork) {
            return void errorEnd(500, 'no currentWork');
        }

        // If the previous block hash doesn't match that of the current work, then the
        // share is for the wrong work (maybe it's too old?)
        const sharePrevHash = headerAndProof.slice(4, 36);
        const currentWorkPrevHash = currentWork.header.slice(4, 36);
        if (currentWorkPrevHash.compare(sharePrevHash)) {
            return void errorEnd(400, "Share is for wrong work, expecting previous hash [" +
                currentWorkPrevHash.toString('hex') + "] but got [" +
                sharePrevHash.toString('hex') + ']');
        }

        // Swap the header from the current work over top of the header in the hap
        do {
            const header = Buffer.from(currentWork.header);
            const merkleRoot = headerAndProof.slice(36, 68);
            merkleRoot.copy(header, 36);
            const nonce = headerAndProof.slice(76, 80);
            nonce.copy(header, 76);
            header.copy(headerAndProof);
        } while (0);

        // Make sure we are able to get the block template, this is zero cost after the
        // first time it's tried...
        // If we're not able to get it then we cannot submit a block.
        ctx.poolClient.getBlockTemplate(w((err, bt) => {
            if (err) { return void errorEnd(500, "Unable to get block template"); }
            blockTemplate = bt;
        }));

        let nt = nThen;
        [0, 1, 2, 3].forEach((num) => {
            if (failed) { return; }
            const os = 4 + (1024 * num);
            const ann = proof.slice(os, os + 1024);

            const parentNum = ann.readUInt32LE(Protocol.ANN_PARENT_HEIGHT_OFFSET);
            const sigKey = ann.slice(
                Protocol.ANN_SIGNING_KEY_OFFSET,
                Protocol.ANN_SIGNING_KEY_OFFSET + 32);

            // Verify the parent number is ok
            if (!parentNumInRange(ctx, parentNum)) {
                errorEnd(400, 'announcement parent block [' + parentNum + '] out of range');
                return;
            }

            if (!isZero(sigKey)) {
                // Signing keys...
                const keys = Util.getKeypair(ctx.mut.cfg.root, parentNum + 1);
                if (!keys) {
                    errorEnd(400, `announcement [${num}] needs signing key ` +
                        `[${sigKey.toString('hex')}] but no key is configured`);
                    return;
                } else {
                    const pubKey = Buffer.from(keys.publicKey);
                    if (Buffer.compare(pubKey, sigKey)) {
                        errorEnd(400, 'announcement [' + num + '] invalid signing key ' +
                            'want [' + pubKey.toString('hex') + '] got [' +
                            sigKey.toString('hex') + ']');
                        return;
                    }
                }

                signatures.push(Tweetnacl.sign.detached(ann, keys.secretKey));
            }

            // Block header hashes
            ctx.poolClient.getWorkByNum(parentNum + 1, w((work) => {
                hashes[num] = work.lastHash;
            }));
        });
        nt(w());

    }).nThen((w) => {
        if (failed) { return; }
        const blockTopArr = [
            headerAndProof
        ];
        if (signatures.length > 0) {
            blockTopArr.push(Util.mkVarInt(Protocol.PC_SIGNATURES_TYPE));
            const sigs = Buffer.concat(signatures);
            blockTopArr.push(Util.mkVarInt(sigs.length));
            blockTopArr.push(sigs);
            //console.error("Added " + sigs.length + " bytes of signatures");
        } else {
            //console.error("no signatures");
        }
        blockTopArr.push(Util.mkVarInt(Protocol.PC_END_TYPE), Util.mkVarInt(0));
        hexblock = Buffer.concat(blockTopArr).toString('hex');

        // just to please flow
        if (!currentWork) { throw new Error(); }
        if (!blockTemplate) { throw new Error(); }

        coinbase = Buffer.from(blockTemplate.transactions[0], 'hex');
        const idx = coinbase.indexOf(COMMIT_PATTERN);
        if (idx < 0) {
            return void errorEnd(500, "Commit pattern not present in blockTemplate");
        }
        coinbaseCommit.copy(coinbase, idx + COMMIT_PATTERN_OS);

        const toSubmit = {
            height: currentWork.height,
            sharetarget: currentWork.shareTarget,
            hexblock: hexblock + '00', // no transactions
            coinbase: coinbase.toString('hex'),
            merklebranch: currentWork.proof.map((x) => x.toString('hex'))
        };

        //console.error(toSubmit);

        ctx.rpcClient.checkPcShare(toSubmit, w((err, ret) => {
            if (err) {
                console.error(err);
                return void errorEnd(400, "Failed validation of share [" + JSON.stringify(err) + "]");
            }
            if (!ret) {
                return void errorEnd(400, "Failed validation of share, no reply");
            }
            submitRet = ret.result;
        }));
    }).nThen((w) => {
        if (failed) { return; }
        if (!currentWork) { return; }
        const shareTarget = currentWork.shareTarget;
        const now = +new Date();
        const cbc = Protocol.coinbaseCommitDecode(coinbaseCommit);
        // Multiply by 2 because even at difficulty 1, 50% of all hashes are no good
        const encryptions = Number(Util.getEffectiveWork(shareTarget, cbc.annMinWork, cbc.annCount)) * 2;
        if (submitRet === 'RESUBMIT_AS_BLOCK' && now - ctx.mut.lastSubmission > 120000) {
            ctx.mut.lastSubmission = now;
            if (!blockTemplate) { throw new Error(); }

            const wholeBlock =
                hexblock +
                Util.mkVarInt(blockTemplate.transactions.length).toString('hex') +
                coinbase.toString('hex') +
                blockTemplate.transactions.slice(1).join('');

            ctx.rpcClient.submitBlock(wholeBlock, w((err, ret) => {
                if (!err && ret) { err = ret.result; }
                if (err) {
                    console.error("error:");
                    console.error(err);
                    const serr = String(err);
                    if (serr.indexOf("rejected: already have block") === 0) {
                        errorEnd(409, "already have block");
                    } else {
                        errorEnd(400, "error submitting block [" + serr + "]");
                    }
                } else {
                    const headerHash = Crypto.createHash('sha256').update(
                        Crypto.createHash('sha256').update(headerAndProof.slice(0, 80)).digest()
                    ).digest().reverse().toString('hex');
                    const result = {
                        result: {
                            type: 'share',
                            payTo: payTo,
                            block: true,
                            time: +new Date(),
                            eventId: shareId.toString('hex'),
                            headerHash: headerHash,
                            target: shareTarget,
                            annCount: cbc.annCount.toString(),
                            annMinWork: cbc.annMinWork,
                            encryptions,
                        },
                        error: [],
                        warn: warn
                    };

                    const out = JSON.stringify(result.result);
                    console.log(out);
                    if (!ctx.mut.logStream) { throw new Error(); }
                    ctx.mut.logStream.write(out + '\n');

                    res.end(JSON.stringify(result));
                }
            }));
            return;
        } else if (submitRet === 'OK' || submitRet === 'RESUBMIT_AS_BLOCK') {
            const result = {
                result: {
                    type: 'share',
                    payTo: payTo,
                    block: false,
                    time: +new Date(),
                    eventId: shareId.toString('hex'),
                    target: shareTarget,
                    annCount: cbc.annCount.toString(),
                    annMinWork: cbc.annMinWork,
                    encryptions,
                },
                error: [],
                warn: warn
            };

            const out = JSON.stringify(result.result);
            console.log(out);
            if (!ctx.mut.logStream) { throw new Error(); }
            ctx.mut.logStream.write(out + '\n');

            res.end(JSON.stringify(result));
            return;
        }
        console.error(submitRet);
        return void errorEnd(500, "Unexpected result from btcd [" + String(submitRet) + "]");
    });
};

const maxConnections = (ctx) => {
    return ctx.mut.cfg.maxConnections || 50;
};

const onReq = (ctx, req, res) => {
    if (!ctx.mut.ready) {
        res.statusCode = 500;
        return void res.end("server not ready");
    }
    if (ctx.mut.connections > maxConnections(ctx)) {
        res.statusCode = 501;
        return void res.end("overloaded");
    }
    ctx.mut.connections++;
    res.on('close', () => {
        ctx.mut.connections--;
    });
    if (req.url === '/submit') { return void onSubmit(ctx, req, res); }
    res.statusCode = 404;
    return void res.end(JSON.stringify({ error: "not found" }));
};

module.exports.create = (cfg /*:BlkHandler_Config_t*/) => {
    const ctx /*:Context_t*/ = Object.freeze({
        workdir: cfg.root.rootWorkdir + '/blk_' + cfg.port,
        rpcClient: Rpc.create(cfg.root.rpc),
        mut: {
            cfg: cfg,
            ready: false,
            lastBlockHash: undefined,
            logStream: undefined,
            connections: 0,
            lastSubmission: 0,

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
        Util.checkMkdir(ctx.workdir + '/paylogdir', w());
    }).nThen((w) => {
        Util.openPayLog(ctx.workdir + '/paylogdir', w((stream) => {
            ctx.mut.logStream = stream;
        }));
    }).nThen((_) => {
        setInterval(() => {
            nThen((w) => {
                Util.openPayLog(ctx.workdir + '/paylogdir', w((stream) => {
                    if (!ctx.mut.logStream) { throw new Error(); }
                    ctx.mut.logStream.close();
                    ctx.mut.logStream = stream;
                }));
            }).nThen((w) => {
                Util.uploadPayLogs(
                    ctx.workdir + '/paylogdir',
                    ctx.poolClient.config.paymakerUrl + '/events',
                    ctx.mut.cfg.root.paymakerHttpPasswd,
                    false,
                    () => { }
                );
            });
        }, 60000);
        ctx.mut.ready = true;
    });
    ctx.poolClient.onWork((w) => {
        // Lets allow immediate blocks once again
        ctx.mut.lastSubmission = 0;
        const hash = Buffer.from(w.lastHash).reverse().toString('hex');
        if (!ctx.mut.lastBlockHash) {
            // first start
            ctx.mut.lastBlockHash = hash;
            return;
        }
        if (ctx.mut.lastBlockHash === hash) {
            // dupe
            return;
        }
        ctx.mut.lastBlockHash = hash;
        ctx.rpcClient.getBlock(hash, (err, ret) => {
            if (!err && ret && ret.error) { err = ret.error; }
            if (err) {
                return void console.error("onWork unable to call getBlock [" + JSON.stringify(err) + "]");
            }
            if (!ret) {
                return void console.error("onWork ret missing without error");
            }
            if (!ret.result) {
                return void console.error("onWork result missing in ret [" + JSON.stringify(ret) + "]");
            }
            const height = ret.result.height;
            const diff = ret.result.difficulty;
            if (!height) {
                return void console.error("onWork missing height");
            }
            if (!diff) {
                return void console.error("onWork missing difficulty");
            }
            const out = JSON.stringify({
                type: 'block',
                hash: hash,
                height: height,
                difficulty: diff,
                time: +new Date(),
                eventId: hash.slice(0, 32)
            });
            console.log(out);
            if (!ctx.mut.logStream) { throw new Error(); }
            ctx.mut.logStream.write(out + '\n');
        });
    });

    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port, cfg.host);
};

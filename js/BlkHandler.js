/*@flow*/
const nThen = require('nthen');
const Http = require('http');
const Tweetnacl = require('tweetnacl');

const Protocol = require('./Protocol.js');
const Util = require('./Util.js');
const PoolClient = require('./PoolClient.js');
const Rpc = require('./Rpc.js');

const SHARE_MAX_LENGTH = 0xffff;

/*::
import type { Config_t } from './Config.js';
import type { PoolClient_t } from './PoolClient.js';
import type { Util_LongPollServer_t, Util_Mutex_t } from './Util.js';
import type { ChildProcess } from 'child_process';
import type { Rpc_Client_t } from './Rpc.js';

export type BlkHandler_Config_t = {
    url: string,
    port: number,
    root: Config_t
}
type Context_t = {
    poolClient: PoolClient_t,
    rpcClient: Rpc_Client_t,
    mut: {
        hashNum: number,
        hashMod: number,

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
    "6a3009f91102fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc"+
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

    let failed = false;
    const errorEnd = (code, message) => {
        if (failed) { return; }
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ result: '', error: [message], warn: [] }));
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

        const proofLen = Util.parseVarInt(headerAndProof.slice(81));
        const proof = headerAndProof.slice(81 + proofLen[1], 81 + proofLen[1] + proofLen[0]);
        do {
            const cpi = Util.getContentProofIdx(headerAndProof.slice(0,80), proof);
            //console.error("Share proof idx " + cpi);
            if (cpi % ctx.mut.hashMod !== ctx.mut.hashNum) {
                return void errorEnd(400, "Share posted to wrong block handler");
            }
        } while (0);

        currentWork = ctx.poolClient.work;
        if (!currentWork) {
            return void errorEnd(500, 'no currentWork');
        }

        // If the previous block hash doesn't match that of the current work, then the
        // share is for the wrong work (maybe it's too old?)
        const sharePrevHash = headerAndProof.slice(4,36);
        const currentWorkPrevHash = currentWork.header.slice(4,36);
        if (currentWorkPrevHash.compare(sharePrevHash)) {
            return void errorEnd(400, "Share is for wrong work, expecting previous hash [" +
                currentWorkPrevHash.toString('hex') + "] but got [" +
                sharePrevHash.toString('hex') + ']');
        }

        // Swap the header from the current work over top of the header in the hap
        do {
            const header = Buffer.from(currentWork.header);
            const merkleRoot = headerAndProof.slice(36,68);
            merkleRoot.copy(header, 36);
            const nonce = headerAndProof.slice(76,80);
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
        [0,1,2,3].forEach((num) => {
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
                if (Buffer.compare(keys.publicKey, sigKey)) {
                    errorEnd(400, 'announcement [' + num + '] invalid signing key ' +
                        'want [' + keys.publicKey.toString('hex') + '] got [' +
                        sigKey.toString('hex') + ']');
                    return;
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
        if (submitRet === 'RESUBMIT_AS_BLOCK') {
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
                    const result = JSON.stringify({
                        result: {
                            payTo: payTo,
                            ok: true,
                            block: false
                        },
                        error: [],
                        warn: []
                    });
                    console.log(result);
                    res.end(result);
                }
            }));
            return;
        } else if (submitRet === 'OK') {
            const result = JSON.stringify({
                result: {
                    payTo: payTo,
                    ok: true,
                    block: true
                },
                error: [],
                warn: []
            });
            console.log(result);
            res.end(result);
            return;
        }
        console.error(submitRet);
        return void errorEnd(500, "Unexpected result from btcd [" + String(submitRet) + "]");
    });
};

const onReq = (ctx, req, res) => {
    if (!ctx.mut.ready) {
        res.statusCode = 500;
        return void res.end("server not ready");
    }
    if (req.url === '/submit') { return void onSubmit(ctx, req, res); }
    res.statusCode = 404;
    return void res.end(JSON.stringify({ error: "not found" }));
};

module.exports.create = (cfg /*:BlkHandler_Config_t*/) => {
    const ctx /*:Context_t*/ = Object.freeze({
        rpcClient: Rpc.create(cfg.root.rpc),
        mut: {
            cfg: cfg,
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
    }).nThen((_) => {
        ctx.mut.ready = true;
    });

    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

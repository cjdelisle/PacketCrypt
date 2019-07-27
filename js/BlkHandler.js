/*@flow*/
const BLOCK_HEADER_OFFSET = 32+8+4+4;
const PROOF_OFFSET = BLOCK_HEADER_OFFSET+80+4;
const FIRST_ANN_OFFSET = PROOF_OFFSET+4;
const ANN_CONTENT_LENGTH_OFFSET = 20;
const ANN_PARENT_HEIGHT_OFFSET = 12;
const ANN_SIGNING_KEY_OFFSET = 56;
const SHARE_MIN_LENGTH = (32+8+4+4)+(80+4+4+(1024*4));
const SHARE_MAX_LENGTH = SHARE_MIN_LENGTH * 4;

const END_TYPE = 0;
const PCP_TYPE = 1;
const SIGNATURES_TYPE = 2;
const CONTENTPROOFS_TYPE = 3;

const nThen = require('nthen');
const Http = require('http');
const Tweetnacl = require('tweetnacl');
const Blake2b = require('blake2b');
const MerkleTree = require('merkletreejs').MerkleTree;

const Util = require('./Util.js');
const PoolClient = require('./PoolClient.js');
const Rpc = require('./Rpc.js');

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

const b2hash = (content) => Blake2b(32).update(content).digest(Buffer.alloc(32));

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
        const mt = new MerkleTree(arr, b2hash);
        return mkProof(mt, arr, blocknum);
    };

    return mkMerkleProof;
})();

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
    const contentProofs = [];

    const hashes = [];
    let bytes;
    let blockTemplate;
    let currentWork;
    let hexblock;
    let submitRet;
    let header;
    let coinbase;
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

        const shareHash = b2hash(bytes.slice(PROOF_OFFSET));
        const contentProofIdx = shareHash.readUInt32LE(0);
        //console.log("Share proof idx " + contentProofIdx);
        if (contentProofIdx % ctx.mut.hashMod !== ctx.mut.hashNum) {
            return void errorEnd(400, "Share posted to wrong block handler");
        }

        currentWork = ctx.poolClient.work;
        if (!currentWork) {
            return void errorEnd(500, 'no currentWork');
        }

        // If the previous block hash doesn't match that of the current work, then the
        // share is for the wrong work (maybe it's too old?)
        const sharePrevHash = bytes.slice(BLOCK_HEADER_OFFSET+4,BLOCK_HEADER_OFFSET+36);
        const currentWorkPrevHash = currentWork.header.slice(4,36);
        if (currentWorkPrevHash.compare(sharePrevHash)) {
            return void errorEnd(400, "Share is for wrong work, expecting previous hash [" +
                currentWorkPrevHash.toString('hex') + "] but got [" +
                sharePrevHash.toString('hex') + ']');
        }

        header = Buffer.from(currentWork.header);
        const merkleRoot = bytes.slice(BLOCK_HEADER_OFFSET+36,BLOCK_HEADER_OFFSET+68);
        merkleRoot.copy(header, 36);
        const nonce = bytes.slice(BLOCK_HEADER_OFFSET+76,BLOCK_HEADER_OFFSET+80);
        nonce.copy(header, 76);

        // Make sure we are able to get the block template, this is zero cost after the
        // first time it's tried...
        // If we're not able to get it then we cannot submit a block.
        ctx.poolClient.getBlockTemplate(w((err, bt) => {
            if (err) { return void errorEnd(500, "Unable to get block template"); }
            blockTemplate = bt;
        }));

        let nt = nThen;
        [0,1,2,3].forEach((num) => {
            const os = FIRST_ANN_OFFSET + (1024 * num);
            const ann = bytes.slice(os, os + 1024);

            const parentNum = ann.readUInt32LE(ANN_PARENT_HEIGHT_OFFSET);
            const sigKey = ann.slice(ANN_SIGNING_KEY_OFFSET, ANN_SIGNING_KEY_OFFSET + 32);
            const contentLen = ann.readUInt32LE(ANN_CONTENT_LENGTH_OFFSET);

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

            // Get announcement content for each ann...
            if (contentLen > 32) {
                const annHash = Blake2b(32).update(ann).digest(Buffer.alloc(32));
                nt = nt((w) => {
                    ctx.poolClient.getAnn(annHash, w((err, content) => {
                        if (err || !content) {
                            errorEnd(400, 'announcement [' + num + '] content is not known');
                            return;
                        }
                        content = content.slice(1024);
                        //console.log('ann ' + annHash.toString('hex') + ' content length ' + content.length);
                        contentProofs.push(mkMerkleProof(content, contentProofIdx));
                    }));
                }).nThen;
            }

            // Block header hashes
            ctx.poolClient.getWorkByNum(parentNum + 1, w((work) => {
                hashes[num] = work.lastHash;
            }));
        });
        nt(w());

    }).nThen((w) => {
        if (failed) { return; }
        // submit: header, length ( type, pcp ), length ( type, signatures ), length ( type, contentProofs )
        const pcp = bytes.slice(PROOF_OFFSET);
        const blockTopArr = [
            header,
            Util.mkVarInt(PCP_TYPE),
            Util.mkVarInt(pcp.length),
            pcp
        ];
        if (signatures.length > 0) {
            blockTopArr.push(Util.mkVarInt(SIGNATURES_TYPE));
            const sigs = Buffer.concat(signatures);
            blockTopArr.push(Util.mkVarInt(sigs.length));
            blockTopArr.push(sigs);
            console.log("Added " + sigs.length + " bytes of signatures");
        } else {
            console.log("no signatures");
        }
        if (contentProofs.length > 0) {
            blockTopArr.push(Util.mkVarInt(CONTENTPROOFS_TYPE));
            const proofs = Buffer.concat(contentProofs);
            blockTopArr.push(Util.mkVarInt(proofs.length));
            blockTopArr.push(proofs);
        }
        blockTopArr.push(Util.mkVarInt(END_TYPE), Util.mkVarInt(0));
        const blockTop = Buffer.concat(blockTopArr);

        // just to please flow
        if (!currentWork) { throw new Error(); }
        if (!blockTemplate) { throw new Error(); }

        coinbase = Buffer.from(blockTemplate.transactions[0], 'hex');
        const idx = coinbase.indexOf(COMMIT_PATTERN);
        if (idx < 0) {
            return void errorEnd(500, "Commit pattern not present in blockTemplate");
        }
        bytes.slice(0, BLOCK_HEADER_OFFSET).copy(coinbase, idx + COMMIT_PATTERN_OS);

        hexblock = blockTop.toString('hex');
        const toSubmit = {
            height: currentWork.height,
            sharetarget: currentWork.shareTarget,
            hexblock: hexblock + '00', // no transactions
            coinbase: coinbase.toString('hex'),
            merklebranch: currentWork.proof.map((x) => x.toString('hex'))
        };

        //console.log(toSubmit);

        ctx.rpcClient.checkPcShare(toSubmit, w((err, ret) => {
            if (err) {
                console.log(err);
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
                    const serr = String(err);
                    if (serr.indexOf("rejected: already have block") === 0) {
                        res.statusCode = 409;
                    } else {
                        res.statusCode = 400;
                    }
                    res.end("Error submitting block [" + String(err) + "]");
                    console.log("error:");
                    console.log(err);
                } else {
                    console.log("Good share from [" + payTo + "]");
                    res.end("OK");
                }
            }));
            return;
        } else if (submitRet === 'OK') {
            console.log("Good share from [" + payTo + "]");
            res.end("OK");
            return;
        }
        console.log(submitRet);
        return void errorEnd(500, "Unexpected result from mantled [" + String(submitRet) + "]");
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

/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const Http = require('http');
const nThen = require('nthen');
const { hash } = require('tweetnacl');
const WriteFileAtomic = require('write-file-atomic');

const Protocol = require('./Protocol.js');
const Rpc = require('./Rpc.js');
const Util = require('./Util.js');

/*::
import type { WriteStream } from 'fs'
import type { IncomingMessage, ServerResponse } from 'http'
import type {
    Protocol_RawBlockTemplate_t,
    Protocol_Work_t,
    Protocol_PcConfigJson_t,
    Protocol_BlockInfo_t,
} from './Protocol.js'
import type { Rpc_Client_t } from './Rpc.js';
import type { Util_LongPollServer_t } from './Util.js';
import type { Config_t } from './Config.js';

export type Master_Config_t = {
    root: Config_t,
    port: number,
    host?: string,
    annMinWork: number,
    shareWorkDivisor?: number,
    shareMinWork?: number,
    annVersions: Array<number>,
    mineOldAnns?: number,
};

type State_t = {|
    work: Protocol_Work_t,
    blockTemplate: Buffer
|};

type Context_t = {
    workdir: string,
    rpcClient: Rpc_Client_t,
    longPollServer: Util_LongPollServer_t,
    blkInfo: {[string]:Protocol_BlockInfo_t},
    mut: {
        cfg: Master_Config_t,
        longPollId: void|string,
        state: void|State_t,

        blockTar: number,
        shareTar: number
    }
}
*/

const CHAIN_HISTORY_DEPTH = 1000;

const headers = (res) => {
    res.setHeader("cache-control", "max-age=1000");
    res.setHeader("content-type", "application/octet-stream");
};

const computeShareTar = (blockTarget /*:number*/, divisor /*:number*/) => {
    return Util.workMultipleToTarget(Util.getWorkMultiple(blockTarget) / divisor);
};

const populateBlkInfo = (ctx /*:Context_t*/, hash /*:string*/, done) => {
    if (hash in ctx.blkInfo) {
        return void done();
    }
    ctx.rpcClient.getBlockHeader(hash, true, (err, ret) => {
        if (err) {
        } else if (!ret) {
        } else if (!ret.result) {
        } else if (!ret.result.previousblockhash) {
        } else if (!/^[a-f0-9]{64}$/.test(ret.result.previousblockhash)) {
        } else {
            // These are not fixed and we want to be able to cache the result forever
            const confs = ret.result.confirmations;
            delete ret.result.confirmations;
            delete ret.result.nextblockhash;

            console.error(`Got block header [${hash} @ ${ret.result.height}]`);

            // We add 1 to the height when computing the keypair because originally
            // the signing keys were attached to the work and the height given in the
            // work is "next" height, but ann miners grab the prev hash out of the
            // template block header to get a hash to work with.
            const keyPair = Util.getKeypair(ctx.mut.cfg.root, ret.result.height + 1);
            const sigKey = keyPair ? Buffer.from(keyPair.publicKey).toString('hex') : null;
            ctx.blkInfo[hash] = {
                header: ret.result,
                sigKey: sigKey,
            };
            if (confs < CHAIN_HISTORY_DEPTH) {
                populateBlkInfo(ctx, ret.result.previousblockhash, done);
            } else {
                done();
            }
            return;
        }
        console.error(`Error getting block header [${hash}], trying again in 5 seconds...`);
        console.error(err);
        console.error(ret);
        setTimeout(() => {
            populateBlkInfo(ctx, hash, done);
        }, 5000);
    });
};

const onBlock = (ctx /*:Context_t*/) => {
    let state;
    let newState;
    let done;
    nThen((w) => {
        // Make work entry
        const startTime = +new Date();
        console.error("begin getrawblocktemplate");
        ctx.rpcClient.getRawBlockTemplate(w((err, ret) => {
            const time = (+new Date()) - startTime;
            console.error("getrawblocktemplate done in " + String(time) + "ms");
            if (err || !ret) {
                console.error("Error getting block template, trying again in 10 seconds...");
                console.error(err);
                console.error(ret);
                setTimeout(() => {
                    onBlock(ctx);
                }, 10000);
                w.abort();
                return;
            }

            const header = Util.bufFromHex(ret.result.header);
            populateBlkInfo(ctx, header.slice(4, 4 + 32).reverse().toString('hex'), w());
            const blockTar = header.readUInt32LE(72);
            if (blockTar !== ctx.mut.blockTar) {
                if (typeof (ctx.mut.cfg.shareWorkDivisor) === 'number') {
                    ctx.mut.shareTar = computeShareTar(blockTar, ctx.mut.cfg.shareWorkDivisor);
                } else if (typeof (ctx.mut.cfg.shareMinWork) === 'number') {
                    ctx.mut.shareTar = ctx.mut.cfg.shareMinWork;
                } else {
                    // nothing specified, pick a reasonable default.
                    console.error("neither shareWorkDivisor nor shareMinWork were specified");
                    console.error("defaulting to shareWorkDivisor = 64");
                    ctx.mut.shareTar = computeShareTar(blockTar, 64);
                }
                ctx.mut.blockTar = blockTar;
            }

            const keyPair = Util.getKeypair(ctx.mut.cfg.root, ret.result.height);
            const sigKey = keyPair ? keyPair.publicKey : undefined;
            let work = Protocol.workFromRawBlockTemplate(ret.result, sigKey,
                ctx.mut.shareTar, ctx.mut.cfg.annMinWork);
            newState = Object.freeze({
                work: work,
                blockTemplate: Protocol.blockTemplateEncode(ret.result)
            });
        }));
    }).nThen((w) => {
        // Check if the work file exists already, if it does then we're going
        // to load it and override our new state to avoid miners submitting
        // shares on the old state and getting rejected.
        const fileName = ctx.workdir + '/work_' + newState.work.height + '.bin';
        const fileNameBT = ctx.workdir + '/bt_' + newState.work.height + '.bin';
        let work;
        let blockTemplate;
        nThen((w) => {
            Fs.readFile(fileName, w((err, ret) => {
                if (err) {
                    if (err.code !== 'ENOENT') { throw err; }
                    return;
                }
                work = Protocol.workDecode(ret);
            }));
            Fs.readFile(fileNameBT, w((err, ret) => {
                if (err) {
                    if (err.code !== 'ENOENT') { throw err; }
                    return;
                }
                blockTemplate = ret;
            }));
        }).nThen((w) => {
            if (work && blockTemplate) {
                console.error("Using an existing block template for block [" +
                    newState.work.height + "]");
                state = Object.freeze({
                    work: work,
                    blockTemplate: blockTemplate
                });
            } else {
                state = newState;
            }
        }).nThen(w());
    }).nThen((w) => {
        if (state !== newState) { return; }
        nThen((w) => {
            // Store the work to disk and also write out the content mapping
            const fileName = ctx.workdir + '/work_' + state.work.height + '.bin';
            const again = () => {
                WriteFileAtomic(fileName, state.work.binary, w((err) => {
                    if (!err) { return; }
                    console.error("Failed to write work to disk [" + err +
                        "], trying again in 1 second");
                    setTimeout(w(again), 1000);
                    return;
                }));
            };
            again();

            const fileNameBT = ctx.workdir + '/bt_' + state.work.height + '.bin';
            const againBT = () => {
                WriteFileAtomic(fileNameBT, state.blockTemplate, w((err) => {
                    if (!err) { return; }
                    console.error("Failed to write block template to disk [" + err +
                        "], trying again in 1 second");
                    setTimeout(w(againBT), 1000);
                    return;
                }));
            };
            againBT();
        }).nThen(w());
    }).nThen((w) => {
        ctx.mut.state = state;
        const work = state.work;
        const lastHash = work.lastHash.reverse().toString('hex');
        console.error("Next block " + work.height + " " + lastHash);
        const again = () => {
            //console.error('getBestBlockHash');
            ctx.rpcClient.getBestBlockHash(w((err, ret) => {
                //console.error('getBestBlockHash done');
                if (err || !ret || !ret.result) {
                    console.error(err);
                    setTimeout(w(again), 1000);
                    return;
                } else {
                    if (lastHash !== ret.result) {
                        console.error("Block found " + ret.result);
                        done = true;
                        onBlock(ctx);
                    } else {
                        setTimeout(w(again), 1000);
                    }
                }

            }));
        };
        again();
    }).nThen((_) => {
        if (!done) {
            console.error("This should never happen");
        }
    });
};

const mkConfig = (
    cfg /*:Master_Config_t*/,
    tipHash /*:string*/,
    height /*:number*/
) /*:Protocol_PcConfigJson_t*/ => {
    return {
        tipHash,
        currentHeight: height,
        masterUrl: cfg.root.masterUrl,
        submitAnnUrls: cfg.root.annHandlers.map((x) => (x.url + '/submit')),
        downloadAnnUrls: cfg.root.annHandlers.map((x) => (x.url)),
        submitBlockUrls: cfg.root.blkHandlers.map((x) => (x.url + '/submit')),
        paymakerUrl: cfg.root.payMaker.url,
        version: Protocol.VERSION,
        softVersion: Protocol.SOFT_VERSION,
        annVersions: cfg.annVersions || [0],
        mineOldAnns: cfg.mineOldAnns || 0,
        annTarget: cfg.annMinWork,
    };
};
module.exports.mkConfig = mkConfig;

const configReq = (
    cfg /*:Master_Config_t*/,
    tipHash /*:string*/,
    height /*:number*/,
    _req /*:IncomingMessage*/,
    res /*:ServerResponse*/
) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'max-age=8 stale-while-revalidate=2');
    res.end(JSON.stringify(mkConfig(cfg, tipHash, height), null, '\t'));
};
module.exports.configReq = configReq;

const onReq = (ctx /*:Context_t*/, req, res) => {
    if (!ctx.mut.state) {
        res.statusCode = 500;
        res.end("Server not ready");
        return;
    }
    const state = ctx.mut.state;
    if (req.url.endsWith('/config.json')) {
        configReq(ctx.mut.cfg, state.work.lastHash.toString('hex'), state.work.height, req, res);
        return;
    }
    let worknum = -1;
    req.url.replace(/.*\/work_([0-9]+)\.bin$/, (_, num) => ((worknum = Number(num)) + ''));
    if (worknum < 0 || isNaN(worknum)) {
    } else if (worknum === (state.work.height + 1)) {
        headers(res);
        ctx.longPollServer.onReq(req, res);
        return;
    } else {
        const fileName = ctx.workdir + '/work_' + worknum + '.bin';
        Fs.stat(fileName, (err, st) => {
            if (err || !st.isFile()) {
                res.statusCode = 404;
                res.end('');
            } else {
                headers(res);
                Fs.createReadStream(fileName).pipe(res);
            }
        });
        return;
    }

    req.url.replace(/.*\/bt_([0-9]+)\.bin$/, (_, num) => ((worknum = Number(num)) + ''));
    if (worknum < 0 || isNaN(worknum)) {
    } else {
        const fileName = ctx.workdir + '/bt_' + worknum + '.bin';
        Fs.stat(fileName, (err, st) => {
            if (err || !st.isFile()) {
                res.statusCode = 404;
                res.end('');
            } else {
                headers(res);
                Fs.createReadStream(fileName).pipe(res);
            }
        });
        return;
    }

    let maybehash;
    req.url.replace(/.*\/blkinfo_([0-9a-f]{64})\.json$/, (_, h) => { maybehash = h; return ''; });
    if (maybehash && maybehash in ctx.blkInfo) {
        res.setHeader("content-type", "application/json");
        res.setHeader("cache-control", "max-age=999999999");
        res.end(JSON.stringify(ctx.blkInfo[maybehash], null, '\t'));
        return;
    }

    res.statusCode = 404;
    res.end('Not found');
    return;
};

module.exports.create = (cfg /*:Master_Config_t*/) => {
    const workdir = cfg.root.rootWorkdir + '/master_' + cfg.port;
    nThen((w) => {
        Util.checkMkdir(workdir, w());
    }).nThen((w) => {
        const ctx = Object.freeze({
            workdir: workdir,
            rpcClient: Rpc.create(cfg.root.rpc),
            longPollServer: Util.longPollServer(workdir),
            blkInfo: {},
            mut: {
                cfg: cfg,
                longPollId: undefined,
                state: undefined,

                blockTar: 0,
                shareTar: 0
            }
        });
        Http.createServer((req, res) => {
            onReq(ctx, req, res);
        }).listen(cfg.port, cfg.host);
        console.error("This pool master is configured to run with the following workers:");
        cfg.root.annHandlers.forEach((h) => { console.error(" - AnnHandler: " + h.url); });
        cfg.root.blkHandlers.forEach((h) => { console.error(" - BlkHandler: " + h.url); });
        console.error("It will tell miners to send their work to those urls.");
        console.error();
        onBlock(ctx);
    });
};

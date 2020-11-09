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
const WriteFileAtomic = require('write-file-atomic');

const Protocol = require('./Protocol.js');
const Rpc = require('./Rpc.js');
const Util = require('./Util.js');

/*::
import type { WriteStream } from 'fs'
import type { IncomingMessage, ServerResponse } from 'http'
import type { Protocol_RawBlockTemplate_t, Protocol_Work_t, Protocol_PcConfigJson_t } from './Protocol.js'
import type { Rpc_Client_t } from './Rpc.js';
import type { Util_LongPollServer_t } from './Util.js';
import type { Config_t } from './Config.js';

export type Master_Config_t = {
    root: Config_t,
    port: number,
    annMinWork: number,
    shareWorkDivisor?: number,
    shareMinWork?: number,
    annVersions: Array<number>,
    mineOldAnns?: number,
};

type State_t = {
    work: Protocol_Work_t,
    keyPair: {
        secretKey: Uint8Array,
        publicKey: Uint8Array
    },
    blockTemplate: Buffer
};

type Context_t = {
    workdir: string,
    rpcClient: Rpc_Client_t,
    longPollServer: Util_LongPollServer_t,
    hashCache: {[string]:string},
    keyCache: {[number]:string},
    mut: {
        cfg: Master_Config_t,
        longPollId: void|string,
        state: void|State_t,

        blockTar: number,
        shareTar: number
    }
}
*/

const headers = (res) => {
    res.setHeader("cache-control", "max-age=1000");
    res.setHeader("content-type", "application/octet-stream");
};

const reverseBuffer = (buf) => {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) { out[out.length-1-i] = buf[i]; }
    return out;
};

const computeShareTar = (blockTarget /*:number*/, divisor /*:number*/) => {
    return Util.workMultipleToTarget( Util.getWorkMultiple(blockTarget) / divisor );
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
            const keyPair = Util.getKeypair(ctx.mut.cfg.root, ret.result.height);
            const header = Util.bufFromHex(ret.result.header);
            const blockTar = header.readUInt32LE(72);
            if (blockTar !== ctx.mut.blockTar) {
                if (typeof(ctx.mut.cfg.shareWorkDivisor) === 'number') {
                    ctx.mut.shareTar = computeShareTar(blockTar, ctx.mut.cfg.shareWorkDivisor);
                } else if (typeof(ctx.mut.cfg.shareMinWork) === 'number') {
                    ctx.mut.shareTar = ctx.mut.cfg.shareMinWork;
                } else {
                    // nothing specified, pick a reasonable default.
                    console.error("neither shareWorkDivisor nor shareMinWork were specified");
                    console.error("defaulting to shareWorkDivisor = 64");
                    ctx.mut.shareTar = computeShareTar(blockTar, 64);
                }
                ctx.mut.blockTar = blockTar;
            }

            let work = Protocol.workFromRawBlockTemplate(ret.result, keyPair.publicKey,
                ctx.mut.shareTar, ctx.mut.cfg.annMinWork);
            newState = Object.freeze({
                work: work,
                keyPair: keyPair,
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
                    keyPair: newState.keyPair,
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
        console.error("Next block prepared " + work.height);
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

const mkConfig = module.exports.mkConfig = (
    cfg /*:Master_Config_t*/,
    height /*:number*/
) /*:Protocol_PcConfigJson_t*/ => {
    return {
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

const configReq = module.exports.configReq = (
    cfg /*:Master_Config_t*/,
    height /*:number*/,
    _req /*:IncomingMessage*/,
    res /*:ServerResponse*/
) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'max-age=8 stale-while-revalidate=2');
    res.end(JSON.stringify(mkConfig(cfg, height), null, '\t'));
};

const onReq = (ctx /*:Context_t*/, req, res) => {
    if (!ctx.mut.state) {
        res.statusCode = 500;
        res.end("Server not ready");
        return;
    }
    const state = ctx.mut.state;
    if (req.url.endsWith('/config.json')) {
        configReq(ctx.mut.cfg, state.work.height, req, res);
        return;
    }
    let worknum = -1;
    req.url.replace(/.*\/work_([0-9]+)\.bin$/, (_, num) => ((worknum = Number(num)) + ''));
    if (worknum < 0 || isNaN(worknum)) {
    } else if (worknum === (state.work.height+1)) {
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
    req.url.replace(/.*\/hashbefore_([0-9a-f]{64})\.hex$/, (_, h) => { maybehash = h; return ''; });
    if (maybehash) {
        const hash = maybehash;
        const resHash = (h) => {
            res.setHeader("content-type", "text/plain");
            res.setHeader("cache-control", "max-age=999999999");
            res.end(h);
        };
        if (hash in ctx.hashCache) {
            resHash(ctx.hashCache[hash]);
        } else {
            ctx.rpcClient.getBlock(hash, (err, ret) => {
                if (err) {
                } else if (!ret) {
                } else if (!ret.result) {
                } else if (!ret.result.previousblockhash) {
                } else if (!/^[a-f0-9]{64}$/.test(ret.result.previousblockhash)) {
                } else {
                    ctx.hashCache[hash] = ret.result.previousblockhash;
                    resHash(ret.result.previousblockhash);
                    return;
                }
                res.statusCode = 500;
                res.end(String(err));
            });
        }
        return;
    }

    let keyNum;
    req.url.replace(/.*\/sigkey_([0-9]+)\.hex$/, (_, num) => ((keyNum = Number(num)) + ''));
    if (keyNum) {
        const complete = (h) => {
            res.setHeader("content-type", "text/plain");
            res.setHeader("cache-control", "max-age=999999999");
            res.end(h);
        };
        if (!ctx.mut.state) {
        } else if (!ctx.mut.state.work) {
        } else if (keyNum > ctx.mut.state.work.height) {
            res.statusCode = 404;
            res.end('');
            return;
        } else if (keyNum in ctx.keyCache) {
            complete(ctx.keyCache[keyNum]);
            return;
        } else {
            const keyPair = Util.getKeypair(ctx.mut.cfg.root, keyNum);
            ctx.keyCache[keyNum] = Buffer.from(keyPair.publicKey).toString('hex');
            complete(ctx.keyCache[keyNum]);
        }
        res.statusCode = 500;
        res.end('');
        return;
    }

    res.statusCode = 404;
    res.end('');
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
            hashCache: {},
            keyCache: {},
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
        }).listen(cfg.port);
        console.error("This pool master is configured to run with the following workers:");
        cfg.root.annHandlers.forEach((h) => { console.error(" - AnnHandler: " + h.url); });
        cfg.root.blkHandlers.forEach((h) => { console.error(" - BlkHandler: " + h.url); });
        console.error("It will tell miners to send their work to those urls.");
        console.error();
        onBlock(ctx);
    });
};

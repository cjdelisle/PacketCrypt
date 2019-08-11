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
    shareMinWork: number
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
    mut: {
        cfg: Master_Config_t,
        longPollId: void|string,
        state: void|State_t
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

const onBlock = (ctx /*:Context_t*/) => {
    let state;
    let newState;
    let done;
    nThen((w) => {
        // Make work entry
        ctx.rpcClient.getRawBlockTemplate(w((err, ret) => {
            if (err || !ret) {
                console.log("Error getting block template, trying again in 10 seconds...");
                console.log(err);
                console.log(ret);
                setTimeout(() => {
                    onBlock(ctx);
                }, 10000);
                w.abort();
                return;
            }
            const keyPair = Util.getKeypair(ctx.mut.cfg.root, ret.result.height);
            let work = Protocol.workFromRawBlockTemplate(ret.result, keyPair.publicKey,
                ctx.mut.cfg.shareMinWork, ctx.mut.cfg.annMinWork);
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
                console.log("Using an existing block template for block [" +
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
        console.log("Block " + (work.height-1) + " " + work.lastHash.toString('hex'));
        let retrying = false;
        const again = () => {
            if (!ctx.mut.longPollId) {
                ctx.rpcClient.getBlockTemplate(w((err, ret) => {
                    if (err || !ret || !ret.result) {
                        console.log(err);
                        setTimeout(w(again), 1000);
                        return;
                    }
                    ctx.mut.longPollId = ret.result.longpollid;
                    again();
                }));
                return;
            }
            ctx.rpcClient.getBlockTemplateLongpoll(ctx.mut.longPollId, w((err, ret) => {
                if (err || !ret) {
                    // couldn't make the block for whatever reason, try again
                    if (!retrying) {
                        console.log(err);
                        retrying = true;
                    }
                    setTimeout(w(again), 100);
                    return;
                }
                retrying = false;
                ctx.mut.longPollId = ret.result.longpollid;
                const lastHashLittle = reverseBuffer(work.lastHash).toString('hex');
                if (ret.result.previousblockhash === lastHashLittle) {
                    again();
                    return;
                }
                done = true;
                onBlock(ctx);
            }));
        };
        again();
    }).nThen((_) => {
        if (!done) {
            console.error("This should never happen");
        }
    });
};

const configReq = (ctx, height, _req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'max-age=8 stale-while-revalidate=2');
    const cfg = ctx.mut.cfg;
    const out /*:Protocol_PcConfigJson_t*/ = {
        currentHeight: height,
        masterUrl: cfg.root.masterUrl,
        submitAnnUrls: cfg.root.annHandlers.map((x) => (x.url + '/submit')),
        downloadAnnUrls: cfg.root.annHandlers.map((x) => (x.url)),
        submitBlockUrls: cfg.root.blkHandlers.map((x) => (x.url + '/submit')),
        version: Protocol.VERSION
    };
    res.end(JSON.stringify(out, null, '\t'));
};

const onReq = (ctx /*:Context_t*/, req, res) => {
    if (!ctx.mut.state) {
        res.statusCode = 500;
        res.end("Server not ready");
        return;
    }
    const state = ctx.mut.state;
    if (req.url.endsWith('/config.json')) {
        configReq(ctx, state.work.height, req, res);
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

    res.statusCode = 404;
    res.end('');
    return;
};

module.exports.create = (cfg /*:Master_Config_t*/) => {
    const workdir = cfg.root.rootWorkdir + '/master_' + cfg.port;
    let ctx;
    let secret;
    nThen((w) => {
        Util.checkMkdir(workdir, w());
    }).nThen((w) => {
        ctx = Object.freeze({
            workdir: workdir,
            rpcClient: Rpc.create(cfg.root.rpc),
            longPollServer: Util.longPollServer(workdir),
            secret: secret,
            mut: {
                cfg: cfg,
                longPollId: undefined,
                state: undefined
            }
        });
    }).nThen((w) => {
        console.log("This pool master is configured to run with the following workers:");
        cfg.root.annHandlers.forEach((h) => { console.log(" - AnnHandler: " + h.url); });
        cfg.root.blkHandlers.forEach((h) => { console.log(" - BlkHandler: " + h.url); });
        console.log("It will tell miners to send their work to those urls.");
        console.log();
        onBlock(ctx);
    });
    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

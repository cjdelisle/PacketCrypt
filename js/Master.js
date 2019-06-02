/*@flow*/
const Crypto = require('crypto');
const Fs = require('fs');
const Http = require('http');
const nThen = require('nthen');
const Blake2b = require('blake2b');
const WriteFileAtomic = require('write-file-atomic');

const Protocol = require('./Protocol.js');
const Rpc = require('./Rpc.js');
const Util = require('./Util.js');

/*::
import type { WriteStream } from 'fs'
import type { IncomingMessage, ServerResponse } from 'http'
import type { Protocol_RawBlockTemplate_t, Protocol_Work_t, Protocol_PcConfigJson_t } from './Protocol.js'
import type { Rpc_Client_t, Rpc_Config_t } from './Rpc.js';
import type { Util_LongPollServer_t } from './Util.js';
import type { Config_t } from './Config.js';

export type Master_Config_t = {
    root: Config_t,
    port: number,
    rpc: Rpc_Config_t,
    annMinWork: number,
    shareMinWork: number
};

type State_t = {
    work: Protocol_Work_t,
    content: Buffer,
    blockTemplate: Buffer
};

type Context_t = {
    workdir: string,
    rpcClient: Rpc_Client_t,
    longPollServer: Util_LongPollServer_t,
    contentByHeight: { [number]:Buffer },
    mut: {
        cfg: Master_Config_t,
        contentFile: WriteStream,
        longPollId: void|string,
        state: void|State_t,
    }
}
*/

const headers = (res) => {
    res.setHeader("cache-control", "max-age=1000");
    res.setHeader("content-type", "application/octet-stream");
};

const getHash = (content) => {
    return (Blake2b(32).update(content.slice(1)).digest(Buffer.alloc(32))/*:Buffer*/);
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
        // Create some content to go with the new work
        const content = Crypto.randomBytes(16);
        content[0] = 15;
        // Make work entry
        ctx.rpcClient.getRawBlockTemplate(w((err, ret) => {
            if (err || !ret) { throw new Error(JSON.stringify(err)); }
            let work = Protocol.workFromRawBlockTemplate(ret.result, getHash(content),
                ctx.mut.cfg.shareMinWork, ctx.mut.cfg.annMinWork);
            newState = Object.freeze({
                work: work,
                content: content,
                blockTemplate: Protocol.blockTemplateEncode(ret.result)
            });
        }));
    }).nThen((w) => {
        // Check if the work file exists already, if it does then we're going
        // to load it and override our new state.
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
            if (work && blockTemplate && ctx.contentByHeight[work.height]) {
                console.log("Using an existing block template for block [" +
                    newState.work.height + "]");
                state = Object.freeze({
                    work: work,
                    content: ctx.contentByHeight[work.height],
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
        }).nThen((w) => {
            if (ctx.contentByHeight[state.work.height]) { return; }
            ctx.mut.contentFile.write(JSON.stringify({
                height: state.work.height,
                content: state.content.toString('hex')
            }) + '\n');
            ctx.contentByHeight[state.work.height] = state.content;
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
        annMinWork: cfg.annMinWork,
        shareMinWork: cfg.shareMinWork
    };
    res.end(JSON.stringify(out, null, '\t'));
};

const COMMIT_PATTERN = Buffer.from(
    "6a3009f91102fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc" +
    "fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc", 'hex');

const submitBlock = (ctx, req, res) => {
    const data = [];
    req.on('data', (d) => { data.push(d); });
    req.on('end', () => {
        if (!Buffer.isBuffer(data[0])) {
            res.statusCode = 400;
            res.end("Invalid post");
            return;
        }
        const state = ctx.mut.state;
        if (!state) {
            res.statusCode = 500;
            res.end("Server not ready (no block template to use)");
            return;
        }
        const dataBuf = Buffer.concat(data);
        //console.log(dataBuf.toString('hex'));
        const shareFile = Protocol.shareFileDecode(dataBuf);

        if (shareFile.work.height !== state.work.height) {
            res.statusCode = 400;
            res.end("Expected share with height [" + state.work.height + "] but " +
                "share height was [" + shareFile.work.height + "]");
            return;
        }

        let blockTemplate = Buffer.from(state.blockTemplate).slice(80);
        // the block template is just the block except invalid.
        // We need to replace the header, find the pattern and insert the
        // coinbase commitment and then we can push the header and PCP
        const offset = blockTemplate.indexOf(COMMIT_PATTERN);
        if (offset === -1) {
            res.statusCode = 400;
            res.end("Could not find coinbase commitment");
            return;
        }
        shareFile.share.coinbaseCommit.copy(blockTemplate, offset+2);

        // We need to split apart the pcp in order to re-add the content
        // to the announcements.
        const anns = [];
        for (let i = 8; i < 4096; i += 1024) {
            const ann = shareFile.share.packetCryptProof.slice(i, i+1024);
            const num = ann.readInt32LE(12) + 1;
            const content = ctx.contentByHeight[num];
            if (!content) {
                console.log("Content at height [" + num + "] is unknown");
                res.statusCode = 400;
                res.end("Could not find ann content at height [" + num + "]");
                return;
            }
            anns.push(ann);
            anns.push(content);
        }

        const blockStr = Buffer.concat([
            shareFile.share.blockHeader,
            shareFile.share.packetCryptProof.slice(0,8),
            Buffer.concat(anns),
            shareFile.share.packetCryptProof.slice(4096+8),
            blockTemplate
        ]).toString('hex');
        //console.log("(apparently) found a block");
        //console.log(blockStr);
        // $FlowFixMe // need to add a type for this function
        ctx.rpcClient.submitBlock(blockStr, (err, ret) => {
            if (!err) { err = ret.result; }
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
                res.end("OK");
            }
        });
    });
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
    if (req.url === '/privileged/block') {
        submitBlock(ctx, req, res);
        return;
    }
    let worknum = -1;
    req.url.replace(/.*\/work_([0-9]+)\.bin$/, (_, num) => ((worknum = Number(num)) + ''));
    if (worknum < 0) {
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
    res.statusCode = 404;
    res.end('');
    return;
};

module.exports.create = (cfg /*:Master_Config_t*/) => {
    const workdir = cfg.root.rootWorkdir + '/master_' + cfg.port;
    let ctx;
    nThen((w) => {
        Util.checkMkdir(workdir, w());
    }).nThen((w) => {
        ctx = Object.freeze({
            workdir: workdir,
            rpcClient: Rpc.create(cfg.rpc),
            longPollServer: Util.longPollServer(workdir),
            contentByHeight: {},
            mut: {
                cfg: cfg,
                contentFile: undefined,
                longPollId: undefined,
                state: undefined
            }
        });
        Fs.readFile(workdir + '/content.ndjson', 'utf8', w((err, ret) => {
            if (err) {
                if (err.code === 'ENOENT') { return; }
                // This will happen during launch so the admin can see it
                console.error("Failed to read [" + workdir + "/content.ndjson], giving up");
                process.exit(100);
            }
            const lines = ret.split('\n');
            lines.forEach((l, i) => {
                if (!l) { return; }
                try {
                    const o = JSON.parse(l);
                    if (typeof(o.height) !== 'number') {
                    } else if (typeof(o.content) !== 'string' || !/[a-f0-9]*/.test(o.content)) {
                    } else {
                        ctx.contentByHeight[o.height] = Buffer.from(o.content, 'hex');
                        return;
                    }
                } catch (_) { }
                console.error("content.ndjson:" + i + " could not be parsed");
            });
        }));
    }).nThen((w) => {
        console.log("This pool master is configured to run with the following workers:");
        cfg.root.annHandlers.forEach((h) => { console.log(" - AnnHandler: " + h.url); });
        cfg.root.blkHandlers.forEach((h) => { console.log(" - BlkHandler: " + h.url); });
        console.log("It will tell miners to send their work to those urls.");
        console.log();

        ctx.mut.contentFile = Fs.createWriteStream(workdir + "/content.ndjson", { flags: "a" });
        // $FlowFixMe // complaining that contentFile is potentially null
        onBlock(ctx);
    });
    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

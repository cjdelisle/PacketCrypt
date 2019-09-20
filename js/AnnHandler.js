/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const Http = require('http');
const Spawn = require('child_process').spawn;
const Crypto = require('crypto');

const nThen = require('nthen');

const Util = require('./Util.js');
const Protocol = require('./Protocol.js');
const PoolClient = require('./PoolClient.js');

/*::
import type { WriteStream } from 'fs';
import type { ChildProcess } from 'child_process';
import type { IncomingMessage, ServerResponse } from 'http';
import type { PoolClient_t } from './PoolClient.js';
import type { Config_t } from './Config.js';
import type { Util_LongPollServer_t } from './Util.js';

export type AnnHandler_Config_t = {
    url: string,
    port: number,
    threads: number,
    root: Config_t
};
type PendingRequest_t = {
    req: IncomingMessage,
    res: ServerResponse,
    warn: Array<string>
};
type Context_t = {
    workdir: string,
    poolClient: PoolClient_t,
    pendingRequests: { [string]: PendingRequest_t },
    mut: {
        hashNum: number,
        hashMod: number,

        payLog: ?WriteStream,
        cfg: AnnHandler_Config_t,
        checkanns: void | ChildProcess,
        anndirLongpoll: void|Util_LongPollServer_t,
        highestAnnFile: number,
        ready: bool
    }
};
*/

const launchCheckanns = (ctx /*:Context_t*/) => {
    const args = [
        '--threads', String(ctx.mut.cfg.threads),
        ctx.workdir + '/indir',
        ctx.workdir + '/outdir',
        ctx.workdir + '/anndir',
        ctx.workdir + '/statedir',
        ctx.workdir + '/tmpdir',
        ctx.workdir + '/contentdir',
        ctx.workdir + '/paylogdir',
    ];
    console.error(ctx.mut.cfg.root.checkannsPath + ' ' + args.join(' '));
    const checkanns = ctx.mut.checkanns = Spawn(ctx.mut.cfg.root.checkannsPath, args, {
        stdio: ['pipe', 1, 2]
    });
    checkanns.on('close', Util.once(() => {
        console.error("checkanns has died, relaunching in 1 second");
        setTimeout(() => { launchCheckanns(ctx); }, 1000);
    }));
};

const AnnPost_HEADER_SZ = 144;

const onSubmit = (ctx, req, res) => {
    if (Util.badMethod('POST', req, res)) { return; }
    const worknum = Number(req.headers['x-pc-worknum']);
    const payTo = req.headers['x-pc-payto'] || '';
    const warn = [];
    if (!Util.isValidPayTo(payTo)) {
        warn.push('Address [' + payTo +
            '] is not a valid pkt address, WORK WILL NOT BE CREDITED');
        // we're not going to clear the payTo, we'll keep it anyway so that
        // we have it in the logs just in case.
    }
    let failed = false;
    const errorEnd = (code, message) => {
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ warn: warn, error: [message], result: '' }));
    };
    if (isNaN(worknum)) {
        return void errorEnd(400, "x-pc-worknum missing or not a number");
    }
    if (!ctx.poolClient.connected) {
        return void errorEnd(500, "disconnected from pool master");
    }
    const currentWork = ctx.poolClient.work;
    if (!currentWork) {
        return void errorEnd(500, "currentWork is unknown");
    }
    if (worknum > ctx.poolClient.currentHeight || worknum < ctx.poolClient.currentHeight-3) {
        return void errorEnd(400, "x-pc-worknum out of range, range: [" +
            (ctx.poolClient.currentHeight-3) + "] to [" + ctx.poolClient.currentHeight + "]");
    }
    const fileName = 'annshare_' + worknum + '_' + Crypto.randomBytes(16).toString('hex') + '.bin';
    const fileUploadPath = ctx.workdir + '/uploaddir/' + fileName;
    const fileInPath = ctx.workdir + '/indir/' + fileName;
    console.error("ann post [" + fileName + "] by [" + payTo + "]");
    let work;
    nThen((w) => {
        ctx.poolClient.getWorkByNum(worknum, w((w) => { work = w; }));
    }).nThen((w) => {
        const stream = Fs.createWriteStream(fileUploadPath);
        const post = {
            hashNum: ctx.mut.hashNum,
            hashMod: ctx.mut.hashMod,
            signingKey: work.signingKey,
            parentBlockHash: work.lastHash,
            minWork: currentWork.annTarget,
            mostRecentBlock: worknum - 1,
            payTo: payTo
        };
        //console.error("Writing: ", post);
        stream.write(Protocol.annPostEncode(post));
        req.pipe(stream).on('finish', w(() => {
            // $FlowFixMe stream.bytesWritten is real
            if (stream.bytesWritten < AnnPost_HEADER_SZ + 1024) {
                return errorEnd(400, "Runt upload");
            }
        }));
    }).nThen((w) => {
        if (failed) { return; }
        Fs.rename(fileUploadPath, fileInPath, w((err) => {
            if (err) { return errorEnd(500, "Failed to move file"); }
            //result = ctx.mut.cfg.url + '/outdir/' + fileName;
            ctx.pendingRequests[ctx.workdir + '/outdir/' + fileName] = {
                req: req,
                res: res,
                warn: warn
            };
        }));
    });
};

const getAnns = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const fileName = req.url.split('/').pop();
    if (fileName === 'index.json') {
        res.setHeader('content-type', 'application/json');
        res.setHeader('cache-control', 'max-age=8 stale-while-revalidate=2');
        res.end(JSON.stringify({ highestAnnFile: ctx.mut.highestAnnFile }));
        return;
    }
    let fileNo = NaN;
    fileName.replace(/^anns_([0-9]+)\.bin$/, (all, a) => {
        fileNo = Number(a);
        return '';
    });
    if (isNaN(fileNo)) {
        res.statusCode = 404;
        return void res.end();
    }
    if (!ctx.mut.anndirLongpoll) { throw new Error(); }
    if (fileNo === ctx.mut.highestAnnFile+1) {
        ctx.mut.anndirLongpoll.onReq(req, res);
    } else {
        Fs.readFile(ctx.workdir + '/anndir/' + fileName, (err, ret) => {
            if (err && err.code === 'ENOENT') {
                res.statusCode = 404;
                return void res.end();
            } else if (err) {
                console.error("Error reading file [" + JSON.stringify(err) + "]");
                res.statusCode = 500;
                return void res.end();
            }
            res.end(ret);
        });
    }
};

const getAnn = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const fileName = req.url.split('/').pop();
    let fileNo;
    fileName.replace(/^ann_([a-fA-F0-9]{64})\.bin$/, (all, a) => {
        fileNo = Buffer.from(a, 'hex');
        return '';
    });
    if (!fileNo) {
        res.statusCode = 404;
        return void res.end();
    }
    Fs.readFile(ctx.workdir + '/contentdir/' + fileName, (err, ret) => {
        if (err && err.code === 'ENOENT') {
            res.statusCode = 404;
            return void res.end();
        } else if (err) {
            console.error("Error reading file [" + JSON.stringify(err) + "]");
            res.statusCode = 500;
            return void res.end();
        }
        res.end(ret);
    });
};

const onReq = (ctx, req, res) => {
    if (!ctx.mut.ready) {
        res.statusCode = 500;
        return void res.end("server not ready");
    }
    if (req.url === '/submit') { return void onSubmit(ctx, req, res); }
    if (req.url.startsWith('/anns/')) { return void getAnns(ctx, req, res); }
    if (req.url.startsWith('/content/')) { return void getAnn(ctx, req, res); }
    res.statusCode = 404;
    return void res.end(JSON.stringify({ error: "not found" }));
};

module.exports.create = (cfg /*:AnnHandler_Config_t*/) => {
    const ctx /*:Context_t*/ = Object.freeze({
        workdir: cfg.root.rootWorkdir + '/ann_' + cfg.port,
        pendingRequests: {},
        mut: {
            cfg: cfg,
            checkanns: undefined,
            anndirLongpoll: undefined,
            highestAnnFile: -1,
            ready: false,
            payLog: undefined,

            hashNum: -1,
            hashMod: -1
        },
        poolClient: PoolClient.create(cfg.root.masterUrl),
    });
    nThen((w) => {
        ctx.poolClient.getMasterConf(w((conf) => {
            if (conf.downloadAnnUrls.indexOf(cfg.url) === -1) {
                console.error("ERROR: This node [" + cfg.url + "] is not authorized by the master");
                console.error("shutting down");
                process.exit(100);
            }
            ctx.mut.hashMod = conf.downloadAnnUrls.length;
            ctx.mut.hashNum = conf.downloadAnnUrls.indexOf(cfg.url);
        }));
        nThen((w) => {
            Util.checkMkdir(ctx.workdir + '/paylogdir', w());
            Util.checkMkdir(ctx.workdir + '/indir', w());
            Util.checkMkdir(ctx.workdir + '/outdir', w());
            Util.checkMkdir(ctx.workdir + '/anndir', w());
            Util.checkMkdir(ctx.workdir + '/statedir', w());
            Util.checkMkdir(ctx.workdir + '/contentdir', w());

            Util.checkMkdir(ctx.workdir + '/tmpdir', w());
            Util.checkMkdir(ctx.workdir + '/uploaddir', w());
        }).nThen((w) => {
            Util.clearDir(ctx.workdir + '/outdir', w());
        }).nThen((w) => {
            Util.clearDir(ctx.workdir + '/tmpdir', w());
            Util.clearDir(ctx.workdir + '/uploaddir', w());

            setInterval(() => {
                Util.uploadPayLogs(
                    ctx.workdir + '/paylogdir',
                    ctx.poolClient.config.paymakerUrl + '/events',
                    ctx.mut.cfg.root.paymakerHttpPasswd,
                    false,
                    ()=>{}
                );
            }, 30000);

            Util.longPollServer(ctx.workdir + '/outdir/').onFileUpdate((file) => {
                const path = ctx.workdir + '/outdir/' + file;
                if (file.indexOf('annshare_') !== 0) {
                    console.error("Stray file update [" + path + "] ignoring");
                    return;
                }
                const pr = ctx.pendingRequests[path];
                if (!pr) {
                    // this happens when the file is deleted
                    return;
                }
                Fs.readFile(path, 'utf8', (err, str) => {
                    if (err) {
                        if (err.code === 'ENOENT') { return; }
                        console.error("Unable to read file [" + path + "] cause: [" + String(err) + "]");
                        return;
                    }
                    let obj;
                    try {
                        obj = JSON.parse(str);
                    } catch (e) {
                        pr.res.statusCode = 500;
                        pr.res.end(JSON.stringify({ warn: pr.warn, error: [
                            "Failed to parse result from validator [" + str + "]"
                        ], result: '' }));
                        delete ctx.pendingRequests[path];
                        return;
                    }
                    const content = JSON.stringify({ warn: pr.warn, error: [], result: obj });
                    pr.res.writeHead(200, {
                        'Content-Type': 'application/json',
                        'Content-Length': String(content.length)
                    });
                    pr.res.end(JSON.stringify({ warn: pr.warn, error: [], result: obj }));
                    delete ctx.pendingRequests[path];
                    Fs.unlink(path, (err) => {
                        if (err) {
                            console.error("Unable to delete [" + path + "]");
                            return;
                        }
                    });
                });
            });

            const lp = ctx.mut.anndirLongpoll = Util.longPollServer(ctx.workdir + '/anndir');
            Fs.readdir(ctx.workdir + '/anndir', w((err, files) => {
                if (!files) { throw err; }
                ctx.mut.highestAnnFile = files.
                    map((f) => (f.replace(/anns_([0-9]*)\.bin/, (all, numS) => (numS)))).
                    map(Number).
                    filter((n) => (!isNaN(n))).
                    reduce((a,c) => (c > a ? c : a), -1);
            }));
            lp.onFileUpdate((f) => {
                // this triggers even if a file is deleted, but that's not a big deal
                // because we're looking for the highest number and we'll never "delete"
                // anything higher than the highest that exists.
                f.replace(/anns_([0-9]*)\.bin/, (all, numS) => {
                    const n = Number(numS);
                    if (isNaN(n)) { return ''; }
                    if (ctx.mut.highestAnnFile < n) { ctx.mut.highestAnnFile = n; }
                    return '';
                });
            });
            ctx.poolClient.onWork((work) => {
                Util.deleteResults(
                    ctx.workdir + '/outdir',
                    work.height - 10,
                    /annshare_([0-9]*)_[0-9a-f]*\.bin/);
                Util.deleteUselessAnns(ctx.workdir + '/anndir', work.height, (f, done) => {
                    console.error("Deleted expired announcements [" + f + "]");
                    let failed = false;
                    nThen((w) => {
                        const path = ctx.workdir + '/anndir/' + f;
                        Fs.unlink(path, w((err) => {
                            if (!err) { return; }
                            console.error("Failed to delete [" + path + "] [" + err.message + "]");
                            failed = true;
                        }));
                    }).nThen((w) => {
                        const path = ctx.workdir + '/statedir/' + (f.replace('anns_', 'state_'));
                        if (failed) { return; }
                        Fs.unlink(path, w((err) => {
                            if (!err) { return; }
                            console.error("Failed to delete [" + path + "] [" + err.message + "]");
                        }));
                    }).nThen(done);
                }, ()=>{});
            });
        }).nThen((_w) => {
            launchCheckanns(ctx);
        }).nThen(w());
    }).nThen((_) => {
        ctx.mut.ready = true;
    });
    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

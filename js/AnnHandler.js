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
type Context_t = {
    workdir: string,
    poolClient: PoolClient_t,
    mut: {
        hashNum: number,
        hashMod: number,

        cfg: AnnHandler_Config_t,
        checkanns: void | ChildProcess,
        outdirLongpoll: void|Util_LongPollServer_t,
        anndirLongpoll: void|Util_LongPollServer_t,
        highestAnnFile: number,
        ready: bool
    }
};
*/

// - grab the rules from the master, if we are not in the handler list then fail
// - check-create the needed folders (including an upload-pad folder)
// - clear upload-pad folder if it contains anything
// - launch checkanns with folders specified
// - start a pool client to stay up to date on work from the pool
// - Allowed anns will have a parent hash of: height, height-1, all others are invalid.
// onUpload:
// - get the work number from the header
//  open a new file in upload-pad, pad the beginning with 84 bytes of nulls
//  begin streaming the upload to the file
//  query the master for the job which was used to create these announcements
//    If no job, kill the upload and send back a "stale work" failure
//  hash the content
//  fill in the rules in the first 84 bytes of the file (do we need to wait for the stream to complete ?)
//  when the upload completes
//    rename the file into the in folder
//    watch for the file to appear in the out folder
//    upon appearence, respond with the stats
//    if it doesn't appear in 30 seconds, send back an error message

const launchCheckanns = (ctx /*:Context_t*/) => {
    const args = [
        '--threads', String(ctx.mut.cfg.threads),
        ctx.workdir + '/indir',
        ctx.workdir + '/outdir',
        ctx.workdir + '/anndir',
        ctx.workdir + '/statedir',
        ctx.workdir + '/tmpdir',
    ];
    console.log(ctx.mut.cfg.root.checkannsPath + ' ' + args.join(' '));
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
    if (isNaN(worknum)) {
        res.statusCode = 400;
        return void res.end("x-pc-worknum missing or not a number");
    }
    if (!ctx.poolClient.connected) {
        res.statusCode = 500;
        return void res.end("disconnected from pool master");
    }
    const currentWork = ctx.poolClient.work;
    if (!currentWork) {
        res.statusCode = 500;
        return void res.end("currentWork is unknown");
    }
    if (worknum > ctx.poolClient.currentHeight || worknum < ctx.poolClient.currentHeight-1) {
        res.statusCode = 400;
        return void res.end("x-pc-worknum out of range, range: [" +
            (ctx.poolClient.currentHeight-1) + "] to [" + ctx.poolClient.currentHeight + "]");
    }
    const fileName = 'annshare_' + worknum + '_' + Crypto.randomBytes(16).toString('hex') + '.bin';
    const fileUploadPath = ctx.workdir + '/uploaddir/' + fileName;
    const fileInPath = ctx.workdir + '/indir/' + fileName;
    console.log("ann post [" + fileName + "] by [" + payTo + "]");
    ctx.poolClient.getWorkByNum(worknum, (work) => {
        const stream = Fs.createWriteStream(fileUploadPath);
        const post = {
            hashNum: ctx.mut.hashNum,
            hashMod: ctx.mut.hashMod,
            contentHash: work.contentHash,
            parentBlockHash: work.lastHash,
            minWork: currentWork.annTarget,
            mostRecentBlock: worknum,
            payTo: payTo
        };
        //console.log("Writing: ", post);
        stream.write(Protocol.annPostEncode(post));
        req.pipe(stream).on('finish', () => {
            // $FlowFixMe stream.bytesWritten is real
            if (stream.bytesWritten < AnnPost_HEADER_SZ + 1024) {
                return res.end(JSON.stringify({
                    warn: [],
                    error: ["Runt upload"],
                    result: ''
                }));
            }
            Fs.rename(fileUploadPath, fileInPath, (err) => {
                const out = {
                    warn: [],
                    error: [],
                    result: ''
                };
                if (err) {
                    res.statusCode = 500;
                    out.error.push("Failed to move file");
                } else {
                    out.result = ctx.mut.cfg.url + '/outdir/' + fileName;
                    if (!Util.isValidPayTo(payTo)) {
                        out.warn.push("invalid payto, cannot credit work");
                    }
                }
                res.end(JSON.stringify(out));
            });
        });
    });
};

const getResult = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const fileName = req.url.split('/').pop();
    if (!/^annshare_[0-9]+_[a-f0-9]+\.bin$/.test(fileName)) {
        res.statusCode = 404;
        return void res.end();
    }
    if (!ctx.mut.outdirLongpoll) { throw new Error(); }
    ctx.mut.outdirLongpoll.onReq(req, res);
};

const getAnns = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const fileName = req.url.split('/').pop();
    if (fileName === 'index.json') {
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
                console.log("Error reading file [" + JSON.stringify(err) + "]");
                res.statusCode = 500;
                return void res.end();
            }
            res.end(ret);
        });
    }
};

const onReq = (ctx, req, res) => {
    if (!ctx.mut.ready) {
        res.statusCode = 500;
        return void res.end("server not ready");
    }
    if (req.url === '/submit') { return void onSubmit(ctx, req, res); }
    if (req.url.startsWith('/outdir/')) { return void getResult(ctx, req, res); }
    if (req.url.startsWith('/anns/')) { return void getAnns(ctx, req, res); }
    res.statusCode = 404;
    return void res.end(JSON.stringify({ error: "not found" }));
};

module.exports.create = (cfg /*:AnnHandler_Config_t*/) => {
    const ctx /*:Context_t*/ = Object.freeze({
        workdir: cfg.root.rootWorkdir + '/ann_' + cfg.port,
        mut: {
            cfg: cfg,
            checkanns: undefined,
            outdirLongpoll: undefined,
            anndirLongpoll: undefined,
            highestAnnFile: -1,
            ready: false,

            hashNum: -1,
            hashMod: -1
        },
        poolClient: PoolClient.create(cfg.root.masterUrl),
    });
    nThen((w) => {
        ctx.poolClient.onWork(Util.once(w()));
        nThen((w) => {
            Util.checkMkdir(ctx.workdir + '/indir', w());
            Util.checkMkdir(ctx.workdir + '/outdir', w());
            Util.checkMkdir(ctx.workdir + '/anndir', w());
            Util.checkMkdir(ctx.workdir + '/statedir', w());

            Util.checkMkdir(ctx.workdir + '/tmpdir', w());
            Util.checkMkdir(ctx.workdir + '/uploaddir', w());
        }).nThen((w) => {
            Util.clearDir(ctx.workdir + '/tmpdir', w());
            Util.clearDir(ctx.workdir + '/uploaddir', w());

            ctx.mut.outdirLongpoll = Util.longPollServer(ctx.workdir + '/outdir');
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
                    console.log("Deleted expired announcements [" + f + "]");
                    let failed = false;
                    nThen((w) => {
                        const path = ctx.workdir + '/anndir/' + f;
                        Fs.unlink(path, w((err) => {
                            if (!err) { return; }
                            console.log("Failed to delete [" + path + "] [" + err.message + "]");
                            failed = true;
                        }));
                    }).nThen((w) => {
                        const path = ctx.workdir + '/statedir/' + (f.replace('anns_', 'state_'));
                        if (failed) { return; }
                        Fs.unlink(path, w((err) => {
                            if (!err) { return; }
                            console.log("Failed to delete [" + path + "] [" + err.message + "]");
                        }));
                    }).nThen(done);
                }, ()=>{});
            });
        }).nThen((_w) => {
            launchCheckanns(ctx);
        }).nThen(w());
        ctx.poolClient.getMasterConf(w((conf) => {
            if (conf.downloadAnnUrls.indexOf(cfg.url) === -1) {
                console.error("ERROR: This node [" + cfg.url + "] is not authorized by the master");
                console.error("shutting down");
                process.exit(100);
            }
            ctx.mut.hashMod = conf.downloadAnnUrls.length;
            ctx.mut.hashNum = conf.downloadAnnUrls.indexOf(cfg.url);
        }));
    }).nThen((_) => {
        ctx.mut.ready = true;
    });
    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
};

/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Spawn = require('child_process').spawn;
const Crypto = require('crypto');
const Fs = require('fs');
const nThen = require('nthen');
const Minimist = require('minimist');

const Pool = require('./js/PoolClient.js');
const Util = require('./js/Util.js');
const Protocol = require('./js/Protocol.js');

const MAX_RAND_CONTENT_SZ = 2048;
const REBUILD_JOB_EVERY_MS = 10000;

const MAX_REQUESTS_IN_FLIGHT = 16;

/*::
import type { PoolClient_t } from './js/PoolClient.js'
import type { Protocol_Work_t, Protocol_AnnResult_t } from './js/Protocol.js'
import type { Config_AnnMiner_t, Config_Miner_Content_t } from './js/Config.js'
import type { Util_Mutex_t } from './js/Util.js'
import type { ChildProcess } from 'child_process'
import type { ClientRequest, IncomingMessage } from 'http'

type Context_t = {
    miner: void|ChildProcess,
    pool: PoolClient_t,
    inMutex: Util_Mutex_t,
    uploads: Array<{ url: string, req: ClientRequest, reqNum: number }>,
    config: Config_AnnMiner_t,
    reqNum: number,
    requestsInFlight: ClientRequest[],
    mineOld: number,
    _submitAnnUrls: Array<string>,
};
*/

const dropRequest = (ctx, req) => {
    const idx = ctx.requestsInFlight.indexOf(req);
    if (idx < 0) {
        console.error("Request was forgotten before it ended");
        return;
    }
    ctx.requestsInFlight.splice(idx, 1);
};

const httpRes = (ctx, req, res /*:IncomingMessage*/, reqNum) => {
    const data = [];
    res.on('data', (d) => { data.push(d.toString('utf8')); });
    res.on('end', () => {
        dropRequest(ctx, req);
        if (res.statusCode !== 200) {
            // if (res.statusCode === 400) {
            //     console.error("Pool replied with error 400 [" + data.join('') + "] stopping");
            //     process.exit(100);
            // }
            console.error("[" + reqNum + "] WARNING: Pool replied with [" + res.statusMessage +
                "] [" + data.join('') + "]");
            return;
        }
        const d = data.join('');
        let result;
        try {
            const o = JSON.parse(d);
            result = o.result;
            if (o.error.length > 0) {
                console.error("[" + reqNum +  "] WARNING: Pool error [" + JSON.stringify(o.error) + "]");
                // we do not proceed
                return;
            }
            if (o.warn.length > 0) {
                console.error("[" + reqNum +  "] WARNING: Pool is warning us [" + JSON.stringify(o.warn) + "]");
            }
            result = o.result;
        } catch (e) {
            console.error("[" + reqNum +  "] WARNING: Pool reply is invalid [" + d + "]");
            return;
        }
        if (typeof(result) !== 'object') {
            console.error("[" + reqNum +  "] WARNING: Pool replied without a result [" + d + "]");
            return;
        }
        if (result.type !== 'anns') {
        } else if (typeof(result.accepted) !== 'number') {
        } else if (typeof(result.dup) !== 'number') {
        } else if (typeof(result.inval) !== 'number') {
        } else if (typeof(result.badHash) !== 'number') {
        } else if (typeof(result.runt) !== 'number') {
        } else if (typeof(result.internalErr) !== 'number') {
        } else if (result.payTo !== ctx.config.paymentAddr) {
        } else if (typeof(result.unsigned) !== 'number') {
        } else if (typeof(result.totalLen) !== 'number') {
        } else if (typeof(result.time) !== 'number') {
        } else if (typeof(result.eventId) !== 'string') {
        } else if (typeof(result.target) !== 'number') {
        } else {
            const invalid = result.inval + result.runt + result.badHash;
            console.error("[" + reqNum +  "] Pool responded: accepted [" + String(result.accepted) + "]" +
                ((result.dup > 0) ? " duplicates [" + String(result.dup) + "]" : "") +
                ((invalid > 0) ? " invalid [" + String(invalid) + "]" : "") +
                ((result.unsigned > 0) ? " accepted unsigned [" + String(result.unsigned) + "]" : "") +
                ((result.totalLen > 0) ? " content length [" + String(result.totalLen) + "]" : "")
            );
            return;
        }
        console.error("[" + reqNum +  "] UNEXPECTED RESULT: [" + JSON.stringify(result) + "]");
    });
};

const getFileName = (config, i) => (config.dir + '/anns_' + i + '.bin');

const messageMiner = (ctx, msg) => {
    if (!ctx.miner) { return; }
    //console.error("Signaling miner " + backtrace());
    ctx.miner.stdin.write(msg);
};

const rotateAndUpload = (ctx /*:Context_t*/, done) => {
    const files = [];
    const fileContent = [];
    let uploaded = false;
    const submitAnnUrls = ctx.pool.config.submitAnnUrls;
    if (JSON.stringify(submitAnnUrls) !== JSON.stringify(ctx._submitAnnUrls)) {
        const oldSubmitAnnUrls = ctx._submitAnnUrls;
        ctx._submitAnnUrls = submitAnnUrls;
        if (submitAnnUrls.length !== oldSubmitAnnUrls.length) {
            // The number of annhandlers has changed, this means we need to kill
            // the miner process because it is creating the wrong number of files.
            if (ctx.miner) { ctx.miner.kill('SIGINT'); }
            return void done();
        }
        // The annhandlers have changed but there are the same number of them which
        // means the files are still good, we can continue with the new ones.
    }
    nThen((w) => {
        submitAnnUrls.forEach((url, i) => {
            const file = getFileName(ctx.config, i);
            Fs.readFile(file, w((err, ret) => {
                // we just received new work right after uploading, pcann hasn't yet made a new file.
                if (err && err.code === 'ENOENT') { return; }
                if (err) { throw err; }
                if (ret.length === 0) { return; }
                files[i] = file;
                fileContent[i] = ret;
                uploaded = true;
                Fs.unlink(file, w((err) => {
                    if (!err) { return; }
                    console.error("Error deleting [" + file + "] [" + err.message + "]");
                    // Lets fail because we don't want the FS to fill up with trash.
                    throw err;
                }));
            }));
        });
    }).nThen((w) => {
        submitAnnUrls.forEach((url, i) => {
            if (!files[i]) { return; }
            const parentBlockHeight = fileContent[i].readUInt32LE(12) + 1;
            const contentLen = fileContent[i].readUInt32LE(20);
            const reqNum = ctx.reqNum++;
            console.error("[" + String(reqNum) + "] worknum [" +
                String(parentBlockHeight) + "] anns [" + String(fileContent[i].length / 1024) +
                    "] content length [" + contentLen + "] posted to [" + url + "]");
            const req = Util.httpPost(url, {
                'Content-Type': 'application/octet-stream',
                'x-pc-worknum': String(parentBlockHeight),
                'x-pc-payto': ctx.config.paymentAddr,
                'x-pc-sver': Protocol.SOFT_VERSION,
                'x-pc-annver': String(fileContent[i][0]),
            }, (res) => { httpRes(ctx, req, res, reqNum); });
            req.on('error', (err) => {
                console.error("[" + reqNum + "] Failed http post to [" + url + "] [" +
                    JSON.stringify(err) + "]");
                dropRequest(ctx, req);
            });
            req.end(fileContent[i]);
            ctx.requestsInFlight.push(req);
        });
    }).nThen((_w) => {
        done(uploaded);
    });
};

/*
typedef struct AnnMiner_Request_s {
    // the bitcoin format hash target which must be beaten in order to
    // output the resulting announcement.
    uint32_t workTarget;

    // the block number of the most recent block
    uint32_t parentBlockHeight;

    // the hash of the most recent block (for proving the time when the ann was created)
    uint8_t parentBlockHash[32];

    // a 32 byte pubkey, if all zeros then it is considered that the ann need not be signed
    uint8_t signingKey[32];

    // Limit the number of announcements generated per second
    uint32_t maxAnnsPerSecond;

    // the type of the announcement content
    uint32_t contentType;

    // the length of the content
    uint32_t contentLen;
} AnnMiner_Request_t;
*/
const rebuildJob = (ctx /*Context_t*/, w /*:Protocol_Work_t*/) => {
    let content = ctx.config.content;
    if (!content && ctx.config.randContent) {
        // output hex content so it is easily identifiable
        const bytes = Crypto.randomBytes(Math.floor(Math.random() * MAX_RAND_CONTENT_SZ / 2));
        const hexContent = Buffer.from(bytes.toString('hex'), 'utf8');
        content = { type: 0, val: hexContent };
    }

    const request = Buffer.alloc(84 + (content ? content.val.length : 0));
    request.writeUInt32LE(w.annTarget, 0);
    request.writeUInt32LE(w.height - 1, 4);
    w.lastHash.copy(request, 8);
    w.signingKey.copy(request, 40);

    let maxAnnsPerSecond = Math.floor(ctx.maxKbps / 8);
    request.writeUInt32LE(maxAnnsPerSecond, 72);

    if (content) {
        request.writeUInt32LE(content.type, 76);
        request.writeUInt32LE(content.val.length, 80);
        content.val.copy(request, 84);
    }

    messageMiner(ctx, request);
    ctx.lastWorkRefresh = +new Date();
};

const getAnnVersion = (ctx) => {
    if (typeof(ctx.config.version) === 'number') {
        if (Protocol.SUPPORTED_ANN_VERSIONS.indexOf(ctx.config.version) === -1) {
            console.error("ERROR: Ann version specified [--version " + ctx.config.version +
                "] is not supported by this version of the miner. " +
                "Supported versions: " + JSON.stringify(Protocol.SUPPORTED_ANN_VERSIONS));
            process.exit(100);
        }
        if (!ctx.pool.config.annVersions) {
            return ctx.config.version;
        }
        if (ctx.pool.config.annVersions.indexOf(ctx.config.version) === -1) {
            console.error("WARNING: Ann version specified [--version " + ctx.config.version +
                "] is not supported by the pool. " +
                "Supported versions: " + JSON.stringify(ctx.pool.config.annVersions || []));
            return ctx.config.version;
        }
    }
    let result = 0;
    Protocol.SUPPORTED_ANN_VERSIONS.forEach((v) => {
        if (!ctx.pool.config.annVersions) { return; }
        if (ctx.pool.config.annVersions.indexOf(v) > -1) {
            result = v;
        }
    });
    return result;
};

const doRefreshWork = (ctx) => {
    if (ctx.requestsInFlight.length > MAX_REQUESTS_IN_FLIGHT) {
        console.error('WARN: doRefreshWork() too many requests in flight: ' +
            ctx.requestsInFlight.length);
        return;
    }
    const av = getAnnVersion(ctx);
    if (av !== ctx.annVersion) {
        console.error("INFO: Announcement version to mine has changed to [" +
            String(av) + "], restarting miner...");
        ctx.annVersion = av;
        if (ctx.miner) {
            ctx.miner.kill('SIGINT');
        }
    }
    if (typeof(ctx.config.mineOldAnns) === 'number') {
        ctx.mineOld = ctx.config.mineOldAnns;
    } else if (ctx.pool.config && typeof(ctx.pool.config.mineOldAnns) === 'number') {
        ctx.mineOld = ctx.pool.config.mineOldAnns;
    } else {
        ctx.mineOld = 0;
    }
    ctx.inMutex((done) => {
        rotateAndUpload(ctx, (didUpload) => {
            const expired = (+new Date()) > (REBUILD_JOB_EVERY_MS + ctx.lastWorkRefresh);
            if (didUpload || expired) {
                ctx.pool.getWorkByNum(ctx.pool.currentHeight - ctx.mineOld, (w) => {
                    rebuildJob(ctx, w);
                });
            }
            done();
        });
    });
};

const refreshWorkLoop2 = (ctx) => {
    const delay = (ctx.config.content || ctx.config.randContent) ?
        500 : ((Math.random() * 10000) + 5000);
    setTimeout(() => { refreshWorkLoop2(ctx); }, delay);
    doRefreshWork(ctx);
};

const mkMiner = (ctx) => {
    const args = [
        '--threads', String(ctx.config.threads || 1),
        '--minerId', String(ctx.config.minerId),
        '--version', String(ctx.annVersion)
    ];
    if (ctx.config.paranoia) {
        args.push('--paranoia');
    }
    ctx._submitAnnUrls.forEach((_, i) => {
        args.push('--out', getFileName(ctx.config, i));
    });
    console.error(ctx.config.corePath + ' ' + args.join(' '));
    return Spawn(ctx.config.corePath, args, {
        stdio: [ 'pipe', 1, 2 ]
    });
};

const launch = (config /*:Config_AnnMiner_t*/) => {
    if (!Util.isValidPayTo(config.paymentAddr)) {
        console.error('Payment address [' + config.paymentAddr +
            '] is not a valid pkt address');
        process.exit(100);
    }
    const pool = Pool.create(config.poolUrl);
    nThen((w) => {
        Util.checkMkdir(config.dir, w());
        Util.clearDir(config.dir, w());
        pool.getMasterConf(w());
    }).nThen((_w) => {
        const ctx = {
            lastWorkRefresh: +new Date(),
            config: config,
            miner: undefined,
            _submitAnnUrls: pool.config.submitAnnUrls,
            pool: pool,
            inMutex: Util.createMutex(),
            uploads: [],
            reqNum: 0,
            requestsInFlight: [],
            annVersion: 0,
            maxKbps: config.maxKbps,
            mineOld: config.mineOldAnns || 0,
        };
        ctx.annVersion = getAnnVersion(ctx);
        ctx.miner = mkMiner(ctx);
        const minerOnClose = () => {
            if (!ctx.miner) { throw new Error(); }
            ctx.miner.on('close', () => {
                console.error("pcann has died, restarting in 1 second");
                ctx.miner = undefined;
                Util.clearDir(config.dir, () => {
                    setTimeout(() => {
                        ctx._submitAnnUrls = pool.config.submitAnnUrls;
                        ctx.miner = mkMiner(ctx);
                        pool.getWork((w) => { rebuildJob(ctx, w); });
                        minerOnClose();
                    }, 1000);
                });
            });
        };
        minerOnClose();

        pool.onWork((w) => { doRefreshWork(ctx); });
        refreshWorkLoop2(ctx);
        // kick it off
        pool.getWork((w) => { rebuildJob(ctx, w); });
    });
    pool.onDisconnected(() => {
        console.error("Lost connection to pool");
    });
    pool.onConnected(() => {
        console.error("Regained connection to pool");
    });
};

const usage = () => {
    console.log("Usage: node annmine.js OPTIONS <poolurl>\n" +
        "    OPTIONS:\n" +
        "        --paymentAddr # the bitcoin address to request payment from the pool\n" +
        "                      # when submitting announcements\n" +
        "        --threads     # number of threads to use for mining\n" +
        "        --corePath    # if specified, this will be the path to the core engine\n" +
        "                      # default is ./bin/pcann\n" +
        "        --dir         # the directory to use for storing temporary state\n" +
        "                      # default is ./datastore/annmine\n" +
        "        --contentType # specify announcement content type\n" +
        "        --content     # specify announcement content\n" +
        "        --contentFile # specify announcement content in a file\n" +
        "        --randContent # mine many announcements, each with random content\n" +
        "        --version     # generate announcements of this version\n" +
        "        --paranoia    # if specified, pcann will validate each announcement after\n" +
        "                      # it is generated\n" +
        "        --maxKbps     # adjust the bandwidth limit (in kilobits) for the miner,\n" +
        "                      # default value is 1024 (a.k.a. one megabit)\n" +
        "        --minerId     # an optional number which will be used when mining\n" +
        "                      # in order to differentiate this miner from others.\n" +
        "                      # if none is specified then a random one will be chosen.\n" +
        "    <poolurl>         # the URL of the mining pool to connect to\n" +
        "\n" +
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/annmine.md\n" +
        "    for more information");
    return 100;
};

const parseContent = (args, then) => {
    let t = 0;
    const ct = args.contentType || args.contenttype;
    if (ct) {
        t = Number(ct);
        if (isNaN(t) || t < 0 || t > 0xffffffff) {
            throw new Error("Failed to parse content type [" + ct + "]");
        }
    }
    const cf = args.contentFile || args.contentfile;
    if (cf) {
        Fs.readFile(cf, (err, ret) => {
            if (err) { throw err; }
            then({ type: t, val: ret });
        });
    } else if (args.content) {
        then({ type: t, val: Buffer.from(args.content, 'utf8') });
    } else {
        then();
    }
};

const DEFAULT_PAYMENT_ADDR = "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2";

const main = (argv) => {
    const defaultConf = {
        corePath: './bin/pcann',
        dir: './datastore/annmine',
        paymentAddr: DEFAULT_PAYMENT_ADDR,
        threads: 1,
        minerId: Math.floor(Math.random()*(1<<30)*2),
    };
    const a = Minimist(argv.slice(2), { boolean: ['randContent','paranoia'] });
    if (!/http(s)?:\/\/.*/.test(a._[0])) { process.exit(usage()); }
    const conf = {
        paymentAddr: a.paymentAddr || defaultConf.paymentAddr,
        threads: a.threads || defaultConf.threads,
        corePath: a.corePath || defaultConf.corePath,
        dir: a.dir || defaultConf.dir,
        content: undefined,
        randContent: a.randContent || false,
        version: a.version || undefined,
        paranoia: a.paranoia || false,
        maxKbps: a.maxKbps || 1024,
        minerId: a.minerId || defaultConf.minerId,
        poolUrl: a._[0],
        mineOldAnns: typeof(a.mineOldAnns) === 'number' ? a.mineOldAnns : null,
    };
    if (isNaN(conf.maxKbps / 1)) {
        console.error("ERROR: --maxKbps value [" + conf.maxKbps + "] is not a number");
        process.exit(100);
    }
    if (!a.maxKbps) {
        console.error("WARNING: You have not passed the --maxKbps flag\n" +
            "    as a default, mining will be limited to 1000kbps (1Mb).");
    }
    if (conf.maxKbps && conf.maxKbps < 8) {
        console.error("WARNING: --maxKbps cannot be less than 8, defaulting to 8");
        conf.maxKbps = 8;
    }
    if (!a.paymentAddr) {
        console.error("WARNING: You have not passed the --paymentAddr flag\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    parseContent(a, (content) => {
        conf.content = content;
        launch(Object.freeze(conf));
    });
};
main(process.argv);

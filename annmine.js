/*@flow*/
const Spawn = require('child_process').spawn;
const Fs = require('fs');
const nThen = require('nthen');
const Minimist = require('minimist');

const Pool = require('./js/PoolClient.js');
const Util = require('./js/Util.js');

/*::
import type { PoolClient_t } from './js/PoolClient.js'
import type { Protocol_Work_t, Protocol_AnnResult_t } from './js/Protocol.js'
import type { Config_Miner_t } from './js/Config.js'
import type { Util_Mutex_t } from './js/Util.js'
import type { ChildProcess } from 'child_process'
import type { ClientRequest, IncomingMessage } from 'http'
type Work_t = {
    request: Buffer,
    protocolWork: Protocol_Work_t
}
type Context_t = {
    miner: void|ChildProcess,
    pool: PoolClient_t,
    currentWork: Work_t|void,
    inMutex: Util_Mutex_t,
    uploads: Array<{ url: string, req: ClientRequest }>,
    submitAnnUrls: Array<string>,
    config: Config_Miner_t,
    resultQueue: Array<string>,
    timeOfLastRotate: number
};
*/

const httpRes = (ctx, res /*:IncomingMessage*/) => {
    const data = [];
    res.on('data', (d) => { data.push(d.toString('utf8')); });
    res.on('end', () => {
        if (res.statusCode !== 200) {
            // if (res.statusCode === 400) {
            //     console.error("Pool replied with error 400 [" + data.join('') + "] stopping");
            //     process.exit(100);
            // }
            console.error("WARNING: Pool replied with [" + res.statusMessage +
                "] [" + data.join('') + "]");
            return;
        }
        const d = data.join('');
        let result;
        try {
            const o = JSON.parse(d);
            result = o.result;
            if (o.error.length > 0) {
                console.error("WARNING: Pool error [" + JSON.stringify(o.error) + "]");
                // we do not proceed
                return;
            }
            if (o.warn.length > 0) {
                console.error("WARNING: Pool is warning us [" + JSON.stringify(o.warn) + "]");
            }
            result = o.result;
        } catch (e) {
            console.error("WARNING: Pool reply is invalid [" + d + "]");
            return;
        }
        if (typeof(result) !== 'string') {
            console.error("WARNING: Pool replied without a result [" + d + "]");
            return;
        }
        ctx.resultQueue.push(result);
    });
};

const getFileName = (config, i) => (config.dir + '/anns_' + i + '.bin');

const rotateAndUpload = (ctx /*:Context_t*/, lastWork /*:Work_t*/, done) => {
    ctx.timeOfLastRotate = +new Date();
    const files = [];
    const fileContent = [];
    nThen((w) => {
        ctx.submitAnnUrls.forEach((url, i) => {
            const file = getFileName(ctx.config, i);
            Fs.readFile(file, w((err, ret) => {
                // we just received new work right after uploading, pcann hasn't yet made a new file.
                if (err && err.code === 'ENOENT') { return; }
                if (err) { throw err; }
                files[i] = file;
                fileContent[i] = ret;

                Fs.unlink(file, w((err) => {
                    if (!err) { return; }
                    console.error("Error deleting [" + file + "] [" + err.message + "]");
                    // Lets fail because we don't want the FS to fill up with trash.
                    throw err;
                }));
            }));
        });
    }).nThen((w) => {
        ctx.submitAnnUrls.forEach((url, i) => {
            if (!files[i] || !fileContent[i].length) { return; }
            const file = getFileName(ctx.config, i);
            console.error("http post [" + url + "] worknum [" +
                String(lastWork.protocolWork.height) + "] file [" + file + "]");
            const req = Util.httpPost(url, {
                'Content-Type': 'application/octet-stream',
                'x-pc-worknum': String(lastWork.protocolWork.height),
                'x-pc-payto': ctx.config.paymentAddr
            }, (res) => { httpRes(ctx, res); });

            ctx.uploads.filter((r) => (r.url === url)).forEach((r) => {
                r.req.abort();
                Util.listRemove(ctx.uploads, r);
            });
            const r = { url: url, req: req };
            ctx.uploads.push(r);
            req.on('error', (err) => {
                console.error("Failed http post to [" + url + "] [" + JSON.stringify(err) + "]");
                Util.listRemove(ctx.uploads, r);
            });
            // If we specified file content then we're only going to do this once...
            // and we're also going to only post the first announcement which the miner
            // found.
            if (ctx.config.content) {
                const content = ctx.config.content;
                req.write(fileContent[i].slice(0,1024));
                if (content.val.length > 32) {
                    req.write(content.val);
                }
                req.end();
                // then we're going to drop any other anns
                files.length = 0;
            } else {
                req.end(fileContent[i]);
            }
        });
    }).nThen((_w) => {
        done();
    });
};

const messageMiner = (ctx, msg) => {
    if (!ctx.miner) { return; }
    ctx.miner.stdin.write(msg);
};

const refreshWorkLoop = (ctx) => {
    // If content is specified then we want to check for a find once every half second
    // and when there is one, we want to submit it as quickly as possible.
    if (ctx.config.content) {
        const to = setTimeout(() => { refreshWorkLoop(ctx); }, 500);
        let hasFind = false;
        ctx.inMutex((done) => {
            nThen((w) => {
                let nt = nThen;
                ctx.submitAnnUrls.forEach((url, i) => {
                    nt = nt((w) => {
                        const file = getFileName(ctx.config, i);
                        Fs.stat(file, w((err, st) => {
                            if (err && err.code === 'ENOENT') { return; }
                            if (err) { return void console.log(err); }
                            if (st.size > 0) { hasFind = true; }
                        }));
                    }).nThen;
                });
                nt(w());
            }).nThen((w) => {
                if (!hasFind) { return; }
                if (!ctx.currentWork) { return; }
                const work = ctx.currentWork;
                rotateAndUpload(ctx, work, w(() => {
                    if (!ctx.currentWork) { throw new Error("currentWork disappeared"); }
                    clearTimeout(to);
                }));
            }).nThen((_) => {
                done();
            });
        });
        return;
    }

    setTimeout(() => { refreshWorkLoop(ctx); }, (Math.random() * 10000) + 5000);
    ctx.inMutex((done) => {
        nThen((w) => {
            if (!ctx.currentWork) { return; }
            const work = ctx.currentWork;
            if (ctx.timeOfLastRotate + 10000 > (+new Date())) { return; }
            rotateAndUpload(ctx, work, w(() => {
                if (!ctx.currentWork) { throw new Error("currentWork disappeared"); }
                messageMiner(ctx, work.request);
            }));
        }).nThen((_) => {
            done();
        });
    });
};

const poolOnWork = (ctx /*:Context_t*/, w) => {
    ctx.inMutex((done) => {
        // send a new request for the miner process
        // we don't really get an acknoledgement back from this so we'll
        // just fire-and-forget
        const request = Buffer.alloc(88+32);
        request.writeUInt32LE(w.annTarget, 8);
        request.writeUInt32LE(w.height - 1, 12);
        w.signingKey.copy(request, 56);
        w.lastHash.copy(request, 88);

        if (ctx.config.content) {
            const content = ctx.config.content;
            request.writeUInt32LE(content.type, 16);
            request.writeUInt32LE(content.val.length, 20);
            if (content.val.length <= 32) {
                content.val.copy(request, 24);
            } else {
                Util.annComputeContentHash(content.val).copy(request, 24);
            }
        }

        // set a random hard_nonce so that we won't collide with other miners
        request.writeInt32LE(ctx.config.minerId, 4);

        const newWork = {
            request: request,
            protocolWork: w
        };

        const done0 = () => {
            messageMiner(ctx, request);
            ctx.currentWork = newWork;
            done();
        };

        if (ctx.currentWork) {
            rotateAndUpload(ctx, ctx.currentWork, done0);
        } else {
            done0();
        }
    });
};

const mkMiner = (config, submitAnnUrls) => {
    const args = [ '--threads', String(config.threads || 1) ];
    submitAnnUrls.forEach((url, i) => {
        args.push('--out', getFileName(config, i));
    });
    console.log(config.corePath + ' ' + args.join(' '));
    return Spawn(config.corePath, args, {
        stdio: [ 'pipe', 1, 2 ]
    });
};

const checkResultLoop = (ctx /*:Context_t*/) => {
    const again = () => {
        if (!ctx.resultQueue.length) { return void setTimeout(again, 5000); }
        const url = ctx.resultQueue.shift();
        Util.httpGetStr(url, (err, res) => {
            if (!res) {
                const e /*:any*/ = err;
                // 404s are normal because we're polling waiting for the file to exist
                if (typeof(e.statusCode) !== 'number' || e.statusCode !== 404) {
                    console.error("Got error from pool [" + JSON.stringify(e) + "]");
                }
                return true;
            }
            try {
                JSON.parse(res);
            } catch (e) {
                console.log("failed to parse result from pool [" + res + "]");
                return void again();
            }
            const result = (JSON.parse(res) /*:Protocol_AnnResult_t*/);
            if (result.payTo !== ctx.config.paymentAddr) {
                console.log("WARNING: pool is paying [" + result.payTo + "] but configured " +
                    "payment address is [" + ctx.config.paymentAddr + "]");
            }
            console.log("RESULT: [" + result.accepted + "] accepted, [" + result.inval +
                "] rejected invalid, [" + result.dup + "] rejected duplicates, [" +
                result.badHash + "] invalid content hash, [" + result.internalErr +
                "] internal err");
            if (ctx.config.content && result.accepted) {
                console.log("Announcement was accepted by the pool, shutting down");
                if (ctx.miner) { ctx.miner.kill(); }
                process.exit(0);
            }
            again();
        });
    };
    again();
};

const launch = (config /*:Config_Miner_t*/) => {
    if (config.paymentAddr.length > 64) {
        throw new Error("Illegal payment address (over 64 bytes long)");
    }
    const pool = Pool.create(config.poolUrl);
    nThen((w) => {
        Util.checkMkdir(config.dir, w());
        pool.getMasterConf(w());
    }).nThen((_w) => {
        const submitAnnUrls = pool.config.submitAnnUrls;
        const ctx = {
            config: config,
            miner: mkMiner(config, submitAnnUrls),
            submitAnnUrls: submitAnnUrls,
            pool: pool,
            currentWork: undefined,
            inMutex: Util.createMutex(),
            uploads: [],
            resultQueue: [],
            timeOfLastRotate: +new Date()
        };
        const minerOnClose = () => {
            if (!ctx.miner) { throw new Error(); }
            ctx.miner.on('close', () => {
                console.error("pcann has died, restarting in 1 second");
                ctx.miner = undefined;
                setTimeout(() => {
                    ctx.miner = mkMiner(config, submitAnnUrls);
                    minerOnClose();
                }, 1000);
            });
        };
        minerOnClose();

        pool.onWork((w) => {
            if (config.old) {
                pool.getWorkByNum(w.height - 3, (ww) => {
                    poolOnWork(ctx, ww);
                });
            } else {
                poolOnWork(ctx, w);
            }
        });
        checkResultLoop(ctx);
        refreshWorkLoop(ctx);
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
        "        --old         # if specified, the mined ann will be 3 blocks old\n" +
        "        --contenttype # specify announcement content type\n" +
        "        --content     # specify announcement content\n" +
        "        --contentfile # specify announcement content in a file\n" +
        "    <poolurl>         # the URL of the mining pool to connect to\n" +
        "\n" +
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/annmine.md\n" +
        "    for more information");
    return 100;
};

const parseContent = (args, then) => {
    let t = 0;
    if (args.contenttype) {
        t = Number(args.contenttype);
        if (isNaN(t) || t < 0 || t > 0xffffffff) {
            throw new Error("Failed to parse content type [" + args.contenttype + "]");
        }
    }
    if (args.contentfile) {
        Fs.readFile(args.contentfile, (err, ret) => {
            if (err) { throw err; }
            then({ type: t, val: ret });
        });
    } else if (args.content) {
        then({ type: t, val: Buffer.from(args.content, 'utf8') });
    } else {
        then();
    }
};

const DEFAULT_PAYMENT_ADDR = "bc1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4st4nj3u";

const main = (argv) => {
    const defaultConf = {
        corePath: './bin/pcann',
        dir: './datastore/annmine',
        paymentAddr: DEFAULT_PAYMENT_ADDR,
        threads: 1,
        minerId: Math.floor(Math.random()*(1<<30)*2)
    };
    const a = Minimist(argv.slice(2), { boolean: 'old' });
    if (!/http(s)?:\/\/.*/.test(a._[0])) { process.exit(usage()); }
    const conf = {
        corePath: a.corePath || defaultConf.corePath,
        dir: a.dir || defaultConf.dir,
        paymentAddr: a.paymentAddr || defaultConf.paymentAddr,
        poolUrl: a._[0],
        threads: a.threads || defaultConf.threads,
        minerId: a.minerId || defaultConf.minerId,
        old: a.old === true,
        content: undefined
    };
    if (!a.paymentAddr) {
        console.log("WARNING: You have not specified a paymentAddr\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    parseContent(a, (content) => {
        conf.content = content;
        launch(Object.freeze(conf));
    });
};
main(process.argv);

/*@flow*/
const Spawn = require('child_process').spawn;
const Fs = require('fs');
const Crypto = require('crypto');
const nThen = require('nthen');
const Minimist = require('minimist');

const Pool = require('./js/PoolClient.js');
const Util = require('./js/Util.js');
const Protocol = require('./js/Protocol.js');

/*::
import type { PoolClient_t } from './js/PoolClient.js'
import type { Protocol_Work_t } from './js/Protocol.js'
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
            if (res.statusCode === 400) {
                console.error("Pool replied with error 400 [" + data.join('') + "] stopping");
                process.exit(100);
            }
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
            if (!files[i]) { return; }
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
            req.end(fileContent[i]);
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
        const request = Buffer.alloc(56+32);
        request.writeUInt32LE(ctx.pool.config.annMinWork, 8);
        request.writeUInt32LE(w.height, 12);
        w.contentHash.copy(request, 24);
        w.lastHash.copy(request, 56);

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
        Util.httpGetBin(url, (err, res) => {
            if (!res) {
                const e /*:any*/ = err;
                // 404s are normal because we're polling waiting for the file to exist
                if (typeof(e.statusCode) !== 'number' || e.statusCode !== 404) {
                    console.error("Got error from pool [" + JSON.stringify(e) + "]");
                }
                return true;
            }
            const result = Protocol.annResultDecode(res);
            if (result.payTo !== ctx.config.paymentAddr) {
                console.log("WARNING: pool is paying [" + result.payTo + "] but configured " +
                    "payment address is [" + ctx.config.paymentAddr + "]");
            }
            console.log("RESULT: [" + result.accepted + "] accepted, [" + result.invalid +
                "] rejected invalid, [" + result.duplicates + "] rejected duplicates");
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
        pool.getMasterConf(Util.once(w()));
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

        pool.onWork((w) => { poolOnWork(ctx, w); });
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
        "    <poolurl>         # the URL of the mining pool to connect to\n" +
        "\n" +
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/annmine.md\n" +
        "    for more information");
    return 100;
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
    const a = Minimist(argv.slice(2));
    if (!/http(s)?:\/\/.*/.test(a._[0])) { process.exit(usage()); }
    const conf = {
        corePath: a.corePath || defaultConf.corePath,
        dir: a.dir || defaultConf.dir,
        paymentAddr: a.paymentAddr || defaultConf.paymentAddr,
        poolUrl: a._[0],
        threads: a.threads || defaultConf.threads,
        minerId: a.minerId || defaultConf.minerId,
        maxAnns: undefined // only used in blkmine
    };
    if (!a.paymentAddr) {
        console.log("WARNING: You have not specified a paymentAddr\n" +
            "    as a default, " + DEFAULT_PAYMENT_ADDR + " will be used,\n" +
            "    cjd appreciates your generosity");
    }
    launch(Object.freeze(conf));
};
main(process.argv);

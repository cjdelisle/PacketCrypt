/*@flow*/
const Fs = require('fs');
const Http = require('http');
const Crypto = require('crypto');
const Querystring = require('querystring');

const RBTree = require('bintrees').RBTree;
const nThen = require('nthen');

const Util = require('./Util.js');
const Rpc = require('./Rpc.js');

// This script implements a simple pplns via a webserver
// API:
//
// POST /events
//  Content is a newline-deliniated list of events.
//
// GET /whotopay
//  Result is:
//  {"result":<<key value map>>,"error":[],"warn":[]}
//  if there is not enough historical data, a warning will be output
//
// Events:
//
// All events must have 3 fields:
// * type: "anns" or "share" or "block"
// * time: The time (milliseconds since the epoch) that the event was processed by the pool server
// * eventId: An opaque string which is unique per unique event, the same event should carry the same eventId
//
// Event types:
//
// * anns: this is a submission of announcements from an announcement miner
//   * payTo: the address which should receive payment for these announcements
//   * accepted: the number of announcements which were accepted
//   * unsigned: the number of unsigned announcements, this will be subtracted from "accepted" to get the paid announcements
// * share: this signifies an accepted block share
//   * payTo: the address which should receive payment for the share
// * block: this signifies a new block having been detected on the chain
//   * difficulty: the multiplier of difficulty for the block
//
// Event examples:
// {"type":"anns","accepted":7,"dup":0,"inval":0,"badHash":0,"runt":0,"internalErr":0,"payTo":"pDSxcZunaUSUSxHrL6r8zpGJvoEropJ3Es","unsigned":0,"totalLen":0,"time":1566739261587,"eventId":"313ee66836ced10b437bf1fbd5f2bb92"}
//
// {"type":"share","payTo":"pMUbxVVJyHQ5sAKVvkwBDswS5ED8w9s3Lp","block":false,"time":1566739275576,"eventId":"df793f683da4e1442b3f559d0c2c6f30"}
//
// {"type":"share","payTo":"pMUbxVVJyHQ5sAKVvkwBDswS5ED8w9s3Lp","block":true,"time":1566739914571,"eventId":"0997905ca7591a8331402502a9ee3394","headerHash":"c752a934e168ece8df2032d86a7a61a67c03756d3c8b517aeed223f7d054346b"}
//
// {"type":"block","hash":"c752a934e168ece8df2032d86a7a61a67c03756d3c8b517aeed223f7d054346b","height":8550,"difficulty":2.29117094,"time":1566739914628,"eventId":"c752a934e168ece8df2032d86a7a61a6"}

/*::
import type { Config_t } from './Config.js';
import type { Rpc_Client_t } from './Rpc.js';
import type { Protocol_AnnsEvent_t, Protocol_ShareEvent_t, Protocol_BlockEvent_t } from './Protocol.js'

type ShareEvent_t = Protocol_ShareEvent_t & {
    credit: number|null
};
type AnnsEvent_t = Protocol_AnnsEvent_t & {
    credit: number|null
};

type BinTree_t<X> = {
    insert: (x:X) => bool,
    remove: (x:X) => bool,
    min: () => ?X,
    max: () => ?X,
    each: ((x:X) => ?bool)=>void,
    reach: ((x:X) => ?bool)=>void,
};

export type PayMaker_Result_t = {
    warn: Array<string>,
    error: Array<string>,
    result: { [string]: number }
};
export type PayMaker_Config_t = {
    url: string,
    port: number,
    updateCycle: number,
    historyDepth: number,
    blockPayoutFraction: number,
    pplnsAnnConstantX: number,
    pplnsBlkConstantX: number,
    defaultAddress: string,
    errorAddress: string,
    updateHook: (x: PayMaker_Result_t) => PayMaker_Result_t,
    root: Config_t,
};
type Context_t = {
    workdir: string,
    rpcClient: Rpc_Client_t,
    blocks: BinTree_t<Protocol_BlockEvent_t>,
    anns: BinTree_t<AnnsEvent_t>,
    shares: BinTree_t<ShareEvent_t>,
    dedupTable: {[string]:bool},
    mut: {
        mostRecentEventTime: number,
        cfg: PayMaker_Config_t
    }
};
*/

// Number of hashes needed for an expectation of a share
// Should be aligned with this:
// https://github.com/pkt-cash/pktd/blob/a1a569152b078ed28f1526ea8e72e76546b940f1/chaincfg/params.go#L644
const BASE_DIFFICULTY = 4096;

const getDifficulty = (ctx, time) => {
    let diff = -1;
    ctx.blocks.reach((b) => {
        if (b.time >= time) { return; }
        diff = b.difficulty * BASE_DIFFICULTY;
        return false;
    });
    return diff;
};

const earliestValidTime = (ctx) => {
    return (+new Date()) - (1000 * ctx.mut.cfg.historyDepth);
};

const isRelevant = (ctx, elem) => {
    // Is it outdated ?
    if (elem.time < earliestValidTime(ctx)) { return false; }
    // Is it a dupe ?
    if (ctx.dedupTable[elem.eventId]) { return false; }
    return true;
};

const onShare = (ctx, elem /*:ShareEvent_t*/, warn) => {
    if (!Util.isValidPayTo(elem.payTo)) {
        warn("Invalid payTo address [" + elem.payTo + "]");
    } else {
        const diff = getDifficulty(ctx, elem.time);
        if (diff < 1) {
            // we can't credit this share because we don't know the diff at that time
            elem.credit = null;
        } else {
            elem.credit = 1 / diff;
        }
        ctx.dedupTable[elem.eventId] = true;
        ctx.shares.insert(elem);
    }
};

const getEffectivePayableAnnCount = (elem /*:AnnsEvent_t*/) => {
    let payableAnnCount = Math.max(0, elem.accepted - elem.unsigned);
    if (elem.totalLen) {
        // for every 16KB of data, we deduct 1 announcement worth of payment
        payableAnnCount = Math.max(0, payableAnnCount - (elem.totalLen >> 14));
    }
    return payableAnnCount;
};

const onAnns = (ctx, elem /*:AnnsEvent_t*/, warn) => {
    if (!Util.isValidPayTo(elem.payTo)) {
        warn("Invalid payTo address [" + elem.payTo + "]");
    } else if (typeof(elem.accepted) !== 'number') {
        warn("accepted missing or not a number");
    } else if (typeof(elem.unsigned) !== 'number') {
        warn("unsigned missing or not a number");
    } else if (typeof(elem.totalLen) !== 'number') {
        warn("totalLen missing or not a number");
    } else {
        const diff = getDifficulty(ctx, elem.time);
        if (diff < 1) {
            // we can't credit these anns because we don't know the diff at that time
            elem.credit = null;
        } else {
            elem.credit = getEffectivePayableAnnCount(elem) / diff;
        }
        ctx.dedupTable[elem.eventId] = true;
        ctx.anns.insert(elem);
    }
};

const onBlock = (ctx, elem /*:Protocol_BlockEvent_t*/, warn) => {
    if (typeof(elem.height) !== 'number') {
        warn("height is missing or invalid");
    } else if (typeof(elem.difficulty) !== 'number') {
        warn("difficulty is missing or not a number");
    } else {
        ctx.dedupTable[elem.eventId] = true;
        ctx.blocks.insert(elem);
    }
};

const handleEvents = (ctx, fileName, dataStr) => {
    const strList = dataStr.split('\n');
    let lineNum = -1;
    let line;
    const warn = (msg) => {
        console.error(fileName + ":" + String(lineNum), msg, " - Event content:", line);
    };
    for (let i = 0; i < strList.length; i++) {
        line = strList[i];
        if (!line.trim()) { continue; }
        lineNum = i;
        let elem;
        try {
            elem = JSON.parse(line);
        } catch (e) {
            warn("unable to parse as json");
            continue;
        }
        if (elem.accepted) {
            elem.type = 'anns';
        }
        if (typeof(elem.type) !== 'string') {
            warn("type field is missing or not a string");
        } else if (typeof(elem.eventId) !== 'string') {
            warn("eventId is missing or not a string");
        } else if (typeof(elem.time) !== 'number') {
            warn("time is missing or not a number");
        } else if (!isRelevant(ctx, elem)) {
            // too old or is a duplicate, we will be quiet
            continue;
        } else if (elem.type === 'share') {
            onShare(ctx, elem, warn);
        } else if (elem.type === 'anns') {
            onAnns(ctx, elem, warn);
        } else if (elem.type === 'block') {
            onBlock(ctx, elem, warn);
        } else {
            warn("Unhandled event type [" + elem.type + "]");
        }
    }
};

const garbageCollectEvents = (ctx, tree) => {
    const toRemove = [];
    const evt = earliestValidTime(ctx);
    tree.each((ev) => {
        if (ev.time >= evt) { return false; }
        toRemove.push(ev);
    });
    toRemove.forEach((ev) => {
        delete ctx.dedupTable[ev.eventId];
        // We hit the limits of what flow can reason about
        tree.remove((ev /*:any*/));
    });
};
const garbageCollect = (ctx) => {
    garbageCollectEvents(ctx, ctx.blocks);
    garbageCollectEvents(ctx, ctx.anns);
    garbageCollectEvents(ctx, ctx.shares);
};

const getNewestTimestamp = (dataStr) => {
    for (;;) {
        const i = dataStr.lastIndexOf('\n');
        if (i < 0) { return null; }
        try {
            const obj = JSON.parse(dataStr.slice(i));
            if (typeof(obj.time) === 'number') {
                return obj.time;
            }
        } catch (e) { }
        // Failed to parse, try looking backward
        dataStr = dataStr.slice(0, i);
    }
};

const onEvents = (ctx, req, res) => {
    if (Util.badMethod('POST', req, res)) { return; }
    let failed = false;
    const errorEnd = (code, message) => {
        if (failed) { return; }
        console.error("Error posting to /events [" + message + "]");
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ result: '', error: [message], warn: [] }));
    };
    let dataStr;
    let fileName;
    let hash;
    nThen((w) => {
        const data = [];
        req.on('data', (d) => { data.push(d); });
        req.on('error', (e) => {
            return void errorEnd(500, "Error reading data [" + String(e) + "]");
        });
        req.on('end', w(() => {
            if (failed) { return; }
            if (Buffer.isBuffer(data[0])) {
                dataStr = Buffer.concat(data).toString('utf8');
            } else {
                dataStr = data.join('');
            }
        }));
    }).nThen((w) => {
        if (failed) { return; }
        hash = Crypto.createHash('sha256').update(dataStr).digest('hex').slice(0,32);
        const d = getNewestTimestamp(dataStr);
        fileName = ctx.workdir + '/paylog_' + String(d) + '_' + hash + '.bin';
        const again = () => {
            Fs.writeFile(fileName, dataStr, { flag: 'ax' }, w((err) => {
                if (!err) { return; }
                if (err.code === 'EEXIST') {
                    Fs.readFile(fileName, 'utf8', w((err, ret) => {
                        if (err) { throw err; }
                        if (ret !== dataStr) {
                            console.error("File [" + fileName +
                                "] exists but with different content, replacing");
                            again();
                        }
                    }));
                    return;
                }
                throw err;
            }));
        };
        again();
    }).nThen((_) => {
        if (failed) { return; }
        res.end(JSON.stringify({
            result: { eventId: hash },
            warn: [],
            error: []
        }));
        handleEvents(ctx, fileName, dataStr);
        garbageCollect(ctx);
    });
};

const computeWhoToPay = (ctx /*:Context_t*/, maxtime) => {
    // 1. Walk backward through blocks until the total reaches blockPayoutFraction
    //   if we reach the beginning, pay everything that is left to defaultAddress
    //   if we reach a share for which the score is null (meaning we don't know
    //   the difficulty at that time) then print a warning.
    // 2. Walk backward through shares until the total reaches 1-blockPayoutFraction
    //   with the same rules applied.
    //
    // At this point, everything should sum to 1
    //
    let remaining = ctx.mut.cfg.blockPayoutFraction;
    const payouts = {};
    const payoutShares = {};
    const warn = [];
    let earliestBlockPayout = Infinity;
    ctx.shares.reach((s) => {
        if (s.time > maxtime) { return; }
        // console.error('share');
        if (s.credit === null) { return false; }
        earliestBlockPayout = s.time;
        let toPay = s.credit / ctx.mut.cfg.pplnsBlkConstantX;
        if (toPay >= remaining) { toPay = remaining; }
        payoutShares[s.payTo] = (payoutShares[s.payTo] || 0) + 1;
        payouts[s.payTo] = (payouts[s.payTo] || 0) + toPay;
        remaining -= toPay;
        if (remaining === 0) { return false; }
    });
    if (remaining) {
        warn.push("Ran out of block shares to pay paying [" + (remaining * 100) + "%] to " +
            "defaultAddress");
        payouts[ctx.mut.cfg.defaultAddress] =
            (payouts[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    // Now we do announcements
    remaining = 1 - ctx.mut.cfg.blockPayoutFraction;
    let earliestAnnPayout = Infinity;
    const payoutAnns = {};
    ctx.anns.reach((a) => {
        if (a.time > maxtime) { return; }
        // console.error('ann');
        if (a.credit === null) { return false; }
        earliestAnnPayout = a.time;
        let toPay = a.credit / ctx.mut.cfg.pplnsAnnConstantX;
        if (toPay >= remaining) { toPay = remaining; }
        payoutAnns[a.payTo] = (payoutAnns[a.payTo] || 0) + getEffectivePayableAnnCount(a);
        payouts[a.payTo] = (payouts[a.payTo] || 0) + toPay;
        remaining -= toPay;
        if (remaining === 0) { return false; }
    });
    if (remaining) {
        warn.push("Ran out of ann shares to pay paying [" + (remaining * 100) + "%] to " +
            "defaultAddress");
        payouts[ctx.mut.cfg.defaultAddress] =
            (payouts[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    let latestPayout = (()=>{
        const m = ctx.shares.max();
        const t0 = m ? m.time : 0;
        const a = ctx.anns.max();
        const t1 = a ? a.time : 0;
        return Math.max(t0, t1);
    })();

    return ctx.mut.cfg.updateHook({
        error: [],
        warn: warn,
        earliestBlockPayout: earliestBlockPayout,
        earliestAnnPayout: earliestAnnPayout,
        latestPayout: latestPayout,
        payoutShares: payoutShares,
        payoutAnns: payoutAnns,
        result: payouts
    });
};

const sendUpdate = (ctx) => {
    const whotopay = computeWhoToPay(ctx, Infinity);
    if (whotopay.error.length) {
        whotopay.error.forEach((e) => {
            console.error("sendUpdate ERROR:", e);
        });
        console.error("sendUpdate due to errors, sending all coins to ", ctx.mut.cfg.errorAddress);
        whotopay.result = {};
        whotopay.result[ctx.mut.cfg.errorAddress] = 1;
    }
    if (whotopay.warn.length > 0) {
        whotopay.warn.forEach((e) => {
            console.error("sendUpdate WARN:", e);
        });
    }
    let failed = false;
    nThen((w) => {
        console.log('configureMiningPayouts call ' + JSON.stringify(whotopay.result));
        ctx.rpcClient.configureMiningPayouts(whotopay.result, w((err, ret) => {
            console.log('configureMiningPayouts done');
            if (err) {
                console.error("sendUpdate:", err);
                failed = true;
            } else if (!ret || ret.result !== null || ret.error !== null) {
                console.error("sendUpdate: unexpected result:", ret);
                failed = true;
            }
        }));
    }).nThen((w) => {
        if (!failed) { return; }
        const wtp = {};
        wtp[ctx.mut.cfg.errorAddress] = 1;
        ctx.rpcClient.configureMiningPayouts(wtp, w((err, ret) => {
            if (err) {
                console.error("sendUpdate:", err);
                failed = true;
            } else if (!ret || ret.result !== null || ret.error !== null) {
                console.error("sendUpdate: unexpected result:", ret);
                failed = true;
            }
            console.error("sendUpdate CRITICAL: unable to configure payout to error address");
        }));
    });
};

const onWhoToPay = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    let maxtime = Infinity;
    if (req.url.indexOf('?') > -1) {
        const q = Querystring.parse(req.url.slice(req.url.indexOf('?') + 1));
        if (typeof(q.maxtime) === 'string' && !isNaN(Number(q.maxtime))) {
            maxtime = Number(q.maxtime);
        }
    }
    const result = computeWhoToPay(ctx, maxtime);
    res.end(JSON.stringify(result));
};

const onReq = (ctx /*:Context_t*/, req, res) => {
    if (req.url.endsWith('/events')) { return void onEvents(ctx, req, res); }
    if (/\/whotopay(\?.*)?$/.test(req.url)) { return void onWhoToPay(ctx, req, res); }
    res.statusCode = 404;
    res.end("not found");
};

const loadData = (ctx /*:Context_t*/, done) => {
    let files;
    nThen((w) => {
        Fs.readdir(ctx.workdir, w((err, ret) => {
            if (err) { throw err; }
            files = ret.filter((f) => /^paylog_[0-9]+_[a-f0-9]+.bin$/.test(f));
        }));
    }).nThen((w) => {
        if (!files.length) { return; }
        console.error("Loading stored data from [" + String(files.length) + "] files");
        // sort files by time, load most recent historyLength blocks worth
        files.forEach((file) => {
            let num = 0;
            file.replace(/^paylog_([0-9]+)_[a-f0-9]+.bin$/, (_all, n) => {
                num = Number(n);
                return '';
            });
            if (num > ctx.mut.mostRecentEventTime) { ctx.mut.mostRecentEventTime = num; }
        });

        files = files.filter((file) => {
            let num = 0;
            file.replace(/^paylog_([0-9]+)_[a-f0-9]+.bin$/, (_all, n) => {
                num = Number(n);
                return '';
            });
            return num >= (ctx.mut.mostRecentEventTime - (1000 * ctx.mut.cfg.historyDepth));
        });
        let nt = nThen;
        files.forEach((f) => {
            nt = nt((w) => {
                const fileName = ctx.workdir + '/' + f;
                console.error("Loading data from from [" + fileName + "]");
                Fs.readFile(fileName, 'utf8', w((err, ret) => {
                    // These files should not be deleted
                    if (err) { throw err; }
                    handleEvents(ctx, fileName, ret);
                }));
            }).nThen;
        });
        nt(w());
    }).nThen((_) => {
        garbageCollect(ctx);
        console.error("Ready");
        done();
    });
};

module.exports.create = (cfg /*:PayMaker_Config_t*/) => {
    const workdir = cfg.root.rootWorkdir + '/paymaker_' + String(cfg.port);
    let ctx;
    if (typeof(cfg.blockPayoutFraction) !== 'number' ||
        cfg.blockPayoutFraction > 1 ||
        cfg.blockPayoutFraction < 0)
    {
        console.error("WARNING: blockPayoutFraction [" + cfg.blockPayoutFraction +
            "] is not a number between 0 and 1, defaulting to 0.5");
        cfg.blockPayoutFraction = 0.5;
    }
    nThen((w) => {
        Util.checkMkdir(workdir, w());
    }).nThen((w) => {
        ctx = Object.freeze({
            workdir: workdir,
            rpcClient: Rpc.create(cfg.root.rpc),
            dedupTable: {},
            blocks: new RBTree((a, b) => (a.time - b.time)),
            anns: new RBTree((a, b) => (a.time - b.time)),
            shares: new RBTree((a, b) => (a.time - b.time)),
            mut: {
                mostRecentEventTime: 0,
                cfg: cfg
            }
        });
        loadData(ctx, w());
    }).nThen((_) => {
        if (cfg.updateCycle > 0) {
            setInterval(() => {
                sendUpdate(ctx);
            }, cfg.updateCycle * 1000);
        }
        Http.createServer((req, res) => {
            onReq(ctx, req, res);
        }).listen(cfg.port);
    });
};

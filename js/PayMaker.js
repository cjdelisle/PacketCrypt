/*@flow*/
const Fs = require('fs');
const Http = require('http');

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
    each: ((x:X) => ?bool)=>void,
    reach: ((x:X) => ?bool)=>void,
};

export type PayMaker_Result_t = {
    warn: Array<string>,
    error: Array<string>,
    result: { [string]: number }
};
export type PayMaker_Config_t = {
    port: number,
    enabled: bool,
    updateCycle: number,
    historyDepth: number,
    blockPayoutFraction: number,
    pplnsAnnConstantX: number,
    pplnsBlkConstantX: number,
    defaultAddress: string,
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
        cfg: PayMaker_Config_t
    }
};
*/

const getDifficulty = (ctx, time) => {
    let diff = -1;
    ctx.blocks.reach((b) => {
        if (b.time >= time) { return; }
        diff = b.difficulty;
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
    if (Util.isValidPayTo(elem.payTo)) {
        warn("Invalid payTo address");
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

const onAnns = (ctx, elem /*:AnnsEvent_t*/, warn) => {
    if (Util.isValidPayTo(elem.payTo)) {
        warn("Invalid payTo address");
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
            let payableAnnCount = Math.min(0, elem.accepted - elem.unsigned);
            if (elem.totalLen) {
                // for every 16KB of data, we deduct 1 announcement worth of payment
                payableAnnCount = Math.min(0, payableAnnCount - (elem.totalLen >> 14));
            }
            elem.credit = payableAnnCount / diff;
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
    let line = -1;
    const warn = (msg) => {
        console.error(fileName + ":" + String(line), msg, "Event content:", line);
    };
    for (let i = 0; i < strList.length; i++) {
        line = strList[i];
        let elem;
        try {
            elem = JSON.parse(line);
        } catch (e) {
            warn("unable to parse as json");
            continue;
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
                return void errorEnd(400, "Data is binary instead of a string");
            }
            dataStr = data.join('');
        }));
    }).nThen((w) => {
        if (failed) { return; }
        hash = Util.b2hash32(Buffer.from(dataStr, 'utf8')).toString('hex').slice(0,32);
        fileName = ctx.workdir + '/paylog_' + String(+new Date()) + '_' + hash + '.bin';
        Fs.writeFile(fileName, dataStr, { flag: 'ax' }, w((err) => {
            if (!err) { return; }
            throw err;
        }));
    }).nThen((_) => {
        res.end(JSON.stringify({
            result: { eventId: hash },
            warn: [],
            error: []
        }));
        handleEvents(ctx, fileName, dataStr);
        garbageCollect(ctx);
    });
};

const computeWhoToPay = (ctx /*:Context_t*/) => {
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
    const warn = [];
    let earliestBlockPayout = Infinity;
    ctx.shares.reach((s) => {
        if (s.credit === null) { return false; }
        earliestBlockPayout = s.time;
        const toPay = s.credit / ctx.mut.cfg.pplnsBlkConstantX;
        if (toPay >= remaining) {
            payouts[s.payTo] = (payouts[s.payTo] || 0) + remaining;
            remaining = 0;
            return false;
        }
        payouts[s.payTo] = (payouts[s.payTo] || 0) + toPay;
    });
    if (remaining) {
        warn.push("WARNING: Ran out of block shares to pay, consider increasing " +
            "historyDepth, paying [" + (remaining * 100) + "%] of the payout to " +
            "defaultAddress");
        payouts[ctx.mut.cfg.defaultAddress] =
            (payouts[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    // Now we do announcements
    remaining = 1 - ctx.mut.cfg.blockPayoutFraction;
    let earliestAnnPayout = Infinity;
    ctx.shares.reach((a) => {
        if (a.credit === null) { return false; }
        earliestAnnPayout = a.time;
        const toPay = a.credit / ctx.mut.cfg.pplnsAnnConstantX;
        if (toPay >= remaining) {
            payouts[a.payTo] = (payouts[a.payTo] || 0) + remaining;
            remaining = 0;
            return false;
        }
        payouts[a.payTo] = (payouts[a.payTo] || 0) + toPay;
    });
    if (remaining) {
        warn.push("WARNING: Ran out of ann shares to pay, consider increasing " +
            "historyDepth, paying [" + (remaining * 100) + "%] of the payout to " +
            "defaultAddress");
        payouts[ctx.mut.cfg.defaultAddress] =
            (payouts[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    return {
        error: [],
        warn: warn,
        earliestBlockPayout: earliestBlockPayout,
        earliestAnnPayout: earliestAnnPayout,
        result: ctx.mut.cfg.updateHook(payouts)
    };
};

const onWhoToPay = (ctx, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    const result = computeWhoToPay(ctx);
    res.end(JSON.stringify(result));
};

const onReq = (ctx /*:Context_t*/, req, res) => {
    if (req.url.endsWith('/events')) { return void onEvents(ctx, req, res); }
    if (req.url.endsWith('/whotopay')) { return void onWhoToPay(ctx, req, res); }
    res.statusCode = 404;
    res.end("not found");
};

const loadData = (ctx /*:Context_t*/, done) => {
    let files;
    nThen((w) => {
        Fs.readdir(ctx.workdir, w((err, ret) => {
            if (err) { throw err; }
            files = ret.filter((f) => /^paylog_[0-9]+_[0-9]+.bin$/.test(f));
        }));
    }).nThen((w) => {
        if (!files.length) { return; }
        console.error("Loading stored data from [" + String(files.length) + "] files");
        // sort files by block number, load most recent historyLength blocks worth
        let biggest = 0;
        files.forEach((file) => {
            let num = 0;
            file.replace(/^paylog_([0-9]+).bin$/, (_all, n) => {
                num = Number(n);
                return '';
            });
            if (num > biggest) { biggest = num; }
        });
        files = files.filter((f) => {
            let num = 0;
            f.replace(/^paylog_([0-9]+).bin$/, (_all, n) => {
                num = Number(n);
                return '';
            });
            return num >= (biggest - (1000 * ctx.mut.cfg.historyDepth));
        });
        let nt = nThen;
        files.forEach((f) => {
            nt = nt((w) => {
                const fileName = ctx.workdir + '/' + f;
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
                cfg: cfg
            }
        });
        loadData(ctx, w());
    }).nThen((_) => {
        Http.createServer((req, res) => {
            onReq(ctx, req, res);
        }).listen(cfg.port);
    });
};

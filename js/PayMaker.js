/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const Http = require('http');
const Crypto = require('crypto');
const Querystring = require('querystring');

const RBTree = require('bintrees').RBTree;
const nThen = require('nthen');
const Saferphore /*:any*/ = require('saferphore'); // flow doesn't like how saferphore exports

const Util = require('./Util.js');
const Rpc = require('./Rpc.js');
const { config } = require('bitcoind-rpc');

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

type ShareEvent_t = Protocol_ShareEvent_t & {|
    credit: number,
|};
type AnnsEvent_t = Protocol_AnnsEvent_t & {
    credit: number,
    encryptions: number,
};
type Event_t = ShareEvent_t & AnnsEvent_t & Protocol_BlockEvent_t;

type BinTree_t<X> = {
    insert: (x:X) => bool,
    gcOld: (x:number) => number,
    min: () => ?X,
    max: () => ?X,
    each: ((x:X) => ?bool)=>void,
    reach: ((x:X) => ?bool)=>void,
    size: ()=>number,
};
export type PayMaker_Result_t = {|
    warn: Array<string>,
    error: Array<string>,
    totalKbps: number,
    totalEncryptionsPerSecond: number,
    blkPayoutWarmupPeriod: number,
    annPayoutWarmupPeriod: number,
    latestPayout: number,
    lastWonBlock: string,
    lastWonBlockTime: number,
    generatedAt: number,
    annMinerStats: {
        [string]: {|
            lastSeen: number,
            kbps: number,
            warmupPercent: number,
            encryptionsPerSecond: number,
        |},
    },
    blkMinerStats: {
        [string]: {|
            lastSeen: number,
            encryptionsPerSecond: number,
        |},
    },
    result: { [string]: number },
    poolFee: number,
    blockMiners: number,
    annMiners: number,
|};
type PayoutAnnStat_t = {|
    accepted: number,
    firstSeen: number,
    lastSeen: number,
    secondNewestCredit: ?AnnCompressorCredit_t,
|};
type AnnCompressorCredit_t = {|
    encryptions: number,
    credit: number,
    accepted: number,
|};
type AnnCompressorSlot_t = {
    time: number, // when this slot ends
    eventId: string,
    credits: { [string]: AnnCompressorCredit_t },
    eventIds: { [string]: bool } | null,
    count: number,
};
type AnnCompressor_t = {
    timespanMs: number,
    slotsToKeepEvents: number,
    insertWarn: (AnnsEvent_t, (any)=>void) => bool,
    insert: (AnnsEvent_t) => bool,
    gcOld: (x:number) => number,
    min: () => ?AnnCompressorSlot_t,
    max: () => ?AnnCompressorSlot_t,
    each: ((x:AnnCompressorSlot_t) => ?bool)=>void,
    reach: ((x:AnnCompressorSlot_t) => ?bool)=>void,
    size: ()=>number,
    vsize: ()=>number,
    anns: BinTree_t<AnnCompressorSlot_t>,
    lostAnns: ()=>number,
};
type AnnCompressorConfig_t = {
    timespanMs: number,
    slotsToKeepEvents: number,
};
export type PayMaker_Config_t = {
    url: string,
    port: number,
    host?: string,
    maxConnections: ?number,
    updateCycle: number,
    historyDepth: number,
    annCompressor: AnnCompressorConfig_t,
    blockPayoutFraction: number,
    poolFee?: number,
    poolFeeAddress?: string,
    pplnsAnnConstantX: number,
    pplnsBlkConstantX: number,
    defaultAddress: string,
    errorAddress: string,
    updateHook: (x: PayMaker_Result_t) => PayMaker_Result_t,
    root: Config_t,
};
const _flow_typeof_saferphore = Saferphore.create(1);
type Context_t = {
    workdir: string,
    rpcClient: Rpc_Client_t,
    blocks: BinTree_t<Protocol_BlockEvent_t>,
    annCompressor: AnnCompressor_t,
    shares: BinTree_t<ShareEvent_t>,
    oes: typeof _flow_typeof_saferphore,
    startTime: number,
    mut: {
        connections: number,
        mostRecentEventTime: number,
        cfg: PayMaker_Config_t,
        ready: bool,
        mostRecentBlockHash: string,
        mostRecentBlockTime: number,
    }
};
*/

// Number of hashes needed for an expectation of a share
// Should be aligned with this:
// https://github.com/pkt-cash/pktd/blob/a1a569152b078ed28f1526ea8e72e76546b940f1/chaincfg/params.go#L644
const BASE_DIFFICULTY = 4096;

const DEFAULT_ANN_COMPRESSOR_CFG = {
    timespanMs: 1000 * 60,
    slotsToKeepEvents: 10,
};

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
    return ctx.mut.mostRecentEventTime - (1000 * ctx.mut.cfg.historyDepth);
};

const onShare = (ctx, elem /*:ShareEvent_t*/, warn) => {
    if (!Util.isValidPayTo(elem.payTo)) {
        warn("Invalid payTo address [" + elem.payTo + "]");
    } else {
        const diff = getDifficulty(ctx, elem.time);
        if (diff < 1) {
            // we can't credit this share because we don't know the diff at that time
            elem.credit = 0;
        } else {
            // console.log("Difficulty: " + diff);
            // console.log("ShareTarget: " + Util.getWorkMultiple(elem.target));
            elem.credit = Util.getWorkMultiple(elem.target) / diff;
        }
        elem.target = diff;
        ctx.shares.insert(elem);
    }

    if (elem.headerHash) {
        ctx.mut.mostRecentBlockHash = elem.headerHash;
        ctx.mut.mostRecentBlockTime = elem.time;
    }
};

const getPayableAnnWork = (elem /*:AnnsEvent_t*/, payUnsigned /*:bool*/) => {
    let payableAnnCount = elem.accepted;
    if (!payUnsigned) {
        payableAnnCount = Math.max(0, elem.accepted - elem.unsigned);
    }
    if (elem.target > 0x207fffff) { return 0; }
    if (elem.totalLen) {
        // for every 16KB of data, we deduct 1 announcement worth of payment
        payableAnnCount = Math.max(0, payableAnnCount - (elem.totalLen >> 14));
    }
    return Util.getWorkMultiple(elem.target) * payableAnnCount;
};

const onAnns = (ctx, elem /*:AnnsEvent_t*/, warn) => {
    if (!Util.isValidPayTo(elem.payTo)) {
        // warn("Invalid payTo address [" + elem.payTo + "]");
    } else if (typeof (elem.accepted) !== 'number') {
        warn("accepted missing or not a number");
    } else if (typeof (elem.unsigned) !== 'number') {
        warn("unsigned missing or not a number");
    } else if (typeof (elem.totalLen) !== 'number') {
        warn("totalLen missing or not a number");
    } else {
        const diff = getDifficulty(ctx, elem.time);
        if (diff < 1) {
            // we can't credit these anns because we don't know the diff at that time
            elem.credit = 0;
        } else {
            elem.credit = getPayableAnnWork(elem, ctx.mut.cfg.root.privateSeed === null) / diff;
            // console.log("ann payable work:", getPayableAnnWork(elem));
            // console.log("difficulty:", diff);
        }
        // Multiply by 4096 because getWorkMultiple divides, and then by 2 because even at
        elem.encryptions = Util.getWorkMultiple(elem.target) * 4096 * elem.accepted;
        ctx.annCompressor.insertWarn(elem, warn);
    }
};

const onBlock = (ctx, elem /*:Protocol_BlockEvent_t*/, warn) => {
    if (typeof (elem.height) !== 'number') {
        warn("height is missing or invalid");
    } else if (typeof (elem.difficulty) !== 'number') {
        warn("difficulty is missing or not a number");
    } else {
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

        // Reduce memory usage
        // Commented out because in testing it didn't reduce anything.
        //elem.eventId = Buffer.from(elem.eventId, 'hex').toString('base64');

        if (typeof (elem.type) !== 'string') {
            warn("type field is missing or not a string");
        } else if (typeof (elem.eventId) !== 'string') {
            warn("eventId is missing or not a string");
        } else if (typeof (elem.time) !== 'number') {
            warn("time is missing or not a number");
        } else if (elem.time < earliestValidTime(ctx)) {
            // too old
            continue;
        } else if (elem.type === 'share') {
            if (!elem.target) {
                elem.target = 0x20000fff;
            }
            onShare(ctx, elem, warn);
        } else if (elem.type === 'anns') {
            if (!elem.target) {
                elem.target = 0x20000fff;
            }
            onAnns(ctx, elem, warn);
        } else if (elem.type === 'block') {
            onBlock(ctx, elem, warn);
        } else {
            warn("Unhandled event type [" + elem.type + "]");
        }
    }
};

const garbageCollect = (ctx) => {
    const evt = earliestValidTime(ctx);
    const b = ctx.blocks.gcOld(evt);
    const a = ctx.annCompressor.gcOld(evt);
    const s = ctx.shares.gcOld(evt);
    console.error(`Garbage collected [blocks:${b} anns:${a} shares:${s}]`);
};

const getNewestTimestamp = (dataStr) => {
    // We're only going to search the last 10000 bytes of the thing for
    // a useful block, if we get uploaded a giant binary we're failing it!
    if (dataStr.length > 10000) {
        dataStr = dataStr.slice(dataStr.length - 10000);
    }
    for (; ;) {
        let i = dataStr.lastIndexOf('\n');
        let toParse = dataStr;
        if (i < 0) {
            if (dataStr.length === 0) { return null; }
        } else {
            toParse = dataStr.slice(i);
        }
        try {
            const obj = JSON.parse(toParse);
            if (typeof (obj.time) === 'number') {
                return obj.time;
            }
        } catch (e) { }
        if (i < 0) {
            return null;
        }
        // Failed to parse, try looking backward
        dataStr = dataStr.slice(0, i);
    }
};

const stats = (ctx) => {
    return 'annSlots:' + ctx.annCompressor.size() +
        ' shares:' + ctx.shares.size() +
        ' blocks:' + ctx.blocks.size() +
        ' conn: ' + ctx.mut.connections +
        ' lost: ' + ctx.annCompressor.lostAnns();
};

const onEvents = (ctx, req, res, done) => {
    if (Util.badMethod('POST', req, res)) { return done(); }
    let failed = false;
    const errorEnd = (code, message) => {
        if (failed) { return; }
        console.error("Error posting to /events [" + message + "]");
        failed = true;
        res.statusCode = code;
        res.end(JSON.stringify({ result: '', error: [message], warn: [] }));
        done();
    };
    let dataStr;
    let fileName;
    let hash;
    let newestTimestamp;
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
        hash = Crypto.createHash('sha256').update(dataStr).digest('hex').slice(0, 32);
        console.error("/events Processing file [" + hash + "] [" + stats(ctx) + "]");
        newestTimestamp = getNewestTimestamp(dataStr);
        if (newestTimestamp === null) {
            return void errorEnd(400, "could not get most recent timestamp from file");
        }
        fileName = ctx.workdir + '/paylog_' + String(newestTimestamp) + '_' + hash + '.bin';
        const again = () => {
            Fs.writeFile(fileName, dataStr, { flag: 'ax' }, w((err) => {
                if (!err) { return; }
                if (err.code === 'EEXIST') {
                    Fs.readFile(fileName, 'utf8', w((err, ret) => {
                        if (err) { throw err; }
                        if (ret !== dataStr) {
                            console.error("File [" + fileName +
                                "] exists but with different content, replacing");
                            Fs.unlink(fileName, w((err) => {
                                if (err) {
                                    return void errorEnd(500, "could delete file to replace it");
                                }
                                again();
                            }));
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
        if (newestTimestamp && ctx.mut.mostRecentEventTime < newestTimestamp) {
            ctx.mut.mostRecentEventTime = newestTimestamp;
        }
        garbageCollect(ctx);
        console.error("/events done processing [" + hash + "]");
        done();
    });
};

const ENCRYPTIONS_PER_SECOND_WINDOW = 1000 * 60 * 10;

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
    const blockMinerWork = {};
    const mostRecentlySeen = {};
    const warn = [];
    let earliestBlockPayout = Infinity;
    const encryptionCountCutoff = (+new Date()) - ENCRYPTIONS_PER_SECOND_WINDOW;
    const blockMinerCredits = {};
    ctx.shares.reach((s) => {
        if (s.time > maxtime) { return; }
        // console.error('share');
        if (s.credit === null) { return false; }
        earliestBlockPayout = s.time;
        let toPay = s.credit / ctx.mut.cfg.pplnsBlkConstantX;
        if (toPay >= remaining) { toPay = remaining; }
        if (s.time > encryptionCountCutoff && s.encryptions) {
            blockMinerWork[s.payTo] = (blockMinerWork[s.payTo] || 0) + s.encryptions;
        }
        if (!mostRecentlySeen[s.payTo]) { mostRecentlySeen[s.payTo] = s.time; }
        blockMinerCredits[s.payTo] = (blockMinerCredits[s.payTo] || 0) + toPay;
        remaining -= toPay;
        if (remaining === 0) { return false; }
    });
    if (remaining) {
        warn.push("Ran out of block shares to pay paying [" + (remaining * 100) + "%] to " +
            "defaultAddress");
        blockMinerCredits[ctx.mut.cfg.defaultAddress] =
            (blockMinerCredits[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    // Now we do announcements
    remaining = 1 - ctx.mut.cfg.blockPayoutFraction;
    let earliestAnnPayout = Infinity;
    const payoutAnnStats /*:{[string]: PayoutAnnStat_t }*/ = {};
    let mostRecentAnns = 0;
    const annMinerCredits = {};
    ctx.annCompressor.reach((a) => {
        if (a.time > maxtime) { return; }
        // console.error('ann');
        const addresses = Object.keys(a.credits);
        for (const payTo of addresses) {
            const credit = a.credits[payTo];
            if (credit.credit === 0) { return; }
            earliestAnnPayout = a.time;
            let toPay = credit.credit / ctx.mut.cfg.pplnsAnnConstantX;
            if (toPay >= remaining) { toPay = remaining; }
            let ps = payoutAnnStats[payTo];
            if (!ps) {
                ps = payoutAnnStats[payTo] = {
                    accepted: 0,
                    firstSeen: 0,
                    lastSeen: a.time,
                    secondNewestCredit: null
                };
                if (a.time > mostRecentAnns) { mostRecentAnns = a.time; }
            } else if (ps.secondNewestCredit === null) {
                ps.secondNewestCredit = credit;
            }
            ps.firstSeen = a.time;
            ps.accepted += credit.accepted;
            annMinerCredits[payTo] = (annMinerCredits[payTo] || 0) + toPay;
            remaining -= toPay;
            if (remaining === 0) { return false; }
        }
    });
    if (remaining) {
        warn.push("Ran out of ann shares to pay paying [" + (remaining * 100) + "%] to " +
            "defaultAddress");
        annMinerCredits[ctx.mut.cfg.defaultAddress] =
            (annMinerCredits[ctx.mut.cfg.defaultAddress] || 0) + remaining;
    }

    const latestPayout = (() => {
        const m = ctx.shares.max();
        const t0 = m ? m.time : 0;
        const a = ctx.annCompressor.max();
        const t1 = a ? a.time : 0;
        return Math.max(t0, t1);
    })();

    const annMinerStats = {};
    let totalKbps = 0;
    let totalEncryptionsPerSecond = 0;
    for (const payTo in payoutAnnStats) {
        const pas = payoutAnnStats[payTo];
        const snc = pas.secondNewestCredit;
        if (!snc) { continue; }
        const apms = snc.accepted / ctx.annCompressor.timespanMs;
        const kbps = Math.floor(apms * 1000 * 8);

        const encryptionsPerSecond =
            Math.floor(snc.encryptions * 1000 / ctx.annCompressor.timespanMs);
        totalEncryptionsPerSecond += encryptionsPerSecond;
        const minerLifetime = pas.lastSeen - pas.firstSeen;
        const timespan = mostRecentAnns - earliestAnnPayout;

        totalKbps += kbps;
        let warmupPercent = Math.floor(minerLifetime / timespan * 100);
        if (warmupPercent > 90) { warmupPercent = 100; }
        annMinerStats[payTo] = {
            kbps,
            warmupPercent,
            currentEncryptionsPerSecond: encryptionsPerSecond,
            lastSeen: pas.lastSeen,
            credits: annMinerCredits[payTo],
        }
    }

    const blkMinerStats = {};
    for (const payTo in mostRecentlySeen) {
        let encryptionsPerSecond = 0;
        if (payTo in blockMinerWork) {
            encryptionsPerSecond =
                Math.floor(blockMinerWork[payTo] / ENCRYPTIONS_PER_SECOND_WINDOW * 1000);
        }
        totalEncryptionsPerSecond += encryptionsPerSecond;
        blkMinerStats[payTo] = {
            currentEncryptionsPerSecond: encryptionsPerSecond,
            lastSeen: mostRecentlySeen[payTo],
            credits: blockMinerCredits[payTo],
        };
    }

    const payoutsList = [];
    for (const bmc in blockMinerCredits) {
        payoutsList.push([bmc, blockMinerCredits[bmc]]);
    }
    for (const amc in annMinerCredits) {
        payoutsList.push([amc, annMinerCredits[amc]]);
    }
    payoutsList.sort((x, y) => y[1] - x[1]);
    const payouts2 = {};
    let poolFee = 0;
    const poolFeeAddress = ctx.mut.cfg.poolFeeAddress || '';
    if (!ctx.mut.cfg.poolFee) {
    } else if (ctx.mut.cfg.poolFee >= 1 || ctx.mut.cfg.poolFee < 0) {
        warn.push(`invalid poolFee ${ctx.mut.cfg.poolFee} must be between 0 and 1`);
    } else if (!Util.isValidPayTo(poolFeeAddress)) {
        warn.push(`invalid poolFeeAddress ${poolFeeAddress}`);
    } else {
        poolFee = ctx.mut.cfg.poolFee || 0;
        payouts2[poolFeeAddress] = poolFee;
    }
    payoutsList.forEach((x) => payouts2[x[0]] = (payouts2[x[0]] || 0) + x[1] * (1 - poolFee));

    return ctx.mut.cfg.updateHook({
        error: [],
        warn: warn,
        totalKbps,
        totalEncryptionsPerSecond,
        blkPayoutWarmupPeriod: latestPayout - earliestBlockPayout,
        annPayoutWarmupPeriod: latestPayout - earliestAnnPayout,
        generatedAt: +new Date(),
        latestPayout: latestPayout,
        lastWonBlock: ctx.mut.mostRecentBlockHash,
        lastWonBlockTime: ctx.mut.mostRecentBlockTime,
        annMinerStats,
        blkMinerStats,
        result: payouts2,
        poolFee,
        blockMiners: ctx.mut.cfg.blockPayoutFraction * (1 - poolFee),
        annMiners: (1 - ctx.mut.cfg.blockPayoutFraction) * (1 - poolFee),
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
        const again = (i) => {
            console.error("configuring payouts [" + stats(ctx) + "]");
            ctx.rpcClient.configureMiningPayouts(whotopay.result, w((err, ret) => {
                if (err) {
                    if ((err /*:any*/).code === -32603 && i < 20) {
                        // This is pktd being dumb
                        setTimeout(() => { again(i + 1); }, 1000);
                        return;
                    }
                    console.error("sendUpdate:", err);
                    failed = true;
                } else if (!ret || ret.result !== null || ret.error !== null) {
                    console.error("sendUpdate: unexpected result:", ret);
                    failed = true;
                }
            }));
        };
        again(0);
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
        if (typeof (q.maxtime) === 'string' && !isNaN(Number(q.maxtime))) {
            maxtime = Number(q.maxtime);
        }
    }
    const result = computeWhoToPay(ctx, maxtime);
    res.end(JSON.stringify(result, null, '\t'));
};

const onStats = (ctx /*:Context_t*/, req, res) => {
    if (Util.badMethod('GET', req, res)) { return; }
    res.end(JSON.stringify({
        blocks: ctx.blocks.size(),
        compressedAnnSlots: ctx.annCompressor.size(),
        shares: ctx.shares.size(),
        memory: process.memoryUsage(),
    }, null, '\t'));
};

const maxConnections = (ctx) => {
    return ctx.mut.cfg.maxConnections || 50;
};

const onReq = (ctx /*:Context_t*/, req, res) => {
    const authLine = 'Basic ' +
        Buffer.from('x:' + ctx.mut.cfg.root.paymakerHttpPasswd, 'utf8').toString('base64');

    if (ctx.mut.connections > maxConnections(ctx)) {
        res.statusCode = 501;
        return void res.end("overloaded");
    }
    ctx.mut.connections++;
    res.on('close', () => {
        ctx.mut.connections--;
    });

    if (req.url.endsWith('/stats')) {
        return void onStats(ctx, req, res);
    }
    if (!ctx.mut.ready) {
        res.writeHead(500);
        res.end("500 Not ready");
        return;
    }
    if (req.url.endsWith('/events')) {
        if (req.headers.authorization !== authLine) {
            res.setHeader("WWW-Authenticate", "Basic realm=paymaker");
            res.writeHead(401);
            res.end("401 Unauthorized");
            return;
        }
        ctx.oes.take((returnAfter) => {
            onEvents(ctx, req, res, returnAfter(() => { }));
        });
        return;
    }
    if (/\/whotopay(\?.*)?$/.test(req.url)) {
        return void onWhoToPay(ctx, req, res);
    }
    res.statusCode = 404;
    res.end("not found");
};

const loadData = (ctx /*:Context_t*/, done) => {
    let files;
    nThen((w) => {
        console.log(ctx.workdir);
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
        files.forEach((f, i) => {
            nt = nt((w) => {
                if (0 === (i % 100)) { garbageCollect(ctx); }
                const fileName = ctx.workdir + '/' + f;
                let dateFile = '<unknown date>';
                fileName.replace(/paylog_([0-9]+)_/, (all, x) => {
                    dateFile = (new Date(Number(x))).toISOString();
                    return '';
                });
                console.error("Loading data from [" + fileName + "] [" +
                    dateFile + "] [" + Math.floor(i * 100 / files.length) + "%] [" + stats(ctx) + "]");
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
        console.error("Ready (in " + (((+new Date()) - ctx.startTime) / 1000) + " seconds)");
        done();
    });
};

const mkTree = /*::<X:{time:number,eventId:string}>*/() /*:BinTree_t<X>*/ => {
    const tree = new RBTree((a, b) => {
        if (a === b) { return 0; }
        if (a.time === b.time) {
            if (a.eventId < b.eventId) { return -1; }
            if (a.eventId > b.eventId) { return 1; }
            return 0;
        }
        return a.time - b.time;
    });
    //const dedup = new RBTree((a,b) => ( (a < b) ? -1 : ((a>b) ? 1 : 0) ));
    const dedup = {};

    return Object.freeze({
        insert: (x /*:X*/) => {
            if (x.eventId in dedup) { return false; }
            dedup[x.eventId] = true;
            return tree.insert(x);
        },
        gcOld: (beforeTime /*:number*/) /*:number*/ => {
            const toRemove = [];
            const oldSize = tree.size;
            tree.each((x) => {
                if (x.time >= beforeTime) { return; }
                toRemove.push(x);
            });
            for (let i = 0; i < toRemove.length; i++) {
                delete dedup[toRemove[i].eventId];
                tree.remove(toRemove[i]);
            }
            if (oldSize - tree.size !== toRemove.length) {
                console.error(`WARNING: removed [${toRemove.length}] items but only ` +
                    `[${oldSize - tree.size}] items actually were removed`);
            }
            return oldSize - tree.size;
        },
        each: (x) => tree.each(x),
        reach: (x) => tree.reach(x),
        min: () => tree.min(),
        max: () => tree.max(),
        size: () => tree.size,
    });
};

const mkCompressor = (cfg /*:AnnCompressorConfig_t*/) /*:AnnCompressor_t*/ => {
    let lostAnns = 0;
    const tree = mkTree/*::<AnnCompressorSlot_t>*/();
    const cctx = Object.freeze({
        timespanMs: cfg.timespanMs || DEFAULT_ANN_COMPRESSOR_CFG.timespanMs,
        slotsToKeepEvents: cfg.slotsToKeepEvents || DEFAULT_ANN_COMPRESSOR_CFG.slotsToKeepEvents,
        anns: tree,
        insertWarn: (x /*:AnnsEvent_t*/, warn) => {
            let newerDs;
            cctx.anns.reach((ds) => {
                // Keep searching back
                if (x.time < ds.time) {
                    newerDs = ds;
                    return;
                }
                if (!newerDs) {
                    // Newer than anything, create a new slot
                    newerDs = {
                        time: ds.time + cctx.timespanMs,
                        eventId: 'COMPRESSED_EVENTS_' + ds.time + cctx.timespanMs,
                        credits: {},
                        eventIds: {},
                        count: 0,
                    };
                    cctx.anns.insert(newerDs);
                    return false;
                }
                // found the correct slot
                return false;
            });
            if (!newerDs) {
                // empty tree or just a single entry in the tree
                const t = x.time - (x.time % cctx.timespanMs);
                newerDs = {
                    time: t,
                    eventId: 'COMPRESSED_EVENTS_' + String(t),
                    credits: {},
                    eventIds: {},
                    count: 0,
                };
                cctx.anns.insert(newerDs);
            }
            if (newerDs.eventIds === null) {
                // this event has had it's event id block garbage collected
                //warn("Unable to add event, compressor entry dedup table was pruned");
                lostAnns++;
                return false;
            } else if (x.eventId in newerDs.eventIds) {
                // dupe
                return false;
            } else {
                newerDs.eventIds[x.eventId] = true;
                const c = newerDs.credits[x.payTo] = (newerDs.credits[x.payTo] || {
                    encryptions: 0, credit: 0, accepted: 0
                });
                c.encryptions += x.encryptions;
                c.credit += x.credit;
                c.accepted += x.accepted;
                newerDs.count++;
                return true;
            }
        },
        gcOld: (earliestValidTime) => {
            const last = cctx.anns.max();
            if (!last) { return 0; }
            const oldestEventsTime = last.time - (cctx.timespanMs * cctx.slotsToKeepEvents);
            const ret = cctx.anns.gcOld(earliestValidTime);
            cctx.anns.reach((slot) => {
                if (slot.time > oldestEventsTime) { return; }
                if (slot.eventIds === null) { return false; }
                slot.eventIds = null;
            });
            return ret;
        },
        insert: (x /*:AnnsEvent_t*/) => cctx.insertWarn(x, (_) => { }),
        each: (x) => tree.each(x),
        reach: (x) => tree.reach(x),
        min: () => tree.min(),
        max: () => tree.max(),
        size: () => tree.size(),
        vsize: () => {
            let out = 0;
            cctx.anns.each((ds) => { out += ds.count; });
            return out;
        },
        lostAnns: () => lostAnns,
    });
    return cctx;
};

module.exports.create = (cfg /*:PayMaker_Config_t*/) => {
    const workdir = cfg.root.rootWorkdir + '/paymaker_' + String(cfg.port);
    let ctx /*:Context_t*/;
    if (typeof (cfg.blockPayoutFraction) !== 'number' ||
        cfg.blockPayoutFraction > 1 ||
        cfg.blockPayoutFraction < 0) {
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
            blocks: mkTree/*::<Protocol_BlockEvent_t>*/(),
            annCompressor: mkCompressor(cfg.annCompressor || DEFAULT_ANN_COMPRESSOR_CFG),
            shares: mkTree/*::<ShareEvent_t>*/(),
            oes: Saferphore.create(1),
            startTime: +new Date(),
            mut: {
                connections: 0,
                mostRecentEventTime: 0,
                cfg: cfg,
                ready: false,

                mostRecentBlockHash: '',
                mostRecentBlockTime: -1,
            }
        });
        Http.createServer((req, res) => {
            onReq(ctx, req, res);
        }).listen(cfg.port, cfg.host);
        loadData(ctx, w());
    }).nThen((_) => {
        if (cfg.updateCycle > 0) {
            setInterval(() => {
                sendUpdate(ctx);
            }, cfg.updateCycle * 1000);
        }
        ctx.mut.ready = true;
    });
};

/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/

const Events = require('events');
const EventEmitter = Events.EventEmitter;

const Protocol = require('./Protocol.js');
const Util = require('./Util.js');

// events:
//// connected -> we are connected to the pool and the current work is valid
//// disconnected -> we lost connection to the pool, suspend mining
//// work -> we are connected to the pool, the work has changed

/*::
import type {
    Protocol_PcConfigJson_t,
    Protocol_Work_t,
    Protocol_RawBlockTemplate_t
} from './Protocol.js'
export type PoolClient_t = {
    _ee: EventEmitter,
    url: string,
    work: Protocol_Work_t|void,
    workByNum: { [number]:Protocol_Work_t },
    connected: bool,
    config: Protocol_PcConfigJson_t,
    currentHeight: number,
    onWork: (f:(w:Protocol_Work_t)=>void)=>void,
    getWork: (f:(w:Protocol_Work_t)=>void)=>void,
    onConnected: (f:()=>void)=>void,
    onDisconnected: (f:()=>void)=>void,
    getMasterConf: ((Protocol_PcConfigJson_t)=>void)=>void,
    getWorkByNum: (number, (Protocol_Work_t)=>void)=>void,
    getAnn: (Buffer, cb:(?Error, ?Buffer)=>void)=>void,
    getBlockTemplate: (cb:(?Error, ?Protocol_RawBlockTemplate_t)=>void)=>void
};
*/

const debug = (msg) => { console.error("PoolClient: " + msg); };

const debugGotWork = (work) => {
    debug("Got work - " + work.height + ' ' + work.lastHash.toString('hex') +
        ' - ' + work.annTarget.toString(16) + ' - ' + work.shareTarget.toString(16));
};

const workUrl2 = (pool /*:PoolClient_t*/, height /*:number*/) => {
    return pool.config.masterUrl + '/work_' + height + '.bin';
};
const btUrl2 = (pool /*:PoolClient_t*/, height /*:number*/) => {
    return pool.config.masterUrl + '/bt_' + height + '.bin';
};

const DISCONNECTED_MS = 15 * 1000;
const CONNECTION_CHECKER_PERIOD_MS = 5 * 1000;

const startLongPoll2 = (pool /*:PoolClient_t*/) => {
    const url = workUrl2(pool, pool.currentHeight + 1);
    Util.httpGetBin(url, (err, res) => {
        if (!res) {
            if (err && (err /*:any*/).code === 'ECONNRESET') {
                return void startLongPoll2(pool);
            } else if ((err /*:any*/).statusCode === 404) {
                // We lost the block, wait and we'll get a new config
                return void setTimeout(() => { startLongPoll2(pool); }, 5000);
            }
            debug("Failed to get [" + url + "] [" + JSON.stringify(err || null) + "]");
            return true;
        }
        const work = Protocol.workDecode(res);
        pool.workByNum[work.height] = work;
        if (work.height >= pool.currentHeight) {
            pool.currentHeight = work.height;
            pool.work = work;
            debugGotWork(work);
            pool._ee.emit('work', work);
        }
        startLongPoll2(pool);
    });
};

const connectionChecker = (pool, first) => {
    const to = setTimeout(() => {
        if (first) { return; }
        pool.connected = false;
        debug("Disconnected");
        pool._ee.emit('disconnected');
    }, DISCONNECTED_MS);

    Util.httpGetStr(pool.url + '/config.json', (err, data) => {
        if (!data) {
            debug("Failed to get config.json [" + JSON.stringify(err || null) + "] retrying");
            return true;
        }
        const config /*:Protocol_PcConfigJson_t*/ = JSON.parse(data);
        const v = typeof (config.version) === 'undefined' ? undefined : config.version;
        if (v !== Protocol.VERSION) {
            console.error("Pool version is [" + String(v) + "] and this miner requires version [" +
                Protocol.VERSION + "] please upgrade");
            process.exit(100);
        }
        const sv = typeof (config.softVersion) === 'undefined' ? undefined : config.softVersion;
        if (sv && sv > Protocol.SOFT_VERSION) {
            console.error("Pool soft version is [" + String(sv) + "], upgrading is recommended");
        }
        if (!first && JSON.stringify(pool.config) !== JSON.stringify(config)) {
            delete pool.workByNum[config.currentHeight];
            pool.getWorkByNum(config.currentHeight, (work) => {
                if (JSON.stringify(work) !== JSON.stringify(pool.work)) {
                    debugGotWork(work);
                    pool.work = work;
                    pool._ee.emit('work', work);
                }
            });
        }
        pool.config = config;
        pool.currentHeight = config.currentHeight;
        setTimeout(() => {
            connectionChecker(pool, false);
        }, CONNECTION_CHECKER_PERIOD_MS);

        if (first) {
            pool.getWorkByNum(pool.currentHeight, (work) => {
                pool.connected = true;
                clearTimeout(to);
                debugGotWork(work);
                pool.work = work;
                pool._ee.emit('work', work);
            });
            startLongPoll2(pool);
        } else if (pool.connected) {
            clearTimeout(to);
        } else {
            pool.connected = true;
            debug("Reconnected");
            pool._ee.emit('connected');
        }
    });
};

const getAnn = (pool, masterConf, hash /*:Buffer*/, cb) => {
    const node = hash.readUInt32LE(0) % masterConf.downloadAnnUrls.length;
    const url = masterConf.downloadAnnUrls[node] + '/ann/ann_' + hash.toString('hex') + '.bin';
    debug("Getting Announcement [" + url + "]");
    Util.httpGetBin(url, (err, res) => {
        if (!res) {
            debug("Failed to get [" + url + "] [" + JSON.stringify(err || null) + "]");
            if ((err /*:any*/).statusCode === 404) {
                return void cb(new Error("not found"));
            }
            return true;
        }
        cb(undefined, res);
    });
};

module.exports.create = (poolUrl /*:string*/) /*:PoolClient_t*/ => {
    const ee = new EventEmitter();
    const pool = {};
    pool._ee = ee;
    pool.url = poolUrl;
    pool.work = undefined;
    pool.bt = undefined;
    pool.workByNum = {};
    pool.connected = false;
    pool.reconnects = 0;
    pool.reconnectTo = undefined;

    const getWork = [];
    pool.getWork = (f /*:(Protocol_Work_t)=>void*/) => {
        if (pool.work) { return void f(pool.work); }
        getWork.push(f);
    };
    ee.on('work', (w) => {
        getWork.forEach((f) => (f(w)));
        getWork.length = 0;
    });

    const getMasterConf = [];
    pool.getMasterConf = (f /*:(Protocol_PcConfigJson_t)=>void*/) => {
        if (pool.config) { return void setTimeout(() => f(pool.config)); }
        getMasterConf.push(f);
    };
    pool.getWork((w) => {
        getMasterConf.forEach((f) => (f(pool.config)));
        getMasterConf.length = 0;
    });

    pool.getBlockTemplate = (f /*:(?Error, ?Protocol_RawBlockTemplate_t)=>void*/) => {
        pool.getWork((w) => {
            if (pool.bt && pool.bt.height === w.height) {
                return void setTimeout(() => {
                    f(undefined, pool.bt);
                });
            }
            const url = btUrl2(pool, w.height);
            //console.log("Getting: " + url);
            Util.httpGetBin(url, (err, ret) => {
                if (!ret) {
                    debug("Error getting [" + url + "] [" + JSON.stringify(err || null) + "], retrying");
                    return true;
                }
                try {
                    pool.bt = Protocol.blockTemplateDecode(ret);
                } catch (e) {
                    console.error("Error decoding ann at [" + url + "] [" + e + "]");
                    f(e);
                    return;
                }
                f(undefined, pool.bt);
            });
        });
    };

    pool.getWorkByNum = (num /*:number*/, f /*:(Protocol_Work_t)=>void*/) => {
        if (pool.workByNum[num]) {
            const work = pool.workByNum[num];
            return void setTimeout(() => { f(work); });
        }
        const url = workUrl2(pool, num);
        Util.httpGetBin(url, (err, res) => {
            if (!res) {
                debug("Error getting [" + url + "] [" + JSON.stringify(err || null) + "], retrying");
                return true;
            }
            const work = pool.workByNum[num] = Protocol.workDecode(res);
            f(work);
        });
    };
    pool.onWork = (f /*:(w:Protocol_Work_t)=>void*/) => {
        if (pool.work) { f(pool.work); }
        ee.on('work', f);
    };
    pool.onConnected = (f /*:()=>void*/) => { ee.on('connected', f); };
    pool.onDisconnected = (f /*:()=>void*/) => { ee.on('disconnected', f); };
    pool.getAnn = (hash /*:Buffer*/, cb /*:(?Error, ?Buffer)=>void*/) => {
        pool.getMasterConf((mc) => { getAnn(pool, mc, hash, cb); });
    };

    connectionChecker(pool, true);
    return pool;
};

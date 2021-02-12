/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const Http = require('http');
const EventEmitter = require('events').EventEmitter;
const Crypto = require('crypto');

const Saferphore = require('saferphore');
const Tweetnacl = require('tweetnacl');
const Blake2b = require('blake2b');
const nThen = require('nthen');
const Bs58Check = require('bs58check');
const Bech32 = require('bech32');
const Agent = require('agentkeepalive');

const keepaliveAgent = new Agent({
    maxSockets: 500,
    maxFreeSockets: 10,
    timeout: 60000, // 60 seconds
    freeSocketTimeout: 30000, // 30 seconds
});

/*::
import type { IncomingMessage, ServerResponse } from 'http'
import type { WriteStream } from 'fs'

import type { Config_t } from './Config.js'
import type { BigInt_t } from './Protocol.js'
import { BigInt } from './Protocol.js'

export type Util_LongPollServer_t = {
    onReq: (IncomingMessage, ServerResponse)=>void,
    // caution, you will get file updates also when a file is deleted, not just when it's created
    onFileUpdate: ((string)=>void)=>void
};
export type Util_Mutex_t = ((()=>void)=>void)=>void;
export type Util_KeyPair_t = {
    secretKey: Uint8Array,
    publicKey: Uint8Array,
}
*/

const checkMkdir = (path /*:string*/, cb /*:()=>void*/) => {
    if (path.endsWith('/')) { path = path.slice(0, -1); }
    Fs.stat(path, (err, _st) => {
        if (err && err.code === 'ENOENT') {
            return void checkMkdir(path.replace(/\/[^\/]+$/, ''), () => {
                Fs.mkdir(path, 0755, (err) => {
                    // race conditions...
                    if (err && err.code !== 'EEXIST') { throw err; }
                    cb();
                });
            });
        }
        if (err) { throw err; }
        cb();
    });
};
module.exports.checkMkdir = checkMkdir;

const clearDir = (path /*:string*/, cb /*:()=>void*/) => {
    Fs.readdir(path, (err, files) => {
        if (err) {
            if (err.code === 'ENOENT') { return void cb(); }
            throw err;
        }
        let nt = nThen;
        files.forEach((f) => {
            const fpath = path + '/' + f;
            let st;
            nt = nt((w) => {
                Fs.stat(fpath, w((err, ret) => {
                    if (err) { throw err; }
                    st = ret;
                }));
            }).nThen((w) => {
                if (st.isDirectory()) {
                    clearDir(fpath, w(() => {
                        Fs.rmdir(fpath, w((err) => {
                            if (err) { throw err; }
                        }));
                    }));
                } else {
                    Fs.unlink(fpath, w((err) => {
                        if (err) { throw err; }
                    }));
                }
            }).nThen;
        });
        nt((_w) => {
            cb();
        });
    });
};
module.exports.clearDir = clearDir;

module.exports.bufFromHex = (
    x /*:string*/
) /*:Buffer*/ => (Buffer.from(x, 'hex'));

module.exports.once = /*::<F:Function>*/(f /*:F*/) /*:F*/ => {
    let guard = false;
    return ((function () {
        if (guard) { return; }
        guard = true;
        return f.apply(null, arguments);
    }/*:any*/) /*:F*/);
};

const MAX_FAST_RECONNECTS = 10;
const FAST_RECONNECT_MS = 1000;
const RECONNECT_MS = 10000;

const httpGet = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?Buffer|string)=>?bool*/
) => {
    let reconnects = 0;
    const ee = new EventEmitter();
    const again = () => {
        let ended = false;
        setTimeout(() => {
            if (ended) { return; }
            console.error("httpGet [" + url + "] has stalled, retrying...");
            ended = true;
            again();
        }, 60000);
        const cb1 = (err, res) => {
            if (ended) { return; }
            ended = true;
            if (cb(err, res) === true) {
                const reconnectMs = (reconnects > MAX_FAST_RECONNECTS) ?
                    RECONNECT_MS : FAST_RECONNECT_MS;
                setTimeout(again, reconnectMs);
                console.error("Reconnect to [" + url + "] in [" + reconnectMs + "]ms");
                reconnects++;
            }
        };
        const h = Http.get(url, { agent: keepaliveAgent }, (res) => {
            if (res.statusCode !== 200) {
                if (res.statusCode === 300 && res.headers['x-pc-longpoll'] === 'try-again') {
                    ended = true;
                    return void again();
                }
                cb1({ statusCode: res.statusCode });
            } else {
                const data = [];
                res.on('data', (d) => { data.push(d); });
                res.on('error', (e) => { cb1(e); });
                res.on('end', () => {
                    if (typeof (data[0]) === 'string') {
                        return cb1(undefined, data.join(''));
                    }
                    return cb1(undefined, Buffer.concat(data));
                });
            }
        });
        h.on('error', (e) => {
            if ((h /*:any*/).reusedSocket && e.code === 'ECONNRESET') {
                // We're trying to reuse a connection but the server had other plans
                // https://github.com/node-modules/agentkeepalive#support-reqreusedsocket
                ended = true;
                return void again();
            }
            cb1(e);
        });
        const l = () => { ee.emit('connection'); };
        h.on('socket', (s) => {
            // cleanup the socket after use because they're reused
            s.on('connect', l);
            const cleanup = () => s.removeListener('connect', l);
            h.on('response', cleanup);
            h.on('error', cleanup);
            h.on('abort', cleanup);
            h.on('end', cleanup);
        });
    };
    again();
};
module.exports.httpGet = httpGet;

const httpGetBin = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?Buffer)=>?bool*/
) /*:void*/ => {
    return httpGet(url, (err, buf) => {
        if (err) { return cb(err); }
        if (typeof (buf) === 'string') { return cb(undefined, Buffer.from(buf, 'utf8')); }
        return cb(undefined, buf);
    });
};
module.exports.httpGetBin = httpGetBin;

module.exports.httpGetStr = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?string)=>?bool*/
) /*:void*/ => {
    return httpGet(url, (err, buf) => {
        if (!buf) { return cb(err); }
        if (typeof (buf) === 'string') { return cb(undefined, buf); }
        return cb(undefined, buf.toString('utf8'));
    });
};

const listRemove = /*::<T>*/(list /*:Array<T>*/, item /*:T*/) /*:bool*/ => {
    const idx = list.indexOf(item);
    if (idx < 0) { return false; }
    list.splice(idx, 1);
    return true;
};
module.exports.listRemove = listRemove;

const emptyResponse = (resp) => {
    resp.statusCode = 300;
    resp.setHeader('cache-control', 'no-store');
    resp.setHeader('x-pc-longpoll', 'try-again');
    resp.end();
};

module.exports.longPollServer = (dir /*:string*/) /*:Util_LongPollServer_t*/ => {
    const requests /*:{ [string]:Array<{ resp: ServerResponse, to: TimeoutID, closed: bool }> }*/ = {};
    const files = {};
    const ee = new EventEmitter();
    const checkFile = (file) => {
        Fs.readFile(dir + '/' + file, (err, ret) => {
            const r = requests[file];
            if (err) {
                if (err.code !== 'ENOENT') { throw err; }
                delete files[file];
                return;
            }
            files[file] = true;
            if (!r) { return; }
            delete requests[file];
            r.forEach((obj) => {
                if (obj.resp.socket.writable) {
                    obj.resp.end(ret);
                }
                clearTimeout(obj.to);
            });
        });
    };
    Fs.watch(dir, (type, file) => {
        ee.emit('update', file);
        checkFile(file);
    });
    return {
        onReq: (req /*:IncomingMessage*/, res /*:ServerResponse*/) => {
            const file = req.url.split('/').pop();
            const x = (requests[file] = requests[file] || []);
            const obj = {};
            obj.closed = false;
            obj.resp = res;
            obj.to = setTimeout(() => {
                if (!obj.closed) {
                    emptyResponse(res);
                }
                listRemove(x, obj);
            }, 30000);
            x.push(obj);
            checkFile(file);
        },
        onFileUpdate: (f) => { ee.on('update', f); }
    };
};

const httpPost = (
    url /*:string*/,
    headers /*:{ [key: string] : mixed, ... }*/,
    cb /*:(IncomingMessage)=>void*/
) /*:Http.ClientRequest*/ => {
    let hostname;
    let port;
    let path;
    url.replace(/http:\/\/([^:\/]+)(:[0-9]+)?(\/.*)$/, (_, h, po, pa) => {
        hostname = h;
        port = po ? Number(po.replace(':', '')) : undefined;
        path = pa;
        return '';
    });
    if (hostname === undefined) {
        throw new Error("Could not understand [" + url + "] as a url");
    }
    return Http.request({
        host: hostname,
        path: path,
        port: port,
        method: 'POST',
        headers: headers,
        agent: keepaliveAgent
    }, cb);
};
module.exports.httpPost = httpPost;

module.exports.createMutex = () /*:Util_Mutex_t*/ => {
    let locked = false;
    let to;
    const withLock = (f /*:(()=>void)=>void*/) => {
        if (to) { return; }
        else if (locked) {
            to = setTimeout(() => {
                to = undefined;
                withLock(f);
            }, 100);
        } else {
            locked = true;
            f(() => {
                locked = false;
            });
        }
    };
    return withLock;
};

const isValidPayTo = (payTo /*:string*/) /*:bool*/ => {
    if (typeof (payTo) !== 'string') { return false; }
    if (payTo.length > 64) { return false; }
    if (!payTo.indexOf('pkt1')) {
        // segwit addr
        try {
            const b = Bech32.decode(payTo);
            return b.prefix === 'pkt';
        } catch (e) {
            return false;
        }
    } else if (!payTo.indexOf('p')) {
        try {
            const d = Bs58Check.decode(payTo);
            return d[0] === 0x75;
        } catch (e) {
            return false;
        }
    } else if (!payTo.indexOf('P')) {
        // Disable these addresses until we're sure we can actually pay them
        if (0) {
            try {
                const d = Bs58Check.decode(payTo);
                if (d[0] === 0x38) { return true; } // script hash addr
                if (d[0] === 0xa3) { return true; } // witness pubkey hash addr
                if (d[0] === 0x22) { return true; } // witness script hash addr
                return false;
            } catch (e) {
                return false;
            }
        }
    }
    return false;
};
module.exports.isValidPayTo = isValidPayTo;

if (!isValidPayTo('p7A4miQjxjmLPfbGyqRqyqTb5be9p527zS')) { throw new Error(); }

module.exports.badMethod = (
    meth /*:string*/,
    req /*:IncomingMessage*/,
    res /*:ServerResponse*/
) /*:bool*/ => {
    if (req.method !== meth) {
        res.statusCode = 405;
        res.end();
        return true;
    }
    return false;
};

module.exports.deleteResults = (dir /*:string*/, minHeight /*:number*/, regex /*:RegExp*/) => {
    Fs.readdir(dir, (err, files) => {
        if (!files) { throw err; }
        let nt = nThen;
        files.forEach((f) => {
            let num = NaN;
            f.replace(regex, (all, numS) => {
                num = Number(numS);
                return '';
            });
            if (isNaN(num)) { return; }
            if (num >= minHeight) { return; }
            nt = nt((w) => {
                Fs.unlink(dir + '/' + f, w((err) => {
                    if (err) { console.error("WARNING failed to delete [" + f + "]"); }
                }));
            }).nThen;
        });
    });
};

const compactToDbl = (c /*:number*/) /*:number*/ => {
    if (c < 1) { return 0; }
    return (c & 0x007fffff) * Math.pow(256, (c >> 24) - 3);
};
module.exports.compactToDbl = compactToDbl;
const dblToCompact = (d) => {
    let exp = 3;
    while (d > 0x007fffff) {
        d /= 256;
        exp++;
    }
    if (exp > 0x20) {
        return 0x207fffff;
    }
    return exp << 24 | d;
};

// work = 2**256 / (target + 1)
const TWO_TO_THE_256 = 1.157920892373162e+77;
const workForTar = (target /*:number*/) /*:number*/ => (TWO_TO_THE_256 / (target + 1));
module.exports.workForTar = workForTar;
const tarForWork = (work) => {
    if (work <= 0) {
        return TWO_TO_THE_256;
    }
    return (TWO_TO_THE_256 - work) / work;
};

module.exports.annWorkToTarget = (work /*:number*/) /*:number*/ => {
    return dblToCompact(tarForWork(work));
};

module.exports.workMultipleToTarget = (work /*:number*/) /*:number*/ => {
    const tar = tarForWork(work * 4096);
    return dblToCompact(tar);
};

module.exports.getWorkMultiple = (target /*:number*/) /*:number*/ => {
    return workForTar(compactToDbl(target)) / 4096;
};

const isWorkUselessExponential = (target /*:number*/, age /*:number*/) /*:bool*/ => {
    if (age < 3) { return false; }
    age -= 3;
    const tar = compactToDbl(target);
    const work = workForTar(tar);
    const degradedWork = work / Math.pow(2, age);
    return degradedWork < 0.25; // lets be safe and check that it's less than 0.25 rather than less than 1.
};
module.exports.isWorkUselessExponential = isWorkUselessExponential;

// readdir
// open each file, check offsets 8 (work bits) and 12 (parent block height)
// convert block height to double
// do the math...
// if the number is bigger than 207fffff then delete the file
module.exports.deleteUselessAnns = (
    dir /*:string*/,
    currentHeight /*:number*/,
    rmcb /*:(string, ()=>void)=>void*/,
    cb /*:(?Error)=>void*/
) => {
    let files;
    nThen((w) => {
        Fs.readdir(dir, w((err, ff) => {
            if (err) { return void cb(err); }
            files = ff;
        }));
    }).nThen((w) => {
        if (!files) { return; }
        const sema = Saferphore.create(8);
        files.forEach((f) => {
            const file = dir + '/' + f;
            sema.take((ra) => {
                const rs = Fs.createReadStream(file, { end: 16 });
                const data = [];
                let len = 0;
                rs.on('error', (e) => {
                    if (e.code === 'ENOENT') {
                        console.error("File [" + file + "] disappeared while accessing");
                        return;
                    }
                    console.error('Error in deleteUselessAnns ' + e);
                    throw e;
                });
                rs.on('data', (d) => {
                    data.push(d);
                    len += d.length;
                });
                rs.on('close', w(ra((err) => {
                    if (len >= 16) {
                        const buf = Buffer.concat(data);
                        const height = buf.readInt32LE(12);
                        const bits = buf.readUInt32LE(8);
                        if (isWorkUselessExponential(bits, currentHeight - height)) {
                            rmcb(f, w());
                        }
                        return;
                    }
                    Fs.stat(file, w((stErr, st) => {
                        if (err) {
                            if (err.code === 'ENOENT') { return; }
                            console.error("Error stating file [" + file + "] [" + String(stErr) + "]");
                        } else if (st.size < 16) {
                            console.error("Deleting [" + file + "] because it's a runt");
                            rmcb(f, w());
                        } else {
                            console.error("Error reading file [" + file + "] [" + err + "]");
                        }
                    }));
                })));
            });
        });
    }).nThen((_) => {
        cb();
    });
};

const mkVarInt = (num /*:number*/) /*:Buffer*/ => {
    if (num <= 0xfc) { return Buffer.from([num]); }
    if (num <= 0xffff) {
        const b = Buffer.alloc(3);
        b[0] = 0xfd;
        b.writeUInt16LE(num, 1);
        return b;
    }
    if (num <= 0xffffffff) {
        const b = Buffer.alloc(5);
        b[0] = 0xfe;
        b.writeUInt32LE(num, 1);
        return b;
    }
    throw new Error("64 bit varint unimplemented");
};
module.exports.mkVarInt = mkVarInt;

const parseVarInt = (buf /*:Buffer*/) /*:[number,number]*/ => {
    if (buf.length < 1) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfc) { return [buf[0], 1]; }
    if (buf.length < 3) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfd) { return [buf.readUInt16LE(1), 3]; }
    if (buf.length < 5) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfe) { return [buf.readUInt32LE(1), 5]; }
    throw new Error("64 bit varint is unimplemented");
};
module.exports.parseVarInt = parseVarInt;

const splitVarInt = (buf /*:Buffer*/) /*:Array<Buffer>*/ => {
    const out = [];
    while (buf.length) {
        const x = parseVarInt(buf);
        if (x[1] + x[0] > buf.length) { throw new Error("ran over the buffer"); }
        out.push(buf.slice(x[1], x[1] + x[0]));
        buf = buf.slice(x[1] + x[0]);
    }
    return out;
};
module.exports.splitVarInt = splitVarInt;

module.exports.joinVarInt = (bufs /*:Array<Buffer>*/) /*:Buffer*/ => {
    const all = [];
    bufs.forEach((b) => {
        all.push(mkVarInt(b.length));
        all.push(b);
    });
    return Buffer.concat(all);
};

module.exports.getKeypair = (rootCfg /*:Config_t*/, height /*:number*/) /*:?Util_KeyPair_t*/ => {
    const ps = rootCfg.privateSeed;
    if (!ps) { return; }
    const h = Buffer.alloc(4);
    h.writeUInt32LE(height, 0);
    const secBuf = Buffer.from(ps, 'utf8');
    const s = Crypto.createHash('sha256').update(Buffer.concat([secBuf, h])).digest();
    return Tweetnacl.sign.keyPair.fromSeed(s);
};

const b2hash32 = (content /*:Buffer*/) /*:Buffer*/ => {
    return Blake2b(32).update(content).digest(Buffer.alloc(32));
};
module.exports.b2hash32 = b2hash32;

const Util_log2ceil = (x) => Math.ceil(Math.log2(x));
const annComputeContentHash = (buf /*:Buffer*/) /*:Buffer*/ => {
    if (buf.length < 32) {
        const out = Buffer.alloc(32);
        buf.copy(out);
        return out;
    }
    let b;
    if (buf.length <= 64) {
        b = Buffer.alloc(64);
        buf.copy(b);
    } else {
        const halfLen = 1 << (Util_log2ceil(buf.length) - 1);
        b = Buffer.concat([
            annComputeContentHash(buf.slice(0, halfLen)),
            annComputeContentHash(buf.slice(halfLen))
        ]);
    }
    return b2hash32(b);
};
module.exports.annComputeContentHash = annComputeContentHash;

module.exports.getShareId = (header /*:Buffer*/, proof /*:Buffer*/) /*:Buffer*/ => {
    const hh = b2hash32(header);
    hh.writeUInt32LE((hh.readUInt32LE(0) ^ proof.readUInt32LE(0)) >>> 0, 0);
    return hh.slice(0, 16);
};

module.exports.openPayLog = (path /*:string*/, cb /*:(WriteStream)=>void*/) => {
    Fs.readdir(path, (err, ret) => {
        // Lets halt over this
        if (err) { throw err; }
        let biggestNumber = 0;
        ret.forEach((f) => {
            let number = -1;
            f.replace(/^paylog_([0-9]+).ndjson$/, (_all, n) => { number = Number(n); return ''; });
            if (number > biggestNumber) { biggestNumber = number; }
        });
        cb(Fs.createWriteStream(path + '/paylog_' + String(biggestNumber + 1) + '.ndjson'));
    });
};

module.exports.uploadPayLogs = (
    path /*:string*/,
    url /*:string*/,
    paymakerPassword /*:string*/,
    includeCurrent /*:bool*/,
    cb /*:()=>void*/) => {
    const authline = 'Basic ' + Buffer.from('x:' + paymakerPassword, 'utf8').toString('base64');
    Fs.readdir(path, (err, ret) => {
        // Lets halt over this
        if (err) { throw err; }
        const logs = [];
        let biggestNumber = 0;
        ret.forEach((f) => {
            let number = -1;
            f.replace(/^paylog_([0-9]+).ndjson$/, (_all, n) => { number = Number(n); return ''; });
            if (number > biggestNumber) { biggestNumber = number; }
            logs.push(number);
        });
        let nt = nThen;
        logs.forEach((n) => {
            // Don't upload the one we're writing to
            if (n === biggestNumber && !includeCurrent) { return; }
            const fileName = path + '/paylog_' + n + '.ndjson';
            let fileBuf;
            let reply;
            let failed = false;
            nt = nt((w) => {
                Fs.readFile(fileName, w((err, ret) => {
                    if (err) {
                        console.error("Unable to read file [" + fileName + "] because [" +
                            String(err) + "]");
                        failed = true;
                        return;
                    }
                    fileBuf = ret;
                }));
            }).nThen((w) => {
                if (failed || fileBuf.length === 0) { return; }
                console.error("Posting [" + fileName + "] to paymaker [" + url + "]");
                const done = w();
                const req = httpPost(url, { Authorization: authline }, (res) => {
                    if (failed) { return; }
                    const data = [];
                    res.on('data', (d) => { data.push(d); });
                    res.on('error', (e) => {
                        console.error("Unable to post file [" + fileName + "] because [" + e + "]");
                        failed = true;
                    });
                    res.on('end', w(() => {
                        if (Buffer.isBuffer(data[0])) {
                            reply = Buffer.concat(data).toString('utf8');
                        } else {
                            reply = data.join('');
                        }
                    }));
                    done();
                }).end(fileBuf);
                req.on('error', (e) => {
                    if (failed) { return; }
                    console.error("Unable to post file [" + fileName + "] because [" + e + "]");
                    failed = true;
                    done();
                });
            }).nThen((w) => {
                if (failed) { return; }
                if (fileBuf.length > 0) {
                    const id = Crypto.createHash('sha256').update(fileBuf).digest('hex').slice(0, 32);
                    let c;
                    try {
                        c = JSON.parse(reply);
                    } catch (e) {
                        console.error("Posting [" + fileName + "] unable to parse reply [" + reply + "]");
                        failed = true;
                        return;
                    }
                    c.error.forEach((e) => {
                        console.error("ERROR Posting [" + fileName + "] paymaker [" + e + "]");
                    });
                    if (c.error.length) {
                        failed = true;
                        return;
                    }
                    c.warn.forEach((e) => {
                        console.error("WARN Posting [" + fileName + "] paymaker [" + e + "]");
                    });
                    const eid = c.result.eventId;
                    if (eid !== id) {
                        console.error("ERROR Posting [" + fileName + "] paymaker eventID mismatch " +
                            "computed [" + id + "] got back [" + eid + "]");
                        failed = true;
                        return;
                    }
                }

                console.error("Deleting [" + fileName + "]");
                Fs.unlink(fileName, w((err) => {
                    if (err) {
                        console.error("ERROR deleting [" + fileName + "]");
                        failed = true;
                        return;
                    }
                }));
            }).nThen;
        });
        nt((_) => {
            cb();
        });
    });
};

module.exports.normalize = (
    obj /*:{[string]:number}*/,
    desiredSum /*:number*/
) => {
    let sum = 0;
    Object.keys(obj).forEach((k) => { sum += obj[k]; });
    if (sum === 0) { return; }
    const multiplier = desiredSum / sum;
    Object.keys(obj).forEach((k) => { obj[k] *= multiplier; });
};

// effective_work = work**3 / 1024 / ann_work / ann_count**2
const getEffectiveWork0 = (
    work /*: BigInt_t*/,
    annWork /*:BigInt_t*/,
    annCount /*:BigInt_t*/
) /*:BigInt_t*/ => {
    let out = work ** BigInt(3);
    out >>= BigInt(10);
    out /= annWork;
    out /= (annCount * annCount);
    return out;
};

module.exports.getEffectiveWork = (
    blockTar /*:number*/,
    annTar /*:number*/,
    annCount /*:BigInt_t*/
) /*:BigInt_t*/ => {
    const blkWork = BigInt(Math.floor(workForTar(compactToDbl(blockTar))));
    const annWork = BigInt(Math.floor(workForTar(compactToDbl(annTar))));
    return getEffectiveWork0(blkWork, annWork, annCount);
};

// $FlowFixMe I want to
Object.freeze(module.exports);

/*@flow*/
const Fs = require('fs');
const Http = require('http');
const EventEmitter = require('events').EventEmitter;
const Crypto = require('crypto');
const Tweetnacl = require('tweetnacl');
const Blake2b = require('blake2b');

const nThen = require('nthen');

/*::
import type { IncomingMessage, ServerResponse } from 'http'

import type { Config_t } from './Config.js'

export type Util_LongPollServer_t = {
    onReq: (IncomingMessage, ServerResponse)=>void,
    // caution, you will get file updates also when a file is deleted, not just when it's created
    onFileUpdate: ((string)=>void)=>void
};
export type Util_Mutex_t = ((()=>void)=>void)=>void;
*/

const checkMkdir = module.exports.checkMkdir = (path /*:string*/, cb /*:()=>void*/) => {
    if (path.endsWith('/')) { path = path.slice(0,-1); }
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

const clearDir = module.exports.clearDir = (path /*:string*/, cb /*:()=>void*/) => {
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

module.exports.bufFromHex = (
    x /*:string*/
) /*:Buffer*/ => ( Buffer.from(x, 'hex') );

const once = module.exports.once = /*::<F:Function>*/(f /*:F*/) /*:F*/ => {
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

const httpGet = module.exports.httpGet = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?Buffer|string)=>?bool*/
) => {
    let reconnects = 0;
    const ee = new EventEmitter();
    const again = () => {
        let ended = false;
        setTimeout(() => {
            if (ended) { return; }
            console.log("httpGet [" + url + "] has stalled, retrying...");
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
                console.log("Reconnect to [" + url + "] in [" + reconnectMs + "]ms");
                reconnects++;
            }
        };
        const h = Http.get(url, (res) => {
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
                    if (typeof(data[0]) === 'string') {
                        return cb1(undefined, data.join(''));
                    }
                    return cb1(undefined, Buffer.concat(data));
                });
            }
        });
        h.on('error', (e) => { cb1(e); });
        h.on('socket', (s) => {
            s.on('connect', () => { ee.emit('connection'); });
        });
    };
    again();
};

const httpGetBin = module.exports.httpGetBin = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?Buffer)=>?bool*/
) => {
    return httpGet(url, (err, buf) => {
        if (err) { return cb(err); }
        if (typeof(buf) === 'string') { return cb(undefined, Buffer.from(buf, 'utf8')); }
        return cb(undefined, buf);
    });
};

const httpGetStr = module.exports.httpGetStr = (
    url /*:string*/,
    cb /*:(?Error|{statusCode:number}, ?string)=>?bool*/
) => {
    return httpGet(url, (err, buf) => {
        if (!buf) { return cb(err); }
        if (typeof(buf) === 'string') { return cb(undefined, buf); }
        return cb(undefined, buf.toString('utf8'));
    });
};

const listRemove = module.exports.listRemove = ((list, item) => {
    const idx = list.indexOf(item);
    if (idx < 0) { return false; }
    list.splice(idx, 1);
    return true;
} /*:<T>(Array<any>, T)=>bool*/);

const emptyResponse = (resp) => {
    resp.statusCode = 300;
    resp.setHeader('cache-control', 'no-store');
    resp.setHeader('x-pc-longpoll', 'try-again');
    resp.end();
};

module.exports.longPollServer = (dir /*:string*/) /*:Util_LongPollServer_t*/ => {
    const requests /*:{ [string]:Array<{ resp: ServerResponse, to: TimeoutID }> }*/ = {};
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
                obj.resp.end(ret);
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
            obj.resp = res;
            obj.to = setTimeout(() => {
                emptyResponse(res);
                listRemove(x, obj);
            }, 30000);
            x.push(obj);
            checkFile(file);
        },
        onFileUpdate: (f) => { ee.on('update', f); }
    };
};

const httpPost = module.exports.httpPost = (
    url /*:string*/,
    headers /*:{ [string]:string }*/,
    cb /*:(IncomingMessage)=>void*/
) => {
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
        headers: headers
    }, cb);
};

const createMutex = module.exports.createMutex = () /*:Util_Mutex_t*/ => {
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

const isValidPayTo = module.exports.isValidPayTo = (payTo /*:string*/) => {
    // TODO: better validation
    return payTo && payTo.length > 10;
};

const badMethod = module.exports.badMethod = (
    meth /*:string*/,
    req /*:IncomingMessage*/,
    res /*:ServerResponse*/
) => {
    if (req.method !== meth) {
        res.statusCode = 405;
        res.end();
        return true;
    }
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
                    if (err) { console.log("WARNING failed to delete [" + f + "]"); }
                }));
            }).nThen;
        });
    });
};

const compactToDbl = (c) => {
    if (c < 1) { return 0; }
    return (c & 0x007fffff) * Math.pow(256, (c >> 24) - 3);
};

// work = 2**256 / (target + 1)
const TWO_TO_THE_256 = 1.157920892373162e+77;
const workForTar = (target) => ( TWO_TO_THE_256 / (target + 1) );

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
        let nt = nThen;
        files.forEach((f) => {
            const file = dir + '/' + f;
            let buf;
            nt = nt((w) => {
                const rs = Fs.createReadStream(file);
                const data = [];
                let len = 0;
                rs.on('error', (e) => {
                    if (e.code === 'ENOENT') {
                        console.error("File [" + file + "] disappeared while accessing");
                        w.abort();
                        return;
                    }
                    console.error('Error in deleteUselessAnns ' + e);
                    throw e;
                })
                rs.on('data', (d) => {
                    if (len > 16) {
                        rs.destroy();
                    } else {
                        data.push(d);
                        len += d.length;
                    }
                });
                rs.on('close', w((err) => {
                    if (len >= 16) {
                        buf = Buffer.concat(data);
                        return;
                    }
                    console.log("Error reading file [" + file + "] [" +
                        ((err) ? err.message : 'runt file') + "]");
                    Fs.stat(file, w((err, st) => {
                        if (err) { return; }
                        if (st.size < 16) {
                            console.log("Deleting [" + file + "] because it's a runt");
                            rmcb(f, w());
                        }
                    }));
                }));
            }).nThen((w) => {
                if (!buf) { return; }
                const height = buf.readInt32LE(12);
                const age = currentHeight - height;
                if (age < 5) { return; }
                const bits = buf.readUInt32LE(8);
                const target = compactToDbl(bits);
                const work = workForTar(target);
                const effectiveWork = work / (age - 3);

                // work of 2 is the point where it's nolonger worth keeping an ann
                // we'll set this to 1.75 in order to not worry about rounding issues
                if (effectiveWork > 1.75) { return; }

                rmcb(f, w());
            }).nThen;
        });
        nt(w());
    }).nThen((_) => {
        cb();
    });
};

const mkVarInt = module.exports.mkVarInt = (num /*:number*/) => {
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

const parseVarInt = module.exports.parseVarInt = (buf /*:Buffer*/) /*:[number,number]*/ => {
    if (buf.length < 1) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfc) { return [ buf[0], 1 ]; }
    if (buf.length < 3) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfd) { return [ buf.readUInt16LE(1), 3 ]; }
    if (buf.length < 5) { throw new Error("ran out of data"); }
    if (buf[0] <= 0xfe) { return [ buf.readUInt32LE(1), 5 ]; }
    throw new Error("64 bit varint is unimplemented");
};

const splitVarInt = module.exports.splitVarInt = (buf /*:Buffer*/) /*:Array<Buffer>*/ => {
    const out = [];
    while (buf.length) {
        const x = parseVarInt(buf);
        if (x[1] + x[0] > buf.length) { throw new Error("ran over the buffer"); }
        out.push(buf.slice(x[1], x[1] + x[0]));
        buf = buf.slice(x[1] + x[0]);
    }
    return out;
};

const joinVarInt = module.exports.joinVarInt = (bufs /*:Array<Buffer>*/) /*:Buffer*/ => {
    const all = [];
    bufs.forEach((b) => {
        all.push(mkVarInt(b.length));
        all.push(b);
    });
    return Buffer.concat(all);
};

const getKeypair = module.exports.getKeypair = (rootCfg /*:Config_t*/, height /*:number*/) => {
    const h = Buffer.alloc(4);
    h.writeUInt32LE(height, 0);
    const secBuf = Buffer.from(rootCfg.privateSeed, 'utf8');
    const s = Crypto.createHash('sha256').update(Buffer.concat([secBuf, h])).digest();
    return Tweetnacl.sign.keyPair.fromSeed(s);
};

const Util_log2ceil = (x) => Math.ceil(Math.log2(x));
const annComputeContentHash = module.exports.annComputeContentHash = (buf /*:Buffer*/) => {
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
            annComputeContentHash(buf.slice(0,halfLen)),
            annComputeContentHash(buf.slice(halfLen))
        ]);
    }
    return Blake2b(32).update(b).digest(Buffer.alloc(32));
};

const b2hash32 = module.exports.b2hash32 = (content /*:Buffer*/) => {
    return Blake2b(32).update(content).digest(Buffer.alloc(32));
};

module.exports.getShareId = (header /*:Buffer*/, proof /*:Buffer*/) /*:Buffer*/ => {
    const hh = b2hash32(header);
    hh.writeUInt32LE((hh.readUInt32LE(0) ^ proof.readUInt32LE(0)) >>> 0, 0);
    return hh.slice(0,16);
};


Object.freeze(module.exports);

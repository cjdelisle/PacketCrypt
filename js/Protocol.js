/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Util = require('./Util.js');

/*::
export type BigInt_t = number;
const BigInt = (n: number):BigInt_t => (n: BigInt_t);
module.exports.BigInt = BigInt;

export type Protocol_PcConfigJson_t = {|
    tipHash: string,
    currentHeight: number,
    masterUrl: string,
    submitAnnUrls: Array<string>,
    downloadAnnUrls: Array<string>,
    submitBlockUrls: Array<string>,
    paymakerUrl: string,
    version: number,
    annVersions?: Array<number>,
    softVersion: ?number,
    mineOldAnns?: number,
    annTarget?: number,
|};

export type Protocol_RawBlockTemplate_t = {|
    height: number,
    header: string,
    coinbase_no_witness: string,
    merklebranch: Array<string>,
    transactions: Array<string>
|};

export type Protocol_Work_t = {|
    height: number,
    coinbase_no_witness: Buffer,
    shareTarget: number,
    annTarget: number,
    header: Buffer,
    lastHash: Buffer,
    signingKey: Buffer,
    proof: Array<Buffer>,
    binary: Buffer,
|};

export type Protocol_Event_t = {|
    time: number,
    eventId: string
|};
export type Protocol_AnnsEvent_t = Protocol_Event_t & {|
    type: "anns",
    accepted: number,
    dup: number,
    inval: number,
    badHash: number,
    runt: number,
    internalErr: number,
    payTo: string,
    unsigned: number,
    totalLen: number,
    target: number
|};
export type Protocol_ShareEvent_t = Protocol_Event_t & {|
    type: "share",
    block: bool,
    headerHash?: string,
    payTo: string,
    target: number,
    annCount?: string,
    annMinWork?: number,
    encryptions?: number,
|};
export type Protocol_BlockEvent_t = Protocol_Event_t & {|
    type: "block",
    hash: string,
    height: number,
    difficulty: number,
|};
export type Protocol_BlockInfo_t = {|
    header: {|
        "hash": string,
        "height": number,
        "version": number,
        "versionHex": string,
        "merkleroot": string,
        "time": number,
        "nonce": number,
        "bits": string,
        "difficulty": number,
        "previousblockhash": string,
    |},
    sigKey: ?string,
|};
export type Protocol_CoinbaseCommit_t = {|
    annMinWork: BigInt_t,
    annCount: number,
    merkleRoot: Buffer,
|};

*/

// This is the "hard" version, if there's a mismatch then the miner will refuse to start up.
module.exports.VERSION = 3;
// This is the "soft" version, if there's a mismatch,
// the miner will start up but with an upgrade recommendation.
module.exports.SOFT_VERSION = 1;

// Ordered least preferential to most preferential
// These are just the versions which this implementation is *capable* of mining
// the versions which the pool will accept are defined in pool.example.js
module.exports.SUPPORTED_ANN_VERSIONS = [0, 1];

module.exports.COINBASE_COMMIT_LEN = 48;

module.exports.PC_END_TYPE = 0;
module.exports.PC_PCP_TYPE = 1;
module.exports.PC_SIGNATURES_TYPE = 2;
module.exports.PC_CONTENTPROOFS_TYPE = 3;
module.exports.PC_VERSION_TYPE = 4;

module.exports.ANN_PARENT_HEIGHT_OFFSET = 12;
module.exports.ANN_CONTENT_LENGTH_OFFSET = 20;
module.exports.ANN_CONTENT_HASH_OFFSET = 24;
module.exports.ANN_SIGNING_KEY_OFFSET = 56;

const bufferFromInt = (i) => {
    const b = Buffer.alloc(4);
    b.writeInt32LE(i, 0);
    return b;
};

const workEncode = (work /*:Protocol_Work_t*/) /*:Buffer*/ => {
    const height = bufferFromInt(work.height);
    const cnwlen = bufferFromInt(work.coinbase_no_witness.length);
    const shareTarget = bufferFromInt(work.shareTarget);
    const annTarget = bufferFromInt(work.annTarget);
    const merkles = Buffer.concat(work.proof);
    return Buffer.concat([
        work.header,
        work.signingKey,
        shareTarget,
        annTarget,
        height,
        cnwlen,
        work.coinbase_no_witness,
        merkles
    ]);
};
module.exports.workEncode = workEncode;

// 80 + 32 + 4 + 4 + 4 + 1024 + 1024
module.exports.workFromRawBlockTemplate = (
    x /*:Protocol_RawBlockTemplate_t*/,
    signingKey /*:?Uint8Array*/,
    shareTarget /*:number*/,
    annTarget /*:number*/
) /*:Protocol_Work_t*/ => {
    const header = Util.bufFromHex(x.header);
    const out = {
        height: x.height,
        coinbase_no_witness: Util.bufFromHex(x.coinbase_no_witness),
        shareTarget: shareTarget,
        annTarget: annTarget,
        header: header,
        signingKey: signingKey ? Buffer.from(signingKey) : Buffer.alloc(32, 0),
        lastHash: header.slice(4, 4 + 32),
        proof: x.merklebranch.map(Util.bufFromHex),
        binary: Buffer.alloc(0),
    };
    out.binary = workEncode(out);
    return Object.freeze(out);
};

const workDecode = (work /*:Buffer*/) /*:Protocol_Work_t*/ => {
    let i = 0;
    const header = work.slice(i, i += 80);
    const signingKey = work.slice(i, i += 32);
    const shareTarget = work.readInt32LE(i); i += 4;
    const annTarget = work.readInt32LE(i); i += 4;
    const height = work.readInt32LE(i); i += 4;
    const cnwlen = work.readInt32LE(i); i += 4;
    const coinbase_no_witness = work.slice(i, i += cnwlen);
    const merkles = work.slice(i);
    const proof = [];
    for (let x = 0; x < merkles.length; x += 32) {
        proof.push(merkles.slice(x, x + 32));
    }
    return Object.freeze({
        header: header,
        signingKey: signingKey,
        shareTarget: shareTarget,
        annTarget: annTarget,
        height: height,
        coinbase_no_witness: coinbase_no_witness,
        proof: proof,
        binary: work,
        lastHash: header.slice(4, 36)
    });
};
module.exports.workDecode = workDecode;

const BLOCK_TEMPLATE_VERSION = 1;
module.exports.BLOCK_TEMPLATE_VERSION = BLOCK_TEMPLATE_VERSION;

module.exports.blockTemplateEncode = (rbt /*:Protocol_RawBlockTemplate_t*/) /*:Buffer*/ => {
    return Util.joinVarInt([
        Util.mkVarInt(BLOCK_TEMPLATE_VERSION),
        Util.mkVarInt(rbt.height),
        Util.bufFromHex(rbt.header),
        Util.bufFromHex(rbt.coinbase_no_witness),
        Util.joinVarInt(rbt.merklebranch.map(Util.bufFromHex)),
        Util.joinVarInt(rbt.transactions.map(Util.bufFromHex))
    ]);
};

module.exports.blockTemplateDecode = (buf /*:Buffer*/) /*:Protocol_RawBlockTemplate_t*/ => {
    const bufs = Util.splitVarInt(buf);
    const version = Util.parseVarInt(bufs[0])[0];
    if (version !== BLOCK_TEMPLATE_VERSION) {
        throw new Error("unexpected version [" + String(version) + "]");
    }
    return {
        height: Util.parseVarInt(bufs[1])[0],
        header: bufs[2].toString('hex'),
        coinbase_no_witness: bufs[3].toString('hex'),
        merklebranch: Util.splitVarInt(bufs[4]).map((x) => (x.toString('hex'))),
        transactions: Util.splitVarInt(bufs[5]).map((x) => (x.toString('hex')))
    };
};

/*
typedef struct AnnPost_s {
    uint32_t version;
    uint8_t hashNum;
    uint8_t hashMod;
    uint16_t _pad;
    Buf32_t contentHash;
    Buf32_t parentBlockHash;
    uint32_t minWork;
    uint32_t mostRecentBlock;
    PacketCrypt_Announce_t anns[IN_ANN_CAP];
} AnnPost_t;
typedef struct Result_s {
    uint32_t accepted;
    uint32_t duplicates;
    uint32_t invalid;
    uint8_t payTo[64];
} Result_t;
*/
/*::
export type Protocol_AnnPost_t = {
    version?: number,
    hashNum: number,
    hashMod: number,
    _pad?: number,
    signingKey: Buffer,
    parentBlockHash: Buffer,
    minWork: number,
    mostRecentBlock: number,
    payTo: string
};


// Align with checkanns.c processAnns()
export type Protocol_AnnResult_t = {
    accepted: number,
    dup: number,
    inval: number,
    badHash: number,
    runt: number,
    internalErr: number,
    payTo: string,
};
*/
module.exports.annPostEncode = (post /*:Protocol_AnnPost_t*/) /*:Buffer*/ => {
    const out = Buffer.alloc(4 + 1 + 1 + 2 + 32 + 32 + 4 + 4 + 64);
    let i = 0;
    if (post.version) { out.writeUInt32LE(post.version, i); } i += 4;
    out[i++] = post.hashNum;
    out[i++] = post.hashMod;
    if (post._pad) { out.writeUInt16LE(post._pad, i); } i += 2;
    post.signingKey.copy(out, i, 0, 32); i += 32;
    post.parentBlockHash.copy(out, i, 0, 32); i += 32;
    out.writeUInt32LE(post.minWork, i); i += 4;
    out.writeUInt32LE(post.mostRecentBlock, i); i += 4;
    Buffer.from(post.payTo, 'utf8').copy(out, i);
    return out;
};

/*
typedef struct ShareHeader_s {
    uint32_t version;
    uint8_t hashNum;
    uint8_t hashMod;
    uint16_t workLen;
    Buf32_t parentHashes[4];
    Buf64_t payTo;
} ShareHeader_t;
*/

/*::
export type Protocol_Share_t = {
    coinbaseCommit: Buffer,
    blockHeader: Buffer,
    packetCryptProof: Buffer
};
export type Protocol_ShareFile_t = {
    version: number,
    hashNum: number,
    hashMod: number,
    hashes: Array<Buffer>,
    payTo: string,
    work: Protocol_Work_t,
    share: Protocol_Share_t
};
*/
const shareEncode = (share /*:Protocol_Share_t*/) /*:Buffer*/ => {
    return Buffer.concat([share.coinbaseCommit, share.blockHeader, share.packetCryptProof]);
};
module.exports.shareEncode = shareEncode;

const shareDecode = (buf /*:Buffer*/) /*:Protocol_Share_t*/ => {
    const out = {};
    let i = 0;
    out.coinbaseCommit = buf.slice(i, (i += 32 + 8 + 4 + 4));
    out.blockHeader = buf.slice(i, (i += 80));
    out.packetCryptProof = buf.slice(i);
    return out;
};
module.exports.shareDecode = shareDecode;

module.exports.shareFileDecode = (buf /*:Buffer*/) /*:Protocol_ShareFile_t*/ => {
    const out = {};
    let x = 0;
    out.version = buf.readUInt32LE(x); x += 4;
    out.hashNum = buf[x++];
    out.hashMod = buf[x++];
    const workLen = buf.readUInt16LE(x); x += 2;
    out.hashes = [];
    for (let i = 0; i < 4; i++) {
        out.hashes[i] = buf.slice(x, (x += 32));
    }
    out.payTo = buf.slice(x, (x += 64)).toString('utf8');
    out.work = workDecode(buf.slice(x, (x += workLen)));
    out.share = shareDecode(buf.slice(x));
    return out;
};

module.exports.shareFileEncode = (share /*:Protocol_ShareFile_t*/) /*:Buffer*/ => {
    const shareBuf = shareEncode(share.share);
    const msg = Buffer.alloc(4 + 1 + 1 + 2 + (32 * share.hashes.length) + 64 + share.work.binary.length + shareBuf.length);
    let i = 0;
    msg.writeUInt32LE(0, i); i += 4;
    msg[i++] = share.hashNum;
    msg[i++] = share.hashMod;
    msg.writeUInt16LE(share.work.binary.length, i); i += 2;
    for (let x = 0; x < share.hashes.length; x++) {
        share.hashes[x].copy(msg, i);
        i += 32;
    }
    Buffer.from(share.payTo.slice(0, 64), 'utf8').copy(msg, i); i += 64;
    share.work.binary.copy(msg, i); i += share.work.binary.length;
    shareBuf.copy(msg, i); i += shareBuf.length;
    if (i !== msg.length) { throw new Error(i + ' !== ' + msg.length); }
    return msg;
};

module.exports.coinbaseCommitDecode = (buf /*:Buffer*/) /*:Protocol_CoinbaseCommit_t*/ => {
    // Skip the magic
    let i = 4;
    const annMinWork = buf.readUInt32LE(i); i += 4;
    const merkleRoot = buf.slice(i, i + 32); i += 32;
    const annCountLow = BigInt(buf.readUInt32LE(i)); i += 4;
    const annCountHigh = (BigInt(buf.readUInt32LE(i)) * BigInt(2) ** BigInt(32)); i += 4;
    return {
        annMinWork,
        merkleRoot,
        annCount: annCountHigh + annCountLow,
    };
};

// $FlowFixMe: I want to do this
Object.freeze(module.exports);

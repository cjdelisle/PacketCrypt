/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Master = require('./js/Master.js');
const PayMaker = require('./js/PayMaker.js');
const AnnHandler = require('./js/AnnHandler.js');
const BlkHandler = require('./js/BlkHandler.js');
const Util = require('./js/Util.js');

/*::
import type { PayMaker_Result_t } from './js/PayMaker.js'
*/

const config = {};

// This seed is used for deriving keys which will be used for signing announcements.
// Announcement signing is one way to prevent other pools from stealing your announcements
// but it also prevents multi-pool mining.
// Unless you have a good reason to use this, you should use block_miner_passwd on the
// ann handler config instead.
config.privateSeed = null;

// Anyone who has this password can make http posts to the paymaker (claim that shares were won)
// You should make this random and also firewall the paymaker from the public.
//
// The upload will be done using Authorization Basic with username "x" and this as the password
// so you can put the paymaker behind an http proxy if you wish.
config.paymakerHttpPasswd = 'anyone with this password can post results to the paymaker';

// Master URL as it is externally visible
// This is used by the PayMaker and the BlockHandler
config.masterUrl = 'http://localhost:8080';

// Path to the pool datastore
config.rootWorkdir = './datastore/pool';

// pktd RPC connection info
config.rpc = {
    protocol: 'https',
    user: 'x',
    pass: 'x',
    host: '127.0.0.1',
    port: 64765,
    rejectUnauthorized: false
};

// List of announcement handlers which will be running
config.annHandlers = [
    {
        // What address should be advertized for accessing this ann handler (external address)
        // You will also need to configure the handler itself in packetcrypt_rs
        url: 'http://h1.mypool.tld',
    },
];

// List of block handlers
// Each block handler must be able to access a pktd node using the RPC credentials above
config.blkHandlers = [
    {
        // What address should be advertized for accessing this block handler (external address)
        //url: 'http://pool.cjdns.fr/ng_blk0',
        url: 'http://localhost:8082',

        // Which port to run this block handler on
        port: 8082,

        // What address to bind to, set to localhost if proxying
        host: '::',

        // Maximum number of simultanious connections to accept before sending 500 errors
        maxConnections: 50,

        root: config
    },
];

// Master config
config.master = {
    // Which port to run the master on
    port: 8080,

    // What address to bind to, set to localhost if proxying
    host: '::',

    // Minimum work for an announcement
    // This number is effectively a bandwidth divisor, every time you
    // double this number you will reduce your bandwidth by a factor of two.
    annMinWork: Util.annWorkToTarget(128),

    // Average number of shares per block, reducing this number will reduce
    // load on your block handlers, but increasing it will allow payment
    // to be spread more evenly between block miners.
    shareWorkDivisor: 4,

    // Which versions of announcements we will accept
    annVersions: [1],

    // Request that ann miners mine announcements that are this many blocks old.
    // Fresh new announcements are not usable until they are 2 blocks old, putting
    // a 3 here will make announcement miners mine announcements which are immediately
    // usable.
    mineOldAnns: 2,

    root: config,
};

// Paymaker config
config.payMaker = {
    // How the miners should access the paymaker (external address)
    url: 'http://localhost:8083',

    // Which port to run the paymaker on
    port: 8083,

    // What address to bind to, set to localhost if proxying
    host: '::',

    // Seconds between sending updates to pktd
    // If this set to zero, the payMaker will accept log uploads but will
    // not send any changes of payout data to pktd.
    //updateCycle: 0, // to disable
    updateCycle: 120,

    // How many seconds backward to keep history in memory
    historyDepth: 60 * 60 * 24 * 2,

    // Maximum number of simultanious connections to accept before sending 500 errors
    maxConnections: 200,

    annCompressor: {
        // Store data in 1 minute aggregations
        timespanMs: 1000 * 60,

        // Allow data to be submitted to any of the last 10 aggregations
        slotsToKeepEvents: 10,
    },

    // What fraction of the payout to pay to block miners (the rest will be paid to ann miners)
    blockPayoutFraction: 0.5,

    // What percent of the total winnings should be taken for pool management
    poolFee: 0.20,

    // The address which should be paid the pool fee
    poolFeeAddress: "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2",

    // This constant will affect how far back into history we pay our announcement miners
    pplnsAnnConstantX: 0.125,

    // This constant will affect how far back into history we pay our block miners
    pplnsBlkConstantX: 2,

    // When there are not enough shares to fairly spread out the winnings,
    // pay what's left over to this address.
    defaultAddress: "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2",

    // When something goes wrong, direct pktd to send all coins here, if this is different
    // from the defaultAddress then it is possible to account for and pay out to the miners
    // later when the problem is fixed.
    errorAddress: "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2",

    // A function which pre-treats updates before they're sent to pktd
    updateHook: (x /*:PayMaker_Result_t*/) => {
        return x;
    },

    root: config,
};

const main = (argv, config) => {
    if (argv.indexOf('--master') > -1) {
        return void Master.create(config.master);
    }
    if (argv.indexOf('--payMaker') > -1) {
        return void PayMaker.create(config.payMaker);
    }
    for (let i = 0; i < config.blkHandlers.length; i++) {
        if (argv.indexOf('--blk' + i) === -1) { continue; }
        return void BlkHandler.create(config.blkHandlers[i]);
    }

    console.log("Usage:");
    console.log("    --master     # launch the master node");
    console.log("    --payMaker   # launch the paymaker on the master node server");
    console.log();
    console.log("    --blk<n>     # launch a block validator node");
    console.log("    NOTE: There are " + config.annHandlers.length + " announcement validators and" +
        " " + config.blkHandlers.length + " block validators which must be launched");
};
main(process.argv, config);

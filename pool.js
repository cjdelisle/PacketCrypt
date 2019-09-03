/*@flow*/
const Master = require('./js/Master.js');
const PayMaker = require('./js/PayMaker.js');
const AnnHandler = require('./js/AnnHandler.js');
const BlkHandler = require('./js/BlkHandler.js');

/*::
import type { Master_Config_t } from './js/Master.js'
import type { AnnHandler_Config_t } from './js/AnnHandler.js'
import type { BlkHandler_Config_t } from './js/BlkHandler.js'
import type { Config_t } from './js/Config.js'
*/

const config = {};

// This seed is used for deriving keys which will be used for signing announcements.
// Each round of work has a different key which is derived from this seed. If you use a weak
// seed then one announcement signing key can be used to guess the seed.
// If the seed is known, other pools can steal your announcements and use them.
config.privateSeed = 'controls who can mine with your announcements, you should change it';

// Anyone who has this password can make http posts to the paymaker (claim that shares were won)
// You should make this random and also firewall the paymaker from the public.
//
// The upload will be done using Authorization Basic with username "x" and this as the password
// so you can put the paymaker behind an http proxy if you wish.
config.paymakerHttpPasswd = 'anyone with this password can post results to the paymaker';

// Master URL as it is externally visible
//config.masterUrl = 'http://pool.cjdns.fr/ng_master';
config.masterUrl = 'http://localhost:8080';

// Path to the pool datastore
config.rootWorkdir = './datastore/pool';

// Path to the checkanns binary
config.checkannsPath = './bin/checkanns';

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
        //url:'http://pool.cjdns.fr/ng_ann0',
        url: 'http://localhost:8081',

        // What port to bind this ann handler on
        port: 8081,

        // Number of threads to use in the checkanns process
        threads: 4,

        root: config
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

        root: config
    },
];

// Master config
config.master = {
    // Which port to run the master on
    port: 8080,

    // Minimum work for an announcement
    annMinWork:   0x20000fff,

    // Minimum work for a block share
    shareMinWork: 0x20000fff,

    root: config,
};

// Paymaker config
config.payMaker = {
    // How the miners should access the paymaker (external address)
    url: 'http://localhost:8083',

    // Which port to run the paymaker on
    port: 8083,

    // Seconds between sending updates to pktd
    // If this set to zero, the payMaker will accept log uploads but will
    // not send any changes of payout data to pktd.
    //updateCycle: 0, // to disable
    updateCycle: 30,

    // How many seconds backward to keep history in memory
    historyDepth: 60*60*24*30,

    // What fraction of the payout to pay to block miners (the rest will be paid to ann miners)
    blockPayoutFraction: 0.5,

    // This constant will affect how far back into history we pay our announcement miners
    pplnsAnnConstantX: 32,

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
    updateHook: (x) => {
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
    for (let i = 0; i < config.annHandlers.length; i++) {
        if (argv.indexOf('--ann' + i) === -1) { continue; }
        return void AnnHandler.create(config.annHandlers[i]);
    }
    for (let i = 0; i < config.blkHandlers.length; i++) {
        if (argv.indexOf('--blk' + i) === -1) { continue; }
        return void BlkHandler.create(config.blkHandlers[i]);
    }

    console.log("Usage:");
    console.log("    --master     # launch the master node");
    console.log("    --payMaker   # launch the paymaker on the master node server");
    console.log();
    console.log("    --ann<n>     # launch an announcement validator node");
    console.log("    --blk<n>     # launch a block validator node");
    console.log("    NOTE: There are " + config.annHandlers.length + " announcement validators and" +
        " " + config.blkHandlers.length + " block validators which must be launched");
};
main(process.argv, config);

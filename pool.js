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
config.privateSeed = 'controls who can mine with your announcements, you should change it';
//config.masterUrl = 'http://pool.cjdns.fr/ng_master';
config.masterUrl = 'http://localhost:8080';
config.rootWorkdir = './datastore/pool';
config.checkannsPath = './bin/checkanns';
config.checksharesPath = './bin/checkshares';
config.rpc = {
    protocol: 'https',
    user: 'x',
    pass: 'x',
    host: '127.0.0.1',
    port: 64765,
    rejectUnauthorized: false
};
config.annHandlers = [
    //{ url: 'http://pool.cjdns.fr/ng_ann0', port: 8081, threads: 4, root: config },
    { url: 'http://localhost:8081', port: 8081, threads: 4, root: config },
];
config.blkHandlers = [
    //{ url: 'http://pool.cjdns.fr/ng_blk0', port: 8083, threads: 4, root: config },
    { url: 'http://localhost:8082', port: 8082, threads: 4, root: config },
];
config.master = {
    port: 8080,
    annMinWork:   0x20000fff,
    shareMinWork: 0x20000fff,
    root: config,
};
config.payMaker = {
    port: 8083,

    // Seconds between sending updates to pktd
    // If this set to zero, the payMaker will accept log uploads but will
    // not send any changes of payout data to pktd.
    //updateCycle: 0, // to disable
    updateCycle: 30,

    // How many seconds backward to keep history in memory
    historyDepth: 60*60*24,

    // What fraction of the payout to pay to block miners (the rest will be paid to ann miners)
    blockPayoutFraction: 0.5,

    // This constant will affect how far back into history we pay our announcement miners
    pplnsAnnConstantX: 10000,

    // This constant will affect how far back into history we pay our block miners
    pplnsBlkConstantX: 1000,

    // When there are not enough shares to fairly spread out the winnings,
    // pay what's left over to this address.
    defaultAddress: "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2",

    // A function which pre-treats updates before they're sent to pktd
    updateHook: (x) => { return x; },

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

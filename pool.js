/*@flow*/
const Master = require('./js/Master.js');
const AnnHandler = require('./js/AnnHandler.js');
const BlkHandler = require('./js/BlkHandler.js');

/*::
import type { Master_Config_t } from './js/Master.js'
import type { AnnHandler_Config_t } from './js/AnnHandler.js'
import type { BlkHandler_Config_t } from './js/BlkHandler.js'
import type { Config_t } from './js/Config.js'
*/

const config = {};
config.masterUrl = 'http://pool.cjdns.fr/ng_master';
config.rootWorkdir = './datastore/pool';
config.checkannsPath = './bin/checkanns';
config.checksharesPath = './bin/checkshares';
config.annHandlers = [
    { url: 'http://pool.cjdns.fr/ng_ann0', port: 8081, threads: 4, root: config },
    //{ url: 'http://localhost:8082', port: 8082, threads: 4, root: config },
];
config.blkHandlers = [
    { url: 'http://pool.cjdns.fr/ng_blk0', port: 8083, threads: 4, root: config },
    //{ url: 'http://localhost:8084', port: 8084, threads: 4, root: config },
];
config.master = {
    port: 8080,
    rpc: {
        protocol: 'https',
        user: '/j/N4iV5SgMzSH6U3t6gkrs04Lg=',
        pass: 'yqHQLrkt/EKUHIGrn7t33O6sDLg=',
        host: '127.0.0.1',
        port: 18334,
        rejectUnauthorized: false
    },
    annMinWork:   0x20000fff,
    shareMinWork: 0x20001fff,
    root: config,
};

const main = (argv, config) => {
    if (argv.indexOf('--master') > -1) {
        return void Master.create(config.master);
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
    console.log("    --ann<n>     # launch an announcement validator node");
    console.log("    --blk<n>     # launch a block validator node");
    console.log("    NOTE: There are " + config.annHandlers.length + " announcement validators and" +
        " " + config.blkHandlers.length + " block validators which must be launched");
};
main(process.argv, config);

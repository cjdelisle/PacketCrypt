/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/

// A tracker is a master node which doesn't issue it's own work.
// It mirrors the work of another master.
// The benefit of using a tracker is you can change the ann handlers,
// block handlers, the difficulty, and accepted versions of anns and
// packetcrypt proofs.

const Http = require('http');

const PoolClient = require('./PoolClient.js');
const Master = require('./Master.js');

/*::
import type { Master_Config_t } from './Master.js'
import type { Config_t } from './Config.js'
export type Tracker_Config_t = {
    root: Config_t,
    masterUrl: string,
    port: number,
    masterConf: Master_Config_t,
};
*/

const forwardReq = (ctx, path, req, res) => {
    //console.error('forarding request to ' + ctx.mut.cfg.masterUrl + path);
    Http.get(ctx.mut.cfg.masterUrl + path, (fres) => {
        res.writeHead(fres.statusCode, fres.statusMessage, fres.headers);
        fres.pipe(res);
    });
};

const onReq = (ctx, req, res) => {
    const currentWork = ctx.poolClient.work;
    if (!currentWork) {
        res.statusCode = 500;
        res.end("Server not ready");
        return;
    }
    if (req.url.endsWith('/config.json')) {
        Master.configReq(ctx.mut.cfg.masterConf, currentWork.height, req, res);
        return;
    }
    let path;
    req.url.replace(/.*\/work_([0-9]+)\.bin$/, (_, num) => {
        path = '/work_' + num + '.bin';
        return '';
    });
    req.url.replace(/.*\/bt_([0-9]+)\.bin$/, (_, num) => {
        path = '/bt_' + num + '.bin';
        return '';
    });
    if (path) {
        forwardReq(ctx, path, req, res);
        return;
    }

    res.statusCode = 404;
    res.end('');
    return;
};

module.exports.create = (cfg /*:Tracker_Config_t*/) => {
    const ctx = Object.freeze({
        poolClient: PoolClient.create(cfg.masterUrl),
        mut: {
            cfg: cfg,
        }
    });
    Http.createServer((req, res) => {
        onReq(ctx, req, res);
    }).listen(cfg.port);
    console.error("Following: " + cfg.masterUrl);
    console.error("This pool tracker is serving the following config:");
    console.error(JSON.stringify(Master.mkConfig(cfg.masterConf, -1), null, '\t'));
    console.error();
};

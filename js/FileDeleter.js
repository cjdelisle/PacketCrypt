
/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const nThen = require('nthen');

const main = () => {
    let dir;
    let pfx;
    const again = () => {
        if (!dir || !pfx) {
            console.error('deleter: no dir configured');
            return void setTimeout(again, 5000);
        }
        Fs.readdir(dir, (err, files) => {
            if (err) {
                console.error("deleter:", JSON.stringify(err));
                return;
            }
            if (!files.length) {
                console.error('deleter: nothing to do, sleep 30 seconds');
                return void setTimeout(again, 30000);
            }
            console.error('deleter: beginning trash cycle [', files.length, '] files');
            let nt = nThen;
            files.forEach((f) => {
                if (f.indexOf(pfx) !== 0) { return; }
                nt = nt((w) => {
                    Fs.unlink(dir + '/' + f, w((err) => {
                        if (err && err.code !== 'ENOENT') {
                            console.error("failed to delete [", dir + '/' + f,
                                "] [", JSON.stringify(err));
                            return;
                        }
                    }));
                }).nThen;
            });
            nt((_) => again());
        });
    };
    process.on('message', (msg) => {
        if (!msg.directory || !msg.prefix) {
            console.error("deleter: got unexpected message", JSON.stringify(msg));
            return;
        }
        dir = msg.directory;
        pfx = msg.prefix;
    });

    process.stdin.resume();
    process.stdin.on('end', () => {
        console.error("deleter: Parent process is gone, exiting");
        process.exit(0);
    });
    again();
};
main();
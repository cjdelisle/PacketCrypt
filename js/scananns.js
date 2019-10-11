/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
const Fs = require('fs');
const nThen = require('nthen');

const printAnns = (f, buf) => {
    let diff = -1;
    let block = -1;
    let count = 0;
    for (let i = 0; i < buf.length; i += 1024) {
        const d = buf.readUInt32LE(i + 8);
        const b = buf.readUInt32LE(i + 12);
        if (d === diff && b === block) {
            count++;
            continue;
        }
        if (count) {
            console.log(f + ',' + diff.toString() + ',' + block.toString() + ',' + count);
        }
        diff = d;
        block = b;
        count = 1;
    }
    if (count) {
        console.log(f + ',' + diff.toString() + ',' + block.toString() + ',' + count);
    }
};

const main = (args) => {
    const dir = args.pop();
    Fs.readdir(dir, (err, files) => {
        if (err) {
            console.error("Unable to open directory [" + dir + "]");
            console.error("Usage: scannanns.js /path/to/announcements/");
            process.exit(100);
        }
        let nt = nThen;
        console.log("file,difficulty,block,count");
        files.forEach((f) => {
            nt = nt((w) => {
                Fs.readFile(dir + '/' + f, w((err, buf) => {
                    if (err) { throw err; }
                    printAnns(f, buf);
                }));
            }).nThen;
        });
    });
};
main(process.argv);

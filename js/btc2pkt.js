/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
const Bech32 = require('bech32');

const addr = process.argv.pop();
try {
    const b = Bech32.decode(addr);
    if (b.prefix === 'bc') {
        console.log(Bech32.encode('pkt', b.words));
    } else if (b.prefix === 'pkt') {
        console.log(Bech32.encode('bc', b.words));
    } else {
        console.log("I don't understand prefix: [" + b.prefix + "]");
    }
} catch (e) {
    console.log(e);
    console.log("Usage: ptc2pkt <bitcoin segwit address>");
    console.log("prints the equivilent pkt address");
}

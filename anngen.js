const Blake2b = require('blake2b');
const Crypto = require('crypto');
const Spawn = require('child_process').spawn;
const THREADS = require('os').cpus().length;

const start = (threads, target, parentBlockHeight, parentBlockHash) => {
    const contentByHash = {};
    const msg = Buffer.alloc(56 + 32);

    const again = () => {
        let content = Crypto.randomBytes(Math.floor(Math.random()*512));
        let realContent;
        if (content.length - 2 <= 0xfc) {
            content = content.slice(1)
            content[0] = content.length - 1;
            realContent = content.slice(1);
        } else {
            content[0] = 0xfd;
            content.writeUInt16LE(content.length - 3, 1);
            realContent = content.slice(3);
        }

        const hash = Blake2b(32).update(realContent).digest('hex');
        contentByHash[hash] = content;

        msg.writeUInt32LE(target, 8);
        msg.writeUInt32LE(parentBlockHeight, 12);
        msg.write(hash, 24, 32, 'hex');
        parentBlockHash.copy(msg, 56);
        pcann.stdin.write(msg, (err) => { if (err) { throw err; } });
    };

    const pcann = Spawn('./pcann', [ String(threads) ]);
    pcann.stderr.on('data', (d) => { process.stderr.write(d); });
    pcann.on('error', (e) => { throw e; });
    pcann.on('close', (_,f) => { if (f) { throw f; } });

    pcann.stdout.on('data', (d) => {
        const h = d.slice(24, 24+32).toString('hex');
        const c = contentByHash[h];
        if (!c) {
            throw new Error("no content for hash [" + h + "]");
        }
        //console.error(h);
        //console.error(c.toString('hex'));
        process.stdout.write(d);
        process.stdout.write(c);
        again();
    });
    again();
}

const usage = () => {
    console.error("Usage: anngen.js OPTIONS");
    console.error("    -w <work target>");
    console.error("    -p <parent_block_height>:<parent_block_hash>");
    console.error("    -t <threads>   # default is number of cores");
    console.error("    -h, --help     # print this message");
}

const main = (argv) => {
    let threads = THREADS;
    let tar = 0x200fffff;
    let parentBlockHeight;
    let parentBlockHash;
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '-w') {
            tar = Number(argv[i+1]);
            if (tar < 0 || tar > 0x207fffff) {
                return void console.error("invalid work target");
            }
        }
        if (argv[i] === '-p') {
            const spl = argv[i+1].split(':');
            if (spl.length !== 2) {
                return void console.error("invalid parent height/hash, expecting one :");
            }
            parentBlockHeight = Number(spl[0]);
            if (isNaN(parentBlockHeight) ||
                parentBlockHeight < 0 ||
                parentBlockHeight !== Math.floor(parentBlockHeight) ||
                parentBlockHeight > 0x7fffffff)
            {
                return void console.error("invalid parent height, must be a positive integer " +
                    "not more than 0x7fffffff");
            }
            parentBlockHash = Buffer.from(spl[1], 'hex');
            if (!parentBlockHash || parentBlockHash.length !== 32) {
                return void console.error("invalid parent hash, must be 32 hex bytes");
            }
        }
        if (argv[i] === '-t') {
            threads = Number(argv[i+1]);
            if (isNaN(threads) || threads < 0 || threads !== Math.floor(threads)) {
                return void console.error('threads must be positive integer');
            }
        }
        if (argv[i] === '--help' || argv[i] === '-h') {
            return void usage();
        }
    }
    if (typeof(parentBlockHeight) === 'undefined' || !parentBlockHash) {
        console.error("must specify -p");
        return void usage();
    }
    start(threads, tar, parentBlockHeight, parentBlockHash);
}
main(process.argv);

const Spawn = require('child_process').spawn;
const THREADS = require('os').cpus().length;

const start = (threads, target, parentBlockHeight, parentBlockHash) => {
    const msg = Buffer.alloc(56 + 32 + 32);
    msg.writeUInt32LE(target, 8);
    msg.writeUInt32LE(parentBlockHeight, 12);
    parentBlockHash.copy(msg, 56);

    //console.error(msg.toString('hex'));

    const pcann = Spawn('./pcann', [ String(threads) ]);
    pcann.stdout.on('data', (d) => { process.stdout.write(d); });
    pcann.stderr.on('data', (d) => { process.stderr.write(d); });
    pcann.stdin.write(msg, (err) => { if (err) { throw err; } });
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
    let tar = 0x2000ffff;
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

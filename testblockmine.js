const Spawn = require('child_process').spawn;
const Fs = require('fs');
const THREADS = require('os').cpus().length;

const mkFakeHeader = (target) => {
    const b = Buffer.alloc(80);
    b.writeUInt32LE(target, 72);
    return b;
}

const start = (threads, target, file) => {
    Fs.readFile(file, (err, announcements) => {
        if (err) { throw err; }
        const pcblk = Spawn('./pcblk', [ String(threads) ]);
        pcblk.stdout.on('data', (d) => {
            if (d.length != 32) {
                console.log(d.toString('utf8'));
                return;
            }
            const fh = mkFakeHeader(target);
            pcblk.stdin.write(fh);
        });
        pcblk.stderr.on('data', (d) => { process.stderr.write(d); });
        const len = Buffer.alloc(4);
        console.log(announcements.length);
        console.log(announcements.length / 1024);
        len.writeInt32LE(announcements.length / 1024);
        pcblk.stdin.write(len);
        pcblk.stdin.write(announcements);
        console.log('launched');
    });
}

const usage = () => {
    console.error("Usage: testblockmine.js OPTIONS");
    console.error("    -w <work target>");
    console.error("    -t <threads>            # default is number of cores");
    console.error("    -f <announcement_file>  # file containing announcements");
    console.error("    -h, --help              # print this message");
}

const main = (argv) => {
    let threads = THREADS;
    let diff = 0x2000ffff;
    let file;
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '-w') {
            diff = Number(argv[i+1]);
            if (diff < 0 || diff > 0x207fffff) {
                return void console.error("invalid work target");
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
        if (argv[i] === '-f') {
            file = argv[i+1];
        }
    }
    if (typeof(file) === 'undefined') {
        console.error("-f is required");
        return void usage();
    }
    start(threads, diff, file);
}
main(process.argv);

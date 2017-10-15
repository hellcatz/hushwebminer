# Hush Web Miner

This miner turns 1 CPU + 256MB RAM + 1 browser tab into HUSH cryptocurrency, a
zkSNARK coin related to Zcash.

# Installation requirements

Perl 5.8 or higher as your system Perl, which just about every operating system has these days. No special CPAN modules are required to be
installed, this repo comes with the CPAN module AnyEvent to implement asynchronous I/O.

No apache is required, no mysql, no php is required. Nginx is recommended to proxy requests in high traffic situations.

The server.pl in this repo implements it's own HTTP server, which is why nothing else is needed. It can serve static files and handle WebSocket connections.


# Installing

You only need webassembly to compile new .WASM files, if you just want to host a webminer
YOU DO NOT NEED the webassembly compiler on your server. Ignore any `make` or compile steps,
just copy the .wasm file to the correct place, directly next to the similarly named .js :

hushwebminer.js
hushwebminer.wasm

DO NOT edit the .js file directly, or the .wasm file will not load correctly. They are a pair.

* Install web assembly on server: http://webassembly.org/getting-started/developers-guide/

```
git clone https://github.com/MyHush/hushwebminer/
cd hushwebminer
cd js-emscripten/ && make  # only if you want to re-compile!!!
```

TODO: explain this stuff more
* Install js-emscripten/miner.html and hushminer.js and hushminer.wasm on web server.
* Install js-backend/ on server as /ws

# CPU Javascript miner for http://miner.myhush.org

Reimplementation of xenoncat/Tromp algorithm, just to understand
it better by myself.   Performs around the same as Tromp's equi1.
It's single-threaded on purpose, and uses 256 MB of memory now.
The aim was the pure C miner with no dependencies, that works of either
little-endian or big-endian platform (ultrasparc speed is so pathetic).

c/ is portable C sources to produce binary for your platform.

js-emscripten/ is a port to emscipten for mining in WebAssembly-compatible
browser

js-backend/ is a server-side support for browser mining, allows many
sessions (tested up to 30K sessions, many thanks to https://github.com/kosjak1)

pool-emu/ may be handy for debugging your miners.

Code used:
- BLAKE2b reference implementation from RFC 7693
- BLAKE2b optimized for SSE4.1/SSE2, taken from equihash by John Tromp
    https://github.com/tromp/equihash
- SHA-256 taken from cgminer by Con Kolivas
    https://github.com/ckolivas/cgminer/
- JSON parser by Serge A. Zaitsev
    https://github.com/zserge/jsmn

How to run binary:
   ./hushminer -l us.madmining.club -u {workername} -d 3

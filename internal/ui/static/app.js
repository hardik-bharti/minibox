// minibox lab: the page side of `minibox ui`.
//
// The server streams every update as a server-sent event (see hub.go for
// the message types). This file turns them into the five panels. Text from
// the server is always inserted with textContent, never as HTML.
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  // h("li", {class: "x"}, "text", child) builds an element safely.
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) {
      if (k == null || k === false) continue;
      e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    return e;
  }

  let INFO = null;
  let running = null; // the job in progress: {job, panel, action}

  // ---------- server calls ----------

  async function post(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Minibox-UI": "1" },
      body: JSON.stringify(body || {}),
    });
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    return r.json();
  }

  function start(action, params) {
    post("api/run", { action, params: params || {} }).catch((e) => toast(e.message));
  }

  let toastTimer;
  function toast(text) {
    const t = $("#toast");
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), 6000);
  }

  // ---------- status, tabs ----------

  function setStatus(kind, text) {
    const s = $("#status");
    s.className = "status " + kind;
    $("#status-text").textContent = text;
    $("#stop").hidden = kind !== "busy";
    $$("button[data-run], #lim-run, .matrix button").forEach((b) => (b.disabled = kind === "busy"));
  }

  function showPanel(name) {
    $$(".tabs [role=tab]").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.panel === name)));
    $$(".panel").forEach((p) => (p.hidden = p.id !== "panel-" + name));
    try { history.replaceState(null, "", "#" + name); } catch (_) { /* not important */ }
  }

  // ---------- command strip and log ----------

  // Shell-style quoting, so the strip shows a command you could paste.
  function shellQuote(a) {
    return /^[\w@%+=:,./-]+$/.test(a) ? a : "'" + a.replace(/'/g, "'\\''") + "'";
  }
  function shortArg(a) {
    const one = a.replace(/\s*\n\s*/g, "; ");
    return one.length > 90 ? one.slice(0, 87) + "…" : one;
  }

  const strips = {};
  function strip(panel) {
    if (!strips[panel]) {
      const root = $(`[data-strip="${panel}"]`);
      strips[panel] = { root, lines: [] };
      idleStrip(panel);
    }
    return strips[panel];
  }
  function idleStrip(panel) {
    const s = strips[panel] || strip(panel);
    s.root.replaceChildren(h("span", { class: "idle" }, "The command behind this view appears here when you run a demo."));
    s.lines = [];
  }
  function stripCmd(panel, argv, note) {
    const s = strip(panel);
    if (!s.lines.length) s.root.replaceChildren();
    if (note) s.root.append(h("div", { class: "line note" }, note));
    const exit = h("span", { class: "exit" }, "running…");
    const line = h("div", { class: "line" }, h("span", { class: "prompt" }, "$"),
      h("span", { title: argv.map(shellQuote).join(" ") }, argv.map((a) => shellQuote(shortArg(a))).join(" ")), exit);
    s.root.append(line);
    s.lines.push({ line, exit });
    // Long jobs (all 17 attacks) run 51 commands: keep the last few here,
    // the full list is in the output log below.
    while (s.root.querySelectorAll(".line:not(.note)").length > 3) s.root.firstElementChild.remove();
  }
  function stripExit(panel, code, ms) {
    const s = strip(panel);
    const last = s.lines[s.lines.length - 1];
    if (!last) return;
    last.exit.replaceChildren("exit ", h("b", {}, String(code)), ` · ${(ms / 1000).toFixed(1)} s`);
  }
  function stripNote(panel, text) {
    strip(panel).root.append(h("div", { class: "line note" }, text));
  }

  function log(panel, text, cls) {
    const pre = $(`[data-log="${panel}"]`);
    if (!pre) return;
    pre.append(h("span", { class: cls }, text + "\n"));
    if (pre.childNodes.length > 1500) pre.firstChild.remove();
    pre.scrollTop = pre.scrollHeight;
  }

  // ---------- event stream ----------

  function connect() {
    const es = new EventSource("api/events");
    es.onopen = async () => {
      try {
        const info = await (await fetch("api/info")).json();
        running = info.running ? { job: info.running.id, panel: info.running.panel, action: info.running.action } : null;
        setStatus(running ? "busy" : "idle", running ? "Running a demo" : "Ready");
      } catch (_) { setStatus("down", "Server unreachable"); }
    };
    es.onerror = () => setStatus("down", "Reconnecting…");
    es.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      handle(m);
    };
  }

  function handle(m) {
    switch (m.type) {
      case "job":
        if (m.state === "start") {
          running = { job: m.job, panel: m.panel, action: m.action };
          setStatus("busy", "Running: " + m.title);
          idleStrip(m.panel);
          log(m.panel, `# ${m.title}`, "cmd");
          panels[m.panel]?.start?.(m);
        } else {
          running = null;
          setStatus("idle", "Ready");
          if (m.error) {
            stripNote(m.panel, "Stopped: " + m.error);
            if (m.error !== "stopped") toast(m.error);
          }
          panels[m.panel]?.end?.(m);
        }
        break;
      case "cmd":
        stripCmd(m.panel, m.argv, m.text);
        log(m.panel, "$ " + m.argv.map(shellQuote).join(" "), "cmd");
        panels[m.panel]?.cmd?.(m);
        break;
      case "line":
        log(m.panel, m.text, m.stream === "err" ? "err" : "");
        break;
      case "exit":
        stripExit(m.panel, m.code, m.ms);
        log(m.panel, `[exit ${m.code}, ${m.ms} ms]`, "err");
        break;
      case "meter":
        limits.meter(m.meter);
        break;
      case "profile":
        profile.event(m.data);
        break;
      case "result":
        panels[m.panel]?.result?.(m.data);
        break;
    }
  }

  // ---------- a small SVG line chart ----------

  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, text) {
    const e = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (text != null) e.textContent = text;
    return e;
  }

  function niceStep(range, count) {
    const raw = range / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const f of [1, 2, 2.5, 5, 10]) if (f * mag >= raw) return f * mag;
    return 10 * mag;
  }

  function LineChart(root) {
    const tip = h("div", { class: "tip", hidden: true });
    root.append(tip);
    let svg = null;
    const st = { points: [], limit: 0, limitLabel: "", events: [], fmt: (v) => String(v), unit: "", minY: 1, minT: 6000 };

    function render() {
      svg?.remove();
      const W = root.clientWidth, H = root.clientHeight;
      if (!W || !H) return;
      const m = { l: 52, r: 18, t: 22, b: 28 };
      const w = W - m.l - m.r, hgt = H - m.t - m.b;
      svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": root.dataset.label || "chart" });
      const pts = st.points;
      const tMax = Math.max(st.minT, pts.length ? pts[pts.length - 1].t : 0);
      const vMax = Math.max(st.minY, st.limit * 1.15, ...pts.map((p) => p.v * 1.1));
      const step = niceStep(vMax, 5);
      const yMax = Math.ceil(vMax / step) * step;
      const x = (t) => m.l + (t / tMax) * w;
      const y = (v) => m.t + hgt - (v / yMax) * hgt;

      const axis = s("g", { class: "axis" });
      for (let v = 0; v <= yMax + 1e-9; v += step) {
        svg.append(s("line", { class: v === 0 ? "baseline" : "gridline", x1: m.l, x2: m.l + w, y1: y(v), y2: y(v) }));
        axis.append(s("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end" }, st.fmt(v)));
      }
      const tStep = niceStep(tMax / 1000, 6) * 1000;
      for (let t = 0; t <= tMax; t += tStep) {
        axis.append(s("text", { x: x(t), y: m.t + hgt + 18, "text-anchor": "middle" }, (t / 1000) + " s"));
      }
      svg.append(axis);

      if (st.limit > 0) {
        svg.append(s("line", { class: "limit", x1: m.l, x2: m.l + w, y1: y(st.limit), y2: y(st.limit) }));
        svg.append(s("text", { class: "limit-label", x: m.l + w, y: y(st.limit) - 6, "text-anchor": "end" }, st.limitLabel));
      }
      for (const ev of st.events) {
        svg.append(s("line", { class: "event-line", x1: x(ev.t), x2: x(ev.t), y1: m.t, y2: m.t + hgt }));
        const anchor = x(ev.t) > m.l + w * 0.7 ? "end" : "start";
        svg.append(s("text", { class: "event-label", x: x(ev.t) + (anchor === "end" ? -6 : 6), y: m.t + 12, "text-anchor": anchor }, ev.label));
      }

      if (pts.length) {
        const d = pts.map((p, i) => (i ? "L" : "M") + x(p.t).toFixed(1) + "," + y(p.v).toFixed(1)).join("");
        svg.append(s("path", { class: "area", d: d + `L${x(pts[pts.length - 1].t)},${y(0)}L${x(pts[0].t)},${y(0)}Z` }));
        svg.append(s("path", { class: "series", d }));
        const last = pts[pts.length - 1];
        svg.append(s("circle", { class: "enddot", cx: x(last.t), cy: y(last.v), r: 4 }));
      } else {
        svg.append(s("text", { class: "placeholder", x: m.l + w / 2, y: m.t + hgt / 2, "text-anchor": "middle" }, "Run the experiment to see live readings"));
      }

      // Crosshair: snaps to the nearest reading under the pointer.
      const cross = s("line", { class: "cross", y1: m.t, y2: m.t + hgt, visibility: "hidden" });
      const hit = s("rect", { x: m.l, y: m.t, width: w, height: hgt, fill: "transparent" });
      svg.append(cross, hit);
      hit.addEventListener("pointermove", (e) => {
        if (!pts.length) return;
        const rect = svg.getBoundingClientRect();
        const t = ((e.clientX - rect.left) * (W / rect.width) - m.l) / w * tMax;
        let best = pts[0];
        for (const p of pts) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
        cross.setAttribute("x1", x(best.t)); cross.setAttribute("x2", x(best.t));
        cross.setAttribute("visibility", "visible");
        tip.replaceChildren(h("b", {}, st.fmt(best.v, true)), `at ${(best.t / 1000).toFixed(1)} s`);
        tip.hidden = false;
        const px = x(best.t) * rect.width / W;
        tip.style.left = Math.min(px + 12, rect.width - tip.offsetWidth - 4) + "px";
        tip.style.top = "8px";
      });
      hit.addEventListener("pointerleave", () => { cross.setAttribute("visibility", "hidden"); tip.hidden = true; });
      root.prepend(svg);
    }

    new ResizeObserver(render).observe(root);
    return {
      reset(opts) { Object.assign(st, { points: [], events: [], limit: 0, limitLabel: "" }, opts); render(); },
      push(p) { st.points.push(p); },
      limit(v, label) { st.limit = v; st.limitLabel = label; },
      event(t, label) { st.events.push({ t, label }); },
      render,
    };
  }

  // ---------- panels ----------

  const fmtMiB = (b) => (b / 1048576).toFixed(b < 10 * 1048576 ? 1 : 0) + " MiB";

  // Phase 1
  const isolation = {
    result(d) {
      const viz = $("#iso-viz");
      if (d.kind === "isolation") {
        const rows = d.facts.map((f) => {
          const hv = d.host[f.key] ?? "", cv = d.container[f.key] ?? "";
          const diff = hv !== cv;
          return h("tr", { class: diff ? "diff" : "" },
            h("th", { scope: "row" }, f.label),
            h("td", { class: "val" }, hv),
            h("td", { class: "val ctr" }, cv),
            h("td", {}, h("span", { class: "tag " + (diff ? "diff" : "same") }, diff ? "different" : "same")),
            h("td", { class: "why" }, f.why));
        });
        viz.replaceChildren(h("div", { class: "tablewrap" }, h("table", { class: "iso" },
          h("thead", {}, h("tr", {}, h("th", { scope: "col" }, ""), h("th", { scope: "col" }, "This VM (a normal process)"),
            h("th", { scope: "col" }, "Inside the container"), h("th", { scope: "col" }, ""), h("th", { scope: "col" }, "Why"))),
          h("tbody", {}, rows))));
      } else if (d.kind === "overlay") {
        viz.replaceChildren(
          h("p", { class: "explain" }, "The container overwrote /etc/motd. The write went to its private overlay upper directory, so the image on disk is unchanged."),
          h("div", { class: "overlay-cmp" },
            h("div", {}, h("span", { class: "where" }, "/etc/motd inside the container"), h("code", {}, d.inside || "(empty)")),
            h("div", {}, h("span", { class: "where" }, d.image_path + " on the host"), h("code", {}, d.image || "(empty)"))));
      }
    },
  };

  // Phase 2
  const limitKinds = {
    memory: {
      title: "Memory used", label: "--memory", minY: 8,
      explain: "The probe allocates 2 MiB every 100 ms and touches each page. When memory.current reaches memory.max, the kernel's OOM killer ends it (exit 137).",
      value: (m) => m.mem / 1048576, limit: (m) => m.mem_max / 1048576,
      fmt: (v, tip) => (tip ? v.toFixed(1) : Math.round(v)) + " MiB",
    },
    pids: {
      title: "Processes in the cgroup", label: "--pids", minY: 5,
      explain: "The shell starts a sleeping child every 100 ms. When pids.current reaches pids.max, fork() fails with EAGAIN and the shell reports \"can't fork\".",
      value: (m) => m.pids, limit: (m) => m.pids_max,
      fmt: (v, tip) => (tip ? `${v} processes` : String(Math.round(v))),
    },
    cpu: {
      title: "CPU used, in CPUs", label: "--cpus", minY: 1,
      explain: "A busy loop wants a whole CPU. cpu.max gives it a quota in every 100 ms period; when the quota is used up, the kernel throttles it until the next period.",
      value: (m) => m.cpu_cores, limit: (m) => m.cpu_limit,
      fmt: (v, tip) => (tip ? v.toFixed(2) + " CPUs" : v.toFixed(v < 1 ? 2 : 1)),
    },
  };

  const limits = {
    kind: "memory", chart: null, last: null, first: null, peak: 0, samples: 0,
    init() {
      this.chart = LineChart($("#lim-chart"));
      $$("#lim-kind [role=radio]").forEach((b) => b.addEventListener("click", () => this.choose(b.dataset.kind)));
      $("#lim-run").addEventListener("click", () => start(this.kind, { limit: $("#lim-value").value }));
      this.choose("memory");
    },
    choose(kind) {
      this.kind = kind;
      $$("#lim-kind [role=radio]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.kind === kind)));
      const k = limitKinds[kind];
      $("#lim-label").textContent = k.label;
      fillSelect($("#lim-value"), actionParam(kind, "limit"));
      $("#lim-explain").textContent = k.explain;
      $("#lim-title").textContent = k.title;
      $("#lim-readout").textContent = "";
      $("#lim-facts").replaceChildren();
      $("#lim-table").replaceChildren();
      this.chart.reset({ fmt: k.fmt, minY: k.minY });
    },
    start(m) {
      if (m.action !== this.kind) this.choose(m.action);
      const k = limitKinds[this.kind];
      this.chart.reset({ fmt: k.fmt, minY: k.minY });
      this.last = this.first = null; this.peak = 0; this.samples = 0;
      $("#lim-facts").replaceChildren();
      $("#lim-table").replaceChildren(h("thead", {}, h("tr", {}, ["time", "memory", "processes", "CPUs used", "throttled", "OOM kills", "forks refused"].map((c) => h("th", { scope: "col", class: c === "time" ? "" : "num" }, c)))), h("tbody"));
    },
    meter(m) {
      if (!running || running.panel !== "limits") return;
      const k = limitKinds[this.kind];
      const v = k.value(m);
      const prev = this.last;
      this.first ??= m;
      this.chart.push({ t: m.t_ms, v });
      const lim = k.limit(m);
      if (lim > 0) this.chart.limit(lim, "limit " + k.fmt(lim, true));
      if (prev && m.oom_kills > prev.oom_kills) this.chart.event(m.t_ms, "OOM kill");
      if (prev && m.pids_rejected > 0 && prev.pids_rejected === 0) this.chart.event(m.t_ms, "first fork refused");
      this.chart.render();
      this.peak = Math.max(this.peak, v);
      this.last = m;
      $("#lim-readout").textContent = k.fmt(v, true) + (lim > 0 ? " of " + k.fmt(lim, true) : "");
      this.facts(m);
      if (this.samples++ % 5 === 0) {
        $("#lim-table tbody").append(h("tr", {}, h("td", {}, (m.t_ms / 1000).toFixed(1) + " s"),
          [fmtMiB(m.mem), m.pids, m.cpu_cores.toFixed(2), m.throttled, m.oom_kills, m.pids_rejected].map((c) => h("td", { class: "num" }, c))));
      }
    },
    facts(m, final) {
      const k = limitKinds[this.kind];
      const rows = [];
      const item = (label, value, small) => h("div", {}, h("dt", {}, label), h("dd", {}, value, small ? h("small", {}, " " + small) : null));
      if (this.kind === "memory") {
        rows.push(item("Peak", k.fmt(this.peak, true)), item("OOM kills", m.oom_kills, "memory.events"));
      } else if (this.kind === "pids") {
        rows.push(item("Peak", this.peak + " processes"), item("Forks refused", m.pids_rejected, "pids.events max"));
      } else {
        const secs = (m.t_ms - this.first.t_ms) / 1000;
        const avg = secs > 0 ? (m.cpu_usec - this.first.cpu_usec) / 1e6 / secs : 0;
        rows.push(item("Average use", avg.toFixed(2) + " CPUs"), item("Throttled periods", m.throttled, "cpu.stat nr_throttled"));
      }
      if (final) rows.push(final);
      $("#lim-facts").replaceChildren(...rows);
    },
    result(d) {
      if (d.kind !== "limit" || !this.last) return;
      let state;
      if (d.limit_kind === "memory") {
        state = d.code === 137 ? h("span", { class: "state bad" }, "✕ Killed by the OOM killer (exit 137)") : h("span", { class: "state warn" }, `Exited with ${d.code}`);
      } else if (d.limit_kind === "pids") {
        const n = Number(d.stats.pids_rejected || 0);
        state = n > 0 ? h("span", { class: "state warn" }, `! ${n} forks refused at the limit`) : h("span", { class: "state good" }, "Never reached the limit");
      } else {
        const n = Number(d.stats.nr_throttled || 0);
        state = h("span", { class: "state warn" }, `! Throttled in ${n} periods`);
      }
      this.facts(this.last, h("div", {}, h("dt", {}, "Outcome"), h("dd", {}, state)));
    },
  };

  // Phase 5
  const profile = {
    seen: new Set(), total: 0, nPaths: 0,
    start(m) {
      if (m.action === "enforce") {
        $("#enf-result").replaceChildren(h("p", { class: "empty" }, "Running…"));
        return;
      }
      this.seen.clear(); this.nPaths = 0;
      $("#prof-syscalls").replaceChildren();
      $("#prof-paths").replaceChildren();
      $("#prof-caps").replaceChildren(h("li", { class: "none" }, "None yet"));
      $("#prof-total").textContent = "";
      drawGrid(new Set());
      $("#prof-compare").textContent = "Profiling…";
    },
    event(e) {
      if (!running || running.panel !== "profile") return;
      if (e.kind === "syscall" && !this.seen.has(e.name)) {
        this.seen.add(e.name);
        const li = h("li", { class: "new" }, e.name);
        $("#prof-syscalls").append(li);
        setTimeout(() => li.classList.remove("new"), 700);
      } else if (e.kind === "path" && this.nPaths++ < 300) {
        $("#prof-paths").append(h("li", {}, h("span", { class: "acc " + e.access }, e.access), h("code", {}, e.path)));
      } else if (e.kind === "cap") {
        const caps = $("#prof-caps");
        caps.querySelector(".none")?.remove();
        caps.append(h("li", {}, h("code", {}, e.name), h("span", { class: "hint" }, e.reason)));
      } else if (e.kind === "progress") {
        $("#prof-total").textContent = `· ${e.total.toLocaleString()} calls traced`;
      }
    },
    result(d) {
      if (d.kind === "policy") {
        const allowed = new Set(d.allowed);
        drawGrid(allowed);
        const docker = INFO.docker_syscalls;
        const extra = d.allowed.filter((x) => !docker.includes(x));
        const pct = (100 * d.allowed.length / docker.length).toFixed(1);
        $("#prof-compare").replaceChildren(
          h("span", { class: "bignum" }, String(d.allowed.length)),
          ` syscalls allowed, ${pct}% of the ${docker.length} Docker's default profile allows. `,
          `Capabilities kept: ${d.capabilities.length ? d.capabilities.join(", ") : "none"}. `,
          `Writable paths: ${d.writable_paths.length ? d.writable_paths.join(", ") : "none (the whole root is read-only)"}.`,
          extra.length ? ` Allowed but not in Docker's list: ${extra.join(", ")}.` : "");
        addPolicy(d.workload);
      } else if (d.kind === "enforce") {
        const ok = d.code === 0;
        $("#enf-result").replaceChildren(
          h("div", {}, h("span", { class: "state " + (ok ? "good" : "bad") }, ok ? "✓ Ran normally (exit 0)" : `✕ Failed under the policy (exit ${d.code})`)),
          h("p", {}, `${d.title}, under the policy profiled from ${workloadTitle(d.policy)}.`),
          d.denied.length ? h("pre", {}, d.denied.slice(0, 6).join("\n")) : null,
          !ok ? h("p", { class: "explain" }, "Anything the profiled run didn't do is denied: syscalls fail with EPERM and writes outside the writable paths hit a read-only filesystem.") : null);
      }
    },
  };

  function drawGrid(on) {
    const g = $("#prof-grid");
    g.replaceChildren(...INFO.docker_syscalls.map((n) => h("span", { class: on.has(n) ? "on" : "", title: n + (on.has(n) ? ": kept" : "") })));
  }

  function workloadTitle(id) {
    const c = actionParam("profile", "workload").choices.find((c) => c.value === id);
    return c ? c.label.toLowerCase() : id;
  }

  function addPolicy(id) {
    const sel = $("#enf-policy");
    if (![...sel.options].some((o) => o.value === id)) sel.append(h("option", { value: id }, actionParam("profile", "workload").choices.find((c) => c.value === id)?.label || id));
    sel.value = id;
    $("#enf-workload").value = id;
    const fs = $("#flt-source");
    if (![...fs.options].some((o) => o.value === "workload:" + id)) fs.append(h("option", { value: "workload:" + id }, "Generated policy: " + workloadTitle(id)));
  }

  // Phase 6
  const attacks = {
    results: {},
    init() {
      const tb = $("#atk-table tbody");
      tb.replaceChildren(...INFO.attacks.map((name) => h("tr", { "data-attack": name },
        h("th", { scope: "row" }, INFO.attack_descriptions[name], h("code", {}, name)),
        ["none", "baseline", "policy"].map((c) => h("td", { class: "cell", "data-config": c }, chip(null))),
        h("td", {}, h("button", { type: "button", onclick: () => start("attack", { attack: name }) }, "Run")))));
      if (!INFO.have.probe) $("#atk-detail").textContent = "The attack probe is not built. Run make probe, then restart minibox ui.";
    },
    start(m) {
      if (m.action === "attack-all") {
        this.results = {};
        $$("#atk-table td.cell").forEach((td) => td.replaceChildren(chip("waiting")));
        this.sums();
      }
    },
    cmd(m) {
      const i = m.argv.indexOf("/probe/probe");
      if (i < 0) return;
      const name = m.argv[i + 1];
      $$("#atk-table tbody tr").forEach((tr) => tr.classList.toggle("running", tr.dataset.attack === name));
    },
    end() { $$("#atk-table tbody tr").forEach((tr) => tr.classList.remove("running")); },
    result(d) {
      if (d.kind !== "attack") return;
      this.results[d.attack + "/" + d.config] = d;
      const td = $(`#atk-table tr[data-attack="${d.attack}"] td[data-config="${d.config}"]`);
      td?.replaceChildren(chip(d));
      this.sums();
    },
    sums() {
      for (const c of ["none", "baseline", "policy"]) {
        const rs = Object.values(this.results).filter((r) => r.config === c);
        $(`#atk-table tfoot [data-sum="${c}"]`).textContent = rs.length ? `${rs.filter((r) => r.result === "BLOCKED").length}/${rs.length}` : "–";
      }
    },
  };

  function chip(r) {
    if (!r || r === "waiting") return h("span", { class: "verdict-chip pending" }, r ? "waiting" : "not run");
    const label = { BLOCKED: "✓ Blocked", ALLOWED: "✕ Allowed", ERROR: "! Error" }[r.result] || r.result;
    return h("button", {
      type: "button", class: "verdict-chip " + r.result,
      "aria-label": `${r.attack} under ${r.config}: ${r.result}. Show details`,
      onclick: () => { $("#atk-detail").textContent = `${r.attack} under ${r.config}: ${r.result} (exit ${r.code}). The probe reported: ${r.detail}`; },
    }, label);
  }

  // Phases 4-5: the filter walkthrough
  const filter = {
    data: null, step: 0, timer: null,
    init() {
      const names = { baseline: "Docker default (baseline)", "attack-probe": "Generated policy: the attack suite's benign service" };
      fillSelect($("#flt-source"), { choices: INFO.filter_sources.map((v) => ({ value: v, label: names[v] || "Generated policy: " + workloadTitle(v.replace("workload:", "")) })) });
      const examples = [["getpid", "getpid"], ["write", "write"], ["openat", "openat"], ["mount", "mount"], ["ptrace", "ptrace"], ["unshare", "unshare"],
        ["clone:fork", "clone (an ordinary fork)"], ["clone:newuser", "clone (CLONE_NEWUSER)"], ["clone3", "clone3"], ["init_module", "init_module"], ["bpf", "bpf"], ["reboot", "reboot"]];
      const sel = $("#flt-syscall");
      sel.replaceChildren(
        h("optgroup", { label: "Examples" }, examples.map(([v, l]) => h("option", { value: v }, l))),
        h("optgroup", { label: "Everything Docker's profile allows" }, INFO.docker_syscalls.map((n) => h("option", { value: n }, n))));
      $("#flt-show").addEventListener("click", () => this.load());
      $("#flt-step").addEventListener("click", () => this.advance());
      $("#flt-play").addEventListener("click", () => this.play());
    },
    async load() {
      const [name, variant] = $("#flt-syscall").value.split(":");
      const q = new URLSearchParams({ source: $("#flt-source").value, syscall: name, variant: variant || "" });
      try {
        const r = await fetch("api/filter?" + q);
        if (!r.ok) throw new Error(await r.text());
        this.data = await r.json();
      } catch (e) { toast(e.message); return; }
      const tb = $("#flt-prog tbody");
      tb.replaceChildren(...this.data.instructions.map((i) => h("tr", { "data-pc": i.pc }, h("td", {}, i.pc), h("td", {}, i.asm), h("td", {}, i.explain))));
      this.step = this.data.trace.path.length; // show the whole path first
      this.paint();
      $("#flt-step").disabled = $("#flt-play").disabled = false;
    },
    paint() {
      const path = this.data.trace.path;
      const visited = new Set(path.slice(0, this.step));
      const cur = path[this.step - 1];
      $$("#flt-prog tbody tr").forEach((tr) => {
        const pc = Number(tr.dataset.pc);
        tr.className = pc === cur ? "current" : visited.has(pc) ? "visited" : this.step >= path.length ? "skipped" : "";
      });
      const row = $(`#flt-prog tr[data-pc="${cur}"]`);
      const box = $("#flt-prog").parentElement;
      if (row) box.scrollTop = Math.max(0, row.offsetTop - box.clientHeight / 2);
      const t = this.data.trace, done = this.step >= path.length;
      const allow = t.result === "ALLOW";
      $("#flt-verdict").replaceChildren(
        h("p", { class: "explain" }, t.label + `, syscall number ${t.nr}`),
        done ? h("p", { class: "res" }, h("span", { class: "state " + (allow ? "good" : "bad") }, (allow ? "✓ " : "✕ ") + t.result)) : h("p", { class: "res" }, `Step ${this.step} of ${path.length}`),
        h("p", {}, `The kernel ran ${path.length} of the filter's ${this.data.instructions.length} instructions and stopped at the first return.`),
        h("p", { class: "explain" }, `This filter allows ${this.data.allowed.length} syscalls. Unlisted syscalls are compared against every allowed number in turn and then fall through to the default action at the end.`));
    },
    advance() {
      const n = this.data.trace.path.length;
      this.step = this.step >= n ? 1 : this.step + 1;
      this.paint();
    },
    play() {
      clearInterval(this.timer);
      this.step = 0;
      this.timer = setInterval(() => {
        this.advance();
        if (this.step >= this.data.trace.path.length) clearInterval(this.timer);
      }, 220);
    },
  };

  const panels = { isolation, limits, profile, attacks, filter };

  // ---------- controls from the action catalogue ----------

  function actionParam(action, name) {
    const a = INFO.actions.find((a) => a.id === action);
    return a?.params?.find((p) => p.name === name) || { choices: [] };
  }

  function fillSelect(sel, param) {
    sel.replaceChildren(...param.choices.map((c) => h("option", { value: c.value }, c.label)));
    if (param.default) sel.value = param.default;
  }

  function params(action) {
    switch (action) {
      case "isolation": return { hostname: $("#iso-hostname").value };
      case "profile": return { workload: $("#prof-workload").value };
      case "enforce": return { policy: $("#enf-policy").value, workload: $("#enf-workload").value };
      default: return {};
    }
  }

  async function init() {
    try {
      INFO = await (await fetch("api/info")).json();
    } catch (e) {
      setStatus("down", "Server unreachable");
      return;
    }
    fillSelect($("#iso-hostname"), actionParam("isolation", "hostname"));
    fillSelect($("#prof-workload"), actionParam("profile", "workload"));
    fillSelect($("#enf-workload"), actionParam("enforce", "workload"));
    $("#enf-policy").replaceChildren();
    for (const id of INFO.policies) if (id !== "attack-probe") addPolicy(id);
    $$("button[data-run]").forEach((b) => b.addEventListener("click", () => start(b.dataset.run, params(b.dataset.run))));
    $("#stop").addEventListener("click", () => post("api/stop").catch((e) => toast(e.message)));
    $$(".tabs [role=tab]").forEach((t) => t.addEventListener("click", () => showPanel(t.dataset.panel)));
    limits.init();
    attacks.init();
    filter.init();
    drawGrid(new Set());
    Object.keys(panels).forEach(strip);
    const hash = location.hash.slice(1);
    showPanel(panels[hash] ? hash : "isolation");
    connect();
  }

  init();
})();

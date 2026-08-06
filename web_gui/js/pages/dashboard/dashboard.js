/*
 * ES: Página Dashboard. Usa DOM seguro: createElement/textContent mediante PraesidiumDom.
 * EN: Dashboard page. Uses safe DOM: createElement/textContent through PraesidiumDom.
 */
(() => {
  "use strict";

  // ES: Helpers comunes y DOM seguro importados desde core.
  // EN: Common helpers and safe DOM imported from core.
  const { t, formatBytes, formatRate, setText } = window.PraesidiumUi;
  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;

  // ES: Crea una fila de métrica tipo label/value.
  // EN: Creates a label/value metric row.
  function metricRow(label, id, initial = "--") {
    return el("div", {}, [el("span", {}, [label]), el("strong", { id }, [initial])]);
  }

  // ES: Construye la estructura visual del dashboard sin innerHTML.
  // EN: Builds the dashboard visual structure without innerHTML.
  function buildDashboardDom() {
    const section = el("section", { id: "praesidium-dashboard", className: "dashboard-shell pf-dashboard" });

    const header = el("div", { className: "dashboard-header cajita-cabecera" }, [
      el("div", {}, [el("h2", {}, [t("dashboard.title")]), el("p", {}, [t("dashboard.subtitle")])]),
      el("span", { id: "dashboard-refresh-status", className: "dashboard-refresh-pill" }, [t("common.loading")]),
    ]);

    const cpuCard = el("article", { className: "dashboard-card dashboard-card-wide" }, [
      el("div", { className: "dashboard-card-header" }, [el("h3", {}, [t("dashboard.cpu_per_core")]), el("span", { id: "dashboard-cpu-average" }, ["--%"])]),
      el("div", { className: "dashboard-chart-box dashboard-chart-box-cpu" }, [el("canvas", { id: "cpuChart" })]),
      el("div", { id: "dashboard-cpu-list", className: "dashboard-kpi-row" }),
    ]);

    const ramCard = el("article", { className: "dashboard-card" }, [
      el("div", { className: "dashboard-card-header" }, [el("h3", {}, [t("dashboard.ram")]), el("span", { id: "dashboard-ram-used-percent" }, ["--%"])]),
      el("div", { className: "dashboard-chart-box dashboard-chart-box-ram" }, [el("canvas", { id: "ramChart" })]),
      el("div", { className: "dashboard-metric-list" }, [
        metricRow(t("dashboard.total"), "ram-total", "-- MB"),
        metricRow(t("dashboard.used_memory"), "ram-used", "-- MB"),
        metricRow(t("dashboard.free_memory"), "ram-free", "-- MB"),
        metricRow(t("dashboard.cached_memory"), "ram-cached", "-- MB"),
      ]),
    ]);

    const diskCard = el("article", { className: "dashboard-card" }, [
      el("div", { className: "dashboard-card-header" }, [el("h3", {}, [t("dashboard.disk")]), el("span", { id: "dashboard-disk-used-percent" }, ["--%"])]),
      el("div", { className: "dashboard-metric-list dashboard-disk-summary-list" }, [
        metricRow(t("dashboard.total"), "disk-total"),
        metricRow(t("dashboard.used"), "disk-used"),
        metricRow(t("dashboard.available"), "disk-available"),
      ]),
      el("div", { className: "dashboard-disk-bar", "aria-hidden": "true" }, [el("span", { id: "dashboard-disk-used-bar" })]),
      el("div", { id: "dashboard-disk-mounts", className: "dashboard-disk-mounts" }),
    ]);

    const networkTable = el("table", { id: "bandwidth-table", className: "dashboard-table" }, [
      el("thead", {}, [tr([th(t("dashboard.interface")), th(t("dashboard.rx_rate")), th(t("dashboard.tx_rate")), th(t("dashboard.rx_total")), th(t("dashboard.tx_total"))])]),
      el("tbody", { id: "dashboard-network-rows" }, [tr([td(t("common.loading"), { colspan: "5" })])]),
    ]);
    const networkCard = el("article", { className: "dashboard-card dashboard-card-wide" }, [
      el("div", { className: "dashboard-card-header" }, [el("h3", {}, [t("dashboard.bandwidth_by_interface")]), el("span", { id: "dashboard-refresh-note" }, [t("dashboard.refresh_interval")])]),
      el("div", { className: "dashboard-table-wrap" }, [networkTable]),
    ]);

    section.append(header, el("div", { className: "dashboard-grid" }, [cpuCard, ramCard, diskCard, networkCard]));
    return section;
  }

  // ES: Convierte segundos de uptime a texto corto traducible.
  // EN: Converts uptime seconds into short translatable text.
  function secondsToUptime(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    if (days > 0) return t("dashboard.days_hours_minutes", { days, hours, minutes });
    if (hours > 0) return t("dashboard.hours_minutes", { hours, minutes });
    return t("dashboard.minutes", { minutes });
  }

  // ES: Crea gráficos Chart.js; si Chart no existe, el dashboard sigue funcionando con barras DOM.
  // EN: Creates Chart.js charts; if Chart is missing, the dashboard still works with DOM bars.
  function createDashboardCharts() {
    if (typeof Chart === "undefined") return { cpuChart: null, ramChart: null };
    const cpuCanvas = document.getElementById("cpuChart");
    const ramCanvas = document.getElementById("ramChart");
    const cpuChart = cpuCanvas ? new Chart(cpuCanvas.getContext("2d"), {
      type: "bar",
      data: { labels: [], datasets: [{ label: t("dashboard.cpu_percent_label"), data: [], backgroundColor: "rgba(58, 134, 255, 0.72)", borderColor: "rgba(58, 134, 255, 1)", borderWidth: 1, borderRadius: 5, minBarLength: 3 }] },
      options: { indexAxis: "y", animation: false, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, max: 100, grid: { color: "rgba(148, 163, 184, 0.14)" }, ticks: { callback: value => `${value}%` } }, y: { grid: { display: false }, ticks: { autoSkip: false } } } },
    }) : null;
    const ramChart = ramCanvas ? new Chart(ramCanvas.getContext("2d"), {
      type: "doughnut",
      data: { labels: [t("dashboard.used_memory"), t("dashboard.free_memory"), t("dashboard.cached_memory")], datasets: [{ data: [0, 0, 0], backgroundColor: ["#3a86ff", "#2dc653", "#ffbe0b"], borderColor: "#111827", borderWidth: 2 }] },
      options: { animation: false, responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { position: "bottom" } } },
    }) : null;
    return { cpuChart, ramChart };
  }

  // ES: Pinta lista de CPU por core sin HTML concatenado.
  // EN: Renders CPU core list without concatenated HTML.
  function paintCpuList(cores) {
    const cpuList = document.getElementById("dashboard-cpu-list");
    if (!cpuList) return;
    replaceChildren(cpuList, cores.map((value, index) => {
      const percent = Math.max(0, Math.min(100, Number(value) || 0));
      const bar = el("span");
      bar.style.width = `${percent || 1}%`;
      return el("div", { className: "dashboard-core-pill" }, [
        el("div", { className: "dashboard-core-pill-top" }, [el("span", {}, [`${t("dashboard.core_label")} ${index}`]), el("strong", {}, [`${percent.toFixed(1)}%`])]),
        el("div", { className: "dashboard-core-bar", "aria-hidden": "true" }, [bar]),
      ]);
    }));
  }

  // ES: Pinta tarjetas de montajes sin innerHTML ni HTML de backend.
  // EN: Renders mount cards without innerHTML or backend-provided HTML.
  function paintMounts(mounts) {
    const mountsEl = document.getElementById("dashboard-disk-mounts");
    if (!mountsEl) return;
    if (!mounts.length) {
      replaceChildren(mountsEl, [el("div", { className: "dashboard-disk-empty" }, [t("dashboard.no_storage_mounts")])]);
      return;
    }
    replaceChildren(mountsEl, mounts.map(mount => {
      const percent = Math.max(0, Math.min(100, Number(mount.used_percent || 0)));
      const bar = el("span");
      bar.style.width = `${percent || 1}%`;
      return el("div", { className: "dashboard-disk-mount", "data-status": mount.status || "ok" }, [
        el("div", { className: "dashboard-disk-mount-top" }, [el("strong", {}, [mount.mountpoint]), el("span", {}, [`${percent.toFixed(1)}%`])]),
        el("div", { className: "dashboard-disk-mount-meta" }, [el("span", {}, [mount.fstype]), el("span", {}, [mount.source])]),
        el("div", { className: "dashboard-disk-mount-values" }, [
          metricValue(t("dashboard.total"), formatBytes(mount.total)),
          metricValue(t("dashboard.used"), formatBytes(mount.used)),
          metricValue(t("dashboard.available"), formatBytes(mount.available)),
        ]),
        el("div", { className: "dashboard-disk-mount-bar", "aria-hidden": "true" }, [bar]),
      ]);
    }));
  }

  // ES: Crea bloque pequeño label/value para montajes.
  // EN: Creates a small label/value block for mounts.
  function metricValue(label, value) {
    return el("div", {}, [el("span", {}, [label]), el("strong", {}, [value])]);
  }

  // ES: Pinta tabla de red con textContent seguro.
  // EN: Renders network table with safe textContent.
  function paintNetworkRows(interfaces) {
    const netRows = document.getElementById("dashboard-network-rows");
    if (!netRows) return;
    if (!interfaces.length) {
      replaceChildren(netRows, [tr([td(t("dashboard.no_interfaces"), { colspan: "5" })])]);
      return;
    }
    replaceChildren(netRows, interfaces.map(item => tr([
      td(el("strong", {}, [item.name])),
      td(formatRate(item.rx_bytes_per_second)),
      td(formatRate(item.tx_bytes_per_second)),
      td(formatBytes(item.rx_bytes)),
      td(formatBytes(item.tx_bytes)),
    ])));
  }

  // ES: Pinta una muestra completa recibida desde GET /api/v1/dashboard/stats.
  // EN: Renders one full sample received from GET /api/v1/dashboard/stats.
  function paintDashboardStats(data, charts) {
    const cpu = data.cpu || {};
    const cores = Array.isArray(cpu.cores) ? cpu.cores : [];
    setText("dashboard-cpu-average", `${Number(cpu.average || 0).toFixed(1)}%`);
    const cpuBox = document.querySelector(".dashboard-chart-box-cpu");
    if (cpuBox) cpuBox.style.height = `${Math.min(760, Math.max(240, cores.length * 34))}px`;
    if (charts.cpuChart) {
      charts.cpuChart.data.labels = cores.map((_, index) => `${t("dashboard.core_label")} ${index}`);
      charts.cpuChart.data.datasets[0].data = cores.map(value => Number(value) || 0);
      charts.cpuChart.update();
    }
    paintCpuList(cores);

    const ram = data.ram || {};
    const ramTotal = Number(ram.total || 0);
    const ramUsed = Number(ram.used || 0);
    const ramFree = Number(ram.free || 0);
    const ramCached = Number(ram.cached || 0);
    setText("dashboard-ram-used-percent", `${Number(ram.used_percent || 0).toFixed(1)}%`);
    setText("ram-total", `${ramTotal} MB`);
    setText("ram-used", `${ramUsed} MB`);
    setText("ram-free", `${ramFree} MB`);
    setText("ram-cached", `${ramCached} MB`);
    if (charts.ramChart) {
      charts.ramChart.data.datasets[0].data = [ramUsed, ramFree, ramCached];
      charts.ramChart.update();
    }

    setText("dashboard-loadavg", Array.isArray(data.load_average) ? data.load_average.join(" / ") : "--");
    setText("dashboard-uptime", secondsToUptime(data.uptime_seconds));
    setText("dashboard-api-status", data.status || "ok");
    setText("dashboard-last-sample", new Date((Number(data.timestamp) || Date.now() / 1000) * 1000).toLocaleTimeString());

    const disk = data.disk || {};
    const summary = disk.summary || {};
    const diskPercent = Math.max(0, Math.min(100, Number(summary.used_percent || 0)));
    setText("dashboard-disk-used-percent", `${diskPercent.toFixed(1)}%`);
    setText("disk-total", formatBytes(summary.total || 0));
    setText("disk-used", formatBytes(summary.used || 0));
    setText("disk-available", formatBytes(summary.available || 0));
    const diskBar = document.getElementById("dashboard-disk-used-bar");
    if (diskBar) {
      diskBar.style.width = `${diskPercent || 1}%`;
      diskBar.dataset.status = diskPercent >= 90 ? "critical" : (diskPercent >= 80 ? "warning" : "ok");
    }
    paintMounts(Array.isArray(disk.mounts) ? disk.mounts : []);

    const network = data.network || {};
    const interfaces = Array.isArray(network.interfaces) ? network.interfaces : [];
    setText("dashboard-network-count", t("dashboard.interfaces_count", { count: interfaces.length }));
    paintNetworkRows(interfaces);
  }

  // ES: Renderiza dashboard, arranca refresco cada 5s y devuelve cleanup para detenerlo.
  // EN: Renders dashboard, starts 5s refresh, and returns cleanup to stop it.
  async function renderDashboard(container) {
    replaceChildren(container, [buildDashboardDom()]);
    const charts = createDashboardCharts();
    let stopped = false;
    const setStatus = (text, mode = "") => {
      const status = document.getElementById("dashboard-refresh-status");
      if (!status) return;
      status.textContent = text;
      status.dataset.mode = mode;
    };
    const refresh = async () => {
      if (stopped) return;
      try {
        setStatus(t("common.updating"));
        const data = await PraesidiumApi.request("/dashboard/stats");
        if (stopped) return;
        paintDashboardStats(data, charts);
        setStatus(t("dashboard.last_updated", { time: new Date().toLocaleTimeString() }), "ok");
      } catch (err) {
        if (stopped) return;
        setStatus(t("dashboard.error_loading", { message: err.message }), "error");
      }
    };
    await refresh();
    const timerId = window.setInterval(refresh, 5000);
    return () => {
      stopped = true;
      window.clearInterval(timerId);
      if (charts.cpuChart) charts.cpuChart.destroy();
      if (charts.ramChart) charts.ramChart.destroy();
    };
  }

  // ES: Registro público de la página Dashboard para el dispatcher central.
  // EN: Public Dashboard page registration for the central dispatcher.
  window.PraesidiumDashboardPage = { render: renderDashboard };
})();

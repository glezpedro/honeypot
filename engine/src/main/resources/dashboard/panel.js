const PLOT = document.getElementById("plot");
const PAD = { top: 16, right: 96, bottom: 24, left: 60 };
const SERIES = {
  rank: ["rankExact", "rankSketch", "Ranking"],
  brute: ["bruteExact", "bruteSketch", "Fuerza bruta"],
  enum: ["enumExact", "enumSketch", "Enumeración"]
};

const HINT = "pasa el ratón por la gráfica";

let tab = "rank";
let hover = -1;
let latest = null;
let polling = false;

function number(value, decimals) {
  return value.toLocaleString("es-ES", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  });
}

function bytes(value) {
  if (value === 0) {
    return "0";
  }
  if (value < 1024) {
    return value + " B";
  }
  const kb = value / 1024;
  if (kb < 1024) {
    return number(kb, kb < 100 && !Number.isInteger(kb) ? 1 : 0) + " KB";
  }
  const mb = kb / 1024;
  return number(mb, Number.isInteger(mb) ? 0 : 1) + " MB";
}

// El techo se redondea en kilobytes para que las lineas de la rejilla caigan en
// cifras enteras en vez de en los 195,3 KB que salen de redondear bytes.
function niceMax(value) {
  const kb = value / 1024;
  if (kb <= 0) {
    return 1024;
  }
  const power = Math.pow(10, Math.floor(Math.log10(kb)));
  for (const step of [1, 1.2, 1.6, 2, 2.4, 3.2, 4, 5, 6, 8, 10]) {
    if (kb <= step * power) {
      return step * power * 1024;
    }
  }
  return 10 * power * 1024;
}

function text(x, y, value, fill, anchor, weight) {
  return `<text x="${x}" y="${y}" fill="${fill}" text-anchor="${anchor || "start"}"`
    + ` font-size="11" font-weight="${weight || 400}"`
    + ` font-family="ui-sans-serif, system-ui, sans-serif">${value}</text>`;
}

function draw() {
  if (!latest) {
    return;
  }
  const style = getComputedStyle(document.body);
  const ink = style.getPropertyValue("--primary").trim();
  const soft = style.getPropertyValue("--muted").trim();
  const grid = style.getPropertyValue("--grid").trim();
  const colours = [style.getPropertyValue("--exact").trim(), style.getPropertyValue("--sketch").trim()];

  const width = PLOT.clientWidth || 880;
  const height = 260;
  PLOT.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const [exactKey, sketchKey] = SERIES[tab];
  const points = latest.history;
  const values = [points.map(p => p[exactKey]), points.map(p => p[sketchKey])];
  const top = niceMax(Math.max(1, ...values[0], ...values[1]));

  const plotWidth = width - PAD.left - PAD.right;
  const plotHeight = height - PAD.top - PAD.bottom;
  const x = i => PAD.left + (points.length < 2 ? 0 : (i / (points.length - 1)) * plotWidth);
  const y = v => PAD.top + plotHeight - (v / top) * plotHeight;

  let svg = "";
  for (let i = 0; i <= 4; i++) {
    const value = (top / 4) * i;
    const line = y(value);
    svg += `<line x1="${PAD.left}" y1="${line}" x2="${PAD.left + plotWidth}" y2="${line}"`
      + ` stroke="${grid}" stroke-width="1"/>`;
    svg += text(PAD.left - 10, line + 4, bytes(Math.round(value)), soft, "end");
  }

  if (points.length > 1) {
    values.forEach((series, index) => {
      const path = series.map((v, i) => `${x(i)},${y(v)}`).join(" ");
      svg += `<polyline points="${path}" fill="none" stroke="${colours[index]}"`
        + ` stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      const last = series[series.length - 1];
      svg += `<circle cx="${x(series.length - 1)}" cy="${y(last)}" r="3.5" fill="${colours[index]}"/>`;
      svg += text(PAD.left + plotWidth + 10, y(last) + 4, bytes(last), colours[index], "start", 600);
    });
  }

  if (hover >= 0 && hover < points.length) {
    const line = x(hover);
    svg += `<line x1="${line}" y1="${PAD.top}" x2="${line}" y2="${PAD.top + plotHeight}"`
      + ` stroke="${soft}" stroke-width="1" stroke-dasharray="3 3"/>`;
    values.forEach((series, index) => {
      svg += `<circle cx="${line}" cy="${y(series[hover])}" r="4" fill="${colours[index]}"`
        + ` stroke="${style.getPropertyValue("--raised").trim()}" stroke-width="2"/>`;
    });
  }

  const seconds = number(points.length * 0.12, 0);
  svg += text(PAD.left, height - 6, `últimos ${seconds} s`, soft, "start");
  svg += text(PAD.left + plotWidth, height - 6, "ahora", ink, "end");
  PLOT.innerHTML = svg;
}

function ratioText(exact, sketch) {
  if (exact === 0 || sketch === 0) {
    return "aún sin datos en esta ventana";
  }
  const ratio = sketch / exact;
  return ratio < 1
    ? `ahora ocupa el ${number(ratio * 100, 0)} % del exacto`
    : `ahora ocupa ${number(ratio, 1)} veces el exacto`;
}

function paintCard(id, detection) {
  const card = document.getElementById(id);
  card.querySelector('[data-field="exact"]').textContent = bytes(detection.exactBytes);
  card.querySelector('[data-field="sketch"]').textContent = bytes(detection.sketchBytes);
  card.querySelector('[data-field="verdict"]').textContent =
    ratioText(detection.exactBytes, detection.sketchBytes);
}

function paintRanking(list, node, colour, best) {
  node.innerHTML = list.map(entry => {
    const share = best > 0 ? (entry.count / best) * 100 : 0;
    return `<li><span class="who"><i style="width:${share}%;background:${colour}"></i>`
      + `<span>${entry.source}</span></span><span class="hits">${number(entry.count, 0)}</span></li>`;
  }).join("");
}

function paintAgreement(id, detection) {
  const cells = document.getElementById(id).querySelectorAll("td");
  cells[0].textContent = number(detection.matched, 0);
  cells[1].textContent = number(detection.extra, 0);
  cells[2].textContent = number(detection.missed, 0);
}

function paintFeed(feed) {
  const node = document.getElementById("feed");
  if (feed.length === 0) {
    node.innerHTML = '<li class="empty">todavía no hay alertas en esta ventana</li>';
    return;
  }
  const scroll = node.scrollTop;
  node.innerHTML = feed.map(row => {
    const kind = row.type === "BRUTE_FORCE" ? "fuerza bruta" : "enumeración";
    const diverges = row.seen !== "ambos" ? " class=\"diverges\"" : "";
    return `<li${diverges}><span class="ip">${row.source}</span>`
      + `<span class="kind">${kind}</span><span class="seen">${row.seen}</span></li>`;
  }).join("");
  node.scrollTop = scroll;
}

function paint(state) {
  latest = state;

  document.getElementById("origin").textContent =
    `${state.origin} · reproducido a x${state.timeScale} sobre el reloj de los eventos`;
  document.getElementById("events").textContent = number(state.events, 0);
  document.getElementById("rate").textContent = number(state.eventsPerSecond, 0);
  document.getElementById("windows").textContent = number(state.windows, 0);

  const status = document.getElementById("state");
  status.textContent = state.running ? "en marcha" : "en pausa";
  status.className = state.running ? "state" : "state paused";
  document.getElementById("toggle").textContent = state.running ? "Pausar" : "Reanudar";

  paintCard("card-brute", state.bruteForce);
  paintCard("card-enum", state.enumeration);
  paintCard("card-rank", {
    exactBytes: state.ranking.exactBytes,
    sketchBytes: state.ranking.sketchBytes
  });

  const style = getComputedStyle(document.body);
  const ranking = state.ranking;
  const best = Math.max(
    ranking.exact.length ? ranking.exact[0].count : 0,
    ranking.sketch.length ? ranking.sketch[0].count : 0);
  paintRanking(ranking.exact, document.getElementById("top-exact"),
    style.getPropertyValue("--exact").trim(), best);
  paintRanking(ranking.sketch, document.getElementById("top-sketch"),
    style.getPropertyValue("--sketch").trim(), best);
  document.getElementById("keys-exact").textContent = `${number(ranking.exactKeys, 0)} claves`;
  document.getElementById("keys-sketch").textContent = `${number(ranking.sketchKeys, 0)} contadores`;

  // Se comparan por pertenencia y no por posicion: cuando dos IPs empatan, cada
  // estructura deshace el empate a su manera y el orden no significa nada.
  const sketchSources = new Set(ranking.sketch.map(entry => entry.source));
  const shared = ranking.exact.filter(entry => sketchSources.has(entry.source)).length;
  document.getElementById("ranking-note").textContent =
    `las mismas ${shared} de ${ranking.exact.length} direcciones`;

  paintFeed(state.feed);

  document.getElementById("ag-windows").textContent = number(state.windows, 0);
  paintAgreement("ag-brute", state.bruteForce);
  paintAgreement("ag-enum", state.enumeration);

  draw();
}

async function poll() {
  if (polling) {
    return;
  }
  polling = true;
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    paint(await response.json());
  } catch (error) {
    const status = document.getElementById("state");
    status.textContent = "sin conexión";
    status.className = "state lost";
  } finally {
    polling = false;
  }
}

async function control(body) {
  try {
    const response = await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    paint(await response.json());
  } catch (error) {
    // El siguiente sondeo ya reflejara el estado real.
  }
}

document.querySelectorAll(".tabs button").forEach(button => {
  button.addEventListener("click", () => {
    tab = button.dataset.tab;
    document.querySelectorAll(".tabs button").forEach(other =>
      other.setAttribute("aria-selected", String(other === button)));
    draw();
  });
});

document.querySelectorAll(".speed button").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".speed button").forEach(other =>
      other.classList.toggle("on", other === button));
    control({ timeScale: Number(button.dataset.scale) });
  });
});

document.getElementById("toggle").addEventListener("click", () =>
  control({ running: !(latest && latest.running) }));
document.getElementById("restart").addEventListener("click", () =>
  control({ restart: true }));

PLOT.addEventListener("mousemove", event => {
  if (!latest || latest.history.length < 2) {
    return;
  }
  const box = PLOT.getBoundingClientRect();
  const width = (PLOT.clientWidth || 880) - PAD.left - PAD.right;
  const offset = event.clientX - box.left - PAD.left;
  const index = Math.round((offset / width) * (latest.history.length - 1));
  hover = Math.max(0, Math.min(latest.history.length - 1, index));
  const point = latest.history[hover];
  const [exactKey, sketchKey, name] = SERIES[tab];
  document.getElementById("hover").textContent =
    `${name}: exacto ${bytes(point[exactKey])} · probabilístico ${bytes(point[sketchKey])}`;
  draw();
});

PLOT.addEventListener("mouseleave", () => {
  hover = -1;
  document.getElementById("hover").textContent = HINT;
  draw();
});

window.addEventListener("resize", draw);

poll();
setInterval(poll, 500);

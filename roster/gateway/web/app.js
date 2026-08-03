const $ = (id) => document.getElementById(id);
const query = new URLSearchParams(window.location.search);
const state = {
  cards: [],
  selected: "",
  auditorListingRef: query.get("auditorListingRef") || query.get("listing") || "",
};

function pretty(value) { return JSON.stringify(value, null, 2); }
function selectedCard() { return state.cards.find((card) => card.name === state.selected) ?? state.cards[0]; }

function choose(name, load = true) {
  state.selected = name;
  document.querySelectorAll(".agent").forEach((el) => el.classList.toggle("active", el.dataset.name === name));
  if (load) loadExample();
}

function loadExample() {
  const card = selectedCard();
  if (!card) return;
  $("goal").value = card.exampleGoal;
  $("input").value = pretty(card.exampleInput);
}

function renderAgents(cards) {
  $("agents").innerHTML = cards.map((card, index) => `
    <button class="agent" data-name="${card.name}" role="option" aria-selected="false">
      <span class="agent-index">${String(index).padStart(2, "0")}</span>
      <span><strong>${card.label}</strong><small>${card.summary}</small></span>
    </button>`).join("");
  document.querySelectorAll(".agent").forEach((button) => button.addEventListener("click", () => choose(button.dataset.name)));
}

async function boot() {
  try {
    const [health, catalog] = await Promise.all([fetch("/health").then((r) => r.json()), fetch("/demo/butler/agents").then((r) => r.json())]);
    state.cards = catalog.agents;
    renderAgents(state.cards);
    $("agent-count").textContent = `${health.agentCount} online`;
    $("status-text").textContent = "Agent network online";
    document.body.classList.add("ready");
    choose(state.cards[0]?.name ?? "");
  } catch {
    $("status-text").textContent = "Agent network unavailable";
    document.querySelector(".status-dot").classList.add("bad");
  }
}

async function run() {
  const button = $("run");
  let input;
  try { input = JSON.parse($("input").value); }
  catch { return showError("Structured input is not valid JSON."); }
  button.disabled = true;
  button.querySelector("span").textContent = "Butler is working…";
  const started = performance.now();
  try {
    if (state.selected === "procurement-butler") {
      await runProcurement(input, started);
      return;
    }
    const response = await fetch("/demo/butler", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ goal: $("goal").value, agent: state.selected, input }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body?.error?.message ?? `Request failed (${response.status})`);
    $("result-panel").hidden = false;
    $("selection").innerHTML = `<strong>${body.butler.label}</strong><span>${body.butler.rationale}</span>`;
    $("run-meta").textContent = `${Math.round(performance.now() - started)} ms · ${body.butler.mode}`;
    $("result").textContent = pretty(body.result);
    $("result-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) { showError(error.message); }
  finally { button.disabled = false; button.querySelector("span").textContent = "Run with Butler"; }
}

async function runProcurement(input, started) {
  const payload = {
    ...input,
    goal: typeof input.goal === "string" && input.goal.trim() ? input.goal : $("goal").value,
    ...(state.auditorListingRef ? { auditorListingRef: state.auditorListingRef } : {}),
  };
  const response = await fetch("/demo/procurement", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  let job = await response.json();
  if (!response.ok) throw new Error(job?.error?.message ?? `Procurement failed to start (${response.status})`);

  $("result-panel").hidden = false;
  $("selection").innerHTML = "<strong>Procurement Butler</strong><span>Supervising the selected Auditor through the complete DACS lifecycle.</span>";
  for (;;) {
    $("run-meta").textContent = `${job.phase} · ${Math.round(performance.now() - started)} ms`;
    $("result").textContent = pretty({ status: job.status, phase: job.phase, events: job.events, result: job.result, error: job.error });
    if (job.status !== "running") break;
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const poll = await fetch(`/demo/procurement/${encodeURIComponent(job.id)}`);
    job = await poll.json();
    if (!poll.ok) throw new Error(job?.error?.message ?? `Procurement status failed (${poll.status})`);
  }
  if (job.status !== "complete") throw new Error(job.error || "Procurement stopped before completion");
  $("result-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showError(message) {
  $("result-panel").hidden = false;
  $("selection").innerHTML = `<strong>Run stopped</strong><span>${message}</span>`;
  $("run-meta").textContent = "validation / network error";
  $("result").textContent = "";
}

$("example").addEventListener("click", loadExample);
$("run").addEventListener("click", run);
boot();

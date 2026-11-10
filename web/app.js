// Hexbane web app. Scan page (load gate): check skills, MCP configs and tools before loading them.
// Chat gate pages (from ScopeGuard): try the mission guard as different users, watch the dashboard, edit the
// policy, measure accuracy, copy integration snippets. Local-first: nothing leaves the browser.
(function () {
  "use strict";

  const { Engine, LABELS } = window.ScopeGuardEngine;
  const Store = window.ScopeGuardStore;

  const TEMPLATE_IDS = ["cad-copilot", "bank-support", "store-support"];
  // Measured, held-out test sets that ship with a template (others: bring your own on the Accuracy page).
  const EVAL_FILES = { "cad-copilot": "policies/cad-copilot.eval.json" };
  const ACTIONS = ["ALLOW", "ADJACENT", "REDIRECT", "THROTTLE", "BLOCK"];
  const STOPPED = new Set(["REDIRECT", "THROTTLE", "BLOCK"]);
  const LABEL_NAMES = { in_scope: "In scope", adjacent: "Adjacent", out_of_scope: "Off-topic" };
  const ACTION_HELP = {
    ALLOW: "On-mission: forwarded to your AI as-is.",
    ADJACENT: "Related: your AI answers briefly, then steers back to the mission.",
    REDIRECT: "Off-mission: polite redirect, your AI is never called.",
    THROTTLE: "Off-topic allowance used up for today.",
    BLOCK: "Jailbreak / prompt-injection attempt.",
  };
  const SOURCE_URL = "https://github.com/juw12/hexbane";
  const SERVER_SOURCE_URL = "https://github.com/juw12/hexbane/tree/main/server";

  const state = {
    templates: {},
    evals: {},
    data: Store.loadData(),
    settings: Store.loadSettings(),
    engine: null,
    chats: {}, // policyId -> [{ role, text, user, decision }]
    selectedDecision: null,
    chatUser: "you",
    accuracyResult: null,
  };

  // ---------- DOM helpers (all user text goes through textContent) ----------

  function h(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) {
        continue;
      }
      if (key === "text") {
        node.textContent = value;
      } else if (key === "class") {
        node.className = value;
      } else if (key === "style") {
        node.setAttribute("style", value);
      } else if (key.startsWith("on")) {
        node.addEventListener(key.slice(2), value);
      } else if (key === "value") {
        node.value = value;
      } else {
        node.setAttribute(key, value === true ? "" : value);
      }
    }
    for (const child of [].concat(children)) {
      if (child !== null && child !== undefined && child !== false) {
        node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
      }
    }
    return node;
  }

  function pill(action) {
    return h("span", { class: `pill ${action}`, text: action, title: ACTION_HELP[action] || "" });
  }

  function card(title, className, children) {
    return h("section", { class: `card ${className}` }, [title ? h("h2", { text: title }) : null, ...children]);
  }

  let toastTimer = null;
  function toast(message) {
    const box = document.getElementById("toast");
    box.textContent = message;
    box.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      box.hidden = true;
    }, 2600);
  }

  function download(filename, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = h("a", { href: url, download: filename });
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function money(value) {
    return "$" + (value < 1 ? value.toFixed(3) : value.toFixed(2));
  }

  function percent(value) {
    return Math.round(value * 100) + "%";
  }

  // ---------- policies & engine ----------

  function allPolicyIds() {
    return [...TEMPLATE_IDS.filter((id) => state.templates[id]), ...Object.keys(state.data.customPolicies)];
  }

  function policyById(id) {
    return state.data.policyOverrides[id] || state.data.customPolicies[id] || state.templates[id] || null;
  }

  function activeId() {
    if (!policyById(state.data.activePolicyId)) {
      state.data.activePolicyId = TEMPLATE_IDS[0];
    }
    return state.data.activePolicyId;
  }

  function activePolicy() {
    return policyById(activeId());
  }

  function learnedFor(id) {
    if (!state.data.learned[id]) {
      state.data.learned[id] = [];
    }
    return state.data.learned[id];
  }

  function sessionsFor(id) {
    if (!state.data.sessions[id]) {
      state.data.sessions[id] = {};
    }
    return state.data.sessions[id];
  }

  function buildEngine() {
    const id = activeId();
    state.engine = new Engine(activePolicy(), learnedFor(id), sessionsFor(id));
  }

  function save() {
    if (!Store.saveData(state.data)) {
      toast("Could not save - browser storage is full or disabled.");
    }
  }

  function guard(user, message) {
    const decision = state.engine.check(user, message);
    const event = {
      id: state.data.nextEventId++,
      ts: Date.now(),
      policyId: activeId(),
      user,
      message: message.slice(0, 2000),
      action: decision.action,
      label: decision.label,
      uncertain: decision.uncertain,
      reason: decision.reason,
      scores: decision.scores,
      costSaved: decision.estCostSavedUsd,
      reviewed: null,
    };
    state.data.events.push(event);
    save();
    return { decision, event };
  }

  function eventsForActive() {
    const id = activeId();
    return state.data.events.filter((event) => event.policyId === id);
  }

  // ---------- header ----------

  function renderHeader() {
    const select = document.getElementById("policy-select");
    select.replaceChildren(
      ...allPolicyIds().map((id) => {
        const policy = policyById(id);
        const edited = state.data.policyOverrides[id] ? " (edited)" : "";
        return h("option", { value: id, text: policy.name + edited });
      })
    );
    select.value = activeId();
    document.getElementById("theme-select").value = state.settings.theme;
    const route = currentRoute();
    const missionBar = document.getElementById("mission-bar");
    missionBar.textContent = route === "scan"
      ? "Load gate: files are scanned in this browser and never uploaded."
      : "Chat gate guarding: " + activePolicy().name + " — mission: " + activePolicy().mission;
    document.getElementById("policy-select").closest("label").hidden = route === "scan";
    for (const link of document.querySelectorAll(".tabs a")) {
      link.classList.toggle("active", link.dataset.route === route);
      if (link.dataset.route === route) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    }
  }

  function applyTheme() {
    let theme = state.settings.theme;
    if (theme === "system") {
      theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute("content", theme === "light" ? "#f4f6fb" : "#0f1420");
    }
  }

  // ---------- Try it ----------

  function chatFor(id) {
    if (!state.chats[id]) {
      state.chats[id] = [];
    }
    return state.chats[id];
  }

  function botText(decision) {
    if (decision.action === "ALLOW") {
      return "✓ Allowed — forwarded to your AI unchanged.";
    }
    if (decision.action === "ADJACENT") {
      return "↪ Allowed with steering — your AI gets this instruction: “" + decision.reply + "”";
    }
    return decision.reply;
  }

  function sendMessage(text) {
    const message = text.trim();
    if (!message) {
      return;
    }
    const user = (state.chatUser || "you").trim().slice(0, 80) || "you";
    const { decision } = guard(user, message);
    const chat = chatFor(activeId());
    chat.push({ role: "user", text: message, user, fresh: true });
    chat.push({ role: "bot", decision, fresh: true });
    state.selectedDecision = decision;
    renderView();
    const input = document.getElementById("chat-input");
    if (input) {
      input.focus();
    }
  }

  function simulateDemo() {
    const policy = activePolicy();
    const demo = policy.demo || {};
    const sessions = sessionsFor(activeId());
    let count = 0;
    for (const [user, messages] of Object.entries(demo)) {
      delete sessions[user]; // replay each demo user from a fresh session
      for (const message of messages) {
        guard(user, message);
        count += 1;
      }
    }
    toast(count ? `Simulated ${count} messages from ${Object.keys(demo).length} users` : "This policy has no demo traffic");
    location.hash = "#/dashboard";
  }

  function scoreBars(scores) {
    const colours = { in_scope: "var(--allow)", adjacent: "var(--adjacent)", out_of_scope: "var(--redirect)" };
    const max = Math.max(0.3, ...LABELS.map((label) => scores[label] || 0));
    return LABELS.map((label) =>
      h("div", { class: "score-row" }, [
        h("span", { text: LABEL_NAMES[label] }),
        h("div", { class: "bar" }, [
          h("span", { style: `width:${(100 * (scores[label] || 0)) / max}%;background:${colours[label]}` }),
        ]),
        h("span", { class: "muted", text: (scores[label] || 0).toFixed(3) }),
      ])
    );
  }

  function explainPanel() {
    const decision = state.selectedDecision;
    if (!decision) {
      return card("Why this decision", "span5", [
        h("p", { class: "explain-empty", text: "Send a message (or tap a sample) to see how the chat gate decides and why." }),
        h("h3", { text: "The five outcomes" }),
        h("div", { class: "stack" }, ACTIONS.map((action) => h("div", { class: "row" }, [pill(action), h("span", { class: "muted", text: ACTION_HELP[action] })]))),
      ]);
    }
    const hasScores = decision.scores && Object.keys(decision.scores).length;
    return card("Why this decision", "span5", [
      h("div", { class: "row" }, [pill(decision.action), h("strong", { text: ACTION_HELP[decision.action] })]),
      hasScores ? h("h3", { text: "Similarity to policy examples" }) : null,
      ...(hasScores ? scoreBars(decision.scores) : []),
      h("dl", { class: "facts" }, [
        h("dt", { text: "Label" }),
        h("dd", { text: decision.label === "abuse" ? "Abuse" : LABEL_NAMES[decision.label] + (decision.uncertain ? " (low confidence — flagged for review)" : "") }),
        h("dt", { text: "Reason" }),
        h("dd", { text: decision.reason }),
        decision.nearestExample ? h("dt", { text: "Closest example" }) : null,
        decision.nearestExample ? h("dd", { text: "“" + decision.nearestExample + "”" }) : null,
        h("dt", { text: "LLM cost avoided" }),
        h("dd", { text: decision.estCostSavedUsd ? "≈ " + money(decision.estCostSavedUsd) + " (estimate)" : "none — request was served" }),
      ]),
    ]);
  }

  function renderTry() {
    const policy = activePolicy();
    const chat = chatFor(activeId());
    const log = h("div", { class: "chat-log", id: "chat-log", "aria-live": "polite" });
    if (!chat.length) {
      log.appendChild(
        h("div", { class: "chat-empty" }, [
          h("p", { text: `You are chatting with “${policy.name}”. Hexbane's chat gate sits in front of it.` }),
          h("p", { text: "Ask something on-mission, something unrelated, or try to jailbreak it." }),
        ])
      );
    }
    for (const entry of chat) {
      if (entry.role === "user") {
        log.appendChild(h("div", { class: "bubble user" + (entry.fresh ? " fresh" : "") }, [h("div", { class: "who", text: entry.user }), entry.text]));
      } else {
        const decision = entry.decision;
        const bubble = h(
          "div",
          {
            class: "bubble bot selectable" + (entry.fresh ? " fresh" : "") + (decision === state.selectedDecision ? " selected" : ""),
            tabindex: "0",
            title: "Show why",
            onclick: () => {
              state.selectedDecision = decision;
              renderView();
            },
          },
          [
            h("div", { class: "who" }, [pill(decision.action), " Hexbane"]),
            botText(decision),
            STOPPED.has(decision.action) ? h("div", { class: "meta", text: "Your AI was not called." }) : null,
          ]
        );
        log.appendChild(bubble);
      }
    }

    const input = h("input", {
      type: "text",
      id: "chat-input",
      placeholder: "Type a message to the assistant…",
      maxlength: "2000",
      "aria-label": "Message",
      onkeydown: (event) => {
        if (event.key === "Enter") {
          sendMessage(event.target.value);
        }
      },
    });
    const userInput = h("input", {
      type: "text",
      id: "chat-user",
      value: state.chatUser,
      maxlength: "80",
      "aria-label": "Chatting as user",
      style: "width:140px",
      oninput: (event) => {
        state.chatUser = event.target.value;
      },
    });

    const chips = (policy.samples || []).map((sample) =>
      h("button", { class: "chip small", type: "button", text: sample, onclick: () => sendMessage(sample) })
    );

    const chatCard = card("Try it — chat as a user", "span7", [
      h("div", { class: "row", style: "margin-bottom:10px" }, [
        h("span", { class: "muted", text: "Chatting as" }),
        userInput,
        h("button", { type: "button", text: "Simulate demo traffic", onclick: simulateDemo, title: "Replay sample users (real, free-ChatGPT, jailbreaker…) and open the dashboard" }),
        h("button", {
          type: "button",
          class: "danger",
          text: "Clear chat",
          onclick: () => {
            state.chats[activeId()] = [];
            state.selectedDecision = null;
            renderView();
          },
        }),
      ]),
      log,
      h("div", { class: "composer" }, [
        input,
        h("button", { class: "primary", type: "button", text: "Send", id: "send-button", onclick: () => sendMessage(input.value) }),
      ]),
      chips.length ? h("div", { class: "chips", "aria-label": "Sample messages" }, chips) : null,
    ]);

    const view = document.getElementById("view");
    view.replaceChildren(chatCard, explainPanel());
    log.scrollTop = log.scrollHeight;
    for (const entry of chat) {
      entry.fresh = false; // only newly sent messages animate; re-renders stay still
    }
  }

  // ---------- Dashboard ----------

  function computeStats(events) {
    const counts = Object.fromEntries(ACTIONS.map((action) => [action, 0]));
    let saved = 0;
    for (const event of events) {
      counts[event.action] = (counts[event.action] || 0) + 1;
      saved += event.costSaved || 0;
    }
    const total = events.length;
    const stopped = ACTIONS.filter((action) => STOPPED.has(action)).reduce((sum, action) => sum + counts[action], 0);
    const offMessages = events.filter((event) => event.action === "REDIRECT" || event.action === "THROTTLE").slice(-500).reverse().map((event) => event.message);
    const flagged = new Map();
    for (const event of events) {
      if (event.action === "BLOCK" || event.action === "THROTTLE") {
        const entry = flagged.get(event.user) || { user: event.user, count: 0, actions: new Set() };
        entry.count += 1;
        entry.actions.add(event.action);
        flagged.set(event.user, entry);
      }
    }
    const reviewed = events.filter((event) => event.reviewed);
    return {
      total,
      counts,
      saved,
      stoppedShare: total ? stopped / total : 0,
      clusters: state.engine.cluster(offMessages),
      flagged: Array.from(flagged.values()).sort((a, b) => b.count - a.count).slice(0, 20),
      queue: events.filter((event) => !event.reviewed && (event.uncertain || event.action === "REDIRECT" || event.action === "THROTTLE")).slice(-25).reverse(),
      recent: events.slice(-30).reverse(),
      agreed: reviewed.filter((event) => event.reviewed === event.label).length,
      corrected: reviewed.filter((event) => event.reviewed !== event.label).length,
    };
  }

  function teach(event, label) {
    event.reviewed = label;
    learnedFor(event.policyId).push([label, event.message]);
    save();
    buildEngine();
    toast(`Learned: “${event.message.slice(0, 40)}” is ${LABEL_NAMES[label].toLowerCase()}`);
    renderView();
  }

  function csvCell(value) {
    let text = String(value ?? "");
    if (/^[=+\-@\t\r]/.test(text)) {
      text = "'" + text; // keep spreadsheet apps from executing formulas in user text
    }
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function exportCsv() {
    const header = ["id", "time", "policy", "user", "message", "action", "label", "uncertain", "reason", "cost_saved_usd", "reviewed_label"];
    const rows = eventsForActive().map((event) => [
      event.id, new Date(event.ts).toISOString(), event.policyId, event.user, event.message, event.action,
      event.label, event.uncertain, event.reason, event.costSaved, event.reviewed || "",
    ]);
    download(`hexbane-log-${activeId()}.csv`, [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n"), "text/csv");
  }

  function renderDashboard() {
    const events = eventsForActive();
    const stats = computeStats(events);
    const kpi = (title, value, sub, id) =>
      h("section", { class: "card kpi" }, [h("h2", { text: title }), h("div", { class: "value", text: value, id }), h("div", { class: "sub", text: sub })]);

    const decisions = card("Decisions", "span4", ACTIONS.map((action) => {
      const count = stats.counts[action];
      const width = stats.total ? (100 * count) / stats.total : 0;
      return h("div", { class: "bar-row" }, [
        pill(action),
        h("div", { class: "bar" }, [h("span", { style: `width:${width.toFixed(1)}%;background:var(--${action.toLowerCase()})` })]),
        h("span", { class: "muted", text: String(count) }),
      ]);
    }));

    const clusters = card("Unmet demand — what users want instead", "span4", stats.clusters.length
      ? stats.clusters.map((cluster) => h("div", { class: "cluster" }, [
          h("div", { class: "theme", text: `${cluster.theme || "(misc)"} — ${cluster.count}×` }),
          h("div", { class: "muted", text: "“" + cluster.example + "”" }),
        ]))
      : [h("p", { class: "muted", text: "No off-mission requests yet." })]);

    const flagged = card("Flagged users", "span4", stats.flagged.length
      ? [h("table", {}, [
          h("thead", {}, [h("tr", {}, [h("th", { text: "User" }), h("th", { text: "Actions" }), h("th", { text: "Count" })])]),
          h("tbody", {}, stats.flagged.map((entry) => h("tr", {}, [
            h("td", { text: entry.user }), h("td", { text: Array.from(entry.actions).join(", ") }), h("td", { text: String(entry.count) }),
          ]))),
        ])]
      : [h("p", { class: "muted", text: "Nobody flagged." })]);

    const queueRows = stats.queue.map((event) => h("tr", {}, [
      h("td", { text: event.user }),
      h("td", { class: "msg", text: event.message }),
      h("td", {}, [pill(event.action)]),
      h("td", { class: "muted", text: event.reason }),
      h("td", {}, [h("div", { class: "row" }, LABELS.map((label) =>
        h("button", { class: "small", type: "button", text: LABEL_NAMES[label], onclick: () => teach(event, label), "data-label": label })
      ))]),
    ]));
    const queue = card("Review queue — correct the classifier (it learns instantly)", "span12", [
      h("div", { class: "table-wrap" }, [h("table", { id: "review-table" }, [
        h("thead", {}, [h("tr", {}, ["User", "Message", "Decision", "Reason", "Correct label"].map((name) => h("th", { text: name })))]),
        h("tbody", {}, queueRows.length ? queueRows : [h("tr", {}, [h("td", { colspan: "5", class: "muted", text: "Queue empty." })])]),
      ])]),
    ]);

    const recent = card("Recent activity", "span12", [
      h("div", { class: "row", style: "margin-bottom:8px" }, [
        h("button", { type: "button", text: "Export CSV", onclick: exportCsv, disabled: !events.length }),
        h("button", {
          type: "button",
          text: "Export JSON",
          disabled: !events.length,
          onclick: () => download(`hexbane-log-${activeId()}.json`, JSON.stringify(events, null, 2), "application/json"),
        }),
        h("button", {
          type: "button",
          class: "danger",
          text: "Clear log for this policy",
          disabled: !events.length,
          onclick: () => {
            if (confirm("Delete all logged messages for this policy?")) {
              const id = activeId();
              state.data.events = state.data.events.filter((event) => event.policyId !== id);
              state.data.sessions[id] = {};
              save();
              buildEngine();
              renderView();
            }
          },
        }),
      ]),
      h("div", { class: "table-wrap" }, [h("table", { id: "recent-table" }, [
        h("thead", {}, [h("tr", {}, ["Time", "User", "Message", "Decision", "Reason"].map((name) => h("th", { text: name })))]),
        h("tbody", {}, stats.recent.length
          ? stats.recent.map((event) => h("tr", {}, [
              h("td", { class: "muted", text: new Date(event.ts).toLocaleTimeString() }),
              h("td", { text: event.user }),
              h("td", { class: "msg", text: event.message }),
              h("td", {}, [pill(event.action)]),
              h("td", { class: "muted", text: event.reason }),
            ]))
          : [h("tr", {}, [h("td", { colspan: "5", class: "muted" }, [
              "No activity yet. ",
              h("a", { href: "#/try", text: "Try it" }),
              " or ",
              h("button", { class: "small", type: "button", text: "simulate demo traffic", onclick: simulateDemo }),
            ])])]),
      ])]),
    ]);

    document.getElementById("view").replaceChildren(
      kpi("Messages checked", stats.total.toLocaleString(), "for this policy", "kpi-total"),
      kpi("Off-mission", percent(stats.stoppedShare), "redirected, throttled or blocked", "kpi-off"),
      kpi("Est. LLM cost avoided", money(stats.saved), "replies your AI didn't have to generate", "kpi-saved"),
      kpi("Classifier learning", String(learnedFor(activeId()).length), `${stats.agreed} agreed · ${stats.corrected} corrected`, "kpi-learned"),
      decisions,
      clusters,
      flagged,
      queue,
      recent
    );
  }

  // ---------- Policy ----------

  function lines(text) {
    return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function words(text) {
    return text.split(/[,\n]/).map((word) => word.trim()).filter(Boolean);
  }

  function readPolicyForm(base) {
    const value = (id) => document.getElementById(id).value;
    const number = (id, fallback) => {
      const parsed = Number(value(id));
      return Number.isFinite(parsed) ? parsed : fallback;
    };
    return {
      ...base,
      name: value("pf-name").trim() || base.name,
      mission: value("pf-mission").trim() || base.mission,
      redirect_message: value("pf-redirect").trim(),
      throttle_message: value("pf-throttle").trim(),
      adjacent_hint: value("pf-hint").trim(),
      core_keywords: words(value("pf-core-kw")),
      adjacent_keywords: words(value("pf-adj-kw")),
      out_of_scope_keywords: words(value("pf-out-kw")),
      examples: {
        in_scope: lines(value("pf-ex-in_scope")),
        adjacent: lines(value("pf-ex-adjacent")),
        out_of_scope: lines(value("pf-ex-out_of_scope")),
      },
      budgets: {
        ...(base.budgets || {}),
        off_topic_allowance: Math.max(0, Math.round(number("pf-allowance", 3))),
      },
      pricing: {
        ...(base.pricing || {}),
        usd_per_1k_tokens: Math.max(0, number("pf-price", 0.01)),
        avg_reply_tokens: Math.max(0, Math.round(number("pf-reply-tokens", 400))),
      },
    };
  }

  function savePolicy() {
    const id = activeId();
    const updated = readPolicyForm(activePolicy());
    try {
      new Engine(updated); // validates and fits; throws on a broken policy
    } catch (error) {
      toast(error.message);
      return;
    }
    if (state.data.customPolicies[id]) {
      state.data.customPolicies[id] = updated;
    } else {
      state.data.policyOverrides[id] = updated;
    }
    save();
    buildEngine();
    renderHeader();
    renderView();
    toast("Policy saved — the guard now uses it.");
  }

  function importPolicy(file) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const policy = JSON.parse(reader.result);
        new Engine(policy);
        let id = String(policy.id || policy.name || "custom").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "custom";
        if (TEMPLATE_IDS.includes(id)) {
          id += "-imported";
        }
        policy.id = id;
        state.data.customPolicies[id] = policy;
        state.data.activePolicyId = id;
        save();
        buildEngine();
        renderHeader();
        renderView();
        toast(`Imported “${policy.name}”`);
      } catch (error) {
        toast("Import failed: " + error.message);
      }
    };
    reader.readAsText(file);
  }

  function exportablePolicy() {
    const policy = JSON.parse(JSON.stringify(activePolicy()));
    const learned = learnedFor(activeId());
    for (const [label, text] of learned) {
      if (!policy.examples[label].includes(text)) {
        policy.examples[label].push(text); // bake reviewed examples into the export
      }
    }
    return policy;
  }

  function renderPolicy() {
    const policy = activePolicy();
    const id = activeId();
    const field = (label, control) => h("label", { class: "field" }, [h("span", { text: label }), control]);
    const input = (id_, value, extra = {}) => h("input", { type: "text", id: id_, value: value ?? "", ...extra });
    const area = (id_, value, extra = {}) => h("textarea", { id: id_, ...extra }, [value ?? ""]);

    const templates = card("Choose an assistant to guard", "span12", [
      h("div", { class: "template-grid" }, allPolicyIds().map((policyId) => {
        const item = policyById(policyId);
        return h("button", {
          type: "button",
          class: "template" + (policyId === id ? " active" : ""),
          onclick: () => selectPolicy(policyId),
        }, [
          h("span", { class: "name", text: item.name }),
          h("span", { class: "desc", text: item.mission }),
        ]);
      })),
      h("div", { class: "row", style: "margin-top:12px" }, [
        h("button", { type: "button", text: "Export policy JSON", onclick: () => download(`${id}.json`, JSON.stringify(exportablePolicy(), null, 2), "application/json"), title: "Includes reviewed examples. Works with the self-hosted server." }),
        h("label", { class: "row" }, [
          h("button", { type: "button", text: "Import policy JSON", onclick: () => document.getElementById("import-file").click() }),
          h("input", { type: "file", id: "import-file", accept: "application/json,.json", hidden: true, onchange: (event) => event.target.files[0] && importPolicy(event.target.files[0]) }),
        ]),
        state.data.policyOverrides[id]
          ? h("button", {
              type: "button",
              class: "danger",
              text: "Reset to built-in template",
              onclick: () => {
                delete state.data.policyOverrides[id];
                save();
                buildEngine();
                renderHeader();
                renderView();
                toast("Template restored.");
              },
            })
          : null,
      ]),
    ]);

    const basics = card("Mission & replies", "span12", [
      h("div", { class: "form-grid" }, [
        field("Assistant name", input("pf-name", policy.name)),
        field("Mission (what the assistant is for)", input("pf-mission", policy.mission)),
        field("Off-topic daily allowance per user", h("input", { type: "number", id: "pf-allowance", min: "0", max: "50", value: (policy.budgets || {}).off_topic_allowance ?? 3 })),
        field("LLM price, USD per 1k tokens", h("input", { type: "number", id: "pf-price", min: "0", step: "0.001", value: (policy.pricing || {}).usd_per_1k_tokens ?? 0.01 })),
        field("Average reply length, tokens", h("input", { type: "number", id: "pf-reply-tokens", min: "0", step: "10", value: (policy.pricing || {}).avg_reply_tokens ?? 400 })),
      ]),
      h("div", { class: "form-grid", style: "margin-top:12px" }, [
        field("Redirect reply (off-topic)", area("pf-redirect", policy.redirect_message, { rows: "3" })),
        field("Throttle reply (allowance used up)", area("pf-throttle", policy.throttle_message, { rows: "3" })),
        field("Steering instruction for related questions", area("pf-hint", policy.adjacent_hint, { rows: "3" })),
      ]),
    ]);

    const examples = card("Examples — one per line (the classifier learns from these)", "span12", [
      h("div", { class: "examples-grid" }, LABELS.map((label) =>
        field(`${LABEL_NAMES[label]} (${policy.examples[label].length})`, area(`pf-ex-${label}`, policy.examples[label].join("\n")))
      )),
      h("div", { class: "form-grid", style: "margin-top:12px" }, [
        field("Core keywords (comma separated)", area("pf-core-kw", (policy.core_keywords || []).join(", "), { rows: "3" })),
        field("Related keywords", area("pf-adj-kw", (policy.adjacent_keywords || []).join(", "), { rows: "3" })),
        field("Off-topic keywords", area("pf-out-kw", (policy.out_of_scope_keywords || []).join(", "), { rows: "3" })),
      ]),
      h("div", { class: "row", style: "margin-top:14px" }, [
        h("button", { class: "primary", type: "button", text: "Save policy", id: "save-policy", onclick: savePolicy }),
        h("span", { class: "muted", text: "Needs at least 3 examples per column. Changes apply immediately." }),
      ]),
    ]);

    const learned = learnedFor(id);
    const learnedCard = card(`Learned from your reviews (${learned.length})`, "span12", learned.length
      ? [h("div", { class: "learned-list" }, learned.map(([label, text], position) => h("div", { class: "learned-item" }, [
          h("span", {}, [h("strong", { text: LABEL_NAMES[label] + ": " }), text]),
          h("button", {
            class: "small danger",
            type: "button",
            text: "Remove",
            onclick: () => {
              learned.splice(position, 1);
              save();
              buildEngine();
              renderView();
            },
          }),
        ])))]
      : [h("p", { class: "muted", text: "Corrections from the dashboard's review queue appear here." })]);

    document.getElementById("view").replaceChildren(templates, basics, examples, learnedCard);
  }

  // ---------- Accuracy ----------

  function parseCases(text) {
    const aliases = { in: "in_scope", in_scope: "in_scope", adjacent: "adjacent", adj: "adjacent", related: "adjacent", off: "out_of_scope", out: "out_of_scope", out_of_scope: "out_of_scope" };
    const cases = [];
    for (const line of lines(text)) {
      const split = line.indexOf("|");
      if (split < 0) {
        continue;
      }
      const expected = line.slice(0, split).split(",").map((part) => aliases[part.trim().toLowerCase()]).filter(Boolean);
      const message = line.slice(split + 1).trim();
      if (expected.length && message) {
        cases.push({ text: message, expected });
      }
    }
    return cases;
  }

  // Same metrics as server/tests.py: strict label match, and served-vs-stopped (what users feel).
  function evaluate(cases, includeLearned) {
    const engine = new Engine(activePolicy(), includeLearned ? learnedFor(activeId()) : []);
    const onMission = new Set(["in_scope", "adjacent"]);
    let strict = 0;
    let binary = 0;
    let redirectedReal = 0;
    let servedOff = 0;
    let realCount = 0;
    let offCount = 0;
    const rows = [];
    for (const item of cases) {
      const result = engine.isAbuse(item.text) ? { label: "out_of_scope" } : engine.classify(item.text);
      const expected = new Set(item.expected);
      const exact = expected.has(result.label);
      const shouldServe = item.expected.some((label) => onMission.has(label));
      const served = onMission.has(result.label);
      strict += exact ? 1 : 0;
      binary += served === shouldServe || exact ? 1 : 0;
      if (shouldServe) {
        realCount += 1;
        redirectedReal += !served && !exact ? 1 : 0;
      } else {
        offCount += 1;
        servedOff += served && !exact ? 1 : 0;
      }
      rows.push({ ...item, got: result.label, exact, ok: served === shouldServe || exact });
    }
    const n = cases.length || 1;
    return { n: cases.length, strict: strict / n, binary: binary / n, redirectedReal, realCount, servedOff, offCount, rows };
  }

  function renderAccuracy() {
    const sets = (state.evals[activeId()] || {}).sets || [];
    const includeLearned = h("input", { type: "checkbox", id: "acc-learned" });
    const run = (title, cases) => {
      state.accuracyResult = { title, ...evaluate(cases, includeLearned.checked) };
      renderView();
    };

    const builtIn = card("Measured test sets", "span6", sets.length
      ? [
          h("p", { class: "muted", text: "Held-out messages that are not in the policy examples. The tuning set was used while designing the classifier, so its score is optimistic — the final set was never tuned against." }),
          h("div", { class: "stack" }, sets.map((set) =>
            h("button", { type: "button", text: `Run: ${set.title} (${set.cases.length})`, "data-set": set.id, onclick: () => run(set.title, set.cases) })
          )),
        ]
      : [h("p", { class: "muted", text: "No built-in test set for this policy yet. Paste your own cases on the right — that's the honest way to know how well it works for your business." })]);

    const custom = h("textarea", {
      id: "custom-cases",
      rows: "9",
      placeholder: "in | how do I reset my password\nadjacent | how does compound interest work\noff | write my history essay\nin,adjacent | an ambiguous one where either is fine",
    });
    const own = card("Your own test cases", "span6", [
      h("p", { class: "muted", text: "One per line: expected label | message. Labels: in, adjacent, off." }),
      custom,
      h("div", { class: "row", style: "margin-top:10px" }, [
        h("button", {
          class: "primary",
          type: "button",
          text: "Run my cases",
          onclick: () => {
            const cases = parseCases(custom.value);
            if (!cases.length) {
              toast("No valid lines — use: label | message");
              return;
            }
            run("Your cases", cases);
          },
        }),
        h("label", { class: "row muted" }, [includeLearned, "include learned examples"]),
      ]),
    ]);

    const children = [builtIn, own];
    const result = state.accuracyResult;
    if (result) {
      const metric = (title, value, good) => h("div", { class: "metric" }, [h("div", { class: "muted", text: title }), h("div", { class: "value " + (good === undefined ? "" : good ? "ok" : "bad"), text: value })]);
      const misses = result.rows.filter((row) => !row.ok);
      children.push(card(`Result — ${result.title}`, "span12", [
        h("div", { class: "metric-grid", id: "accuracy-metrics" }, [
          metric("Messages", String(result.n)),
          metric("Served vs stopped correctly", percent(result.binary), result.binary >= 0.85),
          metric("Exact label match", percent(result.strict)),
          metric("Real users wrongly redirected", `${result.redirectedReal} / ${result.realCount}`, result.redirectedReal === 0),
          metric("Off-topic let through", `${result.servedOff} / ${result.offCount}`, result.servedOff === 0),
        ]),
        h("h3", { text: misses.length ? `Wrong serve/stop decisions (${misses.length})` : "No serve/stop mistakes" }),
        misses.length
          ? h("div", { class: "table-wrap" }, [h("table", {}, [
              h("thead", {}, [h("tr", {}, ["Message", "Expected", "Got"].map((name) => h("th", { text: name })))]),
              h("tbody", {}, misses.map((row) => h("tr", {}, [
                h("td", { class: "msg", text: row.text }),
                h("td", { text: row.expected.map((label) => LABEL_NAMES[label]).join(" or ") }),
                h("td", { text: LABEL_NAMES[row.got] }),
              ]))),
            ])])
          : null,
      ]));
    }
    document.getElementById("view").replaceChildren(...children);
  }

  // ---------- Integrate ----------

  function renderIntegrate() {
    const policy = activePolicy();
    const code = (text) => h("pre", {}, [h("code", { text })]);
    const content = card("Put Hexbane in front of your real agent", "span12 prose", [
      h("p", { text: "Hexbane has three gates. The Scan page is the load gate and runs in your browser. The call gate and the chat gate run in the self-hosted Hexbane server (Python standard library only, no installs) between your app, your LLM and your tools. The browser and the server use the same rules and the same policy JSON." }),
      h("h3", { text: "1. Load gate in CI: scan skills and MCP configs on every pull request" }),
      code(`# .github/workflows/hexbane.yml\non: [pull_request]\npermissions: { contents: read, security-events: write }\njobs:\n  hexbane:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: juw12/hexbane@v0.1.0\n        with:\n          path: .            # skills, .cursor/, .vscode/mcp.json, tools.json ...\n          fail-on: high      # findings show up in the Security tab (SARIF)`),
      code(`# or locally\npython -m hexbane scan ~/.claude/skills --fail-on high\npython -m hexbane lock ./my-mcp-tools          # pin what you approved\npython -m hexbane scan ./my-mcp-tools --lock hexbane.lock.json   # flags rug pulls`),
      h("h3", { text: "2. Start the server (call gate + chat gate)" }),
      h("ol", {}, [
        h("li", {}, ["Design and test your chat policy on the Chat gate page, then ", h("button", { class: "small", type: "button", text: "download the policy JSON", onclick: () => download(`${activeId()}.json`, JSON.stringify(exportablePolicy(), null, 2), "application/json") }), "."]),
        h("li", {}, ["Get the server from ", h("a", { href: SERVER_SOURCE_URL, text: "juw12/hexbane/server", rel: "noopener" }), " and start it:"]),
      ]),
      code(`python -m hexbane serve --policy ${activeId()}.json --port 8787\n# optional: HEXBANE_API_KEY, HEXBANE_ADMIN_KEY, HEXBANE_UPSTREAM, HEXBANE_UPSTREAM_KEY, HEXBANE_JUDGE_MODEL\n# optional: --tool-policy my-tools.json   (allow / ask / deny lists, protected paths, network allow list)\n# dashboard: http://127.0.0.1:8787/`),
      h("h3", { text: "3. Call gate: check each tool call before your agent runs it" }),
      code(`const res = await fetch("http://127.0.0.1:8787/v1/tool-call", {\n  method: "POST",\n  headers: { "Content-Type": "application/json", Authorization: "Bearer " + APP_KEY },\n  body: JSON.stringify({ tool: call.name, arguments: call.args }),\n});\nconst { decision, reasons } = await res.json();   // "allow" | "ask" | "deny"\nif (decision === "deny") return refuse(reasons);\nif (decision === "ask" && !(await askUser(call, reasons))) return refuse(reasons);\nreturn runTool(call);`),
      code(`# and each tool result before the model reads it (web pages, files, API replies)\ncurl -s http://127.0.0.1:8787/v1/tool-output -H "Authorization: Bearer $APP_KEY" \\\n  -d '{"content": "<page text>"}'     # -> {"decision": "quarantine" | "pass", "findings": [...]}`),
      h("h3", { text: "4. Or use the drop-in OpenAI-compatible proxy (change one URL)" }),
      code(`from openai import OpenAI\n\nclient = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key=APP_KEY)\nreply = client.chat.completions.create(model="gpt-4o-mini", user=user_id, messages=messages, tools=tools)\n# Chat gate: off-mission requests come back as a polite redirect; your LLM is never called.\n# Call gate: tool results with injected instructions are replaced before the LLM sees them,\n#            and denied tool calls are removed from the reply (see reply.hexbane.tool_calls).`),
      h("h3", { text: "Good to know" }),
      h("ul", {}, [
        h("li", { text: `Current chat mission: “${policy.mission}”. Keep 20–30 examples per column for best results.` }),
        h("li", { text: "Hexbane matches patterns and wording, not meaning. A determined attacker can phrase around any rule list; treat PASS as 'nothing known-bad found', not as proof of safety." }),
        h("li", { text: "The chat gate's local classifier is TF-IDF; enable the optional LLM judge (HEXBANE_JUDGE_MODEL) for low-confidence messages in production." }),
        h("li", { text: "The proxy does not stream yet (stream=false). Old SCOPEGUARD_* environment variables still work." }),
      ]),
    ]);
    document.getElementById("view").replaceChildren(content);
  }

  // ---------- routing ----------

  function renderScan() {
    window.HexbaneScanView.render(document.getElementById("view"), { h, card, toast, download });
  }

  const VIEWS = { scan: renderScan, try: renderTry, dashboard: renderDashboard, policy: renderPolicy, accuracy: renderAccuracy, integrate: renderIntegrate };

  function currentRoute() {
    const route = (location.hash.match(/^#\/([a-z]+)/) || [])[1];
    return VIEWS[route] ? route : "scan";
  }

  function renderView() {
    renderHeader();
    VIEWS[currentRoute()]();
  }

  function selectPolicy(id) {
    if (!policyById(id)) {
      return;
    }
    state.data.activePolicyId = id;
    state.selectedDecision = null;
    state.accuracyResult = null;
    save();
    buildEngine();
    renderView();
  }

  async function loadJson(path) {
    const response = await fetch(path, { cache: "no-cache" });
    if (!response.ok) {
      throw new Error(`${path}: HTTP ${response.status}`);
    }
    return response.json();
  }

  async function start() {
    const view = document.getElementById("view");
    view.replaceChildren(h("p", { class: "muted", text: "Loading policies…" }));
    try {
      await Promise.all(TEMPLATE_IDS.map(async (id) => {
        state.templates[id] = await loadJson(`policies/${id}.json`);
        state.evals[id] = EVAL_FILES[id] ? await loadJson(EVAL_FILES[id]) : null;
      }));
      buildEngine();
    } catch (error) {
      view.replaceChildren(card("Could not start", "span12", [h("p", { text: error.message })]));
      return;
    }

    document.getElementById("policy-select").addEventListener("change", (event) => selectPolicy(event.target.value));
    document.getElementById("theme-select").addEventListener("change", (event) => {
      state.settings.theme = event.target.value;
      Store.saveSettings(state.settings);
      applyTheme();
    });
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", applyTheme);
    window.addEventListener("hashchange", () => {
      renderView();
      document.getElementById("view").focus({ preventScroll: true });
    });
    applyTheme();
    renderView();
    window.ScopeGuardApp = { state, guard, evaluate, selectPolicy, ready: true };
    window.HexbaneApp = window.ScopeGuardApp;

    // Offline app shell on the real site only; local test servers stay cache-free.
    if ("serviceWorker" in navigator && location.protocol === "https:") {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    }
  }

  start();
})();

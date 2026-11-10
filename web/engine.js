// ScopeGuard engine (browser). A line-for-line port of server/engine.py so the web app and the
// self-hosted server make the same decisions; tests/test_scopeguard_web.py checks parity.
//
// Layers, cheapest first:
//   1. Abuse / jailbreak patterns                                   -> BLOCK
//   2. kNN over TF-IDF (words, bigrams, char 4-grams) vs. labelled policy examples
//      + capped keyword boosts                                       -> in_scope / adjacent / out_of_scope
//   3. Per-user conversation drift + daily off-topic allowance      -> REDIRECT / THROTTLE
(function (global) {
  "use strict";

  const LABELS = ["in_scope", "adjacent", "out_of_scope"];
  const WORD_PATTERN = /[a-z0-9]+/g;

  const STOPWORDS = new Set([
    "a", "an", "the", "and", "or", "but", "of", "to", "in", "on", "for", "with", "at", "by",
    "from", "is", "are", "was", "be", "it", "this", "that", "these", "my", "me", "i", "you",
    "your", "can", "could", "would", "should", "please", "what", "how", "which", "do", "does",
    "some", "any", "about", "into", "as", "so", "we", "our", "us", "s", "its", "it's", "give",
    "tell", "make", "help", "want", "need", "get", "show",
  ]);

  const ABUSE_PATTERNS = [
    /ignore (all |any |your |the )?(previous|prior|above|earlier) (instructions|rules|prompts?)/i,
    /\byou are (now|no longer)\b/i,
    /developer mode|jailbreak/i,
    /pretend (you are|to be|you're) (an? )?(unrestricted|different|general|uncensored)/i,
    /(reveal|print|show|repeat|leak) (me )?(your |the )?(system prompt|hidden instructions|initial instructions)/i,
    /forget (that )?(you are|your (rules|instructions))/i,
    /disregard (your|the|all) (rules|guidelines|instructions)/i,
    // Case-sensitive on purpose: "DAN" is the jailbreak persona, "Dan" is a person's name.
    /\bDAN\b/,
  ];

  const DEFAULT_THRESHOLDS = {
    min_confidence: 0.12,
    keyword_boost: 0.06,
    keyword_boost_cap: 0.12,
    top_k: 3,
    margin_floor: 0.05,
    margin_ratio: 1.5,
  };
  const DEFAULT_BUDGETS = { off_topic_allowance: 3, drift_window: 6, drift_limit: 0.6 };
  const DEFAULT_PRICING = { usd_per_1k_tokens: 0.01, avg_reply_tokens: 400 };

  // Python's round(x, n) for the values used here (no exact half-way ties occur in practice).
  function roundTo(value, digits) {
    return Number(value.toFixed(digits));
  }

  function codePointLength(text) {
    return Array.from(text).length;
  }

  function contentWords(text) {
    const words = String(text).toLowerCase().match(WORD_PATTERN) || [];
    return words.filter((word) => !STOPWORDS.has(word));
  }

  // Very light plural stemming so "holes" matches "hole"; leaves "calculus", "axis", "brass" intact.
  function stem(word) {
    if (word.length <= 3 || word.endsWith("ss") || word.endsWith("us") || word.endsWith("is")) {
      return word;
    }
    if (word.length > 4 && word.endsWith("es") && !word.endsWith("ses")) {
      return "xz".includes(word[word.length - 3]) ? word.slice(0, -2) : word.slice(0, -1);
    }
    if (word.endsWith("s")) {
      return word.slice(0, -1);
    }
    return word;
  }

  function addCount(map, key, amount) {
    map.set(key, (map.get(key) || 0) + amount);
  }

  function extractFeatures(text) {
    const words = contentWords(text);
    const features = new Map();
    for (const word of words) {
      addCount(features, "w:" + stem(word), 1.0);
      const padded = "#" + word + "#";
      for (let start = 0; start < padded.length - 3; start += 1) {
        addCount(features, "c:" + padded.slice(start, start + 4), 0.3);
      }
    }
    for (let index = 0; index + 1 < words.length; index += 1) {
      addCount(features, "b:" + stem(words[index]) + "_" + stem(words[index + 1]), 1.0);
    }
    return features;
  }

  function cosine(vectorA, vectorB) {
    if (vectorA.size > vectorB.size) {
      [vectorA, vectorB] = [vectorB, vectorA];
    }
    let total = 0;
    for (const [key, weight] of vectorA) {
      total += weight * (vectorB.get(key) || 0);
    }
    return total;
  }

  function normalise(vector) {
    let squares = 0;
    for (const weight of vector.values()) {
      squares += weight * weight;
    }
    const norm = Math.sqrt(squares) || 1.0;
    const result = new Map();
    for (const [key, weight] of vector) {
      result.set(key, weight / norm);
    }
    return result;
  }

  class TfidfIndex {
    constructor(labelledTexts) {
      this.labels = labelledTexts.map(([label]) => label);
      this.texts = labelledTexts.map(([, text]) => text);
      const featureSets = this.texts.map(extractFeatures);
      const documentFrequency = new Map();
      for (const features of featureSets) {
        for (const key of features.keys()) {
          addCount(documentFrequency, key, 1);
        }
      }
      const documentCount = Math.max(this.texts.length, 1);
      this.idf = new Map();
      for (const [key, frequency] of documentFrequency) {
        this.idf.set(key, Math.log((1 + documentCount) / (1 + frequency)) + 1.0);
      }
      this.unseenIdf = Math.log(1 + documentCount) + 1.0;
      this.vectors = featureSets.map((features) => this.weight(features));
    }

    weight(features) {
      const vector = new Map();
      for (const [key, count] of features) {
        const idf = this.idf.has(key) ? this.idf.get(key) : this.unseenIdf;
        vector.set(key, count >= 1 ? (1.0 + Math.log(count)) * idf : count * idf);
      }
      return normalise(vector);
    }

    vectorize(text) {
      return this.weight(extractFeatures(text));
    }
  }

  function validatePolicy(policy) {
    const missing = ["name", "mission", "examples"].filter((key) => !(key in (policy || {})));
    if (missing.length) {
      throw new Error("Policy missing keys: " + missing.join(", "));
    }
    for (const label of LABELS) {
      if (!Array.isArray(policy.examples[label]) || policy.examples[label].filter(Boolean).length < 3) {
        throw new Error(`Policy needs at least 3 '${label}' examples`);
      }
    }
    return policy;
  }

  function stemSet(words) {
    return new Set((words || []).map((word) => stem(String(word).toLowerCase())));
  }

  function countHits(stems, keywords) {
    let hits = 0;
    for (const word of stems) {
      if (keywords.has(word)) {
        hits += 1;
      }
    }
    return hits;
  }

  function today() {
    const now = new Date();
    const pad = (value) => String(value).padStart(2, "0");
    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  }

  class Engine {
    constructor(policy, learnedExamples = [], sessions = {}) {
      this.policy = validatePolicy(policy);
      this.thresholds = { ...DEFAULT_THRESHOLDS, ...(policy.thresholds || {}) };
      this.budgets = { ...DEFAULT_BUDGETS, ...(policy.budgets || {}) };
      this.pricing = { ...DEFAULT_PRICING, ...(policy.pricing || {}) };
      this.coreKeywords = stemSet(policy.core_keywords);
      this.adjacentKeywords = stemSet(policy.adjacent_keywords);
      this.outKeywords = stemSet(policy.out_of_scope_keywords);
      this.sessions = sessions; // { userId: { recent: [bool], offTopicUsed, day } } - persisted by the app
      this.rebuild(learnedExamples);
    }

    rebuild(learnedExamples) {
      const labelled = [];
      for (const label of LABELS) {
        for (const text of this.policy.examples[label]) {
          if (text) {
            labelled.push([label, text]);
          }
        }
      }
      for (const [label, text] of learnedExamples || []) {
        if (LABELS.includes(label) && text) {
          labelled.push([label, text]);
        }
      }
      this.index = new TfidfIndex(labelled);
      this.exampleCount = labelled.length;
    }

    isAbuse(message) {
      return ABUSE_PATTERNS.some((pattern) => pattern.test(message));
    }

    classify(message) {
      const index = this.index;
      const query = index.vectorize(message);
      const similaritiesByLabel = { in_scope: [], adjacent: [], out_of_scope: [] };
      let bestSimilarity = 0;
      let nearestExample = "";
      index.vectors.forEach((vector, position) => {
        const similarity = cosine(query, vector);
        similaritiesByLabel[index.labels[position]].push(similarity);
        if (similarity > bestSimilarity) {
          bestSimilarity = similarity;
          nearestExample = index.texts[position];
        }
      });

      const topK = Math.trunc(this.thresholds.top_k);
      const raw = {};
      for (const label of LABELS) {
        const top = similaritiesByLabel[label].slice().sort((a, b) => b - a).slice(0, topK);
        raw[label] = top.length ? top.reduce((sum, value) => sum + value, 0) / top.length : 0;
      }

      const stems = new Set(contentWords(message).map(stem));
      const boost = this.thresholds.keyword_boost;
      const cap = this.thresholds.keyword_boost_cap;
      raw.in_scope += Math.min(countHits(stems, this.coreKeywords) * boost, cap);
      raw.adjacent += Math.min(countHits(stems, this.adjacentKeywords) * boost, cap);
      raw.out_of_scope += Math.min(countHits(stems, this.outKeywords) * boost, cap);
      const scores = {};
      for (const label of LABELS) {
        scores[label] = roundTo(raw[label], 3);
      }

      // First label wins ties, like Python's max(scores, key=scores.get).
      let label = LABELS[0];
      for (const candidate of LABELS) {
        if (scores[candidate] > scores[label]) {
          label = candidate;
        }
      }
      const best = scores[label];
      const runnerUp = LABELS.map((name) => scores[name]).sort((a, b) => a - b)[1];
      const clearMargin =
        label !== "out_of_scope" &&
        best >= this.thresholds.margin_floor &&
        best >= this.thresholds.margin_ratio * Math.max(runnerUp, 1e-6);
      const confident = best >= this.thresholds.min_confidence || clearMargin;

      if (confident) {
        return { label, scores, uncertain: false, reason: `nearest examples: ${label}`, nearestExample };
      }
      // Asymmetric cost: wrongly redirecting a paying user is worse than letting a borderline
      // request through with a steering hint. Lean-on-mission -> benefit of the doubt (flagged).
      if (label !== "out_of_scope" && scores[label] > scores.out_of_scope) {
        return { label: "adjacent", scores, uncertain: true, reason: "low confidence - benefit of the doubt", nearestExample };
      }
      return { label: "out_of_scope", scores, uncertain: true, reason: "low confidence - unfamiliar request", nearestExample };
    }

    session(userId) {
      let session = this.sessions[userId];
      if (!session) {
        session = { recent: [], offTopicUsed: 0, day: "" };
        this.sessions[userId] = session;
      }
      const day = today();
      if (session.day !== day) {
        session.day = day;
        session.offTopicUsed = 0;
      }
      return session;
    }

    remember(session, onMission) {
      session.recent.push(onMission);
      if (session.recent.length > 50) {
        session.recent.splice(0, session.recent.length - 50);
      }
    }

    estimatedCost(message) {
      const tokens = this.pricing.avg_reply_tokens + codePointLength(message) / 4;
      return roundTo((tokens / 1000) * this.pricing.usd_per_1k_tokens, 6);
    }

    check(userId, rawMessage) {
      const message = String(rawMessage || "").trim();
      const policy = this.policy;
      if (this.isAbuse(message)) {
        this.remember(this.session(userId), false);
        return {
          action: "BLOCK", label: "abuse", reason: "jailbreak / prompt-injection pattern", scores: {},
          uncertain: false, nearestExample: "",
          reply: `I can't change how I work, but I'm happy to help with ${policy.mission}.`,
          estCostSavedUsd: this.estimatedCost(message),
        };
      }

      const result = this.classify(message);
      const session = this.session(userId);
      const base = { label: result.label, scores: result.scores, uncertain: result.uncertain, nearestExample: result.nearestExample };
      let decision;
      if (result.label === "in_scope") {
        decision = { ...base, action: "ALLOW", reason: result.reason, reply: "" };
      } else if (result.label === "adjacent") {
        decision = {
          ...base, action: "ADJACENT", reason: result.reason,
          reply: policy.adjacent_hint || `Answer briefly, then relate it back to ${policy.mission}.`,
        };
      } else if (session.offTopicUsed < this.budgets.off_topic_allowance) {
        session.offTopicUsed += 1;
        const left = this.budgets.off_topic_allowance - session.offTopicUsed;
        decision = { ...base, action: "REDIRECT", reason: `${result.reason}; ${left} courtesy replies left`, reply: policy.redirect_message };
      } else {
        decision = {
          ...base, action: "THROTTLE", reason: "off-topic allowance used up for today",
          reply: policy.throttle_message || policy.redirect_message,
        };
      }

      const onMission = decision.action === "ALLOW" || decision.action === "ADJACENT";
      this.remember(session, onMission);
      const window = session.recent.slice(-Math.trunc(this.budgets.drift_window));
      const offShare = window.filter((value) => !value).length / window.length;
      if (decision.action === "ADJACENT" && window.length >= 3 && offShare >= this.budgets.drift_limit) {
        decision.action = "REDIRECT";
        decision.reason += `; conversation drifting (${Math.round(offShare * 100)}% off-mission)`;
        decision.reply = policy.redirect_message;
      }

      decision.estCostSavedUsd =
        decision.action === "REDIRECT" || decision.action === "THROTTLE" ? this.estimatedCost(message) : 0;
      return decision;
    }

    // Group off-mission messages into unmet-demand themes. Word features only, IDF within the
    // batch so filler like "write" counts less, single-link grouping.
    cluster(messages, threshold = 0.2, maxClusters = 8) {
      if (!messages.length) {
        return [];
      }
      const wordLists = messages.map((message) => Array.from(new Set(contentWords(message).map(stem))));
      const documentFrequency = new Map();
      for (const words of wordLists) {
        for (const word of words) {
          addCount(documentFrequency, word, 1);
        }
      }
      const count = messages.length;
      const vectors = wordLists.map((words) => {
        const vector = new Map();
        for (const word of words) {
          vector.set(word, Math.log((1 + count) / (1 + documentFrequency.get(word))) + 1.0);
        }
        return normalise(vector);
      });

      const groups = [];
      messages.forEach((message, position) => {
        let best = null;
        let bestSimilarity = threshold;
        for (const group of groups) {
          const similarity = Math.max(...group.vectors.map((member) => cosine(vectors[position], member)));
          if (similarity >= bestSimilarity) {
            best = group;
            bestSimilarity = similarity;
          }
        }
        if (!best) {
          best = { messages: [], vectors: [], words: new Map() };
          groups.push(best);
        }
        best.messages.push(message);
        best.vectors.push(vectors[position]);
        for (const word of wordLists[position]) {
          addCount(best.words, word, 1);
        }
      });

      return groups
        .map((group, order) => ({ group, order }))
        .sort((a, b) => b.group.messages.length - a.group.messages.length || a.order - b.order)
        .slice(0, maxClusters)
        .map(({ group }) => {
          const ranked = Array.from(group.words.entries()).sort(
            (a, b) => b[1] - a[1] || documentFrequency.get(a[0]) - documentFrequency.get(b[0]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
          );
          return {
            theme: ranked.slice(0, 3).map(([word]) => word).join(", "),
            count: group.messages.length,
            example: group.messages[0],
          };
        });
    }
  }

  global.ScopeGuardEngine = { Engine, LABELS, validatePolicy, contentWords, stem };
})(typeof window !== "undefined" ? window : globalThis);

/* Hexbane browser scanner: a line-for-line port of hexbane/scanner.py using the same rules.json.
   The UI test suite runs both on the whole corpus and requires identical findings (rule, file, line). */
(function (global) {
  "use strict";

  const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const SEVERITY_DOWN = { critical: "high", high: "medium", medium: "low", low: "low", info: "info" };
  const MAX_PER_RULE = 25;
  const INSTRUCTION_EXTS = [".md", ".mdc", ".markdown", ".txt", ".rst"];
  const INSTRUCTION_NAMES = [".cursorrules", ".windsurfrules", ".clinerules", ".goosehints", ".rules"];
  const CODE_EXTS = [".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
    ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".go", ".rs", ".java", ".kt", ".php", ".lua"];
  const PACKAGE_RUNNERS = ["npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "npm"];
  const SHELLS = ["bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"];
  const BROAD_ROOTS = ["c:", "~", "$home", "${home}", "%userprofile%", "/users", "/home", "c:\\users", "c:/users",
    "${userprofile}", "$env:userprofile"];
  const SECRET_KEY = /(key|token|secret|password|passwd|pass|auth|credential|cookie)/i;
  const ENV_REFERENCE = /^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_]+%|\{env:[^}]+\}|\$\{\{[^}]+\}\})\s*$/;
  const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
  const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/g;
  const FRONTMATTER = /^---\s*\n([\s\S]*?)\n---\s*(\n|$)/;

  let R = null;

  function loadRules(data) {
    R = data;
    R.byId = {};
    for (const rule of R.rules) {
      rule.compiled = (rule.patterns || []).map((p) => new RegExp(p, "gi"));
      R.byId[rule.id] = rule;
    }
    for (const key of Object.keys(R.capabilities)) {
      R.capabilities[key].compiled = R.capabilities[key].patterns.map((p) => new RegExp(p, "i"));
    }
    R.sideChannelRe = new RegExp(R.side_channel_words, "i");
    R.commentAiRe = new RegExp(R.comment_ai_words, "i");
    R.commentOrderRe = new RegExp(R.comment_order_words, "i");
    R.negationRe = new RegExp(R.negation_words, "i");
    R.invisibleSet = new Set(R.invisible);
    R.bidiSet = new Set(R.bidi);
    R.foldRules = new Set(R.fold_rules || []);
    const confusableKeys = Object.keys(R.confusables || {}).join("");
    R.confusableRe = confusableKeys ? new RegExp("[" + confusableKeys + "]", "g") : null;
    return R;
  }

  // ------------------------------------------------------------ text helpers
  const isTag = (c) => c >= 0xE0000 && c <= 0xE007F;
  const isEmojiNeighbour = (c) => c >= 0x1F000 || (c >= 0x2600 && c <= 0x27BF) || c === 0xFE0F || (c >= 0x1F3FB && c <= 0x1F3FF);
  const isJoiningScript = (c) => (c >= 0x0600 && c <= 0x06FF) || (c >= 0x0900 && c <= 0x0DFF) || (c >= 0x0750 && c <= 0x077F);
  const isAlnum = (ch) => /^[\p{L}\p{N}]$/u.test(ch);

  function codePoints(text) {
    return Array.from(text);
  }

  function legitJoiner(chars, i) {
    const code = chars[i].codePointAt(0);
    if (code !== 0x200C && code !== 0x200D) return false;
    const before = i > 0 ? chars[i - 1].codePointAt(0) : 0;
    const after = i + 1 < chars.length ? chars[i + 1].codePointAt(0) : 0;
    if (code === 0x200D && (isEmojiNeighbour(before) || isEmojiNeighbour(after))) return true;
    return isJoiningScript(before) || isJoiningScript(after);
  }

  function stripHidden(text) {
    const chars = codePoints(text);
    const out = [];
    for (let i = 0; i < chars.length; i++) {
      const code = chars[i].codePointAt(0);
      if (isTag(code) || R.bidiSet.has(code)) continue;
      if (R.invisibleSet.has(code) && !legitJoiner(chars, i)) continue;
      out.push(chars[i]);
    }
    return out.join("").normalize("NFKC");
  }

  function lineOf(text, index) {
    let count = 1;
    for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) count++;
    return count;
  }

  function visibleLine(text, line) {
    const lines = text.split("\n");
    const raw = line > 0 && line <= lines.length ? lines[line - 1] : "";
    const shown = [];
    let hiddenRun = 0;
    for (const ch of codePoints(raw)) {
      const code = ch.codePointAt(0);
      if (isTag(code)) { hiddenRun++; continue; }
      if (hiddenRun) { shown.push("[" + hiddenRun + " hidden tag chars]"); hiddenRun = 0; }
      if (R.invisibleSet.has(code) || R.bidiSet.has(code)) shown.push("[U+" + code.toString(16).toUpperCase().padStart(4, "0") + "]");
      else if (ch !== "\r") shown.push(ch);
    }
    if (hiddenRun) shown.push("[" + hiddenRun + " hidden tag chars]");
    const snippet = shown.join("").trim();
    return snippet.length <= 200 ? snippet : snippet.slice(0, 197) + "...";
  }

  function maskSecret(value) {
    value = value.trim();
    if (value.length <= 8) return "****";
    return value.slice(0, 4) + "****(" + value.length + " chars)";
  }

  function isPlaceholder(value) {
    const lowered = value.toLowerCase();
    return R.placeholder_words.some((w) => lowered.includes(w));
  }

  function decodeTags(chars) {
    return chars.map((ch) => ch.codePointAt(0)).filter((c) => c >= 0xE0020 && c <= 0xE007E)
      .map((c) => String.fromCharCode(c - 0xE0000)).join("");
  }

  const squash = (s) => s.split(/\s+/).filter(Boolean).join(" ");
  const isDict = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const basename = (p) => p.split(/[\\/]/).pop();
  const extname = (name) => { const i = name.lastIndexOf("."); return i > 0 ? name.slice(i) : ""; };

  // ------------------------------------------------------------ classification
  function findServers(parsed) {
    if (!isDict(parsed)) return null;
    for (const key of ["mcpServers", "servers", "context_servers"]) {
      const value = parsed[key];
      if (isDict(value) && Object.keys(value).length && Object.values(value).every(isDict)) {
        if (Object.values(value).some((v) => "command" in v || "url" in v || "serverUrl" in v)) return value;
      }
    }
    if (isDict(parsed.mcp)) return findServers(parsed.mcp);
    return null;
  }

  function findTools(parsed) {
    let candidates = [];
    if (isDict(parsed) && Array.isArray(parsed.tools)) candidates = parsed.tools;
    else if (isDict(parsed) && isDict(parsed.result) && Array.isArray(parsed.result.tools)) candidates = parsed.result.tools;
    else if (Array.isArray(parsed)) candidates = parsed;
    else if (isDict(parsed) && "name" in parsed && "description" in parsed &&
      ("inputSchema" in parsed || "input_schema" in parsed || "parameters" in parsed)) candidates = [parsed];
    return candidates.filter((t) => isDict(t) && typeof t.name === "string" &&
      typeof (t.description === undefined ? "" : t.description) === "string");
  }

  function classify(path, text) {
    const name = basename(path).toLowerCase();
    const ext = extname(name);
    if (ext === ".json" || ext === ".jsonc" || name.endsWith(".json")) {
      let parsed;
      try { parsed = JSON.parse(text); } catch (e) { return ["other", null]; }
      if (findServers(parsed) !== null) return ["config", parsed];
      if (findTools(parsed).length) return ["tool", parsed];
      return ["other", parsed];
    }
    if (CODE_EXTS.includes(ext)) return ["code", null];
    if (INSTRUCTION_EXTS.includes(ext) || INSTRUCTION_NAMES.includes(name)) return ["instructions", null];
    return ["other", null];
  }

  // ------------------------------------------------------------ file scan state
  class FileScan {
    constructor(path, text, kind) {
      this.path = path; this.text = text; this.kind = kind;
      this.findings = []; this.seen = new Set(); this.perRule = {}; this.lines = text.split("\n");
    }
    add(ruleId, line, opts) {
      opts = opts || {};
      const key = ruleId + "|" + line + "|" + (opts.extraKey || "");
      if (this.seen.has(key)) return;
      if ((this.perRule[ruleId] || 0) >= MAX_PER_RULE) return;
      if (this.suppressed(ruleId, line)) return;
      const rule = R.byId[ruleId];
      this.seen.add(key);
      this.perRule[ruleId] = (this.perRule[ruleId] || 0) + 1;
      this.findings.push({
        rule: ruleId, severity: opts.severity || rule.severity, title: rule.title, file: this.path, line,
        evidence: opts.evidence !== undefined && opts.evidence !== null ? opts.evidence : visibleLine(this.text, line),
        why: rule.why, fix: rule.fix, hidden_text: opts.hidden || null, refs: (rule.refs || []).slice(),
      });
    }
    suppressed(ruleId, line) {
      for (const number of [line, line - 1]) {
        if (number > 0 && number <= this.lines.length) {
          const content = this.lines[number - 1];
          const marker = content.indexOf("hexbane-ignore");
          if (marker === -1) continue;
          if (number === line - 1 && content.indexOf("hexbane-ignore-next-line") === -1) continue;
          const ids = content.slice(marker).match(/HB\d{3}/g) || [];
          if (!ids.length || ids.includes(ruleId)) return true;
        }
      }
      return false;
    }
  }

  function severityFor(rule, kind) {
    return (rule.severity_by_kind || {})[kind] || rule.severity;
  }

  function contextSeverity(rule, kind, text, start) {
    let severity = severityFor(rule, kind);
    const lineStart = text.lastIndexOf("\n", start - 1) + 1;
    const prefix = text.slice(lineStart, start);
    if (kind === "code" && R.comment_prefixes.some((p) => prefix.replace(/^\s+/, "").startsWith(p))) severity = SEVERITY_DOWN[severity];
    if ((R.downgrade_categories.includes(rule.category) || R.downgrade_rules.includes(rule.id)) && R.negationRe.test(prefix)) {
      severity = SEVERITY_DOWN[severity];
    }
    return severity;
  }

  function applies(rule, kind) {
    return !rule.applies || rule.applies.includes(kind);
  }

  function scanPatterns(scan, text, lineOffset, hiddenSource) {
    for (const rule of R.rules) {
      if (!rule.compiled.length || !applies(rule, scan.kind)) continue;
      for (const pattern of rule.compiled) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(text)) !== null) {
          if (match[0].length === 0) { pattern.lastIndex++; continue; }
          const line = lineOffset !== undefined && lineOffset !== null ? lineOffset : lineOf(text, match.index);
          let evidence = null;
          if (rule.mask) {
            if (rule.id === "HB311") {
              const m = match[0];
              const raw = m.slice(m.search(/[:=]/) + 1).trim();
              const quoted = raw.slice(0, 1) === "\"" || raw.slice(0, 1) === "'";
              const value = raw.replace(/^["']+|["']+$/g, "");
              if (isPlaceholder(value) || !(quoted || /\d/.test(value))) continue;
              evidence = m.split(value)[0].trim() + " " + maskSecret(value);
            } else {
              evidence = "secret " + maskSecret(match[0]);
            }
          }
          const severity = lineOffset !== undefined && lineOffset !== null
            ? severityFor(rule, scan.kind) : contextSeverity(rule, scan.kind, text, match.index);
          scan.add(rule.id, line, { evidence, hidden: hiddenSource, severity });
        }
      }
    }
  }

  // ------------------------------------------------------------ disguised text (fold pass)
  const FOLD_ENTITY = /&#(\d{2,5});|&#[xX]([0-9a-fA-F]{2,5});/g;
  const FOLD_STEPS = [
    [/(?<=[A-Za-z])(\*{1,2}|~~|`)(?=[A-Za-z])/g, ""],
    [/(?<=[A-Za-z])(''|"")(?=[A-Za-z])/g, ""],
    [/(?<![A-Za-z] )(?<![A-Za-z])[A-Za-z](?: [A-Za-z])+(?![A-Za-z])(?! [A-Za-z](?![A-Za-z]))/g, "SPACED"],
  ];
  const FOLD_NEWLINE = /(?<=[^\n])\n(?=[^\n])/g;
  const FOLD_GAPS = /(?<=\S)[ \t]{2,}(?=\S)/g;

  // Keep, for every output character, the index of the input character it came from (so findings keep their
  // line numbers) and whether it was produced by undoing a disguise. Mirrors fold_sub in hexbane/scanner.py.
  function foldSub(text, source, disguised, pattern, replace, mark) {
    if (mark === undefined) mark = true;
    let out = "";
    const outSource = [];
    const outDisguised = [];
    let cursor = 0;
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0].length === 0) { pattern.lastIndex++; continue; }
      const start = match.index;
      const end = start + match[0].length;
      out += text.slice(cursor, start);
      for (let i = cursor; i < start; i++) { outSource.push(source[i]); outDisguised.push(disguised[i]); }
      const replacement = replace(match);
      const anchor = source[start];
      out += replacement;
      for (let i = 0; i < replacement.length; i++) { outSource.push(anchor); outDisguised.push(mark); }
      if (mark && !replacement && end < text.length) disguised = disguised.slice(0, end).concat([true], disguised.slice(end + 1));
      cursor = end;
    }
    out += text.slice(cursor);
    for (let i = cursor; i < text.length; i++) { outSource.push(source[i]); outDisguised.push(disguised[i]); }
    return [out, outSource, outDisguised];
  }

  function entityChar(match) {
    const code = match[1] !== undefined ? parseInt(match[1], 10) : parseInt(match[2], 16);
    return code >= 32 && code < 0x110000 ? String.fromCodePoint(code) : match[0];
  }

  function fold(clean) {
    let text = R.confusableRe ? clean.replace(R.confusableRe, (ch) => R.confusables[ch]) : clean;
    let disguised = [];
    for (let i = 0; i < text.length; i++) disguised.push(text[i] !== clean[i]);
    let source = [];
    for (let i = 0; i < text.length; i++) source.push(i);
    [text, source, disguised] = foldSub(text, source, disguised, FOLD_ENTITY, entityChar);
    for (const [pattern, replacement] of FOLD_STEPS) {
      const replace = replacement === "SPACED" ? (m) => m[0].replace(/ /g, "") : () => replacement;
      [text, source, disguised] = foldSub(text, source, disguised, pattern, replace);
    }
    [text, source, disguised] = foldSub(text, source, disguised, FOLD_GAPS, () => " ", false);
    const joined = text.replace(FOLD_NEWLINE, " ");
    if (joined === clean) return null;
    return [joined, source, disguised];
  }

  // Decoded text for a folded match, limited to the original line(s) the match came from.
  function foldWindow(text, source, clean, start, end) {
    const origin = source[start];
    const firstLineStart = origin > 0 ? clean.lastIndexOf("\n", origin - 1) + 1 : 0;
    let lineEnd = clean.indexOf("\n", source[end - 1]);
    if (lineEnd === -1) lineEnd = clean.length;
    let left = start;
    while (left > 0 && start - left < 80 && source[left - 1] >= firstLineStart) left--;
    let right = end;
    while (right < text.length && right - end < 80 && source[right] < lineEnd) right++;
    return squash(text.slice(left, right)).slice(0, 300);
  }

  function scanFolded(scan, clean) {
    const folded = fold(clean);
    if (!folded) return;
    const [text, source, disguised] = folded;
    if (scan.kind === "code" && !disguised.some(Boolean)) return; // only wrapping or spacing changed
    for (const rule of R.rules) {
      if (!R.foldRules.has(rule.id) || !rule.compiled.length || !applies(rule, scan.kind)) continue;
      for (const pattern of rule.compiled) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(text)) !== null) {
          if (match[0].length === 0) { pattern.lastIndex++; continue; }
          const start = match.index;
          const end = start + match[0].length;
          const origin = source[start];
          const line = lineOf(clean, origin);
          if (scan.seen.has(rule.id + "|" + line + "|")) continue;
          const snippet = foldWindow(text, source, clean, start, end);
          const severity = contextSeverity(rule, scan.kind, clean, origin);
          scan.add(rule.id, line, { hidden: snippet, severity });
          if (disguised.slice(start, end).some(Boolean)) scan.add("HB106", line, { hidden: snippet });
        }
      }
    }
  }

  function invisibleSeverity(kind, chars, i) {
    if (kind !== "code") return "high";
    const before = i > 0 ? chars[i - 1] : " ";
    const after = i + 1 < chars.length ? chars[i + 1] : " ";
    return isAlnum(before) && isAlnum(after) ? "high" : "medium";
  }

  function scanHiddenChars(scan) {
    const chars = codePoints(scan.text);
    let start = chars.length && chars[0] === "\uFEFF" ? 1 : 0;
    let line = 1;
    for (let k = 0; k < start; k++) if (chars[k] === "\n") line++;
    let i = start;
    while (i < chars.length) {
      const ch = chars[i];
      const code = ch.codePointAt(0);
      if (ch === "\n") { line++; i++; continue; }
      if (isTag(code)) {
        let end = i;
        while (end < chars.length && isTag(chars[end].codePointAt(0))) end++;
        const hidden = decodeTags(chars.slice(i, end));
        scan.add("HB103", line, { hidden: hidden.slice(0, 300) || null });
        if (hidden) scanPatterns(scan, hidden, line, hidden.slice(0, 300));
        i = end;
        continue;
      }
      if (R.bidiSet.has(code)) scan.add("HB102", line);
      else if (R.invisibleSet.has(code) && !legitJoiner(chars, i)) scan.add("HB101", line, { severity: invisibleSeverity(scan.kind, chars, i) });
      i++;
    }
  }

  function scanComments(scan, clean) {
    if (scan.kind !== "instructions") return;
    HTML_COMMENT.lastIndex = 0;
    let match;
    while ((match = HTML_COMMENT.exec(clean)) !== null) {
      const body = match[1];
      if (body.trim().length < 20) continue;
      if (R.commentAiRe.test(body) && R.commentOrderRe.test(body)) {
        scan.add("HB104", lineOf(clean, match.index), { hidden: squash(body).slice(0, 300) });
      }
    }
  }

  function scanBase64(scan, clean) {
    BASE64_BLOB.lastIndex = 0;
    let match;
    while ((match = BASE64_BLOB.exec(clean)) !== null) {
      const blob = match[0];
      let decoded;
      try { decoded = atob(blob + "=".repeat((4 - (blob.length % 4)) % 4)); } catch (e) { continue; }
      if (!decoded.length) continue;
      let printable = 0;
      for (let k = 0; k < decoded.length; k++) {
        const b = decoded.charCodeAt(k);
        if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) printable++;
      }
      if (printable / decoded.length < 0.9) continue;
      const line = lineOf(clean, match.index);
      const before = scan.findings.length;
      scanPatterns(scan, decoded, line, squash(decoded).slice(0, 300));
      const severity = scan.findings.length > before ? "high" : null;
      scan.add("HB105", line, { hidden: squash(decoded).slice(0, 300), severity });
    }
  }

  function toolLine(text, name) {
    const index = text.indexOf("\"" + name + "\"");
    return index >= 0 ? lineOf(text, index) : 1;
  }

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function scanTools(scan, parsed) {
    const tools = findTools(parsed);
    const names = tools.map((t) => t.name);
    for (const tool of tools) {
      const name = tool.name;
      const line = toolLine(scan.text, name);
      const description = tool.description || "";
      const schema = tool.inputSchema || tool.input_schema || tool.parameters || {};
      const properties = isDict(schema) && isDict(schema.properties) ? schema.properties : {};
      const paramText = Object.entries(properties).filter(([, v]) => isDict(v))
        .map(([k, v]) => k + ": " + (v.description || "")).join("\n");
      const combined = name + "\n" + description + "\n" + paramText;
      const decodedScan = new FileScan(scan.path, combined, scan.kind);
      scanHiddenChars(decodedScan);
      scanPatterns(decodedScan, stripHidden(combined));
      for (const f of decodedScan.findings) {
        scan.add(f.rule, line, { evidence: "tool '" + name + "': " + f.evidence, hidden: f.hidden_text, severity: f.severity });
      }
      if (description.length > 1200) scan.add("HB601", line, { evidence: "tool '" + name + "': description is " + description.length + " characters" });
      for (const [key, value] of Object.entries(properties)) {
        if (R.side_channel_params.includes(key.toLowerCase())) {
          const paramDescription = isDict(value) ? (value.description || "") : "";
          if (R.sideChannelRe.test(description + " " + paramDescription)) {
            scan.add("HB602", line, { evidence: "tool '" + name + "': parameter '" + key + "'", extraKey: key });
          }
        }
      }
      for (const other of names) {
        if (other !== name && other.length >= 4 && new RegExp("(?<![\\w-])" + escapeRe(other) + "(?![\\w-])").test(description)) {
          scan.add("HB603", line, { evidence: "tool '" + name + "' mentions tool '" + other + "'", extraKey: other });
        }
      }
    }
  }

  function packageSpec(command, args) {
    const base = basename(command).toLowerCase().replace(".cmd", "").replace(".exe", "");
    if (!PACKAGE_RUNNERS.includes(base)) return null;
    let rest = args.slice();
    if ((base === "pnpm" || base === "yarn") && rest[0] === "dlx") rest = rest.slice(1);
    else if (base === "npm" && (rest[0] === "exec" || rest[0] === "x")) rest = rest.slice(1);
    else if (base === "pipx" && rest[0] === "run") rest = rest.slice(1);
    else if (["pnpm", "yarn", "npm"].includes(base)) return null;
    let skipNext = false;
    for (const arg of rest) {
      if (skipNext) { skipNext = false; continue; }
      if (["--package", "-p", "--from", "--with", "--python"].includes(arg)) { skipNext = true; continue; }
      if (arg.startsWith("-") || arg === "--") continue;
      return arg;
    }
    return null;
  }

  function isPinned(spec, runner) {
    if (runner === "uvx" || runner === "pipx") {
      return spec.includes("==") || spec.endsWith(".whl") || spec.endsWith(".tar.gz") || spec.startsWith("git+") || spec.startsWith("/") || spec.startsWith(".");
    }
    if ([".", "/", "file:", "git+", "http"].some((p) => spec.startsWith(p))) return true;
    const at = spec.lastIndexOf("@");
    if (at <= 0) return false;
    const version = spec.slice(at + 1);
    return Boolean(version) && !["latest", "next", "*"].includes(version) && !version.startsWith("^") && !version.startsWith("~");
  }

  function isBroadRoot(arg) {
    const normal = arg.trim().toLowerCase();
    if (normal === "/" || normal === "c:\\" || normal === "c:/") return true;
    const trimmed = normal.replace(/[\\/]+$/, "");
    return Boolean(trimmed) && BROAD_ROOTS.includes(trimmed);
  }

  function scanConfig(scan, parsed) {
    const servers = findServers(parsed) || {};
    for (const [name, server] of Object.entries(servers)) {
      const line = toolLine(scan.text, name);
      const command = String(server.command || "");
      const args = (Array.isArray(server.args) ? server.args : []).filter((a) => typeof a === "string" || typeof a === "number").map(String);
      const base = basename(command).toLowerCase();
      const runner = base.replace(".cmd", "").replace(".exe", "");
      const spec = packageSpec(command, args);
      if (spec !== null && !isPinned(spec, runner)) scan.add("HB501", line, { evidence: "server '" + name + "': " + runner + " " + spec, extraKey: name });
      const filesystemLike = name.toLowerCase().includes("filesystem") || args.some((a) => a.toLowerCase().includes("filesystem"));
      for (const arg of args) {
        if (isBroadRoot(arg)) {
          scan.add("HB502", line, { evidence: "server '" + name + "': gets '" + arg + "'", severity: filesystemLike ? "high" : null, extraKey: name });
          break;
        }
      }
      const url = String(server.url || server.serverUrl || "");
      if (url.toLowerCase().startsWith("http://")) {
        const host = url.replace(/^http:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
        if (!["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"].includes(host) && !host.endsWith(".localhost")) {
          scan.add("HB503", line, { evidence: "server '" + name + "': " + url, extraKey: name });
        }
      }
      for (const blockName of ["env", "headers"]) {
        const block = server[blockName];
        if (!isDict(block)) continue;
        for (const [key, raw] of Object.entries(block)) {
          const value = String(raw);
          if (!SECRET_KEY.test(key) || !value.trim()) continue;
          if (ENV_REFERENCE.test(value) || isPlaceholder(value) || value.trim().length < 8) continue;
          if (value.toLowerCase().startsWith("bearer ") && ENV_REFERENCE.test(value.slice(7))) continue;
          scan.add("HB504", line, { evidence: "server '" + name + "': " + blockName + "." + key + " = " + maskSecret(value), extraKey: name + "." + key });
        }
      }
      if (SHELLS.includes(base) && args.some((a) => ["-c", "/c", "-command", "/k", "-encodedcommand", "-e"].includes(a.toLowerCase()))) {
        scan.add("HB505", line, { evidence: "server '" + name + "': " + command + " " + args.join(" ").slice(0, 120), extraKey: name });
      }
      if (runner === "docker") {
        const joined = args.join(" ");
        if (/--privileged|docker\.sock|(-v|--volume)[ =]\/:|--pid[ =]host|--network[ =]host/.test(joined)) {
          scan.add("HB506", line, { evidence: "server '" + name + "': docker " + joined.slice(0, 120), extraKey: name });
        }
      }
    }
  }

  function scanCodeTools(scan, clean) {
    if (scan.kind !== "code") return;
    if (!/@\w+\.tool\b|\.tool\(|server\.setRequestHandler|registerTool\(|ListToolsRequestSchema/.test(clean)) return;
    const re = /\b(def|function|async\s+def)\s+\w+\s*\(([^)]*)\)/g;
    let match;
    while ((match = re.exec(clean)) !== null) {
      const params = match[2].match(/\b(sidenote|side_note)\b/i);
      if (params) scan.add("HB602", lineOf(clean, match.index), { extraKey: params[0] });
    }
  }

  function scanText(path, text) {
    if (text.startsWith("\uFEFF")) text = text.slice(1);
    const [kind, parsed] = classify(path, text);
    const scan = new FileScan(path, text, kind);
    scanHiddenChars(scan);
    const clean = stripHidden(text);
    scanPatterns(scan, clean);
    scanFolded(scan, clean);
    scanComments(scan, clean);
    scanBase64(scan, clean);
    scanCodeTools(scan, clean);
    if (kind === "tool") scanTools(scan, parsed);
    else if (kind === "config") scanConfig(scan, parsed);
    return [kind, scan.findings];
  }

  // ------------------------------------------------------------ skills (scope check)
  function declaredText(skillMd) {
    const match = skillMd.replace(/\r\n/g, "\n").match(FRONTMATTER);
    return (match ? match[1] : skillMd.slice(0, 600)).toLowerCase();
  }

  function capabilityHits(text) {
    const clean = stripHidden(text);
    const hits = {};
    for (const [key, capability] of Object.entries(R.capabilities)) {
      for (const pattern of capability.compiled) {
        const match = pattern.exec(clean);
        if (match) { hits[key] = lineOf(clean, match.index); break; }
      }
    }
    return hits;
  }

  function scopeFindings(skillPath, skillMd, members) {
    const declared = declaredText(skillMd);
    const undeclared = [];
    for (const [path, text] of members) {
      const [kind] = classify(path, text);
      if (!R.capability_kinds.includes(kind) && path !== skillPath) continue;
      const hits = capabilityHits(text);
      for (const key of Object.keys(R.capabilities)) {
        if (!(key in hits)) continue;
        if (undeclared.some((u) => u[0] === key)) continue;
        if (!R.capabilities[key].declare.some((w) => declared.includes(w))) undeclared.push([key, path, hits[key]]);
      }
    }
    if (!undeclared.length) return [];
    const rule = R.byId.HB701;
    const severity = undeclared.some(([k]) => k === "credentials" || k === "persistence") ? "high" : rule.severity;
    const parts = undeclared.map(([k, p, l]) => R.capabilities[k].label + " (" + basename(p) + ":" + l + ")");
    return [{ rule: "HB701", severity, title: rule.title, file: skillPath, line: 1,
      evidence: "description never mentions: " + parts.join("; "), why: rule.why, fix: rule.fix,
      hidden_text: null, refs: (rule.refs || []).slice() }];
  }

  // ------------------------------------------------------------ report
  function verdictFor(severity) {
    const level = SEVERITY_ORDER[severity] || 0;
    if (level >= SEVERITY_ORDER.high) return "FAIL";
    if (level >= SEVERITY_ORDER.medium) return "REVIEW";
    return "PASS";
  }

  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  function scanFiles(files, skipped) {
    const findings = [];
    const fileRows = [];
    for (const [path, text] of files) {
      const [kind, fileFindings] = scanText(path, text);
      findings.push(...fileFindings);
      fileRows.push({ path, kind, findings: fileFindings.length });
    }
    const dirOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
    const leaf = (p) => p.split("/").pop();
    const skillRoots = Array.from(new Set(files.filter(([p]) => leaf(p).toLowerCase() === "skill.md").map(([p]) => dirOf(p)))).sort(cmp);
    for (const root of skillRoots) {
      const prefix = root ? root + "/" : "";
      const skillMdPath = files.find(([p]) => p.toLowerCase() === (prefix + "skill.md").toLowerCase())[0];
      const skillMd = files.find(([p]) => p === skillMdPath)[1];
      const nested = skillRoots.filter((r) => r !== root && r.startsWith(prefix));
      const members = files.filter(([p]) => p.startsWith(prefix) && !nested.some((n) => p.startsWith(n + "/")));
      findings.push(...scopeFindings(skillMdPath, skillMd, members));
    }
    return buildReport(findings, fileRows, skipped || []);
  }

  function buildReport(findings, fileRows, skipped) {
    findings.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.rule, b.rule));
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const perFile = {};
    for (const f of findings) {
      const current = perFile[f.file] || "info";
      if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[current]) perFile[f.file] = f.severity;
    }
    for (const row of fileRows) row.verdict = verdictFor(perFile[row.path] || "info");
    const worst = findings.reduce((m, f) => Math.max(m, SEVERITY_ORDER[f.severity]), 0);
    const worstName = Object.keys(SEVERITY_ORDER).find((k) => SEVERITY_ORDER[k] === worst);
    return { tool: "hexbane", version: R.version, verdict: verdictFor(worstName), counts,
      files_scanned: fileRows.length, files: fileRows, skipped: skipped || [], findings };
  }

  global.HexbaneScan = { loadRules, scanFiles, scanText, stripHidden, verdictFor, get rules() { return R; } };
})(typeof window !== "undefined" ? window : globalThis);

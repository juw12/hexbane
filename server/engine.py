"""
Hexbane chat-gate engine (from ScopeGuard): decides whether a message fits a business AI assistant's mission.

Pure Python standard library. Layers, cheapest first:
    1. Abuse / jailbreak patterns            -> BLOCK
    2. kNN over TF-IDF (words, bigrams, char 4-grams) against labelled policy examples
       + a capped keyword boost               -> in_scope / adjacent / out_of_scope
    3. Optional LLM judge for low-confidence messages
    4. Per-user conversation drift + daily off-topic allowance -> REDIRECT / THROTTLE
"""

import json
import math
import re
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

LABELS = ("in_scope", "adjacent", "out_of_scope")

WORD_PATTERN = re.compile(r"[a-z0-9]+")

STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "of", "to", "in", "on", "for", "with", "at", "by",
    "from", "is", "are", "was", "be", "it", "this", "that", "these", "my", "me", "i", "you",
    "your", "can", "could", "would", "should", "please", "what", "how", "which", "do", "does",
    "some", "any", "about", "into", "as", "so", "we", "our", "us", "s", "its", "it's", "give",
    "tell", "make", "help", "want", "need", "get", "show",
}

ABUSE_PATTERNS = [
    r"ignore (all |any |your |the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"\byou are (now|no longer)\b",
    r"developer mode|jailbreak",
    r"pretend (you are|to be|you're) (an? )?(unrestricted|different|general|uncensored)",
    r"(reveal|print|show|repeat|leak) (me )?(your |the )?(system prompt|hidden instructions|initial instructions)",
    r"forget (that )?(you are|your (rules|instructions))",
    r"disregard (your|the|all) (rules|guidelines|instructions)",
]


# Case-sensitive on purpose: "DAN" is the jailbreak persona, "Dan" is a person's name.
CASE_SENSITIVE_ABUSE_PATTERNS = [r"\bDAN\b"]


def content_words(text: str) -> list[str]:
    return [word for word in WORD_PATTERN.findall(text.lower()) if word not in STOPWORDS]


def stem(word: str) -> str:
    """Very light plural stemming so 'holes' matches 'hole'; leaves 'calculus', 'axis', 'brass' intact."""
    if len(word) <= 3 or word.endswith(("ss", "us", "is")):
        return word
    if len(word) > 4 and word.endswith("es") and not word.endswith("ses"):
        return word[:-2] if word[-3] in "xz" else word[:-1]
    if word.endswith("s"):
        return word[:-1]
    return word


def extract_features(text: str) -> Counter:
    words = content_words(text)
    features = Counter()
    for word in words:
        features["w:" + stem(word)] += 1.0
        padded = f"#{word}#"
        for start in range(len(padded) - 3):
            features["c:" + padded[start:start + 4]] += 0.3
    for first, second in zip(words, words[1:]):
        features[f"b:{stem(first)}_{stem(second)}"] += 1.0
    return features


def cosine(vector_a: dict, vector_b: dict) -> float:
    if len(vector_a) > len(vector_b):
        vector_a, vector_b = vector_b, vector_a
    return sum(weight * vector_b.get(key, 0.0) for key, weight in vector_a.items())


class TfidfIndex:
    """Small TF-IDF index; vectors are L2-normalised so dot product = cosine."""

    def __init__(self, labelled_texts: list[tuple[str, str]]):
        self.labels = [label for label, _ in labelled_texts]
        self.texts = [text for _, text in labelled_texts]
        feature_sets = [extract_features(text) for text in self.texts]
        document_frequency = Counter()
        for features in feature_sets:
            document_frequency.update(features.keys())
        document_count = max(len(self.texts), 1)
        self.idf = {
            key: math.log((1 + document_count) / (1 + frequency)) + 1.0
            for key, frequency in document_frequency.items()
        }
        self.unseen_idf = math.log(1 + document_count) + 1.0
        self.vectors = [self._weight(features) for features in feature_sets]

    def _weight(self, features: Counter) -> dict:
        vector = {
            key: (1.0 + math.log(count)) * self.idf.get(key, self.unseen_idf) if count >= 1
            else count * self.idf.get(key, self.unseen_idf)
            for key, count in features.items()
        }
        norm = math.sqrt(sum(weight * weight for weight in vector.values())) or 1.0
        return {key: weight / norm for key, weight in vector.items()}

    def vectorize(self, text: str) -> dict:
        return self._weight(extract_features(text))


@dataclass
class Classification:
    label: str
    scores: dict
    uncertain: bool
    reason: str
    nearest_example: str = ""


@dataclass
class Decision:
    action: str            # ALLOW | ADJACENT | REDIRECT | THROTTLE | BLOCK
    label: str             # in_scope | adjacent | out_of_scope | abuse
    reason: str
    scores: dict
    uncertain: bool
    reply: str = ""        # text to show the user (REDIRECT/THROTTLE/BLOCK) or steering hint (ADJACENT)
    est_cost_saved_usd: float = 0.0


@dataclass
class UserSession:
    recent_on_mission: deque = field(default_factory=lambda: deque(maxlen=50))
    off_topic_used: int = 0
    day: str = ""


def load_policy(path: Path) -> dict:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [key for key in ("name", "mission", "examples") if key not in policy]
    if missing:
        raise ValueError(f"Policy missing keys: {missing}")
    for label in LABELS:
        if len(policy["examples"].get(label, [])) < 3:
            raise ValueError(f"Policy needs at least 3 '{label}' examples")
    return policy


class Engine:
    def __init__(
        self,
        policy: dict,
        learned_examples: Optional[list[tuple[str, str]]] = None,
        llm_judge: Optional[Callable[[str, str], Optional[str]]] = None,
    ):
        self.policy = policy
        self.thresholds = {
            "min_confidence": 0.12,
            "keyword_boost": 0.06,
            "keyword_boost_cap": 0.12,
            "top_k": 3,
            "margin_floor": 0.05,
            "margin_ratio": 1.5,
            **policy.get("thresholds", {}),
        }
        self.budgets = {
            "off_topic_allowance": 3,
            "drift_window": 6,
            "drift_limit": 0.6,
            **policy.get("budgets", {}),
        }
        self.pricing = {"usd_per_1k_tokens": 0.01, "avg_reply_tokens": 400, **policy.get("pricing", {})}
        self.core_keywords = {stem(word.lower()) for word in policy.get("core_keywords", [])}
        self.adjacent_keywords = {stem(word.lower()) for word in policy.get("adjacent_keywords", [])}
        self.out_keywords = {stem(word.lower()) for word in policy.get("out_of_scope_keywords", [])}
        self.abuse_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in ABUSE_PATTERNS]
        self.abuse_patterns += [re.compile(pattern) for pattern in CASE_SENSITIVE_ABUSE_PATTERNS]
        self.llm_judge = llm_judge
        self.sessions: dict[str, UserSession] = defaultdict(UserSession)
        self._lock = threading.Lock()
        self.rebuild(learned_examples or [])

    def rebuild(self, learned_examples: list[tuple[str, str]]) -> None:
        """(Re)fit the index from policy examples + admin-labelled examples."""
        labelled = [
            (label, text)
            for label in LABELS
            for text in self.policy["examples"][label]
        ]
        labelled += [(label, text) for label, text in learned_examples if label in LABELS]
        index = TfidfIndex(labelled)
        with self._lock:
            self.index = index
            self.example_count = len(labelled)

    # ---------- classification ----------

    def is_abuse(self, message: str) -> bool:
        return any(pattern.search(message) for pattern in self.abuse_patterns)

    def classify(self, message: str) -> Classification:
        with self._lock:
            index = self.index
        query = index.vectorize(message)
        similarities_by_label = defaultdict(list)
        best_match = (0.0, "")
        for label, text, vector in zip(index.labels, index.texts, index.vectors):
            similarity = cosine(query, vector)
            similarities_by_label[label].append(similarity)
            if similarity > best_match[0]:
                best_match = (similarity, text)

        top_k = int(self.thresholds["top_k"])
        scores = {}
        for label in LABELS:
            top = sorted(similarities_by_label[label], reverse=True)[:top_k]
            scores[label] = sum(top) / len(top) if top else 0.0

        stems = {stem(word) for word in content_words(message)}
        boost, cap = self.thresholds["keyword_boost"], self.thresholds["keyword_boost_cap"]
        scores["in_scope"] += min(len(stems & self.core_keywords) * boost, cap)
        scores["adjacent"] += min(len(stems & self.adjacent_keywords) * boost, cap)
        scores["out_of_scope"] += min(len(stems & self.out_keywords) * boost, cap)
        scores = {label: round(score, 3) for label, score in scores.items()}

        label = max(scores, key=scores.get)
        best = scores[label]
        runner_up = sorted(scores.values())[-2]
        clear_margin = (
            label != "out_of_scope"
            and best >= self.thresholds["margin_floor"]
            and best >= self.thresholds["margin_ratio"] * max(runner_up, 1e-6)
        )
        confident = best >= self.thresholds["min_confidence"] or clear_margin
        if confident:
            return Classification(label, scores, False, f"nearest examples: {label}", best_match[1])

        if self.llm_judge:
            judged = self.llm_judge(self.policy["mission"], message)
            if judged in LABELS:
                return Classification(judged, scores, False, f"LLM judge: {judged}", best_match[1])

        # Asymmetric cost: wrongly redirecting a paying user is worse than letting a borderline
        # request through with a steering hint. Lean-on-mission -> benefit of the doubt (flagged).
        if label != "out_of_scope" and scores[label] > scores["out_of_scope"]:
            return Classification("adjacent", scores, True, "low confidence - benefit of the doubt", best_match[1])
        return Classification("out_of_scope", scores, True, "low confidence - unfamiliar request", best_match[1])

    # ---------- decision with session state ----------

    def check(self, user_id: str, message: str) -> Decision:
        message = (message or "").strip()
        if self.is_abuse(message):
            decision = Decision(
                "BLOCK", "abuse", "jailbreak / prompt-injection pattern", {}, False,
                f"I can't change how I work, but I'm happy to help with {self.policy['mission']}.",
            )
            self._record_session(user_id, on_mission=False)
            decision.est_cost_saved_usd = self._estimated_cost(message)
            return decision

        result = self.classify(message)
        with self._lock:
            session = self._session(user_id)
            if result.label == "in_scope":
                decision = Decision("ALLOW", result.label, result.reason, result.scores, result.uncertain)
            elif result.label == "adjacent":
                decision = Decision(
                    "ADJACENT", result.label, result.reason, result.scores, result.uncertain,
                    self.policy.get(
                        "adjacent_hint",
                        f"Answer briefly, then relate it back to {self.policy['mission']}.",
                    ),
                )
            elif session.off_topic_used < self.budgets["off_topic_allowance"]:
                session.off_topic_used += 1
                left = self.budgets["off_topic_allowance"] - session.off_topic_used
                decision = Decision(
                    "REDIRECT", result.label, f"{result.reason}; {left} courtesy replies left",
                    result.scores, result.uncertain, self.policy["redirect_message"],
                )
            else:
                decision = Decision(
                    "THROTTLE", result.label, "off-topic allowance used up for today",
                    result.scores, result.uncertain,
                    self.policy.get("throttle_message", self.policy["redirect_message"]),
                )

            on_mission = decision.action in ("ALLOW", "ADJACENT")
            session.recent_on_mission.append(on_mission)
            window = list(session.recent_on_mission)[-int(self.budgets["drift_window"]):]
            off_share = window.count(False) / len(window)
            if decision.action == "ADJACENT" and len(window) >= 3 and off_share >= self.budgets["drift_limit"]:
                decision.action = "REDIRECT"
                decision.reason += f"; conversation drifting ({off_share:.0%} off-mission)"
                decision.reply = self.policy["redirect_message"]

        if decision.action in ("REDIRECT", "THROTTLE"):
            decision.est_cost_saved_usd = self._estimated_cost(message)
        return decision

    def _session(self, user_id: str) -> UserSession:
        session = self.sessions[user_id]
        today = time.strftime("%Y-%m-%d")
        if session.day != today:
            session.day = today
            session.off_topic_used = 0
        return session

    def _record_session(self, user_id: str, on_mission: bool) -> None:
        with self._lock:
            self._session(user_id).recent_on_mission.append(on_mission)

    def _estimated_cost(self, message: str) -> float:
        tokens = self.pricing["avg_reply_tokens"] + len(message) / 4
        return round(tokens / 1000 * self.pricing["usd_per_1k_tokens"], 6)

    # ---------- analytics ----------

    def cluster(self, messages: list[str], threshold: float = 0.2, max_clusters: int = 8) -> list[dict]:
        """Group off-mission messages into unmet-demand themes.

        Uses word features only (spelling fragments dilute topical overlap), weighted by IDF within
        the batch so filler like 'write' counts less, with single-link grouping.
        """
        if not messages:
            return []
        word_sets = [list(dict.fromkeys(stem(word) for word in content_words(message))) for message in messages]
        document_frequency = Counter(word for words in word_sets for word in words)
        count = len(messages)
        vectors = []
        for words in word_sets:
            vector = {word: math.log((1 + count) / (1 + document_frequency[word])) + 1.0 for word in words}
            norm = math.sqrt(sum(weight * weight for weight in vector.values())) or 1.0
            vectors.append({word: weight / norm for word, weight in vector.items()})

        groups = []
        for message, words, vector in zip(messages, word_sets, vectors):
            best, best_similarity = None, threshold
            for group in groups:
                similarity = max(cosine(vector, member) for member in group["vectors"])
                if similarity >= best_similarity:
                    best, best_similarity = group, similarity
            if best is None:
                best = {"messages": [], "vectors": [], "words": Counter()}
                groups.append(best)
            best["messages"].append(message)
            best["vectors"].append(vector)
            best["words"].update(words)

        result = []
        for group in sorted(groups, key=lambda g: len(g["messages"]), reverse=True)[:max_clusters]:
            ranked = sorted(group["words"].items(), key=lambda item: (-item[1], document_frequency[item[0]], item[0]))
            result.append({
                "theme": ", ".join(word for word, _ in ranked[:3]),
                "count": len(group["messages"]),
                "example": group["messages"][0],
            })
        return result


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def open_url(request: urllib.request.Request, timeout: float):
    """Open a URL; loopback hosts (e.g. a local LLM) bypass any system proxy."""
    host = urllib.parse.urlsplit(request.full_url).hostname or ""
    if host in LOOPBACK_HOSTS:
        return _direct_opener.open(request, timeout=timeout)
    return urllib.request.urlopen(request, timeout=timeout)


def make_openai_judge(base_url: str, api_key: str, model: str, timeout: float = 8.0):
    """Optional LLM judge using any OpenAI-compatible endpoint. Returns a label or None on failure."""

    def judge(mission: str, message: str) -> Optional[str]:
        prompt = (
            f"An AI assistant exists ONLY for: {mission}.\n"
            f"User message: {message!r}\n"
            "Reply with exactly one word: IN (part of the mission), ADJACENT (closely related, "
            "useful to the mission) or OUT (unrelated)."
        )
        body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 3,
            "temperature": 0,
        }).encode()
        request = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        )
        try:
            with open_url(request, timeout) as response:
                answer = json.loads(response.read())["choices"][0]["message"]["content"].strip().upper()
        except Exception:
            return None
        return {"IN": "in_scope", "ADJACENT": "adjacent", "OUT": "out_of_scope"}.get(answer.split()[0] if answer else "")

    return judge

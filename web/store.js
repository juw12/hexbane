// Local persistence for ScopeGuard. Everything stays in this browser's localStorage.
(function (global) {
  "use strict";

  const DATA_KEY = "scopeguard-data-v1";
  const SETTINGS_KEY = "scopeguard-settings-v1";
  const MAX_EVENTS = 2000;

  function read(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function write(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (error) {
      return false;
    }
  }

  function emptyData() {
    return {
      activePolicyId: "cad-copilot",
      policyOverrides: {}, // edited copies of the built-in templates, by id
      customPolicies: {}, // imported policies, by id
      events: [],
      learned: {}, // policyId -> [[label, text], ...]
      sessions: {}, // policyId -> engine session state per user
      nextEventId: 1,
    };
  }

  const Store = {
    loadData() {
      const data = { ...emptyData(), ...read(DATA_KEY, {}) };
      if (!Array.isArray(data.events)) {
        data.events = [];
      }
      return data;
    },

    saveData(data) {
      if (data.events.length > MAX_EVENTS) {
        data.events.splice(0, data.events.length - MAX_EVENTS);
      }
      return write(DATA_KEY, data);
    },

    loadSettings() {
      return { theme: "system", ...read(SETTINGS_KEY, {}) };
    },

    saveSettings(settings) {
      return write(SETTINGS_KEY, settings);
    },

    clearAll() {
      try {
        localStorage.removeItem(DATA_KEY);
      } catch (error) {
        // storage unavailable - nothing to clear
      }
      return emptyData();
    },
  };

  global.ScopeGuardStore = Store;
})(window);

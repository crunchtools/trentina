"use strict";
// Drives src/trentina/gateway/approval_page.js without a browser (RT#1609), so a
// Python suite that cannot run the script can still prove its load path: fill the
// code fields from the #fragment, remember the code for the tab, strip it from
// the address bar, reload when a re-tapped link changes only the fragment, and
// reload on a back/forward (bfcache) restore. Invoked as:
//     node approval_page_probe.js <path to approval_page.js>
// Exits non-zero, naming the failed checks, when any does not hold. The script
// runs in a `vm` sandbox whose globals are the stubbed DOM below — not `eval`.
const fs = require("fs");
const vm = require("vm");
const script = fs.readFileSync(process.argv[2], "utf8");

const fails = [];
const ok = (name, cond) => {
  if (!cond) fails.push(name);
};

const codeInputs = [{ value: "" }, { value: "" }];
const store = {};
const listeners = {};
let reloads = 0;
let strippedTo = null;

const location = {
  hash: "#code=abcd-efgh-jkmn",
  pathname: "/approve/setup",
  search: "",
  reload: () => {
    reloads += 1;
  },
};
const sandbox = {
  // No "#pk" element, so the script returns after the load path and before the
  // passkey ceremony — exactly the part this probe covers.
  document: {
    getElementById: (id) => (id === "ttl" ? { dataset: { seconds: "120" }, textContent: "" } : null),
    querySelectorAll: (sel) => (sel === "input[name=code]" ? codeInputs : []),
  },
  location,
  history: {
    replaceState: (_state, _title, url) => {
      strippedTo = url;
    },
  },
  sessionStorage: {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => {
      store[k] = v;
    },
    removeItem: (k) => {
      delete store[k];
    },
  },
  addEventListener: (ev, fn) => {
    (listeners[ev] = listeners[ev] || []).push(fn);
  },
  window: {},
  setInterval: () => 0,
};

vm.runInNewContext(script, sandbox);

ok("both code fields filled from the fragment", codeInputs.every((i) => i.value === "abcd-efgh-jkmn"));
ok("the code is remembered for this tab", store["tz-enrol-code"] === "abcd-efgh-jkmn");
ok("the code is stripped from the address bar", strippedTo === "/approve/setup");

// A re-tapped link changes only the fragment; the page must reload to re-read it.
location.hash = "#code=mnpq-rstu-vwxy";
(listeners.hashchange || []).forEach((fn) => fn());
ok("a re-tapped link reloads", reloads === 1);

// A fragment with no code must not reload.
location.hash = "#done";
(listeners.hashchange || []).forEach((fn) => fn());
ok("a code-less fragment does not reload", reloads === 1);

// A back/forward (bfcache) restore reloads so the server-rendered path runs.
(listeners.pageshow || []).forEach((fn) => fn({ persisted: true }));
ok("a bfcache restore reloads", reloads === 2);

if (fails.length) {
  console.error("FAIL: " + fails.join("; "));
  process.exit(1);
}
console.log("ok");

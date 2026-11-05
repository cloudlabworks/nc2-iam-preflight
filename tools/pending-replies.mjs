// Pending Chrome DevTools Protocol replies, keyed by request id. A Map rather than an object, so an id read
// from the socket can only reach a callback this script registered: "__proto__", "constructor" and unknown
// ids find nothing. Messages without a matching id (CDP events) are ignored.
export function createPending() {
  const pend = new Map();
  return {
    add(id, cb) { pend.set(id, cb); },
    settle(msg) {
      const cb = msg && pend.get(msg.id);
      if (typeof cb !== "function") return false;
      pend.delete(msg.id); cb(msg); return true;
    },
    get size() { return pend.size; },
  };
}

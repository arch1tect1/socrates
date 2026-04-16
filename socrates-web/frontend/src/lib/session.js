const SESSION_KEY = "socrates_session_id";

export function getSessionId() {
  if (typeof window === "undefined" || !window.crypto?.randomUUID) {
    return "";
  }
  let id = localStorage.getItem(SESSION_KEY);
  if (!id) {
    id = window.crypto.randomUUID();
    localStorage.setItem(SESSION_KEY, id);
  }
  return id;
}

// Session storage is scoped to this tab and exact origin, including its port.
// Cookies must never carry cockpit credentials to applications on other ports.
export const SESSION_KEY = "ravage.cockpit.session";

export function sessionToken() {
  return window.sessionStorage.getItem(SESSION_KEY) || "";
}

function privateFetch(path, token, options = {}) {
  const destination = new URL(path, window.location.href);
  if (destination.origin !== window.location.origin || !destination.pathname.startsWith("/api/")) {
    throw new Error("Cockpit credentials require a same-origin API destination");
  }
  return fetch(destination.href, {
    ...options,
    headers: { ...options.headers, Authorization: `Bearer ${token}` },
    credentials: "omit",
    mode: "same-origin",
    // Firefox otherwise inherits no-referrer and sends Origin: null on POST.
    referrerPolicy: "same-origin",
    redirect: "error",
    cache: "no-store",
  });
}

export async function cockpitFetch(path, options = {}) {
  const token = sessionToken();
  if (!token) throw new Error("Open the private cockpit link to connect");
  const response = await privateFetch(path, token, options);
  if (response.status === 401) {
    window.sessionStorage.removeItem(SESSION_KEY);
    window.location.replace("/");
    throw new Error("The cockpit session has expired");
  }
  return response;
}

export async function openCockpitSession() {
  const capability = new URLSearchParams(window.location.hash.slice(1)).get("token");
  window.history.replaceState(null, "", window.location.pathname);
  const status = document.querySelector("#session-status");
  try {
    const token = capability || sessionToken();
    if (token) {
      const response = await privateFetch("/api/session", token, capability ? { method: "POST" } : {});
      if (response.ok) {
        if (capability) {
          const payload = await response.json();
          if (typeof payload.session_token !== "string" || !payload.session_token) {
            throw new Error("The cockpit did not provide a session");
          }
          window.sessionStorage.setItem(SESSION_KEY, payload.session_token);
        }
        window.location.replace("/index.html");
        return;
      }
      window.sessionStorage.removeItem(SESSION_KEY);
    }
    status.textContent = "Open the private cockpit link printed by Ravage to connect.";
  } catch {
    status.textContent = "The cockpit connection failed. Reopen the link printed by Ravage.";
  }
}

export async function consumeEventStream(body, onEvent) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) return;
      pending += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = pending.indexOf("\n\n")) !== -1) {
        const frame = pending.slice(0, boundary);
        pending = pending.slice(boundary + 2);
        let type = "message";
        const data = [];
        for (const line of frame.split("\n")) {
          if (line.startsWith("event:")) type = line.slice(6).trim();
          if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        }
        if (data.length) onEvent({ type, data: data.join("\n") });
      }
    }
  } finally {
    reader.releaseLock();
  }
}

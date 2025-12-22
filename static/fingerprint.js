(() => {
  const enc = new TextEncoder();

  function fnv1aHex(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16).padStart(8, "0");
  }

  async function sha256Hex(input) {
    try {
      if (!crypto || !crypto.subtle || !crypto.subtle.digest) {
        return typeof input === "string" ? fnv1aHex(input) : "";
      }
      const data = typeof input === "string" ? enc.encode(input) : input;
      const digest = await crypto.subtle.digest("SHA-256", data);
      const bytes = new Uint8Array(digest);
      let out = "";
      for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
      return out;
    } catch (_) {
      return "";
    }
  }

  async function canvasHash() {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext("2d");
      if (!ctx) return "";

      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(100, 1, 80, 22);
      ctx.fillStyle = "#069";
      ctx.fillText("Cwm fjordbank glyphs vext quiz", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("Cwm fjordbank glyphs vext quiz", 4, 17);

      const dataUrl = canvas.toDataURL();
      return await sha256Hex(dataUrl);
    } catch (_) {
      return "";
    }
  }

  function webglInfo() {
    try {
      const canvas = document.createElement("canvas");
      const gl =
        canvas.getContext("webgl") ||
        canvas.getContext("experimental-webgl") ||
        canvas.getContext("webgl2");
      if (!gl) return { vendor: "", renderer: "" };

      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : "";
      const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "";
      return { vendor: String(vendor || ""), renderer: String(renderer || "") };
    } catch (_) {
      return { vendor: "", renderer: "" };
    }
  }

  function payloadBase() {
    const langs = Array.isArray(navigator.languages) ? navigator.languages.slice(0, 8) : [];
    const maxTouchPoints = Number.isFinite(navigator.maxTouchPoints) ? navigator.maxTouchPoints : 0;
    return {
      v: 1,
      webdriver: navigator.webdriver === true,
      max_touch_points: maxTouchPoints,
      touch_event: "ontouchstart" in window,
      platform: String(navigator.platform || ""),
      tz: (() => {
        try {
          return String(Intl.DateTimeFormat().resolvedOptions().timeZone || "");
        } catch (_) {
          return "";
        }
      })(),
      langs,
      hardware_concurrency: Number.isFinite(navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : 0,
      device_memory: Number.isFinite(navigator.deviceMemory) ? navigator.deviceMemory : 0,
      screen_w: Number.isFinite(screen.width) ? screen.width : 0,
      screen_h: Number.isFinite(screen.height) ? screen.height : 0,
      dpr: Number.isFinite(window.devicePixelRatio) ? window.devicePixelRatio : 0,
      plugins: navigator.plugins ? navigator.plugins.length : 0,
    };
  }

  async function run() {
    try {
      const base = payloadBase();
      base.canvas = await canvasHash();
      const w = webglInfo();
      base.webgl_vendor = w.vendor;
      base.webgl_renderer = w.renderer;

      const resp = await fetch("/__aqua/axis_order", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(base),
      });

      if (!resp.ok) return;
      const data = await resp.json().catch(() => null);
      if (data && data.ok === true) {
        // Retry original request (this page was served at the original URL).
        location.reload();
      }
    } catch (_) {
      // Stay blank.
    }
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    run();
  } else {
    document.addEventListener("DOMContentLoaded", run, { once: true });
  }
})();

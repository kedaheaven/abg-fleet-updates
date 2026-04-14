(() => {
  const DATA_POLL_MS = 1000;
  const UI_TICK_MS = 250;
  const PROMO_ROTATE_MS = 5000;
  const PROMO_FADE_MS = 220;

  const PROMOS_PATHS = ["../data/promos.json", "data/promos.json", "../promos.json", "promos.json"];
  const SESSION_JSON_PATHS = ["../data/session.json", "data/session.json", "../session.json", "session.json"];
  const SESSION_JS_PATHS = ["../data/session.js", "data/session.js", "../session.js", "session.js"];
  const DEFAULT_HELP_URL = "https://allbirdies.powerappsportals.com/bay-help/";

  const $ = (id) => document.getElementById(id);

  const ui = {
    nowClock: $("nowClock"),
    headerBayPill: $("headerBayPill"),
    bayLabel: $("bayLabel"),
    displayName: $("displayName"),
    statusPill: $("statusPill"),
    memberPill: $("memberPill"),
    tierPill: $("tierPill"),
    countdown: $("countdown"),
    bannerText: $("bannerText"),
    statusDetail: $("statusDetail"),
    progressFill: $("progressFill"),
    startLocal: $("startLocal"),
    endLocal: $("endLocal"),
    helpUrlText: $("helpUrlText"),
    debugLine: $("debugLine"),
    promoCard: $("promoCard"),
    promoKicker: $("promoKicker"),
    promoTitle: $("promoTitle"),
    promoBody: $("promoBody"),
    promoCtaWrap: $("promoCtaWrap"),
    promoCtaText: $("promoCtaText"),
    promoDots: $("promoDots"),
    promoSection: $("promoSection"),
    promoBg: $("promoBg"),
    promoOverlay: $("promoOverlay"),
    promoQrWrap: $("promoQrWrap"),
    promoQrCaption: $("promoQrCaption"),
    promoQrImg: $("promoQrImg"),
  };

  const DEFAULT_STATE = {
    status: "READY",
    mode: "",
    bayLabel: "",
    locationLabel: "",
    displayName: "",
    customerDisplayName: "",
    bannerText: "",
    statusDetail: "",
    helpUrl: DEFAULT_HELP_URL,
    startUtc: null,
    endUtc: null,
    sessionStartUtc: null,
    sessionEndUtc: null,
    timing: null,
    customer: null,
    updatedUtc: null,
    showDebug: true,
    _source: "",
  };

  let state = { ...DEFAULT_STATE };
  let loadOk = false;
  let lastErr = "";

  let promos = [];
  let eligiblePromos = [];
  let promoIndex = 0;
  let lastPromoSwapAt = 0;
  let lastEligibilityKey = "";

  const TIME_FMT = new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit' });
  function fmtClock(d) { return TIME_FMT.format(d); }
  function parseUtc(s) {
    if (!s) return null;
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }
  function pick(obj, ...keys) {
    for (const k of keys) {
      if (!obj) continue;
      const v = obj[k];
      if (v !== undefined && v !== null && v !== "") return v;
    }
    return "";
  }
  function getStartEndUtc(s) {
    const start = parseUtc(pick(s, "startUtc", "sessionStartUtc")) || (s.timing ? parseUtc(pick(s.timing, "startUtc")) : null);
    const end = parseUtc(pick(s, "playEndUtc", "sessionEndUtc", "endUtc")) || (s.timing ? parseUtc(pick(s.timing, "playEndUtc", "endUtc")) : null);
    return { start, end };
  }
  function formatRemaining(ms) {
    if (ms < 0) ms = 0;
    const total = Math.floor(ms / 1000);
    const hh = Math.floor(total / 3600);
    const mm = Math.floor((total % 3600) / 60);
    const ss = total % 60;
    if (hh > 0) return `${String(hh).padStart(2, "0")}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
    return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
  }
  function formatLocalTime(d) {
    if (!d) return "--:--";
    return TIME_FMT.format(d);
  }

  function normalizeStatus(s) {
    const status = (pick(s, "status") || "").toUpperCase();
    const mode = (pick(s, "mode") || "").toUpperCase();
    if (status) return status;
    if (mode === "PREP") return "PREP";
    if (mode === "START") return "ACTIVE";
    if (mode === "WARN5") return "ENDING";
    if (mode === "END") return "ENDED";
    return "READY";
  }
  function normalizeDisplayName(s) {
    const cust = s.customer || {};
    return pick(s, "displayName", "customerDisplayName") || pick(cust, "displayName") || "Guest";
  }
  function normalizeBayLabel(s) {
    return pick(s, "bayLabel", "locationLabel") || "Bay";
  }
  function normalizeHelpUrl(s) {
    return pick(s, "helpUrl") || DEFAULT_HELP_URL;
  }

  function promoDurationMs(p) {
    if (!p) return PROMO_ROTATE_MS;

    const ms = Number(p.durationMs);
    if (Number.isFinite(ms) && ms >= 1000) return ms;

    const s = Number(p.durationSeconds);
    if (Number.isFinite(s) && s > 0) return Math.max(1000, Math.round(s * 1000));

    return PROMO_ROTATE_MS;
  }

  // PREP behavior:
  // - Show countdown to START (not end)
  // - Ignore stale banner text (e.g., "On time") that might have been carried over

  function computeEndingLabel(endUtc) {
    if (!endUtc) return "⚠ 5 minutes left";
    const ms = endUtc.getTime() - Date.now();
    if (ms <= 0) return "Session ending now";
    const mins = Math.max(1, Math.min(59, Math.ceil(ms / 60000)));
    return mins === 1 ? "⚠ 1 minute left" : `⚠ ${mins} minutes left`;
  }

  // PREP behavior:
  // - Show countdown to START (not end)
  // - Ignore stale banner text (e.g., "On time") that might have been carried over
  // ENDING behavior:
  // - Always show a computed warning (do not rely on bannerText)
  function computeStatusDetail(s, status, startUtc, endUtc) {
    const mode = (pick(s, "mode") || "").toUpperCase();
    const explicit = pick(s, "statusDetail", "bannerText");

    if (status === "PREP" || mode === "PREP") {
      if (startUtc && startUtc.getTime() > Date.now()) return "Starts in";
      return "Getting your bay ready…";
    }

    if (status === "ENDING" || mode === "WARN5") return computeEndingLabel(endUtc);
    if (status === "ACTIVE") return explicit || "In progress.";
    if (status === "ENDED" || mode === "END") return explicit || "Thanks for choosing All Birdies.";
    return explicit || "";
  }

  function computeProgressPercent(start, end) {
    if (!start || !end) return 0;
    const total = end.getTime() - start.getTime();
    if (total <= 0) return 0;
    const elapsed = Date.now() - start.getTime();
    const pct = Math.max(0, Math.min(1, elapsed / total));
    return pct * 100;
  }

  async function fetchJsonAny(paths) {
    let last = null;
    for (const p of paths) {
      try {
        const res = await fetch(`${p}?ts=${Date.now()}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const obj = await res.json();
        obj._source = p;
        return obj;
      } catch (e) {
        last = e;
      }
    }
    throw last || new Error("fetch failed");
  }

  function loadJsOnce(paths) {
    return new Promise((resolve, reject) => {
      let i = 0;
      const tryNext = () => {
        if (i >= paths.length) return reject(new Error("session.js not found"));
        const p = paths[i++];
        const url = `${p}?ts=${Date.now()}`;

        const old = document.getElementById("abg-session-script");
        if (old && old.parentNode) old.parentNode.removeChild(old);

        try { delete window.ABG_SESSION; } catch (_) { window.ABG_SESSION = undefined; }

        const s = document.createElement("script");
        s.id = "abg-session-script";
        s.src = url;
        s.onload = () => {
          if (window.ABG_SESSION && typeof window.ABG_SESSION === "object") {
            const obj = window.ABG_SESSION;
            obj._source = p;
            resolve(obj);
          } else {
            tryNext();
          }
        };
        s.onerror = () => tryNext();
        document.head.appendChild(s);
      };
      tryNext();
    });
  }

  function promoEligible(p, ctx) {
    if (!p) return false;
    const t = p.target || {};
    const isMember = !!(ctx.customer && ctx.customer.isMember);
    const tier = pick(ctx.customer?.membership || {}, "tier");
    const planName = pick(ctx.customer?.membership || {}, "planName");
    const tags = Array.isArray(ctx.customer?.tags) ? ctx.customer.tags : [];

    if (t.isMember !== undefined && t.isMember !== isMember) return false;
    if (Array.isArray(t.membershipTierIn) && t.membershipTierIn.length && !t.membershipTierIn.includes(tier)) return false;
    if (Array.isArray(t.membershipPlanIn) && t.membershipPlanIn.length && !t.membershipPlanIn.includes(planName)) return false;
    if (Array.isArray(t.tagsAny) && t.tagsAny.length) {
      const ok = t.tagsAny.some(x => tags.includes(x));
      if (!ok) return false;
    }
    if (Array.isArray(t.statusesIn) && t.statusesIn.length) {
      const st = normalizeStatus(ctx);
      if (!t.statusesIn.includes(st)) return false;
    }
    return true;
  }

  function buildEligibilityKey(ctx) {
    const st = normalizeStatus(ctx);
    const isMember = !!(ctx.customer && ctx.customer.isMember);
    const tier = pick(ctx.customer?.membership || {}, "tier");
    const plan = pick(ctx.customer?.membership || {}, "planName");
    const tags = Array.isArray(ctx.customer?.tags) ? ctx.customer.tags.slice().sort().join(",") : "";
    return `${st}|${isMember}|${tier}|${plan}|${tags}`;
  }

  function recomputeEligiblePromos(ctx) {
    const key = buildEligibilityKey(ctx);
    if (key === lastEligibilityKey) return false;

    lastEligibilityKey = key;
    eligiblePromos = (promos || []).filter(p => promoEligible(p, ctx));
    if (!eligiblePromos.length) eligiblePromos = (promos || []).slice(0, 1);
    promoIndex = 0;
    lastPromoSwapAt = 0;
    renderPromo(true);
    return true;
  }

  function renderDots() {
    ui.promoDots.innerHTML = "";
    const n = eligiblePromos.length;
    if (n <= 1) return;
    for (let i = 0; i < n; i++) {
      const d = document.createElement("div");
      d.className = "abg-dot" + (i === promoIndex ? " abg-dot--active" : "");
      ui.promoDots.appendChild(d);
    }
  }

  function applyPromoBackground(p, immediate = false) {
    if (!ui.promoBg || !ui.promoOverlay) return;
    const bg = (p && p.bg) ? p.bg : null;
    const src = bg && bg.src ? String(bg.src) : "";
    const overlay = (bg && bg.overlay ? String(bg.overlay) : "dark").trim();
    const overlayKey = overlay ? overlay : "dark";

    ui.promoOverlay.className = `abg-promos__overlay abg-promos__overlay--${overlayKey}`;

    if (src) {
      ui.promoBg.style.display = "";
      ui.promoBg.style.backgroundImage = `url('${src}')`;
      ui.promoBg.style.backgroundPosition = (bg && bg.position) ? bg.position : "center center";
      ui.promoBg.style.backgroundSize = (bg && bg.size) ? bg.size : "cover";
    } else {
      ui.promoBg.style.backgroundImage = "none";
      ui.promoBg.style.display = "none";
    }

    if (immediate) {
      ui.promoBg.classList.remove("is-fading");
      ui.promoOverlay.classList.remove("is-fading");
    }
  }

  function getPromoQrImageUrl(p) {
    if (!p) return "";
    const local = p.qrSrc || (p.qr && p.qr.src);
    if (local) return local;

    const url = p.qrUrl || p.ctaUrl;
    if (!url) return "";

    const size = 180;
    return `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(url)}`;
  }

  function renderPromo(immediate = false) {
    const p = eligiblePromos[promoIndex];

    const apply = () => {
      if (!p) {
        ui.promoKicker.style.display = "none";
        ui.promoTitle.textContent = "Welcome to All Birdies.";
        ui.promoBody.textContent = "";
        ui.promoCtaWrap.style.display = "none";
        renderDots();
        applyPromoBackground(null, true);

        // ✅ NEW: hide QR when no promo
        if (ui.promoQrWrap && ui.promoQrImg) {
          ui.promoQrWrap.style.display = "none";
          ui.promoQrImg.removeAttribute("src");
        }

        return;
      }

      const kicker = p.kicker || "";
      ui.promoKicker.style.display = kicker ? "" : "none";
      if (kicker) ui.promoKicker.textContent = kicker;

      ui.promoTitle.textContent = p.title || "Club Notes";
      ui.promoBody.textContent = p.body || "";

      const hasCta = !!(p.ctaText && p.ctaUrl);
      ui.promoCtaWrap.style.display = hasCta ? "" : "none";
      if (hasCta) ui.promoCtaText.textContent = `${p.ctaText} ${p.ctaUrl}`;

      applyPromoBackground(p, true);

      // ✅ NEW: promo QR (top-right)
      if (ui.promoQrWrap && ui.promoQrImg && ui.promoQrCaption) {
        const qrImgUrl = getPromoQrImageUrl(p); // uses p.qrSrc OR p.qrUrl OR p.ctaUrl
        const caption = (p.qrLabel || (p.qr && p.qr.label)) ? (p.qrLabel || p.qr.label) : "SCAN";

        if (qrImgUrl) {
          ui.promoQrWrap.style.display = "";
          ui.promoQrCaption.textContent = caption;
          ui.promoQrImg.src = qrImgUrl;
          ui.promoQrImg.alt = p.ctaText ? `Scan for ${p.ctaText}` : "Scan for details";
        } else {
          ui.promoQrWrap.style.display = "none";
          ui.promoQrImg.removeAttribute("src");
        }
      }

      renderDots();
    };

    if (immediate) { apply(); return; }

    ui.promoCard.classList.add("is-fading");
    if (ui.promoBg) ui.promoBg.classList.add("is-fading");
    if (ui.promoOverlay) ui.promoOverlay.classList.add("is-fading");

    // (Optional) fade QR too during transitions
    if (ui.promoQrWrap) ui.promoQrWrap.classList.add("is-fading");

    setTimeout(() => {
      apply();
      ui.promoCard.classList.remove("is-fading");
      if (ui.promoBg) ui.promoBg.classList.remove("is-fading");
      if (ui.promoOverlay) ui.promoOverlay.classList.remove("is-fading");
      if (ui.promoQrWrap) ui.promoQrWrap.classList.remove("is-fading");
    }, PROMO_FADE_MS);
  }

  function maybeRotatePromo() {
    if (eligiblePromos.length <= 1) return;
    const now = Date.now();
    if (!lastPromoSwapAt) lastPromoSwapAt = now;

    const cur = eligiblePromos[promoIndex];
    const dur = promoDurationMs(cur);

    if (now - lastPromoSwapAt < dur) return;

    lastPromoSwapAt = now;
    promoIndex = (promoIndex + 1) % eligiblePromos.length;
    renderPromo(false);
  }

  function setStatusPillClass(status) {
    ui.statusPill.classList.remove("is-prep", "is-ending", "is-ended");
    if (status === "PREP") ui.statusPill.classList.add("is-prep");
    else if (status === "ENDING") ui.statusPill.classList.add("is-ending");
    else if (status === "ENDED") ui.statusPill.classList.add("is-ended");
  }

  function render() {
    ui.nowClock.textContent = fmtClock(new Date());

    const st = normalizeStatus(state);
    ui.statusPill.textContent = st;
    setStatusPillClass(st);


    // Visual emphasis in the main card for key phases
    const sessionCard = document.querySelector('.abg-session');
    if (sessionCard) {
      sessionCard.classList.toggle('is-ending', st === 'ENDING');
    }


    const name = normalizeDisplayName(state);
    ui.displayName.textContent = name;

    const bay = normalizeBayLabel(state);
    ui.bayLabel.textContent = bay;

    // SINGLE bay display: header pill only
    ui.headerBayPill.style.display = bay ? "" : "none";
    ui.headerBayPill.textContent = bay ? bay.toUpperCase() : "BAY";

    const helpUrl = normalizeHelpUrl(state);
    ui.helpUrlText.textContent = helpUrl;

    const cust = state.customer || {};
    const isMember = !!cust.isMember;
    ui.memberPill.style.display = isMember ? "" : "none";
    if (isMember) ui.memberPill.textContent = "Member";

    const tier = pick(cust.membership || {}, "tier");
    ui.tierPill.style.display = tier ? "" : "none";
    if (tier) ui.tierPill.textContent = tier;

    const { start, end } = getStartEndUtc(state);
    ui.startLocal.textContent = formatLocalTime(start);
    ui.endLocal.textContent = formatLocalTime(end);

    // Countdown logic:
    // - PREP => countdown to START
    // - ACTIVE/ENDING => countdown to END
    if (st === "PREP" && start) {
      ui.countdown.textContent = formatRemaining(start.getTime() - Date.now());
    } else if ((st === "ACTIVE" || st === "ENDING") && end) {
      ui.countdown.textContent = formatRemaining(end.getTime() - Date.now());
    } else if (st === "ENDED") {
      ui.countdown.textContent = "00:00";
    } else {
      ui.countdown.textContent = "--:--";
    }

    // Banner (shown only when both bannerText and statusDetail are provided)
    // If statusDetail is blank, we intentionally rely on computeStatusDetail() which can fall back to bannerText.
    const bannerRaw = (pick(state, "bannerText") || "").trim();
    const statusDetailRaw = (pick(state, "statusDetail") || "").trim();
    const showBanner = !!bannerRaw && !!statusDetailRaw && st !== "PREP";
    if (ui.bannerText) {
      ui.bannerText.style.display = showBanner ? "" : "none";
      ui.bannerText.textContent = showBanner ? bannerRaw : "";
    }

    ui.statusDetail.textContent = computeStatusDetail(state, st, start, end);

    const pct = computeProgressPercent(start, end);
    ui.progressFill.style.width = `${pct.toFixed(1)}%`;

    const showDebug = pick(state, "showDebug");
    if (showDebug === false || showDebug === "false") ui.debugLine.classList.add("is-hidden");
    else {
      ui.debugLine.classList.remove("is-hidden");
      if (loadOk) {
        const u = pick(state, "updatedUtc") || "--";
        ui.debugLine.textContent = `Updated: ${u} • Source: ${pick(state, "_source") || "--"}`;
      } else {
        ui.debugLine.textContent = `No data • ${lastErr || "waiting…"}`;
      }
    }

    recomputeEligiblePromos(state);
    maybeRotatePromo();
  }

  async function loadPromos() {
    try {
      const p = await fetchJsonAny(PROMOS_PATHS);
      promos = Array.isArray(p) ? p : (Array.isArray(p.promos) ? p.promos : []);
      if (!Array.isArray(promos)) promos = [];
    } catch (_) {
      promos = [];
    }
  }

  async function refreshSession() {
    try {
      const obj = await fetchJsonAny(SESSION_JSON_PATHS);
      state = { ...DEFAULT_STATE, ...obj, _source: obj._source };
      loadOk = true; lastErr = "";
    } catch (e1) {
      try {
        const obj = await loadJsOnce(SESSION_JS_PATHS);
        state = { ...DEFAULT_STATE, ...obj, _source: obj._source };
        loadOk = true; lastErr = "";
      } catch (e2) {
        loadOk = false;
        lastErr = (e2 && e2.message) ? e2.message : String(e2);
      }
    }
  }

  (async () => {
    await loadPromos();
    await refreshSession();
    render();
    setInterval(loadPromos, 60000);
    setInterval(refreshSession, DATA_POLL_MS);
    setInterval(render, UI_TICK_MS);
  })();
})();
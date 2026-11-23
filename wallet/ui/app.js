"use strict";
const { invoke } = window.__TAURI__.core;

const I18N = {
  ar: {
    balance: "الرصيد", send: "إرسال", receive: "استلام", peers: "العقد المتصلة", height: "ارتفاع السلسلة",
    receiveHint: "شارك هذا العنوان لاستلام RiyalCoin. يُفضّل استخدام عنوان جديد لكل عملية.",
    copy: "نسخ", copied: "تم النسخ", newAddr: "عنوان جديد", toAddr: "عنوان المستلم", amount: "المبلغ (RYL)",
    feeNote: "تُضاف رسوم الشبكة تلقائيًا.", review: "مراجعة", history: "السجل", noTx: "لا توجد معاملات بعد.",
    network: "الشبكة", seeds: "عقد البذور (seed) — سطر لكل host:port", saveRestart: "حفظ وإعادة التشغيل",
    seedHint: "لا توجد عقد بذور مدمجة؛ أدخل عقدة منشورة من مُطلِق الشبكة.",
    security: "الأمان", encStatus: "تشفير المحفظة", encrypt: "تشفير المحفظة", lockNow: "قفل الآن",
    backup: "نسخة احتياطية من المحفظة", cancel: "إلغاء", confirm: "تأكيد",
    tabHome: "الرئيسية", tabSend: "إرسال", tabReceive: "استلام", tabHistory: "السجل", tabSettings: "الإعدادات",
    starting: "جارٍ تشغيل العقدة…", synced: "الكتل", warn: "برنامج غير مُدقَّق أمنيًا. لا تستخدمه بأموال حقيقية قبل مراجعة مستقلة.",
    confirmSend: "تأكيد الإرسال", sendTo: "إرسال", to: "إلى", pass: "عبارة المرور", pass2: "أعد كتابة عبارة المرور",
    encTitle: "تشفير المحفظة", encWarn: "اختر عبارة مرور (8 أحرف على الأقل). إن فقدتها فلن تستطيع استعادة أموالك.",
    unlockTitle: "فتح المحفظة", sent: "تم الإرسال. المعرّف: ", yes: "مشفّرة", no: "غير مشفّرة", locked: " (مقفلة)",
    mismatch: "عبارتا المرور غير متطابقتين", encDone: "تم تشفير المحفظة", lockedOk: "تم القفل",
    backupDone: "تم حفظ النسخة في: ", backupWarn: "النسخة تحتوي مفاتيحك (يُفضّل تشفير المحفظة أولًا). انسخ النص أدناه واحفظه في مكان آمن.",
    saved: "تم الحفظ. أعد تشغيل التطبيق لتطبيق الإعدادات.", send_cat: "إرسال", receive_cat: "استلام", generate_cat: "تعدين",
    unconf: "غير مؤكدة", scan: "مسح QR بالكاميرا", scanNA: "المسح بالكاميرا متاح في تطبيق الهاتف فقط؛ الصق العنوان.",
    restoreLbl: "استعادة من نسخة احتياطية (الصق النص)", restore: "استعادة المحفظة",
    restoreWarn: "ستُستبدل المحفظة الحالية بالنسخة الملصقة (تُحفظ القديمة باسم wallet.dat.bak). سيُعاد تشغيل التطبيق.", restoreDone: "تمت الاستعادة. أعد فتح التطبيق إن لم يُعد تشغيله."
  },
  en: {
    balance: "Balance", send: "Send", receive: "Receive", peers: "Connected peers", height: "Chain height",
    receiveHint: "Share this address to receive RiyalCoin. Prefer a fresh address for each payment.",
    copy: "Copy", copied: "Copied", newAddr: "New address", toAddr: "Recipient address", amount: "Amount (RYL)",
    feeNote: "Network fee is added automatically.", review: "Review", history: "History", noTx: "No transactions yet.",
    network: "Network", seeds: "Seed nodes — one host:port per line", saveRestart: "Save and restart",
    seedHint: "There are no built-in seeds; enter a node published by whoever launches the network.",
    security: "Security", encStatus: "Wallet encryption", encrypt: "Encrypt wallet", lockNow: "Lock now",
    backup: "Back up wallet", cancel: "Cancel", confirm: "Confirm",
    tabHome: "Home", tabSend: "Send", tabReceive: "Receive", tabHistory: "History", tabSettings: "Settings",
    starting: "Starting node…", synced: "Blocks", warn: "Not independently audited. Do not use with real funds before a security review.",
    confirmSend: "Confirm payment", sendTo: "Send", to: "to", pass: "Passphrase", pass2: "Repeat passphrase",
    encTitle: "Encrypt wallet", encWarn: "Choose a passphrase (min 8 chars). If you lose it your funds cannot be recovered.",
    unlockTitle: "Unlock wallet", sent: "Sent. Transaction id: ", yes: "encrypted", no: "not encrypted", locked: " (locked)",
    mismatch: "Passphrases do not match", encDone: "Wallet encrypted", lockedOk: "Locked",
    backupDone: "Backup saved to: ", backupWarn: "The backup contains your keys (encrypt the wallet first). Copy the text below and keep it safe.",
    saved: "Saved. Restart the app to apply.", send_cat: "send", receive_cat: "receive", generate_cat: "mined",
    unconf: "unconfirmed", scan: "Scan QR with camera", scanNA: "Camera scanning is available in the phone app only; paste the address.",
    restoreLbl: "Restore from backup (paste text)", restore: "Restore wallet",
    restoreWarn: "The current wallet will be replaced by the pasted backup (the old one is kept as wallet.dat.bak). The app will restart.", restoreDone: "Restored. Reopen the app if it does not restart."
  }
};

let lang = "ar";
try { const s = localStorage.getItem("lang"); if (s === "ar" || s === "en") lang = s; } catch (_) {}
const t = (k) => (I18N[lang] && I18N[lang][k]) || k;
const $ = (id) => document.getElementById(id);

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  $("langBtn").textContent = lang === "ar" ? "EN" : "ع";
  $("banner").textContent = t("warn");
  $("banner").hidden = false;
  refresh();
}
$("langBtn").onclick = () => {
  lang = lang === "ar" ? "en" : "ar";
  try { localStorage.setItem("lang", lang); } catch (_) {}
  applyLang();
};

// ---- navigation
function go(page) {
  document.querySelectorAll(".page").forEach((p) => (p.hidden = p.id !== "page-" + page));
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.go === page));
  if (page === "receive" && $("addr").textContent === "—") newAddress();
  if (page === "history") loadHistory();
  if (page === "settings") loadSettings();
}
document.querySelectorAll("[data-go]").forEach((b) => (b.onclick = () => go(b.dataset.go)));

// ---- rpc helper
const rpc = (method, params = []) => invoke("rpc", { method, params });
function setMsg(id, text, cls) { const e = $(id); e.textContent = text || ""; e.className = "msg " + (cls || ""); }
const errText = (e) => (typeof e === "string" ? e : (e && e.message) || String(e));

// ---- dialog (passphrase / confirmation)
function ask({ title, body = "", pass = 0, ok }) {
  return new Promise((resolve) => {
    const d = $("dlg");
    $("dlgTitle").textContent = title;
    $("dlgBody").textContent = body;
    const p1 = $("dlgPass"), p2 = $("dlgPass2");
    p1.hidden = pass < 1; p2.hidden = pass < 2;
    p1.value = ""; p2.value = "";
    p1.placeholder = t("pass"); p2.placeholder = t("pass2");
    $("dlgOk").textContent = ok || t("confirm");
    const done = (v) => { d.close(); p1.value = ""; p2.value = ""; resolve(v); };
    $("dlgCancel").onclick = () => done(null);
    $("dlgForm").onsubmit = (e) => { e.preventDefault(); done({ p1: p1.value, p2: p2.value }); };
    d.oncancel = () => resolve(null);
    d.showModal();
    if (pass) p1.focus();
  });
}

// ---- state refresh
let walletInfo = { encrypted: false, locked: false };
let startedOnce = false;

async function refresh() {
  try {
    const st = await invoke("node_status");
    if (st === "starting") { $("syncLine").textContent = t("starting"); return; }
    if (st.startsWith("error")) { $("syncLine").textContent = st; return; }
    const [info, bal, wi] = await Promise.all([rpc("getinfo"), rpc("getbalance"), rpc("getwalletinfo")]);
    walletInfo = wi;
    $("bal").textContent = bal;
    $("peers").textContent = info.peers;
    $("height").textContent = info.blocks;
    $("netBadge").textContent = info.chain;
    $("syncLine").textContent = t("synced") + ": " + info.blocks;
    startedOnce = true;
  } catch (e) {
    $("syncLine").textContent = errText(e);
  }
}
setInterval(refresh, 5000);

// ---- receive
async function newAddress() {
  try {
    const a = await rpc("getnewaddress");
    $("addr").textContent = a;
    QR.draw($("qr"), a, 8);
  } catch (e) { $("addr").textContent = errText(e); $("qr").width = 0; }
}
$("newAddr").onclick = newAddress;
$("copyAddr").onclick = async () => {
  try { await navigator.clipboard.writeText($("addr").textContent); $("copyAddr").textContent = t("copied"); }
  catch (_) {}
  setTimeout(() => ($("copyAddr").textContent = t("copy")), 1200);
};

// ---- send
async function unlockIfNeeded() {
  const wi = await rpc("getwalletinfo");
  if (!(wi.encrypted && wi.locked)) return true;
  const r = await ask({ title: t("unlockTitle"), pass: 1 });
  if (!r) return false;
  await rpc("walletpassphrase", [r.p1, "60"]);
  return true;
}
$("sendForm").onsubmit = async (e) => {
  e.preventDefault();
  setMsg("sendMsg", "");
  const to = $("toAddr").value.trim();
  const amt = $("sendAmt").value.trim().replace(",", ".");
  if (!/^\d+(\.\d{1,11})?$/.test(amt) || Number(amt) <= 0) return setMsg("sendMsg", t("amount"), "err");
  const r = await ask({ title: t("confirmSend"), body: `${t("sendTo")} ${amt} RYL ${t("to")}\n${to}` });
  if (!r) return;
  try {
    if (!(await unlockIfNeeded())) return;
    const id = await rpc("sendtoaddress", [to, amt]);
    setMsg("sendMsg", t("sent") + id, "ok");
    $("toAddr").value = ""; $("sendAmt").value = "";
    if (walletInfo.encrypted) rpc("walletlock").catch(() => {});
    refresh();
  } catch (err) { setMsg("sendMsg", errText(err), "err"); }
};

// ---- camera QR scan (native scanner on Android/iOS)
$("scanBtn").onclick = async () => {
  setMsg("sendMsg", "");
  const bs = window.__TAURI__ && window.__TAURI__.barcodeScanner;
  if (!bs) return setMsg("sendMsg", t("scanNA"), "err");
  try {
    if (bs.requestPermissions) await bs.requestPermissions();
    const r = await bs.scan({ windowed: false, formats: ["QR_CODE"] });
    let text = (r && r.content ? r.content : "").trim();
    // accept "riyalcoin:ADDRESS?amount=1.5" as well as a bare address
    const m = text.match(/^riyalcoin:([^?]+)(?:\?(.*))?$/i);
    if (m) {
      text = m[1];
      const am = /(?:^|&)amount=([0-9.]+)/.exec(m[2] || "");
      if (am) $("sendAmt").value = am[1];
    }
    if (text) $("toAddr").value = text;
  } catch (e) { setMsg("sendMsg", errText(e), "err"); }
};

// ---- history
async function loadHistory() {
  const ul = $("txList");
  ul.textContent = "";
  try {
    const items = (await rpc("listtransactions", ["50"])).reverse();
    $("txEmpty").hidden = items.length > 0;
    for (const x of items) {
      const li = document.createElement("li");
      const left = document.createElement("div");
      const cat = document.createElement("div");
      cat.textContent = t(x.category + "_cat") !== x.category + "_cat" ? t(x.category + "_cat") : x.category;
      const id = document.createElement("div");
      id.className = "id"; id.textContent = x.txid;
      left.append(cat, id);
      const amt = document.createElement("b");
      amt.dir = "ltr";
      amt.className = String(x.amount).startsWith("-") ? "neg" : "pos";
      amt.textContent = x.amount;
      li.append(left, amt);
      ul.append(li);
    }
  } catch (e) { $("txEmpty").hidden = false; $("txEmpty").textContent = errText(e); }
}

// ---- settings
async function loadSettings() {
  try {
    const c = await invoke("get_config");
    $("netSel").value = c.net;
    $("seeds").value = (c.seeds || []).join("\n");
    const wi = await rpc("getwalletinfo");
    walletInfo = wi;
    $("encState").textContent = (wi.encrypted ? t("yes") : t("no")) + (wi.encrypted && wi.locked ? t("locked") : "");
    $("encBtn").disabled = wi.encrypted;
    $("lockBtn").disabled = !wi.encrypted || wi.locked;
  } catch (e) { setMsg("setMsg", errText(e), "err"); }
}
$("saveCfg").onclick = async () => {
  try {
    await invoke("set_config", { net: $("netSel").value, seeds: $("seeds").value.split("\n") });
    setMsg("setMsg", t("saved"), "ok");
    setTimeout(() => invoke("restart_app"), 900);
  } catch (e) { setMsg("setMsg", errText(e), "err"); }
};
$("encBtn").onclick = async () => {
  const r = await ask({ title: t("encTitle"), body: t("encWarn"), pass: 2 });
  if (!r) return;
  if (r.p1 !== r.p2) return setMsg("setMsg", t("mismatch"), "err");
  try { await rpc("encryptwallet", [r.p1]); setMsg("setMsg", t("encDone"), "ok"); loadSettings(); }
  catch (e) { setMsg("setMsg", errText(e), "err"); }
};
$("lockBtn").onclick = async () => {
  try { await rpc("walletlock"); setMsg("setMsg", t("lockedOk"), "ok"); loadSettings(); }
  catch (e) { setMsg("setMsg", errText(e), "err"); }
};
$("backupBtn").onclick = async () => {
  try {
    const r = await invoke("backup_wallet");
    setMsg("setMsg", t("backupDone") + r.path + " — " + t("backupWarn"), "ok");
    $("bkText").value = r.hex; $("bkBox").hidden = false;
  }
  catch (e) { setMsg("setMsg", errText(e), "err"); }
};

$("restoreBtn").onclick = async () => {
  const text = $("rsText").value.trim();
  if (!text) return;
  const r = await ask({ title: t("restore"), body: t("restoreWarn") });
  if (!r) return;
  try {
    await invoke("restore_wallet", { backupHex: text });
    $("rsText").value = "";
    setMsg("setMsg", t("restoreDone"), "ok");
    setTimeout(() => invoke("restart_app"), 1200);
  } catch (e) { setMsg("setMsg", errText(e), "err"); }
};
$("bkCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("bkText").value); $("bkCopy").textContent = t("copied"); } catch (_) {}
  setTimeout(() => ($("bkCopy").textContent = t("copy")), 1200);
};

applyLang();
go("home");

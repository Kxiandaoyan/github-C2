// i18n.js v3 — 中英文切换（安全版：不影响主应用，出错静默降级）
//
// 设计原则：
// 1. 所有操作 try-catch 包裹，任何异常不影响页面正常加载
// 2. 延迟执行：等 app.js 完成初始化后再做 DOM 扫描
// 3. MutationObserver 只观察新增节点，不干扰现有 DOM

const PACK = { zh: window.LANG_ZH || {}, en: window.LANG_EN || {} };
let currentLang = "zh";
const ORIGINALS = new Map();  // 元素→原始文本

function initI18n() {
  try {
    const saved = localStorage.getItem("panel-lang");
    if (saved === "en" || saved === "zh") {
      currentLang = saved;
    } else {
      const bl = (navigator.language || "en").toLowerCase();
      currentLang = bl.startsWith("zh") ? "zh" : "en";
    }
    if (currentLang === "en") {
      // 延迟 1s 等 app.js 初始化完成后再翻译
      setTimeout(() => safeApplyI18n(currentLang), 1000);
    }
    updateToggleBtn();
  } catch(e) { console.warn("i18n init:", e); }
}

function toggleLang() {
  try {
    currentLang = currentLang === "zh" ? "en" : "zh";
    localStorage.setItem("panel-lang", currentLang);
    safeApplyI18n(currentLang);
    updateToggleBtn();
  } catch(e) { console.warn("i18n toggle:", e); }
}

function t(zh) { return currentLang === "en" ? (PACK.en[zh] || zh) : zh; }

function updateToggleBtn() {
  const btn = document.getElementById("lang-toggle");
  if (btn) btn.textContent = currentLang === "zh" ? "EN" : "中文";
}

function translateText(text) {
  if (!text || currentLang === "zh") return null;
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (PACK.en[trimmed]) return PACK.en[trimmed];
  return null;
}

function safeApplyI18n(lang) {
  try {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";

    // 只处理有直接中文文本的叶子元素（不递归整个 DOM）
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: (node) => {
        if (!node.textContent || !node.textContent.trim()) return NodeFilter.FILTER_REJECT;
        if (node.parentElement && ["SCRIPT","STYLE","CODE","PRE"].includes(node.parentElement.tagName))
          return NodeFilter.FILTER_REJECT;
        return /[\u4e00-\u9fff]/.test(node.textContent) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    }, false);

    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const node of nodes) {
      const parent = node.parentElement;
      if (!parent) continue;
      const key = ORIGINALS.get(parent) || node.textContent.trim();
      ORIGINALS.set(parent, key);
      if (lang === "zh") {
        node.textContent = key;  // 恢复原文
      } else {
        const translated = translateText(key);
        if (translated) node.textContent = translated;
      }
    }

    // placeholder
    document.querySelectorAll("[placeholder]").forEach(el => {
      const key = ORIGINALS.get(el) || el.placeholder;
      if (!ORIGINALS.has(el)) ORIGINALS.set(el, key);
      if (lang === "en") {
        const translated = translateText(key);
        if (translated) el.placeholder = translated;
      } else {
        el.placeholder = key;
      }
    });

    // title (tooltip)
    document.querySelectorAll("[title]").forEach(el => {
      if (!ORIGINALS.has(el)) ORIGINALS.set(el, { title: el.title });
      const orig = ORIGINALS.get(el);
      if (lang === "en") {
        const translated = translateText(orig.title);
        if (translated) el.title = translated;
      } else {
        el.title = orig.title;
      }
    });

    // data-i18n 显式标注（最高优先级）
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const key = el.dataset.i18n;
      const pack = PACK[lang];
      if (pack && pack[key]) el.textContent = pack[key];
    });

  } catch(e) { console.warn("i18n apply:", e); }
}

// MutationObserver（安全版：只处理新增的文本节点，不遍历整棵树）
let observer = null;
function startObserver() {
  try {
    if (observer) observer.disconnect();
    if (currentLang === "zh") return;  // 中文模式不需要观察
    observer = new MutationObserver((mutations) => {
      if (currentLang === "zh") return;
      for (const mut of mutations) {
        for (const node of mut.addedNodes) {
          if (node.nodeType === Node.TEXT_NODE && /[\u4e00-\u9fff]/.test(node.textContent || "")) {
            const translated = translateText(node.textContent.trim());
            if (translated) node.textContent = translated;
          } else if (node.nodeType === Node.ELEMENT_NODE && node.children.length === 0) {
            const translated = translateText(node.textContent.trim());
            if (translated) node.textContent = translated;
          }
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: false });
  } catch(e) { console.warn("i18n observer:", e); }
}

// 页面就绪后启动
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => { initI18n(); startObserver(); });
} else {
  initI18n();
  startObserver();
}

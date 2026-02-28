/**
 * background.js — Service Worker for Tech Detector.
 * Handles: on-demand detection (triggered by popup click), header detection
 * via fetch, programmatic content script injection, badge updates.
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  // In-memory detection store: tabId -> { url, detections[] }
  const tabDetections = {};

  // Pending detection promises: tabId -> { resolve, timer }
  const pendingDetections = new Map();

  // Load technologies.json
  let technologies = null;
  async function loadTechnologies() {
    try {
      const url = api.runtime.getURL('technologies.json');
      const resp = await fetch(url);
      technologies = await resp.json();
    } catch (e) {
      console.error('Tech Detector: Failed to load technologies.json', e);
    }
  }

  /**
   * Detect technologies from response headers.
   */
  function detectFromHeaders(techs, headers) {
    const results = [];
    for (const tech of techs) {
      if (!tech.headers) continue;
      for (const [headerName, pattern] of Object.entries(tech.headers)) {
        const value = headers[headerName.toLowerCase()];
        if (value === undefined) continue;
        if (!pattern) {
          results.push({
            name: tech.name,
            category: tech.category,
            version: null,
            methods: ['headers']
          });
          break;
        }
        try {
          const re = new RegExp(pattern, 'i');
          const match = re.exec(value);
          if (match) {
            results.push({
              name: tech.name,
              category: tech.category,
              version: match[1] || null,
              methods: ['headers']
            });
            break;
          }
        } catch {
          // invalid regex
        }
      }
    }
    return results;
  }

  /**
   * Merge new detections into existing ones for a tab.
   */
  function mergeDetections(existing, incoming) {
    const map = new Map();
    for (const d of existing) {
      map.set(d.name, { ...d, methods: [...(d.methods || [])] });
    }
    for (const d of incoming) {
      const e = map.get(d.name);
      if (e) {
        if (!e.version && d.version) e.version = d.version;
        for (const m of (d.methods || [])) {
          if (!e.methods.includes(m)) e.methods.push(m);
        }
      } else {
        map.set(d.name, {
          name: d.name,
          category: d.category,
          version: d.version || null,
          methods: [...(d.methods || [])]
        });
      }
    }
    return Array.from(map.values());
  }

  /**
   * Update the extension badge for a tab.
   */
  function updateBadge(tabId) {
    const data = tabDetections[tabId];
    const count = data ? data.detections.length : 0;
    const text = count > 0 ? String(count) : '';
    api.action.setBadgeText({ text, tabId });
    api.action.setBadgeBackgroundColor({ color: '#4A90D9', tabId });
  }

  /**
   * Run full detection for a tab (headers via fetch + content script injection).
   */
  async function runDetection(tabId, tabUrl) {
    // Cancel any pending detection for this tab
    if (pendingDetections.has(tabId)) {
      clearTimeout(pendingDetections.get(tabId).timer);
      pendingDetections.delete(tabId);
    }

    // Reset detections
    tabDetections[tabId] = { url: tabUrl, detections: [] };

    if (!technologies) await loadTechnologies();
    if (!technologies) return tabDetections[tabId];

    // 1. Header detection via fetch
    try {
      const resp = await fetch(tabUrl, { method: 'HEAD' });
      const headers = {};
      resp.headers.forEach((value, name) => {
        headers[name.toLowerCase()] = value;
      });
      const headerResults = detectFromHeaders(technologies.technologies, headers);
      if (headerResults.length > 0) {
        tabDetections[tabId].detections = mergeDetections(
          tabDetections[tabId].detections,
          headerResults
        );
      }
    } catch {
      // Fetch may fail for chrome://, file://, etc.
    }

    // 2. Inject content scripts programmatically
    try {
      await api.scripting.executeScript({
        target: { tabId },
        files: ['browser-polyfill.js', 'detect.js', 'content.js']
      });
      await api.scripting.executeScript({
        target: { tabId },
        files: ['content-main.js'],
        world: 'MAIN'
      });
    } catch {
      // May fail on restricted pages (chrome://, about://, etc.)
      updateBadge(tabId);
      return tabDetections[tabId];
    }

    // 3. Wait for content script results (with timeout)
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingDetections.delete(tabId);
        updateBadge(tabId);
        resolve(tabDetections[tabId]);
      }, 3000);

      pendingDetections.set(tabId, { resolve, timer });
    });
  }

  // Listen for messages
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Content script detection results
    if (message.type === 'DETECTION_RESULT' && sender.tab) {
      const tabId = sender.tab.id;
      if (!tabDetections[tabId]) {
        tabDetections[tabId] = {
          url: message.url || sender.tab.url,
          detections: []
        };
      }
      tabDetections[tabId].detections = mergeDetections(
        tabDetections[tabId].detections,
        message.detections || []
      );

      // Resolve pending detection if any
      if (pendingDetections.has(tabId)) {
        const pending = pendingDetections.get(tabId);
        clearTimeout(pending.timer);
        updateBadge(tabId);
        pending.resolve(tabDetections[tabId]);
        pendingDetections.delete(tabId);
      }

      return false;
    }

    // Run detection (triggered by popup click)
    if (message.type === 'RUN_DETECTION') {
      runDetection(message.tabId, message.url).then((result) => {
        sendResponse(result);
      }).catch(() => {
        sendResponse({ url: message.url || '', detections: [] });
      });
      return true; // async sendResponse
    }

    // Get cached detections
    if (message.type === 'GET_DETECTIONS') {
      const data = tabDetections[message.tabId] || { url: '', detections: [] };
      sendResponse(data);
      return false;
    }

    return false;
  });

  // Open popup window centered on screen
  api.action.onClicked.addListener(async (tab) => {
    const width = 750;
    const height = 900;
    const currentWindow = await api.windows.getCurrent();
    const left = Math.round(currentWindow.left + (currentWindow.width - width) / 2);
    const top = Math.round(currentWindow.top + (currentWindow.height - height) / 2);
    const params = new URLSearchParams({ tabId: tab.id, tabUrl: tab.url });
    api.windows.create({
      url: `${api.runtime.getURL('popup.html')}?${params}`,
      type: 'popup',
      width,
      height,
      left,
      top
    });
  });

  // Clean up when tabs are closed
  api.tabs.onRemoved.addListener((tabId) => {
    delete tabDetections[tabId];
    if (pendingDetections.has(tabId)) {
      clearTimeout(pendingDetections.get(tabId).timer);
      pendingDetections.delete(tabId);
    }
  });

  // Initialize
  loadTechnologies();
})();

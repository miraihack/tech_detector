/**
 * popup.js — Popup UI logic for Tech Detector.
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  const CATEGORY_LABELS = {
    'js-framework': 'JS フレームワーク',
    'js-library': 'JS ライブラリ',
    'css-framework': 'CSS フレームワーク',
    'cms': 'CMS / EC',
    'server': 'Web サーバー',
    'analytics': 'アナリティクス',
    'cdn': 'CDN',
    'font': 'フォント',
    'hosting': 'ホスティング',
    'build': 'ビルドツール',
    'security': 'セキュリティ',
    'os': 'サーバー OS'
  };

  const CATEGORY_ORDER = [
    'js-framework', 'js-library', 'css-framework', 'cms', 'server', 'os',
    'analytics', 'cdn', 'font', 'hosting', 'build', 'security'
  ];

  function getHostname(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url || '';
    }
  }

  /**
   * Extract registered domain from a hostname.
   */
  function getRegisteredDomain(hostname) {
    const h = hostname.replace(/^www\./, '');
    const parts = h.split('.');
    const ccSld = ['co', 'com', 'net', 'org', 'ac', 'gov', 'edu', 'ne', 'or'];
    if (parts.length >= 3) {
      const sld = parts[parts.length - 2];
      if (ccSld.includes(sld) && parts[parts.length - 1].length <= 2) {
        return parts.slice(-3).join('.');
      }
    }
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return h;
  }

  // ─── DNS helpers ───

  async function queryTxt(name) {
    const resp = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`
    );
    if (!resp.ok) return [];
    const data = await resp.json();
    if (data.Status !== 0 || !data.Answer) return [];
    return data.Answer
      .filter(a => a.type === 16)
      .map(a => a.data.replace(/^"|"$/g, ''));
  }

  // ─── Email Authentication ───

  async function checkEmailAuth(tabUrl) {
    const parsed = new URL(tabUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;

    const domain = getRegisteredDomain(parsed.hostname);
    const dkimSelectors = [
      'default', 'google', 'selector1', 'selector2',
      'k1', 's1', 's2', 'dkim', 'mail'
    ];

    const [spfRecords, dmarcRecords, ...dkimResults] = await Promise.all([
      queryTxt(domain),
      queryTxt(`_dmarc.${domain}`),
      ...dkimSelectors.map(sel => queryTxt(`${sel}._domainkey.${domain}`))
    ]);

    const spfRecord = spfRecords.find(r => r.startsWith('v=spf1'));
    const dmarcRecord = dmarcRecords.find(r =>
      r.toUpperCase().startsWith('V=DMARC1')
    );

    let dkimFound = null;
    for (let i = 0; i < dkimSelectors.length; i++) {
      const record = dkimResults[i].find(r =>
        r.toUpperCase().includes('V=DKIM1')
      );
      if (record) {
        dkimFound = { selector: dkimSelectors[i], record };
        break;
      }
    }

    return { spf: spfRecord || null, dmarc: dmarcRecord || null, dkim: dkimFound };
  }

  // ─── Encryption / TLS ───

  async function checkEncryption(tabId, tabUrl) {
    const isHttps = tabUrl.startsWith('https://');
    if (!isHttps) return { https: false };

    const domain = getRegisteredDomain(new URL(tabUrl).hostname);

    const [httpResult, headResp, sslData] = await Promise.all([
      // HTTP protocol version from content script
      api.scripting.executeScript({
        target: { tabId },
        func: () => {
          const e = performance.getEntriesByType('navigation');
          return e[0] ? e[0].nextHopProtocol : '';
        }
      }).catch(() => [{ result: '' }]),

      // HSTS from HEAD response
      fetch(tabUrl, { method: 'HEAD' }).catch(() => null),

      // SSL Labs cached TLS data (4s timeout)
      fetchWithTimeout(
        `https://api.ssllabs.com/api/v3/analyze?host=${domain}&fromCache=on&all=done`,
        4000
      ).then(r => r.ok ? r.json() : null).catch(() => null)
    ]);

    const result = { https: true };

    // HTTP version
    const proto = httpResult[0]?.result || '';
    const protoMap = { 'h2': 'HTTP/2', 'h3': 'HTTP/3', 'http/1.1': 'HTTP/1.1' };
    result.httpVersion = protoMap[proto] || proto || null;

    // HSTS
    if (headResp) {
      result.hsts = headResp.headers.get('strict-transport-security') || null;
    }

    // SSL Labs
    if (sslData && sslData.status === 'READY') {
      // Endpoint TLS details
      if (sslData.endpoints) {
        const ep = sslData.endpoints.find(e => e.grade) || sslData.endpoints[0];
        if (ep) {
          result.grade = ep.grade || null;
          const details = ep.details;
          if (details) {
            if (details.protocols) {
              result.tlsVersions = details.protocols
                .filter(p => p.name === 'TLS')
                .map(p => p.version)
                .sort()
                .reverse();
            }
            if (details.suites) {
              const sorted = [...details.suites].sort((a, b) => (b.protocol || 0) - (a.protocol || 0));
              for (const suite of sorted) {
                if (suite.list && suite.list.length > 0) {
                  result.cipher = suite.list[0].name;
                  result.cipherStrength = suite.list[0].cipherStrength;
                  break;
                }
              }
            }
          }
        }
      }

      // Certificate info (leaf cert is first in certs array)
      if (sslData.certs && sslData.certs.length > 0) {
        const leaf = sslData.certs[0];
        result.cert = {
          subject: leaf.subject || null,
          issuer: leaf.issuerSubject || null,
          sigAlg: leaf.sigAlg || null,
          keyAlg: leaf.keyAlg || null,
          keySize: leaf.keySize || null,
          notBefore: leaf.notBefore || null,
          notAfter: leaf.notAfter || null,
          altNames: leaf.altNames || null
        };
      }
    }

    return result;
  }

  function fetchWithTimeout(url, ms) {
    return fetch(url, { signal: AbortSignal.timeout(ms) });
  }

  // ─── Shared UI helpers ───

  function createTechIcon(tech) {
    const icon = document.createElement('img');
    icon.className = 'tech-icon';
    icon.src = `techs/${tech.icon || tech.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '.svg'}`;
    icon.alt = tech.name;
    icon.onerror = function () {
      const placeholder = document.createElement('div');
      placeholder.className = 'tech-icon-placeholder';
      placeholder.textContent = tech.name.charAt(0).toUpperCase();
      this.replaceWith(placeholder);
    };
    return icon;
  }

  /**
   * Create a row for info sections (Encryption / Email Auth).
   * @param {'pass'|'fail'|'neutral'} status
   * @param {string} label
   * @param {string} detail
   */
  function createInfoRow(status, label, detail) {
    const row = document.createElement('div');
    row.className = 'info-row';

    const dot = document.createElement('span');
    dot.className = `info-status ${status}`;
    row.appendChild(dot);

    const nameEl = document.createElement('span');
    nameEl.className = 'info-label';
    nameEl.textContent = label;
    row.appendChild(nameEl);

    const detailEl = document.createElement('span');
    detailEl.className = 'info-detail';
    detailEl.textContent = detail;
    row.appendChild(detailEl);

    return row;
  }

  // ─── Render functions ───

  function renderEncryption(data) {
    const section = document.getElementById('encryption-section');
    const content = document.getElementById('encryption-content');

    if (!data) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    content.innerHTML = '';

    if (!data.https) {
      content.appendChild(createInfoRow('fail', 'プロトコル', 'HTTP（暗号化なし）'));
      return;
    }

    // Protocol + grade
    const protoDetail = data.grade ? `HTTPS（グレード: ${data.grade}）` : 'HTTPS';
    content.appendChild(createInfoRow('pass', 'プロトコル', protoDetail));

    // TLS versions
    if (data.tlsVersions && data.tlsVersions.length > 0) {
      const hasTls13 = data.tlsVersions.includes('1.3');
      content.appendChild(createInfoRow(
        hasTls13 ? 'pass' : 'neutral',
        'TLS',
        data.tlsVersions.map(v => `${v}`).join(', ')
      ));
    }

    // Cipher suite
    if (data.cipher) {
      const detail = data.cipherStrength
        ? `${data.cipher} (${data.cipherStrength}-bit)`
        : data.cipher;
      content.appendChild(createInfoRow('pass', '暗号スイート', detail));
    }

    // HTTP version
    if (data.httpVersion) {
      content.appendChild(createInfoRow('pass', 'HTTP', data.httpVersion));
    }

    // HSTS
    content.appendChild(createInfoRow(
      data.hsts ? 'pass' : 'fail',
      'HSTS',
      data.hsts || '未設定'
    ));
  }

  function formatCertDate(ms) {
    if (!ms) return null;
    try {
      return new Date(ms).toLocaleDateString('ja-JP', {
        year: 'numeric', month: 'short', day: 'numeric'
      });
    } catch {
      return null;
    }
  }

  /**
   * Extract human-readable issuer name from issuerSubject DN.
   * e.g. "CN=R3, O=Let's Encrypt, C=US" → "Let's Encrypt"
   * e.g. "CN=WE2, O=Google Trust Services, C=US" → "Google Trust Services"
   */
  function extractIssuerName(issuerSubject) {
    if (!issuerSubject) return null;
    // Try O= (Organization) first
    const oMatch = issuerSubject.match(/O=([^,]+)/);
    if (oMatch) return oMatch[1].trim();
    // Fall back to CN=
    const cnMatch = issuerSubject.match(/CN=([^,]+)/);
    if (cnMatch) return cnMatch[1].trim();
    return issuerSubject;
  }

  /**
   * Parse subject DN fields into key-value pairs.
   * e.g. "CN=example.com, O=Example Inc, L=Tokyo, ST=Tokyo, C=JP"
   */
  function parseSubjectDN(subject) {
    if (!subject) return [];
    const fields = [];
    const labels = {
      'CN': 'コモンネーム',
      'O': '組織名',
      'OU': '部署名',
      'L': '市区町村',
      'ST': '都道府県',
      'C': '国'
    };
    for (const part of subject.split(',')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const key = part.substring(0, eq).trim();
      const value = part.substring(eq + 1).trim();
      if (value) {
        fields.push([labels[key] || key, value]);
      }
    }
    return fields;
  }

  function renderCert(cert) {
    const section = document.getElementById('cert-section');
    const content = document.getElementById('cert-content');

    if (!cert) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    content.innerHTML = '';

    // Issuer (CA)
    const issuerName = extractIssuerName(cert.issuer);
    if (issuerName) {
      content.appendChild(createInfoRow('neutral', '発行元', issuerName));
    }
    if (cert.issuer && issuerName !== cert.issuer) {
      content.appendChild(createInfoRow('neutral', '発行元 DN', cert.issuer));
    }

    // Subject (CSR info)
    const subjectFields = parseSubjectDN(cert.subject);
    for (const [label, value] of subjectFields) {
      content.appendChild(createInfoRow('neutral', label, value));
    }

    // Key & signature
    if (cert.keyAlg) {
      const keyDetail = cert.keySize
        ? `${cert.keyAlg} ${cert.keySize}-bit`
        : cert.keyAlg;
      content.appendChild(createInfoRow('neutral', '鍵', keyDetail));
    }
    if (cert.sigAlg) {
      content.appendChild(createInfoRow('neutral', '署名', cert.sigAlg));
    }

    // Validity
    const from = formatCertDate(cert.notBefore);
    const to = formatCertDate(cert.notAfter);
    if (from && to) {
      const now = Date.now();
      const expired = cert.notAfter < now;
      const daysLeft = Math.ceil((cert.notAfter - now) / 86400000);
      const daysLabel = expired
        ? `（${-daysLeft}日前に失効）`
        : `（残り${daysLeft}日）`;
      content.appendChild(createInfoRow(
        expired ? 'fail' : daysLeft <= 30 ? 'fail' : 'pass',
        '有効期間',
        `${from} — ${to} ${daysLabel}`
      ));
    }

    // SANs (show count + first few)
    if (cert.altNames && cert.altNames.length > 0) {
      const display = cert.altNames.length <= 3
        ? cert.altNames.join(', ')
        : `${cert.altNames.slice(0, 3).join(', ')} (+${cert.altNames.length - 3})`;
      content.appendChild(createInfoRow('neutral', 'SANs', display));
    }
  }

  function renderEmailAuth(auth) {
    const section = document.getElementById('email-auth-section');
    const content = document.getElementById('email-auth-content');

    if (!auth) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow(
      auth.spf ? 'pass' : 'fail', 'SPF',
      auth.spf || '未設定'
    ));
    content.appendChild(createInfoRow(
      auth.dmarc ? 'pass' : 'fail', 'DMARC',
      auth.dmarc || '未設定'
    ));
    content.appendChild(createInfoRow(
      auth.dkim ? 'pass' : 'fail', 'DKIM',
      auth.dkim ? `セレクタ: ${auth.dkim.selector}` : '未検出'
    ));
  }

  function renderDetections(data) {
    const loading = document.getElementById('loading');
    const noResults = document.getElementById('no-results');
    const techList = document.getElementById('tech-list');
    const totalCount = document.getElementById('total-count');
    const hostname = document.getElementById('hostname');

    loading.hidden = true;
    techList.innerHTML = '';

    hostname.textContent = getHostname(data.url);

    const detections = data.detections || [];

    if (detections.length === 0) {
      noResults.hidden = false;
      totalCount.textContent = '検出: 0件';
    } else {
      noResults.hidden = true;
      totalCount.textContent = `検出: ${detections.length}件`;

      const groups = {};
      for (const det of detections) {
        const cat = det.category || 'other';
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(det);
      }

      for (const cat of CATEGORY_ORDER) {
        const items = groups[cat];
        if (!items || items.length === 0) continue;

        const group = document.createElement('div');
        group.className = 'category-group';

        const header = document.createElement('div');
        header.className = 'category-header';

        const label = document.createElement('span');
        label.textContent = CATEGORY_LABELS[cat] || cat;
        header.appendChild(label);

        const count = document.createElement('span');
        count.className = 'category-count';
        count.textContent = items.length;
        header.appendChild(count);

        group.appendChild(header);

        items.sort((a, b) => a.name.localeCompare(b.name));

        for (const tech of items) {
          const item = document.createElement('div');
          item.className = 'tech-item';

          item.appendChild(createTechIcon(tech));

          const name = document.createElement('span');
          name.className = 'tech-name';
          name.textContent = tech.name;
          item.appendChild(name);

          if (tech.version) {
            const version = document.createElement('span');
            version.className = 'tech-version';
            version.textContent = `v${tech.version}`;
            item.appendChild(version);
          }

          group.appendChild(item);
        }

        techList.appendChild(group);
      }
    }
  }

  // ─── Security Headers ───

  async function checkSecurityHeaders(tabUrl) {
    const resp = await fetch(tabUrl, { method: 'HEAD' });
    const g = (name) => resp.headers.get(name) || null;
    return {
      csp: g('content-security-policy'),
      xContentTypeOptions: g('x-content-type-options'),
      xFrameOptions: g('x-frame-options'),
      xXssProtection: g('x-xss-protection'),
      referrerPolicy: g('referrer-policy'),
      permissionsPolicy: g('permissions-policy'),
      coop: g('cross-origin-opener-policy'),
      corp: g('cross-origin-resource-policy'),
      server: g('server'),
      xPoweredBy: g('x-powered-by'),
      cors: g('access-control-allow-origin')
    };
  }

  function renderSecurityHeaders(data) {
    const section = document.getElementById('sec-headers-section');
    const content = document.getElementById('sec-headers-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    const headers = [
      ['CSP', data.csp],
      ['X-Content-Type', data.xContentTypeOptions],
      ['X-Frame-Options', data.xFrameOptions],
      ['X-XSS-Protection', data.xXssProtection],
      ['Referrer-Policy', data.referrerPolicy],
      ['Permissions', data.permissionsPolicy],
      ['COOP', data.coop],
      ['CORP', data.corp]
    ];

    for (const [label, value] of headers) {
      content.appendChild(createInfoRow(
        value ? 'pass' : 'fail',
        label,
        value || '未設定'
      ));
    }
  }

  function renderInfoLeakage(data) {
    const section = document.getElementById('info-leak-section');
    const content = document.getElementById('info-leak-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow(
      data.server ? 'fail' : 'pass',
      'Server',
      data.server || '非公開'
    ));
    content.appendChild(createInfoRow(
      data.xPoweredBy ? 'fail' : 'pass',
      'X-Powered-By',
      data.xPoweredBy || '非公開'
    ));
    content.appendChild(createInfoRow(
      !data.cors ? 'pass' : data.cors === '*' ? 'fail' : 'neutral',
      'CORS',
      data.cors || '未設定'
    ));
  }

  // ─── Cookie Security ───

  async function checkCookies(tabUrl) {
    const cookies = await api.cookies.getAll({ url: tabUrl });
    if (cookies.length === 0) return { total: 0, issues: [] };

    let noSecure = 0;
    let noHttpOnly = 0;
    let noSameSite = 0;

    for (const c of cookies) {
      if (!c.secure) noSecure++;
      if (!c.httpOnly) noHttpOnly++;
      if (!c.sameSite || c.sameSite === 'unspecified' || c.sameSite === 'no_restriction') {
        noSameSite++;
      }
    }

    return { total: cookies.length, noSecure, noHttpOnly, noSameSite };
  }

  function renderCookies(data) {
    const section = document.getElementById('cookie-section');
    const content = document.getElementById('cookie-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow('neutral', '合計', `${data.total}個`));

    if (data.total === 0) return;

    content.appendChild(createInfoRow(
      data.noSecure === 0 ? 'pass' : 'fail',
      'Secure',
      data.noSecure === 0 ? '全て設定済み' : `${data.noSecure}個が未設定`
    ));
    content.appendChild(createInfoRow(
      data.noHttpOnly === 0 ? 'pass' : 'fail',
      'HttpOnly',
      data.noHttpOnly === 0 ? '全て設定済み' : `${data.noHttpOnly}個が未設定`
    ));
    content.appendChild(createInfoRow(
      data.noSameSite === 0 ? 'pass' : 'fail',
      'SameSite',
      data.noSameSite === 0 ? '全て設定済み' : `${data.noSameSite}個が未設定`
    ));
  }

  // ─── DNS Security ───

  async function checkDnsSecurity(tabUrl) {
    const parsed = new URL(tabUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;

    const domain = getRegisteredDomain(parsed.hostname);

    const [dnsResp, caaResp, bimiRecords, mxResp] = await Promise.all([
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`)
        .then(r => r.json()),
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CAA`)
        .then(r => r.json()),
      queryTxt(`default._bimi.${domain}`),
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`)
        .then(r => r.json())
    ]);

    const dnssec = dnsResp.AD === true;
    const caaRecords = (caaResp.Answer || [])
      .filter(a => a.type === 257)
      .map(a => a.data);
    const bimi = bimiRecords.find(r => r.toUpperCase().startsWith('V=BIMI1')) || null;
    const mx = (mxResp.Answer || [])
      .filter(a => a.type === 15)
      .map(a => a.data.replace(/\.$/, ''));

    return { dnssec, caa: caaRecords, bimi, mx };
  }

  function renderDnsSecurity(data) {
    const section = document.getElementById('dns-sec-section');
    const content = document.getElementById('dns-sec-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow(
      data.dnssec ? 'pass' : 'fail',
      'DNSSEC',
      data.dnssec ? '有効' : '無効'
    ));
    content.appendChild(createInfoRow(
      data.caa.length > 0 ? 'pass' : 'fail',
      'CAA',
      data.caa.length > 0 ? data.caa.join(', ') : '未設定'
    ));
    content.appendChild(createInfoRow(
      data.bimi ? 'pass' : 'fail',
      'BIMI',
      data.bimi || '未設定'
    ));
    if (data.mx.length > 0) {
      content.appendChild(createInfoRow('neutral', 'MX', data.mx.join(', ')));
    } else {
      content.appendChild(createInfoRow('neutral', 'MX', 'なし'));
    }
  }

  // ─── DNS Info (IP / Reverse / NS) ───

  async function checkDnsInfo(tabUrl) {
    const parsed = new URL(tabUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;

    const hostname = parsed.hostname;
    const domain = getRegisteredDomain(hostname);

    const [aResp, nsResp] = await Promise.all([
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`)
        .then(r => r.json()),
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`)
        .then(r => r.json())
    ]);

    const ips = (aResp.Answer || [])
      .filter(a => a.type === 1)
      .map(a => a.data);
    const ns = (nsResp.Answer || [])
      .filter(a => a.type === 2)
      .map(a => a.data.replace(/\.$/, ''));

    // Reverse DNS for first IP
    let ptr = null;
    if (ips.length > 0) {
      const reversed = ips[0].split('.').reverse().join('.');
      const ptrResp = await fetch(
        `https://dns.google/resolve?name=${reversed}.in-addr.arpa&type=PTR`
      ).then(r => r.json()).catch(() => null);
      if (ptrResp) {
        const ptrRecords = (ptrResp.Answer || [])
          .filter(a => a.type === 12)
          .map(a => a.data.replace(/\.$/, ''));
        ptr = ptrRecords[0] || null;
      }
    }

    return { ips, ptr, ns };
  }

  function renderDnsInfo(data) {
    const section = document.getElementById('dns-info-section');
    const content = document.getElementById('dns-info-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    // IP addresses
    if (data.ips.length > 0) {
      content.appendChild(createInfoRow('neutral', 'IP', data.ips.join(', ')));
    }

    // Reverse DNS
    content.appendChild(createInfoRow(
      'neutral', '逆引き',
      data.ptr || '該当なし'
    ));

    // Nameservers
    if (data.ns.length > 0) {
      content.appendChild(createInfoRow('neutral', 'NS', data.ns.join(', ')));
    }
  }

  // ─── Page Diagnosis ───

  async function checkPageSecurity(tabId) {
    const results = await api.scripting.executeScript({
      target: { tabId },
      func: () => {
        const isHttps = location.protocol === 'https:';
        const ownHost = location.hostname;

        // Mixed content
        let mixedCount = 0;
        if (isHttps) {
          document.querySelectorAll('[src],[href]').forEach(el => {
            const val = el.src || el.href;
            if (val && val.startsWith('http://')) mixedCount++;
          });
        }

        // External scripts + SRI check
        const extDomains = new Set();
        let noSri = 0;
        document.querySelectorAll('script[src]').forEach(s => {
          try {
            const h = new URL(s.src).hostname;
            if (h !== ownHost) {
              extDomains.add(h);
              if (!s.integrity) noSri++;
            }
          } catch {}
        });
        document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => {
          try {
            const h = new URL(l.href).hostname;
            if (h !== ownHost && !l.integrity) noSri++;
          } catch {}
        });

        // Inline event handlers
        const events = ['onclick','onload','onerror','onmouseover','onfocus',
          'onsubmit','onchange','onkeyup','onkeydown','onmouseenter'];
        let inlineHandlers = 0;
        for (const attr of events) {
          inlineHandlers += document.querySelectorAll(`[${attr}]`).length;
        }

        // Password on HTTP
        const httpPassword = !isHttps &&
          document.querySelectorAll('input[type="password"]').length > 0;

        // Third-party iframes
        const iframeDomains = new Set();
        document.querySelectorAll('iframe[src]').forEach(f => {
          try {
            const h = new URL(f.src).hostname;
            if (h !== ownHost) iframeDomains.add(h);
          } catch {}
        });

        // Insecure form actions
        let insecureForms = 0;
        if (isHttps) {
          document.querySelectorAll('form[action]').forEach(f => {
            if (f.action.startsWith('http://')) insecureForms++;
          });
        }

        // target="_blank" without noopener
        let unsafeLinks = 0;
        document.querySelectorAll('a[target="_blank"]').forEach(a => {
          const rel = (a.getAttribute('rel') || '').toLowerCase();
          if (!rel.includes('noopener')) unsafeLinks++;
        });

        return {
          mixedContent: mixedCount,
          externalScripts: extDomains.size,
          externalDomains: [...extDomains].slice(0, 10),
          unsafeLinks,
          noSri,
          inlineHandlers,
          httpPassword,
          iframes: [...iframeDomains].slice(0, 10),
          insecureForms
        };
      }
    });
    return results[0]?.result || null;
  }

  function renderPageSecurity(data) {
    const section = document.getElementById('page-diag-section');
    const content = document.getElementById('page-diag-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow(
      data.mixedContent === 0 ? 'pass' : 'fail',
      'Mixed Content',
      data.mixedContent === 0 ? 'なし' : `${data.mixedContent}件検出`
    ));

    const extDetail = data.externalScripts === 0
      ? 'なし'
      : `${data.externalScripts}ドメイン（${data.externalDomains.join(', ')}）`;
    content.appendChild(createInfoRow(
      data.externalScripts <= 3 ? 'pass' : 'neutral',
      '外部スクリプト',
      extDetail
    ));

    content.appendChild(createInfoRow(
      data.noSri === 0 ? 'pass' : 'fail',
      'SRI',
      data.noSri === 0 ? '全て設定済み' : `${data.noSri}件が未設定`
    ));

    content.appendChild(createInfoRow(
      data.inlineHandlers === 0 ? 'pass' : 'neutral',
      'インラインJS',
      data.inlineHandlers === 0 ? 'なし' : `${data.inlineHandlers}件`
    ));

    if (data.httpPassword) {
      content.appendChild(createInfoRow('fail', 'パスワード', 'HTTP上にパスワード入力欄あり'));
    }

    if (data.iframes.length > 0) {
      content.appendChild(createInfoRow(
        'neutral', 'iframe',
        `${data.iframes.length}ドメイン（${data.iframes.join(', ')}）`
      ));
    }

    if (data.insecureForms > 0) {
      content.appendChild(createInfoRow(
        'fail', 'フォーム',
        `${data.insecureForms}件がHTTP送信`
      ));
    }

    content.appendChild(createInfoRow(
      data.unsafeLinks === 0 ? 'pass' : 'fail',
      'noopener',
      data.unsafeLinks === 0 ? '問題なし' : `${data.unsafeLinks}件が未設定`
    ));
  }

  // ─── Public Files ───

  async function checkPublicFiles(tabUrl) {
    const origin = new URL(tabUrl).origin;

    const [secResp, robotsResp] = await Promise.all([
      fetchWithTimeout(`${origin}/.well-known/security.txt`, 3000).catch(() => null),
      fetchWithTimeout(`${origin}/robots.txt`, 3000).catch(() => null)
    ]);

    const securityTxt = secResp && secResp.ok;

    let robotsTxt = false;
    const sensitiveRobots = [];
    if (robotsResp && robotsResp.ok) {
      robotsTxt = true;
      const text = await robotsResp.text().catch(() => '');
      const sensitive = ['/admin', '/wp-admin', '/login', '/dashboard',
        '/phpmyadmin', '/cpanel', '/manager', '/config', '/backup', '/.env', '/.git'];
      for (const line of text.toLowerCase().split('\n')) {
        if (line.startsWith('disallow:')) {
          const path = line.replace('disallow:', '').trim();
          if (path && sensitive.some(p => path.includes(p))) {
            sensitiveRobots.push(path);
          }
        }
      }
    }

    return { securityTxt, robotsTxt, sensitiveRobots };
  }

  function renderPublicFiles(data) {
    const section = document.getElementById('public-files-section');
    const content = document.getElementById('public-files-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    content.appendChild(createInfoRow(
      data.securityTxt ? 'pass' : 'fail',
      'security.txt',
      data.securityTxt ? '設定済み' : '未設定'
    ));

    if (!data.robotsTxt) {
      content.appendChild(createInfoRow('neutral', 'robots.txt', '未設定'));
    } else if (data.sensitiveRobots.length > 0) {
      content.appendChild(createInfoRow(
        'fail', 'robots.txt',
        `機密パス露出: ${data.sensitiveRobots.join(', ')}`
      ));
    } else {
      content.appendChild(createInfoRow('pass', 'robots.txt', '設定済み（機密パスなし）'));
    }
  }

  // ─── WordPress details ───

  async function checkWordPress(tabId) {
    const results = await api.scripting.executeScript({
      target: { tabId },
      func: () => {
        const themes = new Set();
        const plugins = new Set();
        const html = document.documentElement.outerHTML.substring(0, 200000);

        for (const m of html.matchAll(/wp-content\/themes\/([a-zA-Z0-9_-]+)/g)) {
          themes.add(m[1]);
        }
        for (const m of html.matchAll(/wp-content\/plugins\/([a-zA-Z0-9_-]+)/g)) {
          plugins.add(m[1]);
        }

        return {
          theme: [...themes][0] || null,
          plugins: [...plugins].sort()
        };
      }
    });
    return results[0]?.result || null;
  }

  function renderWordPress(wpInfo) {
    const section = document.getElementById('wp-section');
    const content = document.getElementById('wp-content');

    if (!wpInfo || (!wpInfo.theme && wpInfo.plugins.length === 0)) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    content.innerHTML = '';

    if (wpInfo.theme) {
      content.appendChild(createInfoRow('neutral', 'テーマ', wpInfo.theme));
    }
    if (wpInfo.plugins.length > 0) {
      content.appendChild(createInfoRow(
        'neutral', 'プラグイン',
        wpInfo.plugins.join(', ')
      ));
    }
  }

  // ─── VirusTotal ───

  async function checkVirusTotal(tabUrl) {
    const result = await api.storage.sync.get('vtApiKey');
    const key = result.vtApiKey;
    if (!key) return { noKey: true };

    // Base64url encode the URL (VT v3 convention)
    const id = btoa(tabUrl).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    try {
      const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { 'x-apikey': key },
        signal: AbortSignal.timeout(8000)
      });
      if (resp.status === 404) return { notFound: true };
      if (resp.status === 429) return { rateLimited: true };
      if (!resp.ok) return { error: true };

      const json = await resp.json();
      const attrs = json.data.attributes;
      const stats = attrs.last_analysis_stats || {};
      return {
        stats,
        reputation: attrs.reputation,
        lastAnalysisDate: attrs.last_analysis_date
          ? new Date(attrs.last_analysis_date * 1000) : null
      };
    } catch {
      return { error: true };
    }
  }

  function renderVirusTotal(data) {
    const section = document.getElementById('vt-section');
    const content = document.getElementById('vt-content');

    if (!data) { section.hidden = true; return; }

    section.hidden = false;
    content.innerHTML = '';

    if (data.noKey) {
      const row = document.createElement('div');
      row.className = 'info-row';
      row.style.cursor = 'pointer';

      const dot = document.createElement('span');
      dot.className = 'info-status neutral';
      row.appendChild(dot);

      const label = document.createElement('span');
      label.className = 'info-label';
      label.style.width = 'auto';
      label.textContent = 'APIキー未設定';
      row.appendChild(label);

      const link = document.createElement('span');
      link.className = 'info-detail';
      link.textContent = '設定を開く';
      link.style.color = '#4A90D9';
      link.style.cursor = 'pointer';
      row.appendChild(link);

      row.addEventListener('click', () => api.runtime.openOptionsPage());
      content.appendChild(row);
      return;
    }

    if (data.notFound) {
      content.appendChild(createInfoRow('neutral', '結果', 'URL未登録'));
      return;
    }

    if (data.rateLimited) {
      content.appendChild(createInfoRow('fail', '結果', 'レート制限中（しばらく待ってください）'));
      return;
    }

    if (data.error) {
      content.appendChild(createInfoRow('fail', '結果', '取得エラー'));
      return;
    }

    // Determine verdict
    const s = data.stats;
    const malicious = s.malicious || 0;
    const suspicious = s.suspicious || 0;
    const harmless = s.harmless || 0;
    const undetected = s.undetected || 0;

    let verdict, verdictStatus;
    if (malicious > 0) {
      verdict = '危険';
      verdictStatus = 'fail';
    } else if (suspicious > 0) {
      verdict = '疑わしい';
      verdictStatus = 'fail';
    } else {
      verdict = '安全';
      verdictStatus = 'pass';
    }

    content.appendChild(createInfoRow(verdictStatus, '判定', verdict));
    content.appendChild(createInfoRow(
      malicious > 0 ? 'fail' : 'pass', '検出',
      `悪意: ${malicious} / 疑わしい: ${suspicious} / 安全: ${harmless} / 未検出: ${undetected}`
    ));

    if (data.reputation != null) {
      content.appendChild(createInfoRow('neutral', '評価', `${data.reputation}`));
    }

    if (data.lastAnalysisDate) {
      content.appendChild(createInfoRow('neutral', '最終分析',
        data.lastAnalysisDate.toLocaleDateString('ja-JP', {
          year: 'numeric', month: 'short', day: 'numeric'
        })
      ));
    }
  }

  // ─── Init ───

  async function init() {
    try {
      // Read target tab from URL params (popup window mode) or fallback to active tab
      const params = new URLSearchParams(location.search);
      let tabId, tabUrl;
      if (params.has('tabId') && params.has('tabUrl')) {
        tabId = Number(params.get('tabId'));
        tabUrl = params.get('tabUrl');
      } else {
        const tabs = await api.tabs.query({ active: true, currentWindow: true });
        if (!tabs[0]) return;
        tabId = tabs[0].id;
        tabUrl = tabs[0].url;
      }

      // Run all checks in parallel
      const [response, encryption, secHeaders, cookies, emailAuth, dnsSec, dnsInfo, pageSec, publicFiles, vtResult] = await Promise.all([
        api.runtime.sendMessage({ type: 'RUN_DETECTION', tabId, url: tabUrl }),
        checkEncryption(tabId, tabUrl).catch(() => null),
        checkSecurityHeaders(tabUrl).catch(() => null),
        checkCookies(tabUrl).catch(() => null),
        checkEmailAuth(tabUrl).catch(() => null),
        checkDnsSecurity(tabUrl).catch(() => null),
        checkDnsInfo(tabUrl).catch(() => null),
        checkPageSecurity(tabId).catch(() => null),
        checkPublicFiles(tabUrl).catch(() => null),
        checkVirusTotal(tabUrl).catch(() => null)
      ]);

      const data = response || { url: tabUrl, detections: [] };
      renderDetections(data);

      // WordPress details (only when WordPress is detected)
      const detections = data.detections || [];
      if (detections.some(d => d.name === 'WordPress')) {
        checkWordPress(tabId).then(renderWordPress).catch(() => {});
      }

      renderEncryption(encryption);
      renderCert(encryption?.cert || null);
      renderSecurityHeaders(secHeaders);
      renderInfoLeakage(secHeaders);
      renderCookies(cookies);
      renderEmailAuth(emailAuth);
      renderDnsSecurity(dnsSec);
      renderDnsInfo(dnsInfo);
      renderPageSecurity(pageSec);
      renderPublicFiles(publicFiles);
      renderVirusTotal(vtResult);
    } catch (e) {
      console.error('Tech Detector popup error:', e);
      document.getElementById('loading').textContent = '読み込みエラー';
    }
  }

  init();
})();

/* Unlock screen of the online copy (GitHub Pages, built by _src/tools/publish/build_pages.mjs).
   Every data and code file is stored AES-256-GCM encrypted as <path>.enc (12-byte IV + ciphertext + tag).
   The key is derived from the password with PBKDF2-SHA256 (salt + iterations in lock.json) and, if wanted,
   remembered in this browser so the password is asked only once per device. */
(function () {
  'use strict';
  const LS = 'hsk6hskk.key';
  const V = window.LOCK_V || 0;
  const app = document.getElementById('app');
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
  let key = null;

  const decrypt = (buf) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12) }, key, new Uint8Array(buf, 12));
  const fetchDec = async (path, v) => {
    const r = await fetch(path + '.enc' + (v ? '?v=' + v : ''));
    if (!r.ok) throw new Error(path + ' (' + r.status + ')');
    return decrypt(await r.arrayBuffer());
  };
  const store = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) {} };
  const read = (k) => { try { return localStorage.getItem(k) || sessionStorage.getItem(k); } catch (e) { return null; } };
  window.LOCK = {
    fetch: (path) => fetchDec(path),
    // forget the password on this device (Cài đặt → Dữ liệu học tập)
    forget() {
      store(LS, null);
      try { sessionStorage.removeItem(LS); } catch (e) {}
      location.reload();
    },
  };

  const useRaw = async (raw, cfg) => {
    key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    try {
      return new TextDecoder().decode(await decrypt(b64d(cfg.check).buffer)) === 'hsk6hskk';
    } catch (e) {
      return false;
    }
  };

  const ask = (cfg) => new Promise((done) => {
    app.innerHTML = `<div class="page narrow" style="max-width:440px"><div class="card" style="margin-top:8vh">
      <h2 style="margin-top:0">Mở web luyện thi</h2>
      <p class="small muted">Nội dung trên mạng đã được mã hoá. Nhập mật khẩu bạn đặt khi đưa web lên GitHub.</p>
      <form id="lockForm">
        <input type="password" id="lockPw" autocomplete="current-password" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="Mật khẩu" style="width:100%;font-size:17px;padding:10px 12px">
        <label class="check" style="display:block;margin:12px 0"><input type="checkbox" id="lockKeep" checked> Ghi nhớ trên máy này (không phải nhập lại)</label>
        <button class="btn primary" id="lockGo" style="width:100%">Mở</button>
        <p id="lockMsg" class="small" style="min-height:1.4em;margin-bottom:0"></p>
      </form></div></div>`;
    const pw = document.getElementById('lockPw');
    const msg = document.getElementById('lockMsg');
    const go = document.getElementById('lockGo');
    pw.focus();
    document.getElementById('lockForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!pw.value) return;
      go.disabled = true;
      msg.textContent = 'Đang kiểm tra…';
      try {
        const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw.value.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
        const raw = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64d(cfg.salt), iterations: cfg.iter, hash: 'SHA-256' }, base, 256);
        if (await useRaw(raw, cfg)) {
          if (document.getElementById('lockKeep').checked) store(LS, b64e(raw));
          else try { sessionStorage.setItem(LS, b64e(raw)); } catch (e2) {}
          return done();
        }
        msg.innerHTML = '<span style="color:var(--bad)">Sai mật khẩu, hãy thử lại.</span>';
      } catch (err) {
        msg.textContent = 'Lỗi: ' + (err.message || err.name);
      }
      go.disabled = false;
      pw.select();
    });
  });

  const fail = (err) => {
    app.innerHTML = `<div class="page narrow"><div class="card warn"><h3>Không tải được nội dung</h3>
      <p class="small">${String(err && (err.message || err.name) || err).replace(/[<&]/g, '')}</p>
      <p class="small">Hãy kiểm tra mạng rồi tải lại trang.</p>
      <div class="row"><button class="btn primary" onclick="location.reload()">Tải lại</button><button class="btn ghost" onclick="LOCK.forget()">Nhập lại mật khẩu</button></div></div></div>`;
  };

  (async () => {
    if (!window.crypto || !crypto.subtle) throw new Error('Trình duyệt không hỗ trợ giải mã (cần mở bằng link https).');
    const cfg = await (await fetch('lock.json?v=' + V)).json();
    const saved = read(LS);
    if (!(saved && (await useRaw(b64d(saved), cfg)))) {
      if (saved) store(LS, null);
      await ask(cfg);
    }
    app.innerHTML = '<p class="muted" style="padding:24px">Đang giải mã nội dung…</p>';
    const codes = await Promise.all((window.LOCK_SCRIPTS || []).map((p) => fetchDec(p, V)));
    const td = new TextDecoder();
    codes.forEach((buf) => {
      const s = document.createElement('script');
      s.textContent = td.decode(buf);
      document.body.appendChild(s);
    });
    window.App.start();
  })().catch(fail);
})();

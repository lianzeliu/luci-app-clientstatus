'use strict';
'require view';
'require xhr';
'require poll';
'require ui';

var CSS = `
.cs { --surface: #fff; --text: #171717; --text2: #6b7280; --text3: #9ca3af;
  --line: #f1f2f4; --line2: #e5e7eb; --accent: #2563eb; --green: #16a34a; --red: #dc2626;
  --radius: 10px; max-width: 1100px; margin: 0 auto; color: var(--text); font-size: 14px; }
html[data-theme="dark"] .cs, .dark .cs {
  --surface: #17181c; --text: #e8e9ec; --text2: #9aa0aa; --text3: #6b7280;
  --line: #232529; --line2: #2e3138; --accent: #5b9cf8; --green: #4ade80; --red: #f87171; }
.cs-top { display: flex; justify-content: space-between; align-items: flex-end;
  padding: 6px 2px 18px; gap: 16px; flex-wrap: wrap; }
.cs-title h2 { margin: 0; font-size: 20px; font-weight: 650; letter-spacing: .2px; }
.cs-title p { margin: 5px 0 0; font-size: 13px; color: var(--text2); }
.cs-title p b { color: var(--text); font-weight: 600; }
.cs-wan { text-align: right; }
.cs-wan .cs-wan-label { font-size: 11px; color: var(--text3); letter-spacing: 1px; margin-bottom: 2px; }
.cs-wan .cs-wan-nums { display: flex; gap: 18px; justify-content: flex-end;
  font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums; }
.cs-wan .cs-wan-down { font-size: 24px; font-weight: 650; color: var(--green); }
.cs-wan .cs-wan-up { font-size: 24px; font-weight: 650; color: var(--accent); }
.cs-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.cs-search { flex: 1; min-width: 160px; max-width: 320px; padding: 8px 12px;
  border: 1px solid var(--line2); border-radius: 8px; font-size: 13px;
  background: var(--surface); color: var(--text); outline: none; }
.cs-search::placeholder { color: var(--text3); }
.cs-search:focus { border-color: var(--accent); }
.cs-sel { padding: 8px 10px; border: 1px solid var(--line2); border-radius: 8px;
  font-size: 13px; background: var(--surface); color: var(--text2); outline: none; cursor: pointer; }
.cs-bar .cs-sp { flex: 1; }
.cs-btn { padding: 8px 14px; border: 1px solid var(--line2); border-radius: 8px;
  font-size: 13px; background: var(--surface); color: var(--text2); cursor: pointer;
  white-space: nowrap; }
.cs-btn:hover { border-color: var(--accent); color: var(--accent); }
.cs-btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.cs-btn.primary:hover { opacity: .88; color: #fff; }
.cs-card { background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); overflow: hidden; }
.cs-table { width: 100%; border-collapse: collapse; }
.cs-table th { padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600;
  color: var(--text3); text-transform: uppercase; letter-spacing: .8px;
  border-bottom: 1px solid var(--line); white-space: nowrap;
  cursor: pointer; user-select: none; }
.cs-table th:hover { color: var(--accent); }
.cs-table td { padding: 11px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.cs-table tr:last-child td { border-bottom: none; }
.cs-table tbody tr:hover { background: rgba(127,127,127,.05); }
.cs-table tbody tr.off { opacity: .55; }
.cs-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 9px; }
.cs-dot.on { background: var(--green); box-shadow: 0 0 6px rgba(22,163,74,.5); }
.cs-dot.off { background: var(--text3); }
.cs-name { font-weight: 550; cursor: pointer; }
.cs-name:hover { color: var(--accent); }
.cs-mac { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11.5px; color: var(--text3); margin-top: 2px; }
.cs-ip { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 13px; }
.cs-dur { color: var(--text2); font-variant-numeric: tabular-nums; white-space: nowrap; }
.cs-spd { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 13px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.cs-spd.dn { color: var(--green); } .cs-spd.up { color: var(--accent); }
.cs-spd.zero { color: var(--text3); }
.cs-tot { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  font-size: 11px; color: var(--text3); margin-top: 2px; font-variant-numeric: tabular-nums; }
.cs-acl { font-size: 12.5px; padding: 5px 12px; border-radius: 20px; cursor: pointer;
  border: 1px solid transparent; white-space: nowrap; }
.cs-acl.allow { color: var(--green); background: rgba(22,163,74,.08); }
.cs-acl.allow:hover { color: var(--red); background: rgba(220,38,38,.08); }
.cs-acl.block { color: var(--red); background: rgba(220,38,38,.08); }
.cs-acl.block:hover { color: var(--green); background: rgba(22,163,74,.08); }
.cs-acl:disabled { opacity: .4; pointer-events: none; }
.cs-empty { text-align: center; padding: 70px 20px; color: var(--text3); font-size: 14px; }
.cs-foot { display: flex; justify-content: space-between; align-items: center;
  padding: 12px 2px 0; font-size: 12px; color: var(--text3); }
.cs-edit { padding: 4px 8px; border: 1px solid var(--accent); border-radius: 6px;
  font-size: 13px; outline: none; background: var(--surface); color: var(--text); width: 170px; }
@media (max-width: 760px) {
  .cs-top { align-items: flex-start; }
  .cs-wan { text-align: left; }
  .cs-wan .cs-wan-nums { justify-content: flex-start; }
  .cs-wan .cs-wan-down, .cs-wan .cs-wan-up { font-size: 20px; }
  .cs-card { overflow-x: auto; }
  .cs-table { min-width: 640px; }
  .cs-bar .cs-sp { display: none; }
}
`;

function fmt(b) {
  if (!b || b <= 0) return '–';
  if (b < 1024) return b + ' B/s';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB/s';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB/s';
  return (b / 1073741824).toFixed(2) + ' GB/s';
}
function fmtTot(b) {
  if (!b || b <= 0) return '–';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}
function esc(s) {
  var d = document.createElement('div');
  d.textContent = s == null ? '' : s;
  return d.innerHTML;
}

return view.extend({
  clients: [],
  speeds: {},
  sortK: 'status',
  sortA: true,
  mtime: -1,

  load: function() {
    return xhr.get(L.url('admin/services/clientstatus/data')).then(function(res) {
      return res;
    });
  },

  render: function(data) {
    var self = this;
    this.clients = (data && data.clients) || [];

    var style = E('style', {}, [CSS]);
    var root = E('div', { 'class': 'cs' });

    root.appendChild(E('div', { 'class': 'cs-top' }, [
      E('div', { 'class': 'cs-title' }, [
        E('h2', {}, [_('Client Status')]),
        E('p', { 'id': 'cs-summary' }, [])
      ]),
      E('div', { 'class': 'cs-wan' }, [
        E('div', { 'class': 'cs-wan-label' }, ['WAN ' + _('Realtime')]),
        E('div', { 'class': 'cs-wan-nums' }, [
          E('span', { 'class': 'cs-wan-down' }, ['↓ ', E('span', { 'id': 'cs-wan-dn' }, ['–'])]),
          E('span', { 'class': 'cs-wan-up' }, ['↑ ', E('span', { 'id': 'cs-wan-up' }, ['–'])])
        ])
      ])
    ]));

    var bar = E('div', { 'class': 'cs-bar' }, [
      E('input', { 'class': 'cs-search', 'id': 'cs-q', 'placeholder': _('Search hostname / IP / MAC') }),
      E('select', { 'class': 'cs-sel', 'id': 'cs-f' }, [
        E('option', { 'value': 'all' }, [_('All')]),
        E('option', { 'value': 'online' }, [_('Online')]),
        E('option', { 'value': 'offline' }, [_('Offline')])
      ]),
      E('select', { 'class': 'cs-sel', 'id': 'cs-a' }, [
        E('option', { 'value': 'all' }, ['ACL: ' + _('All')]),
        E('option', { 'value': 'Allowed' }, [_('Allowed')]),
        E('option', { 'value': 'Blocked' }, [_('Blocked')])
      ]),
      E('span', { 'class': 'cs-sp' }),
      E('button', { 'class': 'cs-btn', 'id': 'cs-resetbtn' }, [_('Reset')]),
      E('button', { 'class': 'cs-btn primary', 'id': 'cs-refreshbtn' }, [_('Refresh')])
    ]);
    root.appendChild(bar);

    var table = E('table', { 'class': 'cs-table' }, [
      E('thead', {}, [E('tr', {}, [
        E('th', { 'data-k': 'status' }, [_('Status')]),
        E('th', { 'data-k': 'hostname' }, [_('Hostname')]),
        E('th', { 'data-k': 'ipv4' }, [_('IP')]),
        E('th', { 'data-k': 'rx' }, ['↓']),
        E('th', { 'data-k': 'tx' }, ['↑']),
        E('th', { 'data-k': 'duration' }, [_('Duration')]),
        E('th', { 'data-k': 'acl' }, ['ACL'])
      ])]),
      E('tbody', { 'id': 'cs-rows' })
    ]);
    var card = E('div', { 'class': 'cs-card' }, [table,
      E('div', { 'class': 'cs-empty', 'id': 'cs-empty', 'style': 'display:none' }, [_('No clients found')])
    ]);
    root.appendChild(card);

    root.appendChild(E('div', { 'class': 'cs-foot' }, [
      E('span', { 'id': 'cs-updated' }),
      E('span', {}, [_('Auto refresh every 2s')])
    ]));

    var container = E('div', {}, [style, root]);
    this.bindEvents(container);
    this.renderRows();

    poll.add(function() {
      return xhr.get(L.url('admin/services/clientstatus/speed') + '?_=' + Date.now()).then(function(res) {
        if (res && res.clients) {
          self.speeds = res.clients;
          self.renderRows();
        }
      });
    }, 2);

    poll.add(function() {
      return xhr.get(L.url('admin/services/clientstatus/mtime') + '?_=' + Date.now()).then(function(res) {
        if (res && res.mtime !== undefined && (self.mtime < 0 || res.mtime !== self.mtime)) {
          self.mtime = res.mtime;
          return xhr.get(L.url('admin/services/clientstatus/data')).then(function(d) {
            if (d && d.clients) { self.clients = d.clients; self.renderRows(); }
          });
        }
      });
    }, 30);

    return container;
  },

  val: function(c, k) {
    switch (k) {
      case 'status': return c.status === 'online' ? 0 : 1;
      case 'hostname': return (c.hostname || '').toLowerCase();
      case 'ipv4': return c.ipv4 || '';
      case 'rx': return (this.speeds[c.mac] || {}).rx || 0;
      case 'tx': return (this.speeds[c.mac] || {}).tx || 0;
      case 'duration': return this.parseDur(c.duration || '');
      case 'acl': return c.acl === 'Blocked' ? 0 : 1;
    }
    return '';
  },

  parseDur: function(s) {
    var t = 0, m;
    m = s.match(/(\d+)d/); if (m) t += +m[1] * 86400;
    m = s.match(/(\d+)h/); if (m) t += +m[1] * 3600;
    m = s.match(/(\d+)m/); if (m) t += +m[1] * 60;
    m = s.match(/(\d+)s/); if (m) t += +m[1];
    return t;
  },

  renderRows: function() {
    var self = this;
    var q = document.getElementById('cs-q');
    q = q ? q.value.toLowerCase() : '';
    var f = document.getElementById('cs-f');
    f = f ? f.value : 'all';
    var a = document.getElementById('cs-a');
    a = a ? a.value : 'all';
    var tbody = document.getElementById('cs-rows');
    if (!tbody) return;

    var list = this.clients.slice().sort(function(x, y) {
      var va = self.val(x, self.sortK), vb = self.val(y, self.sortK);
      if (typeof va === 'number') return self.sortA ? va - vb : vb - va;
      return self.sortA ? (va < vb ? -1 : va > vb ? 1 : 0) : (va > vb ? -1 : va < vb ? 1 : 0);
    });

    var html = '', n = 0, on = 0;
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (f !== 'all' && c.status !== f) continue;
      if (a !== 'all' && c.acl !== a) continue;
      if (q && (c.hostname + ' ' + c.mac + ' ' + (c.ipv4 || '')).toLowerCase().indexOf(q) < 0) continue;
      if (c.status === 'online') on++;
      var sp = this.speeds[c.mac] || { rx: 0, tx: 0, rx_tot: 0, tx_tot: 0 };
      var dot = c.status === 'online' ? 'on' : 'off';
      var blk = c.acl === 'Blocked';
      html += '<tr class="' + (c.status === 'online' ? '' : 'off') + '">'
        + '<td><span class="cs-dot ' + dot + '"></span></td>'
        + '<td><span class="cs-name" data-mac="' + esc(c.mac) + '" data-nm="' + esc(c.hostname) + '">' + esc(c.hostname) + '</span>'
        + '<div class="cs-mac">' + esc(c.mac) + '</div></td>'
        + '<td class="cs-ip">' + (c.status === 'online' ? esc(c.ipv4 || '–') : '–') + '</td>'
        + '<td><div class="cs-spd dn' + (sp.rx ? '' : ' zero') + '">' + fmt(sp.rx) + '</div>'
        + '<div class="cs-tot">' + fmtTot(sp.rx_tot) + '</div></td>'
        + '<td><div class="cs-spd up' + (sp.tx ? '' : ' zero') + '">' + fmt(sp.tx) + '</div>'
        + '<div class="cs-tot">' + fmtTot(sp.tx_tot) + '</div></td>'
        + '<td class="cs-dur">' + esc(c.duration || '–') + '</td>'
        + '<td><button class="cs-acl ' + (blk ? 'block' : 'allow') + '" data-mac="' + esc(c.mac) + '">'
        + (blk ? _('Blocked') : _('Allowed')) + '</button></td></tr>';
      n++;
    }
    tbody.innerHTML = html;
    document.getElementById('cs-empty').style.display = n ? 'none' : 'block';
    document.getElementById('cs-summary').innerHTML = '<b>' + on + '</b> ' + _('online') + ' · <b>' + (this.clients.length - on) + '</b> ' + _('offline');

    var dr = 0, ur = 0;
    for (var m in this.speeds) { dr += this.speeds[m].rx || 0; ur += this.speeds[m].tx || 0; }
    document.getElementById('cs-wan-dn').textContent = fmt(dr);
    document.getElementById('cs-wan-up').textContent = fmt(ur);
    document.getElementById('cs-updated').textContent = _('Updated') + ' ' + new Date().toTimeString().slice(0, 8);
  },

  bindEvents: function(container) {
    var self = this;

    container.querySelector('#cs-q').addEventListener('input', function() { self.renderRows(); });
    container.querySelector('#cs-f').addEventListener('change', function() { self.renderRows(); });
    container.querySelector('#cs-a').addEventListener('change', function() { self.renderRows(); });

    container.querySelectorAll('.cs-table th[data-k]').forEach(function(th) {
      th.addEventListener('click', function() {
        var k = th.getAttribute('data-k');
        if (self.sortK === k) self.sortA = !self.sortA;
        else { self.sortK = k; self.sortA = true; }
        self.renderRows();
      });
    });

    container.querySelector('#cs-refreshbtn').addEventListener('click', function() {
      xhr.get(L.url('admin/services/clientstatus/data')).then(function(d) {
        if (d && d.clients) { self.clients = d.clients; self.renderRows(); }
      });
    });

    container.querySelector('#cs-resetbtn').addEventListener('click', function() {
      xhr.post(L.url('admin/services/clientstatus/reset'), { token: L.env.token }).then(function(r) {
        if (r && r.ok) { self.speeds = {}; ui.addNotification(null, E('p', _('Cleared')), 'info'); self.renderRows(); }
      });
    });

    container.querySelector('#cs-rows').addEventListener('click', function(e) {
      var b = e.target.closest('.cs-acl');
      if (b) {
        b.disabled = true;
        xhr.post(L.url('admin/services/clientstatus/toggle_acl'), { token: L.env.token, mac: b.getAttribute('data-mac') }).then(function(r) {
          b.disabled = false;
          if (r && r.ok) {
            ui.addNotification(null, E('p', b.getAttribute('data-mac') + (r.blocked ? ' → ' + _('Blocked') : ' → ' + _('Allowed'))), 'info');
            xhr.get(L.url('admin/services/clientstatus/data')).then(function(d) {
              if (d && d.clients) { self.clients = d.clients; self.renderRows(); }
            });
          }
        });
        return;
      }
      var nm = e.target.closest('.cs-name');
      if (nm && !nm.querySelector('input')) {
        var mac = nm.getAttribute('data-mac'), cur = nm.getAttribute('data-nm');
        var inp = document.createElement('input');
        inp.className = 'cs-edit'; inp.value = cur; inp.maxLength = 64;
        nm.textContent = ''; nm.appendChild(inp); inp.focus(); inp.select();
        var done = false;
        function fin(ok) {
          if (done) return; done = true;
          if (ok && inp.value.trim() !== cur) {
            xhr.post(L.url('admin/services/clientstatus/save_hostname'), { token: L.env.token, mac: mac, hostname: inp.value.trim() }).then(function(r) {
              ui.addNotification(null, E('p', r && r.ok ? _('Saved') : 'Error'), r && r.ok ? 'info' : 'error');
              xhr.get(L.url('admin/services/clientstatus/data')).then(function(d) {
                if (d && d.clients) { self.clients = d.clients; self.renderRows(); }
              });
            });
          } else self.renderRows();
        }
        inp.addEventListener('keydown', function(ev) {
          if (ev.key === 'Enter') fin(true);
          if (ev.key === 'Escape') fin(false);
        });
        inp.addEventListener('blur', function() { setTimeout(function() { fin(true); }, 120); });
      }
    });
  }
});

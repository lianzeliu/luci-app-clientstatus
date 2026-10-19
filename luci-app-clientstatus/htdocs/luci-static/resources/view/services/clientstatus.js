'use strict';
'require view';

return view.extend({
	load: function() {
		return fetch(L.url('admin/services/clientstatus/data'), { credentials: 'same-origin' })
			.then(function(r) { return r.json(); });
	},

	render: function(data) {
		var clients = (data && data.clients) || [];
		var speeds = {};
		var sortK = 'status';
		var sortA = true;
		var mtime = -1;
		var timers = [];

		var css = document.createElement('style');
		css.textContent = '.cs{--surface:#fff;--text:#171717;--text2:#6b7280;--text3:#9ca3af;--line:#f1f2f4;--line2:#e5e7eb;--accent:#2563eb;--green:#16a34a;--red:#dc2626;--radius:10px;max-width:1100px;margin:0 auto;color:var(--text);font-size:14px}'
			+ 'html[data-theme="dark"] .cs{--surface:#17181c;--text:#e8e9ec;--text2:#9aa0aa;--text3:#6b7280;--line:#232529;--line2:#2e3138;--accent:#5b9cf8;--green:#4ade80;--red:#f87171}'
			+ '.cs-top{display:flex;justify-content:space-between;align-items:flex-end;padding:6px 2px 18px;gap:16px;flex-wrap:wrap}'
			+ '.cs-title h2{margin:0;font-size:20px;font-weight:650}'
			+ '.cs-title p{margin:5px 0 0;font-size:13px;color:var(--text2)}'
			+ '.cs-title p b{color:var(--text)}'
			+ '.cs-wan{text-align:right}.cs-wan-label{font-size:11px;color:var(--text3);letter-spacing:1px;margin-bottom:2px}'
			+ '.cs-wan-nums{display:flex;gap:18px;justify-content:flex-end;font-family:ui-monospace,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}'
			+ '.cs-wan-down{font-size:24px;font-weight:650;color:var(--green)}'
			+ '.cs-wan-up{font-size:24px;font-weight:650;color:var(--accent)}'
			+ '.cs-bar{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap}'
			+ '.cs-search{flex:1;min-width:160px;max-width:320px;padding:8px 12px;border:1px solid var(--line2);border-radius:8px;font-size:13px;background:var(--surface);color:var(--text);outline:none}'
			+ '.cs-sel{padding:8px 10px;border:1px solid var(--line2);border-radius:8px;font-size:13px;background:var(--surface);color:var(--text2);outline:none;cursor:pointer}'
			+ '.cs-sp{flex:1}'
			+ '.cs-btn{padding:8px 14px;border:1px solid var(--line2);border-radius:8px;font-size:13px;background:var(--surface);color:var(--text2);cursor:pointer;white-space:nowrap}'
			+ '.cs-btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}'
			+ '.cs-card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}'
			+ '.cs-table{width:100%;border-collapse:collapse}'
			+ '.cs-table th{padding:10px 14px;text-align:left;font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--line);white-space:nowrap;cursor:pointer;user-select:none}'
			+ '.cs-table td{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:middle}'
			+ '.cs-table tr:last-child td{border-bottom:none}'
			+ '.cs-table tbody tr.off{opacity:.55}'
			+ '.cs-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:9px}'
			+ '.cs-dot.on{background:var(--green)}'
			+ '.cs-dot.off{background:var(--text3)}'
			+ '.cs-name{font-weight:550;cursor:pointer}'
			+ '.cs-mac{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:var(--text3);margin-top:2px}'
			+ '.cs-ip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}'
			+ '.cs-dur{color:var(--text2);font-variant-numeric:tabular-nums;white-space:nowrap}'
			+ '.cs-spd{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;font-variant-numeric:tabular-nums;white-space:nowrap}'
			+ '.cs-spd.dn{color:var(--green)}.cs-spd.up{color:var(--accent)}.cs-spd.zero{color:var(--text3)}'
			+ '.cs-tot{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:var(--text3);margin-top:2px}'
			+ '.cs-acl{font-size:12.5px;padding:5px 12px;border-radius:20px;cursor:pointer;border:1px solid transparent;white-space:nowrap}'
			+ '.cs-acl.allow{color:var(--green);background:rgba(22,163,74,.08)}'
			+ '.cs-acl.block{color:var(--red);background:rgba(220,38,38,.08)}'
			+ '.cs-empty{text-align:center;padding:70px 20px;color:var(--text3)}'
			+ '.cs-foot{display:flex;justify-content:space-between;padding:12px 2px 0;font-size:12px;color:var(--text3)}'
			+ '.cs-edit{padding:4px 8px;border:1px solid var(--accent);border-radius:6px;font-size:13px;outline:none;background:var(--surface);color:var(--text);width:170px}'
			+ '@media(max-width:760px){.cs-card{overflow-x:auto}.cs-table{min-width:640px}.cs-bar .cs-sp{display:none}}';

		function apiGet(path) {
			return fetch(L.url(path) + '?_=' + Date.now(), { credentials: 'same-origin' })
				.then(function(r) { return r.json(); });
		}
		function apiPost(path, params) {
			var body = 'token=' + encodeURIComponent(L.env.token);
			for (var k in params)
				body += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
			return fetch(L.url(path), {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body
			}).then(function(r) { return r.json(); });
		}
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
			return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
		}
		function parseDur(s) {
			var t = 0, m;
			m = s.match(/(\d+)d/); if (m) t += +m[1] * 86400;
			m = s.match(/(\d+)h/); if (m) t += +m[1] * 3600;
			m = s.match(/(\d+)m/); if (m) t += +m[1] * 60;
			m = s.match(/(\d+)s/); if (m) t += +m[1];
			return t;
		}
		function val(c, k) {
			switch (k) {
				case 'status': return c.status === 'online' ? 0 : 1;
				case 'hostname': return (c.hostname || '').toLowerCase();
				case 'ipv4': return c.ipv4 || '';
				case 'rx': return (speeds[c.mac] || {}).rx || 0;
				case 'tx': return (speeds[c.mac] || {}).tx || 0;
				case 'duration': return parseDur(c.duration || '');
				case 'acl': return c.acl === 'Blocked' ? 0 : 1;
			}
			return '';
		}

		var root = document.createElement('div');
		root.className = 'cs';
		root.innerHTML =
			'<div class="cs-top"><div class="cs-title"><h2>' + _('Client Status') + '</h2>' +
			'<p id="cs-summary"></p></div>' +
			'<div class="cs-wan"><div class="cs-wan-label">WAN ' + _('Realtime') + '</div>' +
			'<div class="cs-wan-nums"><span class="cs-wan-down">↓ <span id="cs-wan-dn">–</span></span>' +
			'<span class="cs-wan-up">↑ <span id="cs-wan-up">–</span></span></div></div></div>' +
			'<div class="cs-bar"><input class="cs-search" id="cs-q" placeholder="' + _('Search hostname / IP / MAC') + '">' +
			'<select class="cs-sel" id="cs-f"><option value="all">' + _('All') + '</option>' +
			'<option value="online">' + _('Online') + '</option><option value="offline">' + _('Offline') + '</option></select>' +
			'<select class="cs-sel" id="cs-a"><option value="all">ACL: ' + _('All') + '</option>' +
			'<option value="Allowed">' + _('Allowed') + '</option><option value="Blocked">' + _('Blocked') + '</option></select>' +
			'<span class="cs-sp"></span>' +
			'<button class="cs-btn" id="cs-resetbtn">' + _('Reset') + '</button>' +
			'<button class="cs-btn primary" id="cs-refreshbtn">' + _('Refresh') + '</button></div>' +
			'<div class="cs-card"><table class="cs-table"><thead><tr>' +
			'<th data-k="status">' + _('Status') + '</th><th data-k="hostname">' + _('Hostname') + '</th>' +
			'<th data-k="ipv4">' + _('IP') + '</th><th data-k="rx">↓</th><th data-k="tx">↑</th>' +
			'<th data-k="duration">' + _('Duration') + '</th><th data-k="acl">ACL</th>' +
			'</tr></thead><tbody id="cs-rows"></tbody></table>' +
			'<div class="cs-empty" id="cs-empty" style="display:none">' + _('No clients found') + '</div></div>' +
			'<div class="cs-foot"><span id="cs-updated"></span><span>' + _('Auto refresh') + '</span></div>';

		var wrap = document.createElement('div');
		wrap.appendChild(css);
		wrap.appendChild(root);

		function renderRows() {
			var q = (wrap.querySelector('#cs-q') || {}).value || '';
			var f = (wrap.querySelector('#cs-f') || {}).value || 'all';
			var a = (wrap.querySelector('#cs-a') || {}).value || 'all';
			q = q.toLowerCase();
			var tbody = wrap.querySelector('#cs-rows');
			if (!tbody) return;

			var list = clients.slice().sort(function(x, y) {
				var va = val(x, sortK), vb = val(y, sortK);
				if (typeof va === 'number') return sortA ? va - vb : vb - va;
				return sortA ? (va < vb ? -1 : va > vb ? 1 : 0) : (va > vb ? -1 : va < vb ? 1 : 0);
			});

			var html = '', n = 0, on = 0;
			for (var i = 0; i < list.length; i++) {
				var c = list[i];
				if (f !== 'all' && c.status !== f) continue;
				if (a !== 'all' && c.acl !== a) continue;
				if (q && (c.hostname + ' ' + c.mac + ' ' + (c.ipv4 || '')).toLowerCase().indexOf(q) < 0) continue;
				if (c.status === 'online') on++;
				var sp = speeds[c.mac] || { rx: 0, tx: 0, rx_tot: 0, tx_tot: 0 };
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
			wrap.querySelector('#cs-empty').style.display = n ? 'none' : 'block';
			wrap.querySelector('#cs-summary').innerHTML = '<b>' + on + '</b> ' + _('online') + ' · <b>' + (clients.length - on) + '</b> ' + _('offline');

			var dr = 0, ur = 0;
			for (var m in speeds) { dr += speeds[m].rx || 0; ur += speeds[m].tx || 0; }
			wrap.querySelector('#cs-wan-dn').textContent = fmt(dr);
			wrap.querySelector('#cs-wan-up').textContent = fmt(ur);
			wrap.querySelector('#cs-updated').textContent = _('Updated') + ' ' + new Date().toTimeString().slice(0, 8);
		}

		function onUnload() {
			for (var i = 0; i < timers.length; i++) clearInterval(timers[i]);
			timers = [];
		}

		wrap.querySelector('#cs-q').addEventListener('input', renderRows);
		wrap.querySelector('#cs-f').addEventListener('change', renderRows);
		wrap.querySelector('#cs-a').addEventListener('change', renderRows);

		var ths = wrap.querySelectorAll('.cs-table th[data-k]');
		for (var ti = 0; ti < ths.length; ti++) {
			(function(th) {
				th.addEventListener('click', function() {
					var k = th.getAttribute('data-k');
					if (sortK === k) sortA = !sortA;
					else { sortK = k; sortA = true; }
					renderRows();
				});
			})(ths[ti]);
		}

		wrap.querySelector('#cs-refreshbtn').addEventListener('click', function() {
			apiGet('admin/services/clientstatus/data').then(function(d) {
				if (d && d.clients) { clients = d.clients; renderRows(); }
			});
		});

		wrap.querySelector('#cs-resetbtn').addEventListener('click', function() {
			apiPost('admin/services/clientstatus/reset', {}).then(function(r) {
				if (r && r.ok) { speeds = {}; renderRows(); }
			});
		});

		wrap.querySelector('#cs-rows').addEventListener('click', function(e) {
			var b = e.target.closest ? e.target.closest('.cs-acl') : null;
			if (b) {
				b.disabled = true;
				apiPost('admin/services/clientstatus/toggle_acl', { mac: b.getAttribute('data-mac') }).then(function(r) {
					b.disabled = false;
					if (r && r.ok) {
						apiGet('admin/services/clientstatus/data').then(function(d) {
							if (d && d.clients) { clients = d.clients; renderRows(); }
						});
					}
				});
				return;
			}
			var nm = e.target.closest ? e.target.closest('.cs-name') : null;
			if (nm && !nm.querySelector('input')) {
				var mac = nm.getAttribute('data-mac'), cur = nm.getAttribute('data-nm');
				var inp = document.createElement('input');
				inp.className = 'cs-edit'; inp.value = cur; inp.maxLength = 64;
				nm.textContent = ''; nm.appendChild(inp); inp.focus(); inp.select();
				var done = false;
				function fin(ok) {
					if (done) return; done = true;
					if (ok && inp.value.trim() !== cur) {
						apiPost('admin/services/clientstatus/save_hostname', { mac: mac, hostname: inp.value.trim() }).then(function() {
							apiGet('admin/services/clientstatus/data').then(function(d) {
								if (d && d.clients) { clients = d.clients; renderRows(); }
							});
						});
					} else renderRows();
				}
				inp.addEventListener('keydown', function(ev) {
					if (ev.key === 'Enter') fin(true);
					if (ev.key === 'Escape') fin(false);
				});
				inp.addEventListener('blur', function() { setTimeout(function() { fin(true); }, 120); });
			}
		});

		renderRows();

		timers.push(setInterval(function() {
			apiGet('admin/services/clientstatus/speed').then(function(res) {
				if (res && res.clients) { speeds = res.clients; renderRows(); }
			});
		}, 2000));

		timers.push(setInterval(function() {
			apiGet('admin/services/clientstatus/mtime').then(function(res) {
				if (res && res.mtime !== undefined && (mtime < 0 || res.mtime !== mtime)) {
					mtime = res.mtime;
					apiGet('admin/services/clientstatus/data').then(function(d) {
						if (d && d.clients) { clients = d.clients; renderRows(); }
					});
				}
			});
		}, 30000));

		this.onUnload = onUnload;

		return wrap;
	},

	onUnload: function() {}
});

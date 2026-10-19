'use strict';
'require view';
'require form';
'require uci';

return view.extend({
  render: function() {
    var m, s, o;

    m = new form.Map('clientstatus', _('Client Management Settings'),
      _('Note: Restart the service if the page does not display correctly after changing network settings.'));

    s = m.section(form.TypedSection, 'clientstatus', _('General Settings'));
    s.anonymous = true;
    s.addremove = false;

    o = s.option(form.Flag, 'enabled', _('Enable'),
      _('Enable or disable the client status monitoring service.'));
    o.default = '0';
    o.rmempty = false;

    o = s.option(form.Value, 'interval', _('Refresh Interval (seconds)'),
      _('How often to scan all clients. Default: 30 seconds.'));
    o.default = '30';
    o.datatype = 'and(uinteger,min(20))';
    o.rmempty = false;

    o = s.option(form.ListValue, 'lan_iface', _('LAN Interface'),
      _('Network interface to scan for clients. Usually br-lan.'));
    o.widget = 'select';
    o.default = 'br-lan';

    return uci.load('network').then(function() {
      var ifaces = [];
      uci.sections('network', 'interface', function(s) {
        if (s['.name'] !== 'loopback' && s.proto && s.device)
          ifaces.push(s.device);
      });
      ifaces.sort();
      for (var i = 0; i < ifaces.length; i++)
        o.value(ifaces[i]);
      return m.render();
    });
  }
});

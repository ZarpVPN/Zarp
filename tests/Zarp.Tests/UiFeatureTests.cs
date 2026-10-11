using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Zarp.Core;

// Окна страновых фильтров, сервера и эндпоинтов. Настоящие WARP и WinDivert не затрагиваются.
static partial class Program
{
    static void SetChecked(Control toggle, bool value) => toggle.GetType().GetProperty("Checked").SetValue(toggle, value);
    static bool IsChecked(Control toggle) => (bool)toggle.GetType().GetProperty("Checked").GetValue(toggle);

    static void TestConnectionForm()
    {
        var engine = NewEngine();
        using (var form = NewForm("ConnectionForm", engine))
        {
            PositionOffscreen(form);
            form.Show();
            Application.DoEvents();
            var useProxy = GetPrivate<Control>(form, "_useProxy");
            var link = GetPrivate<Control>(form, "_link");
            var dns = GetPrivate<Control>(form, "_dns");
            var endpoints = GetPrivate<Control>(form, "_endpoints");
            var save = GetPrivate<Button>(form, "_save");
            var reset = GetPrivate<Button>(form, "_reset");
            var serverPanel = GetPrivate<Control>(form, "_serverPanel");
            var warpPanel = GetPrivate<Control>(form, "_warpPanel");
            var endpointStatus = GetPrivate<Label>(form, "_endpointStatus");
            var linkStatus = GetPrivate<Label>(form, "_linkStatus");

            Check(!IsChecked(useProxy) && warpPanel.Visible && !serverPanel.Visible && !save.Enabled && !reset.Visible, "WARP endpoints are shown first and there is nothing to save");

            // эндпоинты WARP
            endpoints.Text = "162.159.198.2:8443\nnot an endpoint";
            Check(!save.Enabled && endpointStatus.Text == L.T("endpoint.invalid") && reset.Visible, "An invalid endpoint cannot be saved and is explained");
            endpoints.Text = "162.159.198.2:8443\n[2606:4700::1]:443";
            Check(save.Enabled && endpointStatus.Text == "", "Valid endpoints can be saved");
            engine.Config.Results["warp-q-google6"] = new TestResult { StrategyId = "warp-q-google6", Ok = true, Confirmed = true };
            save.PerformClick();
            Check(engine.Config.CustomEndpoints == "162.159.198.2:8443\n[2606:4700::1]:443" && engine.Config.Results.Count == 0 && !save.Enabled,
                "Saving stores the endpoints, clears the old checks and waits for the next change");
            Check(AppConfig.Load(Path.Combine(engine.DataDir, "zarp.json")).CustomEndpoints.Contains("2606:4700::1"), "The endpoints survive a restart");
            reset.PerformClick();
            Check(endpoints.Text == "" && save.Enabled && !reset.Visible, "Reset empties the list; saving it returns the WARP defaults");
            save.PerformClick();
            Check(engine.Config.CustomEndpoints == "", "Defaults are restored");

            // собственный сервер
            SetChecked(useProxy, true);
            Check(serverPanel.Visible && !warpPanel.Visible && !save.Enabled, "A server needs a link first");
            link.Text = "vless://nope";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.invalid"), "A bad link is explained and cannot be saved: " + linkStatus.Text);
            // ссылка из другой программы с XHTTP: принимается, как любая другая (подключение идёт через мост Xray)
            link.Text = "vless://" + TestUuid + "@docs.example:8433?encryption=none&extra=%7B%22mode%22%3A%22auto%22%2C%22seqKey%22%3A%22X-Seq%22%7D&mode=auto&path=%2F&security=tls&type=xhttp";
            Check(save.Enabled && linkStatus.Text == "VLESS: docs.example:8433", "An XHTTP link can be saved: " + linkStatus.Text);
            link.Text = "vless://" + TestUuid + "@docs.example:8433?security=tls&type=xhttp&extra=nope";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.extra"), "An extra parameter that is not JSON is explained: " + linkStatus.Text);
            link.Text = "vless://" + TestUuid + "@docs.example:8433?security=tls&type=xhttp&allowInsecure=1";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.insecure"), "XHTTP without the certificate check is explained: " + linkStatus.Text);
            link.Text = "vmess://abc";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.scheme"), "Another kind of link says which links are accepted: " + linkStatus.Text);
            link.Text = "trojan://secret@proxy.example:443?type=kcp";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.transport", "kcp") && !linkStatus.Text.Contains("secret"), "An unsupported transport is named: " + linkStatus.Text);
            link.Text = "trojan://secret@proxy.example:443?headerType=http";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.param", "headerType") && !linkStatus.Text.Contains("secret"), "An unsupported parameter is named: " + linkStatus.Text);
            Check(linkStatus.Text.Length > 0 && TextRenderer.MeasureText(linkStatus.Text, linkStatus.Font, new System.Drawing.Size(linkStatus.Width, int.MaxValue), TextFormatFlags.WordBreak).Height <= linkStatus.Height,
                "The explanation fits the space under the link");
            link.Text = "trojan://secret@proxy.example:443";
            Check(save.Enabled && linkStatus.Text == "Trojan: proxy.example:443" && !linkStatus.Text.Contains("secret"), "A good link shows the protocol and address, never the password");
            dns.Text = "not-an-ip";
            Check(!save.Enabled && linkStatus.Text == L.T("proxy.dnsInvalid"), "A bad DNS server cannot be saved");
            dns.Text = "9.9.9.9, 1.1.1.1";
            SetChecked(GetPrivate<Control>(form, "_ipv6"), false);
            Check(save.Enabled, "Setup: ready to save the server");
            engine.Config.Results["x"] = new TestResult { StrategyId = "x", Ok = true };
            save.PerformClick();
            var c = engine.Config;
            Check(c.UseProxy && c.ProxyUri == "trojan://secret@proxy.example:443" && !c.ProxyIpv6 && c.ProxyDns == "9.9.9.9, 1.1.1.1" && c.Results.Count == 0 &&
                  engine.Strategies.Count > 0 && engine.Strategies.All(s => s.IsProxy && s.UsesZapret && s.Profile.Host == "proxy.example"), "Saving switches the engine to the server");
            var saved = AppConfig.Load(Path.Combine(engine.DataDir, "zarp.json"));
            Check(saved.UseProxy && saved.ProxyUri == c.ProxyUri && !saved.ProxyIpv6, "The server settings are stored");

            // во время операции менять сервер нельзя
            link.Text = "trojan://secret@other.example:443";
            Check(save.Enabled, "Setup: a changed link can be saved");
            SetPrivate(engine, "<State>k__BackingField", EngineState.Searching);
            typeof(Engine).GetMethod("SetDetail", PrivateInstance).Invoke(engine, new object[] { new Msg("detail.preparing") }); // сообщает окну об изменении
            Application.DoEvents();
            Check(!save.Enabled, "Nothing can be saved while a search runs");
            SetPrivate(engine, "<State>k__BackingField", EngineState.Idle);
        }
    }

    static void TestCountryFilterControl()
    {
        var engine = NewEngine();
        using (var settings = NewForm("SettingsForm", engine))
        {
            PositionOffscreen(settings);
            settings.Show();
            Application.DoEvents();
            var filter = GetPrivate<Button>(settings, "_filter");
            var list = GetPrivate<ListView>(settings, "_list");
            var menu = (ContextMenuStrip)filter.GetType().GetField("_menu", PrivateInstance).GetValue(filter);
            int all = list.Items.Count;
            filter.PerformClick(); // меню открывается, и только тогда его пункты откликаются на нажатие
            Check(menu.Visible && menu.Items.Count == 4, "The menu offers All and three countries");
            Check(all == engine.Strategies.Count && filter.Text == L.T("filter.button", L.T("country.all")), "All strategies are listed at first");

            menu.Items[2].PerformClick(); // Иран: фейки российских сервисов в список не попадают
            Check(engine.Config.StrategyCountry == "ir" && list.Items.Count == StrategyFilter.Apply(engine.Strategies, "ir").Count && list.Items.Count < all,
                "Choosing a country filters the list and saves the choice: " + engine.Config.StrategyCountry + ", " + list.Items.Count + " of " + all);
            Check(AppConfig.Load(Path.Combine(engine.DataDir, "zarp.json")).StrategyCountry == "ir", "The choice survives a restart");
            menu.Items[1].PerformClick(); // и Россия
            Check(engine.Config.StrategyCountry == "ru,ir" && filter.Text == L.T("filter.button", L.T("country.ru") + ", " + L.T("country.ir")) &&
                  ((ToolStripMenuItem)menu.Items[1]).Checked && ((ToolStripMenuItem)menu.Items[2]).Checked && !((ToolStripMenuItem)menu.Items[0]).Checked &&
                  list.Items.Count == all, "Several countries can be chosen at once, form a union and are shown in the button");
            Check(list.Items.Cast<ListViewItem>().All(i => ((Strategy)i.Tag).UsesZapret), "Strategies without desync are not listed under a country");
            menu.Items[0].PerformClick(); // все
            Check(engine.Config.StrategyCountry == "all" && list.Items.Count == all && ((ToolStripMenuItem)menu.Items[0]).Checked, "All clears the filter");
            menu.Items[3].PerformClick(); // Китай
            menu.Items[3].PerformClick(); // и снова: выключенная последняя страна - это «все»
            Check(engine.Config.StrategyCountry == "all", "Switching the last country off returns to All");

            Check(menu.Visible, "The menu stays open while countries are chosen");
            menu.Close();

            // фильтр нельзя менять во время поиска
            SetPrivate(engine, "<State>k__BackingField", EngineState.Searching);
            settings.GetType().GetMethod("UpdateButtons", PrivateInstance).Invoke(settings, null);
            Check(!filter.Enabled, "The filter is locked while a search runs");
            SetPrivate(engine, "<State>k__BackingField", EngineState.Idle);
            settings.GetType().GetMethod("UpdateButtons", PrivateInstance).Invoke(settings, null);
        }
    }
}

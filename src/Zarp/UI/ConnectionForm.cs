using System;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Windows.Forms;
using Zarp.Core;

namespace Zarp.UI
{
    /// <summary>
    /// Эндпоинты WARP и собственный сервер вместо WARP. Изменения применяются при следующем подключении,
    /// а прежние результаты проверок сбрасываются: они относились к другому серверу.
    /// </summary>
    sealed class ConnectionForm : DialogBase
    {
        readonly Engine _engine;
        readonly ToggleSwitch _useProxy = new ToggleSwitch(L.T("proxy.enable"));
        readonly ToggleSwitch _ipv6 = new ToggleSwitch(L.T("proxy.ipv6"));
        readonly DarkTextBox _link = new DarkTextBox(true);
        readonly DarkTextBox _dns = new DarkTextBox(false);
        readonly DarkTextBox _endpoints = new DarkTextBox(true);
        readonly Label _linkStatus = new Label();
        readonly Label _endpointStatus = new Label();
        readonly Panel _serverPanel = new Panel();
        readonly Panel _warpPanel = new Panel();
        readonly DarkButton _reset, _save, _close;
        readonly int _statusHeight;
        bool _loading;
        // загрузка подписки идёт (кнопка «Сохранить» ждёт) и её последняя неудача: показывается, пока текст в поле не изменили
        bool _loadingSubscription;
        readonly System.Threading.CancellationTokenSource _cancel = new System.Threading.CancellationTokenSource();
        Msg _failure;
        string _failureFor;

        public ConnectionForm(Engine engine) : base(L.T("endpoint.title"))
        {
            _engine = engine;
            const int Pad = 20, W = 600;
            var mono = new Font("Consolas", 9.5f);

            var title = Heading(L.T("endpoint.title"), new Point(Pad - 2, 16));
            _useProxy.Location = new Point(Pad, title.Bottom + 12);

            // ---- собственный сервер
            var proxyHint = Note(L.T("proxy.hint"), new Point(0, 0), W);
            _link.EditorFont = mono;
            _link.AccessibleName = L.T("proxy.link");
            _link.Bounds = new Rectangle(0, proxyHint.Bottom + 8, W, 92);
            _link.MaxLength = 8192;
            // одна высота для любой подсказки под ссылкой: самая длинная из возможных (имя в подсказке - до 24 знаков)
            string longest = new string('W', 24);
            var reasons = new[] { L.T("proxy.subHttp", "503"), L.T("proxy.subTimeout"), L.T("proxy.subNetwork"), L.T("proxy.subTls"), L.T("proxy.subBig"), L.T("proxy.subRedirect"), L.T("proxy.subEmpty") };
            _statusHeight = new[]
            {
                L.T("proxy.invalid"), L.T("proxy.dnsInvalid"), L.T("proxy.extra"), L.T("proxy.insecure"), L.T("proxy.scheme"),
                L.T("proxy.param", longest), L.T("proxy.transport", longest), L.T("proxy.security", longest),
                L.T("proxy.subscription", new string('w', 40)), L.T("proxy.subscriptionKnown", 200, "31.12.2026 23:59"), L.T("proxy.subscriptionLoading"),
                L.T("proxy.subscriptionHttps"), L.T("proxy.subscriptionUrl"), L.T("proxy.subscriptionEmpty"), L.T("proxy.subscriptionJson"), L.T("proxy.subscriptionHtml"),
            }.Concat(reasons.Select(r => L.T("proxy.subscriptionFailed", r))).Max(text => Note(text, Point.Empty, W).Height);
            _linkStatus.Bounds = new Rectangle(0, _link.Bottom + 6, W, _statusHeight);
            _linkStatus.AutoSize = false;
            _linkStatus.AutoEllipsis = true;
            _ipv6.Location = new Point(0, _linkStatus.Bottom + 6);
            // шрифт задан явно: ширина считается сейчас, до того как метка попадёт на форму и унаследует его
            var dnsLabel = new Label { Text = L.T("proxy.dns"), Font = Font, AutoSize = true, ForeColor = Theme.Text };
            dnsLabel.Location = new Point(0, 0);
            _dns.AccessibleName = L.T("proxy.dns");
            _dns.EditorFont = mono;
            _dns.Size = new Size(170, 32);
            _dns.Location = new Point(W - _dns.Width, _ipv6.Top - 1);
            dnsLabel.Location = new Point(_dns.Left - 10 - dnsLabel.PreferredWidth, _ipv6.Top + 6);
            _serverPanel.Size = new Size(W, Math.Max(_ipv6.Bottom, _dns.Bottom) + 2);
            _serverPanel.Controls.AddRange(new Control[] { proxyHint, _link, _linkStatus, _ipv6, dnsLabel, _dns });

            // ---- эндпоинты WARP
            var warpTitle = new Label { Text = L.T("endpoint.warp"), Font = Theme.Font(10.5f, FontStyle.Bold), AutoSize = true, Location = Point.Empty };
            var warpHint = Note(L.T("endpoint.hint"), new Point(0, warpTitle.PreferredHeight + 6), W);
            _endpoints.EditorFont = mono;
            _endpoints.AccessibleName = L.T("endpoint.warp");
            _endpoints.Bounds = new Rectangle(0, warpHint.Bottom + 8, W, 128);
            _endpointStatus.Bounds = new Rectangle(0, _endpoints.Bottom + 6, W, Note(L.T("endpoint.invalid"), Point.Empty, W).Height);
            _endpointStatus.AutoSize = false;
            _reset = Theme.FlatButton(L.T("endpoint.reset"), 160);
            _reset.Location = new Point(0, _endpointStatus.Bottom + 6);
            _reset.Click += (s, e) => _endpoints.Text = "";
            _warpPanel.Size = new Size(W, _reset.Bottom + 2);
            _warpPanel.Controls.AddRange(new Control[] { warpTitle, warpHint, _endpoints, _endpointStatus, _reset });

            int panelHeight = Math.Max(_serverPanel.Height, _warpPanel.Height);
            _serverPanel.Location = _warpPanel.Location = new Point(Pad, _useProxy.Bottom + 10);
            _serverPanel.Height = _warpPanel.Height = panelHeight;

            var applies = Note(L.T("endpoint.applies"), new Point(Pad, _serverPanel.Bottom + 8), W);
            _save = Theme.FlatButton(L.T("btn.save"), 110, primary: true);
            _close = Theme.FlatButton(L.T("btn.close"), 110);
            _close.Location = new Point(Pad + W - _close.Width, applies.Bottom + 14);
            _save.Location = new Point(_close.Left - 8 - _save.Width, _close.Top);
            _save.Click += (s, e) => Save();
            _close.Click += (s, e) => Close();

            ClientSize = new Size(W + Pad * 2, _close.Bottom + 18);
            Controls.AddRange(new Control[] { title, _useProxy, _serverPanel, _warpPanel, applies, _save, _close });

            LoadValues();
            _useProxy.CheckedChanged += (s, e) => Changed();
            _ipv6.CheckedChanged += (s, e) => Changed();
            _link.TextChanged += (s, e) => Changed();
            _dns.TextChanged += (s, e) => Changed();
            _endpoints.TextChanged += (s, e) => Changed();
            engine.Changed += OnEngineChanged;
            Changed();
        }

        void LoadValues()
        {
            _loading = true;
            var c = _engine.Config;
            _useProxy.Checked = c.UseProxy;
            _link.Text = c.ProxyUri;
            _ipv6.Checked = c.ProxyIpv6;
            _dns.Text = c.ProxyDns;
            _endpoints.Text = c.CustomEndpoints;
            _loading = false;
        }

        static bool DnsValid(string text)
        {
            var parts = (text ?? "").Split(',').Select(p => p.Trim()).ToList();
            return parts.Count > 0 && parts.All(p => IPAddress.TryParse(p, out _));
        }

        /// <summary>Пересчитать подсказки и доступность кнопки сохранения.</summary>
        void Changed()
        {
            if (_loading) return;
            bool proxy = _useProxy.Checked;
            _serverPanel.Visible = proxy;
            _warpPanel.Visible = !proxy;

            ProxyProfile.TryParse(_link.Text, out var profile);
            bool subscription = Subscription.IsUrl(_link.Text);
            bool dnsOk = DnsValid(_dns.Text);
            bool failed = _failure != null && _failureFor == _link.Text.Trim();
            if ((profile != null || subscription) && dnsOk && !failed)
            {
                _linkStatus.ForeColor = Theme.TextDim;
                _linkStatus.Text = subscription ? SubscriptionStatus() : profile.Title + ": " + profile.Endpoint;
            }
            else
            {
                _linkStatus.ForeColor = Theme.Bad;
                _linkStatus.Text = failed ? _failure.ToString() : _link.Text.Trim().Length == 0 ? ""
                    : profile == null && !subscription ? (ProxySource.Explain(_link.Text) ?? new Msg("proxy.invalid")).ToString() : L.T("proxy.dnsInvalid");
            }

            bool endpointsOk = EndpointParser.TryParse(_endpoints.Text, out _);
            _endpointStatus.ForeColor = Theme.Bad;
            _endpointStatus.Text = endpointsOk ? "" : L.T("endpoint.invalid");
            _reset.Visible = _endpoints.Text.Trim().Length > 0;

            var c = _engine.Config;
            bool dirty = _useProxy.Checked != c.UseProxy || _link.Text.Trim() != c.ProxyUri.Trim() || _ipv6.Checked != c.ProxyIpv6
                         || _dns.Text.Trim() != c.ProxyDns || _endpoints.Text.Trim() != c.CustomEndpoints.Trim();
            // подписку «Сохранить» ещё и загружает заново: так обновляют список серверов, не меняя адрес
            _save.Enabled = !_engine.IsBusy && !_loadingSubscription && (dirty || (proxy && subscription)) && endpointsOk && (!proxy || ((profile != null || subscription) && dnsOk));
        }

        /// <summary>Подпись под полем для подписки: что загружается, сколько серверов в сохранённом списке и когда он обновлён.</summary>
        string SubscriptionStatus()
        {
            string url = _link.Text.Trim();
            if (_loadingSubscription) return L.T("proxy.subscriptionLoading");
            var snapshot = _engine.SubscriptionSnapshot(url);
            return snapshot == null
                ? L.T("proxy.subscription", Subscription.HostOf(url))
                : L.T("proxy.subscriptionKnown", snapshot.Links.Count, snapshot.Updated.ToLocalTime().ToString("g"));
        }

        async void Save()
        {
            if (!_save.Enabled) return;
            string text = _link.Text.Trim();
            if (_useProxy.Checked && Subscription.IsUrl(text))
            {
                // список серверов загружается сразу: так сразу видно, что подписка работает и сколько в ней серверов
                _loadingSubscription = true;
                Changed();
                SubscriptionResult result = null;
                Msg failure = null;
                try { result = await _engine.LoadSubscriptionAsync(text, _cancel.Token); }
                catch (SubscriptionException e) { failure = new Msg("proxy.subscriptionFailed", e.Describe().ToString()); }
                catch (OperationCanceledException) { return; }
                catch (Exception) { failure = new Msg("proxy.subscriptionFailed", L.T("proxy.subNetwork")); }
                finally { _loadingSubscription = false; }
                if (IsDisposed) return;
                if (failure == null && result.Servers.Count == 0)
                    failure = new Msg(result.Json ? "proxy.subscriptionJson" : result.Html ? "proxy.subscriptionHtml" : "proxy.subscriptionEmpty");
                if (failure != null)
                {
                    _failure = failure;
                    _failureFor = text;
                    Changed();
                    return;
                }
                _failure = null;
            }
            var c = _engine.Config;
            c.ProxyIpv6 = _ipv6.Checked;
            c.ProxyDns = _dns.Text.Trim();
            _engine.ApplyConnection(_endpoints.Text, _useProxy.Checked, _link.Text);
            Changed();
        }

        void OnEngineChanged()
        {
            if (!IsHandleCreated || IsDisposed) return;
            try { BeginInvoke((Action)(() => { if (!IsDisposed) Changed(); })); }
            catch (InvalidOperationException) { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _engine.Changed -= OnEngineChanged;
                try { _cancel.Cancel(); } catch (ObjectDisposedException) { }
            }
            base.Dispose(disposing);
        }
    }
}

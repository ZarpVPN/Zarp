using System;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using Zarp.Core;

namespace Zarp.UI
{
    sealed class WarpPlusForm : DialogBase
    {
        readonly Engine _engine;
        readonly DarkTextBox _key = new DarkTextBox(false);
        readonly Label _account, _status;
        readonly DarkButton _apply, _refresh;
        readonly CancellationTokenSource _cancel = new CancellationTokenSource();
        bool _working;

        public WarpPlusForm(Engine engine) : base(L.T("warpPlus.title"))
        {
            _engine = engine;
            const int Pad = 20, W = 560;
            var title = Heading(L.T("warpPlus.title"), new Point(Pad - 2, 16));
            var hint = Note(L.T("warpPlus.hint"), new Point(Pad, title.Bottom + 12), W);
            _account = Note(L.T("warpPlus.account", L.T("warpPlus.unknown")), new Point(Pad, hint.Bottom + 14), W);
            var label = Note(L.T("warpPlus.key"), new Point(Pad, _account.Bottom + 16), W);
            _key.Bounds = new Rectangle(Pad, label.Bottom + 6, W, 32);
            _key.AccessibleName = L.T("warpPlus.key");
            _key.Editor.UseSystemPasswordChar = true;
            _key.MaxLength = 128;
            var privacy = Note(L.T("warpPlus.privacy"), new Point(Pad, _key.Bottom + 8), W);
            string[] messages = { "invalid", "loading", "applying", "applied", "unconfirmed", "applyFailed", "accountFailed", "timeout", "busy", "noWarp" };
            int height = messages.Max(key => Note(L.T("warpPlus." + key), Point.Empty, W).Height);
            _status = Note("", new Point(Pad, privacy.Bottom + 12), W);
            _status.AutoSize = false;
            _status.Height = height;
            _apply = Theme.FlatButton(L.T("warpPlus.apply"), 150, primary: true);
            _refresh = Theme.FlatButton(L.T("warpPlus.refresh"), 150);
            var close = Theme.FlatButton(L.T("btn.close"), 110);
            _apply.Location = new Point(Pad, _status.Bottom + 14);
            _refresh.Location = new Point(_apply.Right + 8, _apply.Top);
            close.Location = new Point(Pad + W - close.Width, _apply.Top);
            _apply.Click += (s, e) => Run(apply: true);
            _refresh.Click += (s, e) => Run(apply: false);
            close.Click += (s, e) => Close();
            _key.TextChanged += (s, e) =>
            {
                if (!_working) ShowStatus(_key.Text.Length > 0 && !Warp.IsLicenseValid(_key.Text) ? L.T("warpPlus.invalid") : "", error: true);
                UpdateButtons();
            };
            Controls.AddRange(new Control[] { title, hint, _account, label, _key, privacy, _status, _apply, _refresh, close });
            ClientSize = new Size(W + Pad * 2, close.Bottom + 18);
            engine.Changed += OnEngineChanged;
            Shown += (s, e) => Run(apply: false);
            UpdateButtons();
        }

        async void Run(bool apply)
        {
            if (_working || _engine.IsBusy || (apply && !Warp.IsLicenseValid(_key.Text))) return;
            _working = true;
            UpdateButtons();
            ShowStatus(L.T(apply ? "warpPlus.applying" : "warpPlus.loading"));
            try
            {
                var account = apply ? await _engine.ApplyWarpLicenseAsync(_key.Text, _cancel.Token)
                                    : await _engine.ReadWarpAccountAsync(_cancel.Token);
                if (IsDisposed) return;
                _account.Text = L.T("warpPlus.account", L.T("warpPlus." + account.ToString().ToLowerInvariant()));
                if (apply)
                {
                    _key.Text = "";
                    bool plus = account == WarpAccountType.Plus || account == WarpAccountType.Unlimited;
                    ShowStatus(L.T(plus ? "warpPlus.applied" : "warpPlus.unconfirmed"), error: !plus);
                }
                else ShowStatus("");
            }
            catch (OperationCanceledException) { if (!IsDisposed) ShowStatus(""); }
            catch (Exception e)
            {
                if (!IsDisposed)
                {
                    _account.Text = L.T("warpPlus.account", L.T("warpPlus.unknown"));
                    // Только собственные безопасные сообщения; сырой вывод warp-cli никогда не попадает в UI.
                    string[] errors = { "invalid", "noWarp", "busy", "applyFailed", "accountFailed", "timeout" };
                    ShowStatus(errors.Select(k => L.T("warpPlus." + k)).FirstOrDefault(t => t == e.Message)
                               ?? L.T(apply ? "warpPlus.applyFailed" : "warpPlus.accountFailed"), error: true);
                }
            }
            finally { _working = false; if (!IsDisposed) UpdateButtons(); }
        }

        void ShowStatus(string text, bool error = false)
        {
            _status.Text = text;
            _status.ForeColor = error ? Theme.Bad : Theme.TextDim;
        }

        void UpdateButtons()
        {
            bool available = !_working && !_engine.IsBusy;
            _apply.Enabled = available && Warp.IsLicenseValid(_key.Text);
            _refresh.Enabled = available;
            _key.Enabled = available;
        }

        void OnEngineChanged()
        {
            if (!IsHandleCreated || IsDisposed) return;
            try { BeginInvoke((Action)(() => { if (!IsDisposed) UpdateButtons(); })); }
            catch (InvalidOperationException) { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _engine.Changed -= OnEngineChanged;
                try { _cancel.Cancel(); } catch (ObjectDisposedException) { }
                _key.Text = "";
            }
            base.Dispose(disposing);
        }
    }
}

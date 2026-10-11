using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using Zarp.Core;

// Причины отказов моста Xray на настоящем сервере: что пользователь увидит в журнале, когда сервер есть, а подключение не получается.
static partial class Program
{
    /// <summary>
    /// Тот же сервер, но ссылка с испорченным параметром (From - регулярное выражение, To - замена). Проверка соединения не проходит, а
    /// причина, если Xray её назвал, показана без пути XHTTP и адресов страниц. Expect - что должно быть в причине; пусто - Xray
    /// молчит (сервер с неверным UUID просто закрывает соединение, и причины в журнале нет: сообщение остаётся общим).
    /// </summary>
    static void TestXrayFailureReasons() => WithEmbeddedEngines((box, xray) =>
    {
        const string OtherUuid = "00000000-0000-4000-8000-0000000000ff";
        var cases = new (string Variant, string Name, string From, string To, string Expect)[]
        {
            ("tls-stream-up", "wrong certificate pin", "pcs=[0-9a-f]{64}", "pcs=" + new string('0', 64), "pinnedPeerCertSha256"),
            ("tls-stream-up", "wrong uuid", TestUuid, OtherUuid, null),
            ("tls-stream-up", "wrong path", "path=%2Fxh", "path=%2Fsecret-nope", "404"),
            ("none", "wrong uuid", TestUuid, OtherUuid, null),
            ("none", "wrong path", "path=%2Fxh", "path=%2Fsecret-nope", "404"),
            ("reality", "wrong public key", "pbk=[A-Za-z0-9_-]+", "pbk=" + TestRealityKey, "REALITY"),
            ("reality", "wrong short id", "sid=0123abcd", "sid=ffff", "certificate"),
            ("reality", "wrong uuid", TestUuid, OtherUuid, null),
        };
        var runtime = new ProxyRuntime(box, xray);
        using (var web = new FakeServer(new byte[16]))
        {
            foreach (var group in cases.GroupBy(c => c.Variant))
            using (var dest = group.Key.StartsWith("reality") ? StartLoopbackServer(box, "trojan") : null)
            using (var server = StartXrayServer(box, xray, group.Key, dest))
            {
                // сначала исправная ссылка: тот же сервер и страница отвечают, значит отказ ниже вызван именно испорченным параметром
                try
                {
                    var good = runtime.NewSession(ProxyProfile.Parse(server.Link));
                    good.Address = "127.0.0.1";
                    Check(StartRuntime(runtime, good) == null, group.Key + ": the intact link must start");
                    SetPrivate(runtime, "TraceUrl", web.Url("/trace"));
                    var ok = Sync(() => runtime.MeasureAsync(good, 1, 10000, CancellationToken.None));
                    Check(ok.Ok, group.Key + ": the intact link must pass the check, " + ok.Error);
                }
                finally { runtime.Stop(); }

                foreach (var c in group)
                {
                    string link = Regex.Replace(server.Link, c.From, c.To);
                    Check(link != server.Link, "Setup: the link must change for " + c.Name);
                    try
                    {
                        var session = runtime.NewSession(ProxyProfile.Parse(link));
                        session.Address = "127.0.0.1";
                        var err = StartRuntime(runtime, session);
                        Check(err == null, c.Variant + " / " + c.Name + ": the session must start: " + err);
                        SetPrivate(runtime, "TraceUrl", web.Url("/trace"));
                        var m = Sync(() => runtime.MeasureAsync(session, 1, 8000, CancellationToken.None));
                        string why = runtime.LastError();
                        string name = c.Variant + " / " + c.Name;
                        Check(!m.Ok && m.Failed == 2, name + ": the check must fail, ok=" + m.Ok + ", failed=" + m.Failed);
                        Check(why == null || (!why.Contains("secret-nope") && !why.Contains("http://") && !why.Contains(TestUuid)), name + ": the reason shows no path, address of a page or UUID: " + why);
                        if (c.Expect != null)
                            Check(why != null && why.Contains(c.Expect), name + ": the reason must name '" + c.Expect + "', got: " + (why ?? "nothing") + Environment.NewLine + xray.ReadLog());
                    }
                    finally { runtime.Stop(); }
                }
            }
        }
    });
}

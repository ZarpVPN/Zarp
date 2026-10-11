using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Zarp.Core;

// Движок в режиме собственного сервера. sing-box подменён: ни процессов, ни сети, ни адаптера. winws2 подменён программой,
// которая просто живёт: настоящий winws2 и WinDivert не запускаются, но движок видит процесс по пути, как настоящий.
static partial class Program
{
    sealed class FakeProxy : ProxyRuntime
    {
        public readonly List<ProxySession> Started = new List<ProxySession>();
        public Func<ProxySession, Msg> StartResult = s => null;
        public Func<ProxySession, ProxyMeasure> Measure = s => new ProxyMeasure { Ok = true, FirstMs = 120, PingMs = 40 };
        public ProxySession AdoptResult;
        public bool IsRunning, Adapter = true, TunnelOk = true;
        public int Stops;
        /// <summary>Сколько раз просили приготовить мост Xray и что ответить. Исключение вместо ответа - как антивирус, заблокировавший файл.</summary>
        public int BridgePrepared;
        public Func<bool> BridgeResult = () => true;
        /// <summary>sing-box на месте, а мост Xray пропал.</summary>
        public bool BridgeDied;
        /// <summary>Вызывается при каждом запуске сессии: тест смотрит, что в этот момент делает winws2.</summary>
        public Action<ProxySession> OnStart;

        public FakeProxy(string dir) : base(new SingBox(dir)) { }
        public override bool Running => IsRunning;
        public override bool Intact => IsRunning && !BridgeDied;
        public override bool BridgeLost => IsRunning && BridgeDied;
        public override void Stop() { Stops++; IsRunning = false; }
        public override bool Prepare() => true;
        public override bool PrepareBridge() { BridgePrepared++; return BridgeResult(); }
        public override ProxySession NewSession(ProxyProfile profile) => new ProxySession { Profile = profile, Port = 18080, User = "zarp", Password = "pw" };
        /// <summary>Какие имена просили разрешить, по порядку.</summary>
        public readonly List<string> Resolved = new List<string>();
        public Func<string, string> Resolve = host => "203.0.113.9";
        public override Task<string> ResolveAsync(string host, CancellationToken ct)
        {
            lock (Resolved) Resolved.Add(host);
            string address = Resolve(host);
            return address != null ? Task.FromResult(address) : Task.FromException<string>(new IOException("cannot resolve " + host));
        }
        public override Task<Msg> StartAsync(ProxySession session, CancellationToken ct)
        {
            Started.Add(session);
            OnStart?.Invoke(session);
            var err = StartResult(session);
            IsRunning = err == null;
            return Task.FromResult(err);
        }
        /// <summary>Сколько раз просили один запрос и полный замер. Полный замер нужен только паре, у которой прошёл первый запрос.</summary>
        public int Probes, Measures;
        /// <summary>Ответ на первый запрос; без него - тот же, что у замера.</summary>
        public Func<ProxySession, ProxyMeasure> Probe;
        public override Task<ProxyMeasure> MeasureAsync(ProxySession session, int samples, int timeoutMs, CancellationToken ct) { Measures++; return Task.FromResult(Measure(session)); }
        public override Task<ProxyMeasure> ProbeAsync(ProxySession session, int timeoutMs, CancellationToken ct) { Probes++; return Task.FromResult((Probe ?? Measure)(session)); }
        public override Task<bool> WaitAdapterAsync(CancellationToken ct) => Task.FromResult(Adapter);
        public override Task<bool> CheckTunnelAsync(int timeoutMs, CancellationToken ct) => Task.FromResult(TunnelOk);
        public override string LastError() => null;
        /// <summary>Подхват по серверу (если серверов несколько); без него любой сервер получает AdoptResult.</summary>
        public Func<ProxyProfile, ProxySession> AdoptFor;
        public override ProxySession Adopt(ProxyProfile profile) => AdoptFor != null ? AdoptFor(profile) : AdoptResult;
    }

    const string TestLink = "trojan://secret@proxy.example:443?sni=front.example";

    static readonly string[] AllCountries = { "ru", "ir", "cn" };

    /// <summary>
    /// Небольшой известный набор стратегий zapret2 для тестов движка: две под TLS по TCP и две под QUIC, вперемешку, как в настоящем
    /// каталоге. Названия и аргументы настоящие по виду, но весь каталог (его проверяют отдельные тесты) в движковых тестах не нужен.
    /// </summary>
    static List<Strategy> TestZapretStrategies() => new List<Strategy>
    {
        new Strategy { Id = "t-split", Name = "WARP TLS: split", Transport = WarpTransport.MasqueH2, Args = "--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld", Countries = AllCountries },
        new Strategy { Id = "q-fake", Name = "WARP QUIC: fake", Transport = WarpTransport.MasqueH3, Args = "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6", Countries = AllCountries },
        new Strategy { Id = "t-disorder", Name = "WARP TLS: disorder", Transport = WarpTransport.MasqueH2, Args = "--payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld", Countries = AllCountries },
        new Strategy { Id = "q-fake3", Name = "WARP QUIC: fake x3", Transport = WarpTransport.MasqueH3, Args = "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3", Countries = AllCountries },
    };

    /// <summary>Аргументы стратегии так, как их видит работающий winws2 (последняя строка файла конфигурации).</summary>
    static string ArgsOf(string id) => TestZapretStrategies().Single(s => s.Id == id).Args.Trim();

    static Engine ProxyEngine(out FakeProxy fake, string link = TestLink, bool smallCatalog = true)
    {
        var engine = NewEngine();
        fake = new FakeProxy(Path.Combine(engine.DataDir, "fake-singbox"));
        SetPrivate(engine, "Proxy", fake);
        SetPrivate(engine, "FindForeignVpns", (Func<List<string>>)(() => new List<string>()));
        // zapret2 подменён: файлы-заглушки и программа, которая просто живёт; пауза после запуска короткая, а не две секунды
        StubFiles(engine.Zapret.Dir, "v1.0", SleepingWinws());
        SetPrivate(engine.Zapret, "SettleDelayMs", 10);
        if (smallCatalog) SetPrivate(engine, "ZapretStrategies", (Func<List<Strategy>>)TestZapretStrategies);
        engine.Config.UseProxy = true;
        engine.Config.ProxyUri = link;
        engine.ReloadStrategies();
        return engine;
    }

    /// <summary>Содержимое файла конфигурации, с которым winws2 запускался в последний раз.</summary>
    static string ZapretConfig(Engine engine) => File.ReadAllText(Path.Combine(engine.Zapret.Dir, "zarp.cfg"));

    static async Task TestProxyModeEngineAsync()
    {
        // WARP в этом движке не установлен: любое обращение к warp-cli упало бы с ошибкой
        var engine = ProxyEngine(out var fake);
        engine.Config.StopAfterWorking = 1;
        var server = ProxyProfile.Parse(TestLink);
        string split = "t-split@" + server.Id, disorder = "t-disorder@" + server.Id;

        // стратегия режима - пара «стратегия zapret2 + сервер»; серверу с TLS по TCP подходят только стратегии под TLS
        Check(engine.ProxyMode && engine.Strategies.Select(s => s.Id).SequenceEqual(new[] { split, disorder }) && engine.Candidates.Count == 2 &&
              engine.Strategies.All(s => s.IsProxy && s.UsesZapret && s.Profile.Id == server.Id && s.Transport == WarpTransport.MasqueH2),
            "A server gets the strategies of its transport: " + string.Join(",", engine.Strategies.Select(s => s.Id)));
        Check(engine.Strategies[0].Name == "TLS: split + Trojan: proxy.example:443" && engine.Strategies[0].ProtocolTitle == "Trojan", "A pair is named after its strategy and its server: " + engine.Strategies[0].Name);

        // с нуля: проверка и перепроверка пары, потом подключение (сначала без адаптера, потом с ним)
        var winwsSeen = new List<string>();
        fake.OnStart = s => winwsSeen.Add(engine.Zapret.RunningStrategyArgs());
        await engine.ConnectAsync();
        var pair = engine.Strategies[0];
        Check(engine.State == EngineState.Connected && engine.Detail == L.T("detail.strategy", pair.Name) && engine.Selected == pair, "Connected: " + engine.State + " " + engine.Detail);
        Check(fake.Started.Select(s => s.Tun).SequenceEqual(new[] { false, false, false, true }),
            "Test, recheck and the probe run without the adapter; the real connection has it: " + string.Join(",", fake.Started.Select(s => s.Tun)));
        Check(fake.Started.All(s => s.Address == "203.0.113.9" && s.Ipv6 && s.Dns == "1.1.1.1" && s.Profile.Id == server.Id), "Sessions use the resolved address and the settings");
        Check(fake.IsRunning && engine.Config.SelectedStrategyId == pair.Id, "The tunnel runs and the pair is remembered");
        var result = engine.Config.Results[pair.Id];
        Check(result.Ok && result.Confirmed && result.ConnectMs == 120 && result.PingMs == 40 && !result.Independent && result.Endpoint == "proxy.example:443",
            "The result keeps the time of the first answer and the ping, and is honestly marked as not independent");
        Check(AppConfig.Load(Path.Combine(engine.DataDir, "zarp.json")).Results.ContainsKey(pair.Id), "The result is saved");

        // zapret2 обязателен: winws2 со стратегией пары уже работает, когда sing-box идёт к серверу, и остаётся включённым, пока работает туннель
        Check(winwsSeen.Count == 4 && winwsSeen.All(a => a == ArgsOf("t-split")), "winws2 runs with the strategy of the pair whenever sing-box reaches the server: " + string.Join(" | ", winwsSeen));
        Check(engine.Zapret.Running && engine.Zapret.RunningStrategyArgs() == ArgsOf("t-split"), "winws2 stays on while the tunnel is up");
        string cfg = ZapretConfig(engine);
        Check(cfg.Contains("'--wf-tcp-out=443'") && cfg.Contains("ip.DstAddr==203.0.113.9") && cfg.Contains("ip.SrcAddr==203.0.113.9") && !cfg.Contains("162.159") && cfg.TrimEnd().EndsWith(ArgsOf("t-split")),
            "winws2 intercepts the connection to the server and nothing else: " + cfg);

        // наблюдение: жив и отвечает
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Connected, "A running tunnel stays connected under observation");
        fake.Measure = s => new ProxyMeasure { Error = "timeout" };
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("err.proxyNoTraffic"), "A tunnel that stopped carrying traffic is reported: " + engine.Detail);
        fake.Measure = s => new ProxyMeasure { Ok = true, FirstMs = 100, PingMs = 30 };
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Connected, "The state recovers when traffic returns");
        engine.Zapret.Stop();
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("detail.winwsFailed"), "Without winws2 new connections would not pass DPI, and that is reported: " + engine.State + " " + engine.Detail);
        Check(await engine.Zapret.StartAsync(pair, ZapretTarget.For("203.0.113.9", pair.Profile)) == null, "Setup: winws2 is back");
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Connected, "The state recovers when winws2 is back");
        fake.IsRunning = false;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("detail.singboxFailed"), "A vanished sing-box is reported: " + engine.State + " " + engine.Detail);
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.disconnected"), "The next observation, with nothing running, says disconnected: " + engine.Detail);
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Idle, "An idle state is left alone");

        // потерянный туннель забирает с собой и winws2: он перехватывал бы соединение с сервером впустую
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && engine.Zapret.Running, "Setup: connected again, winws2 on");
        fake.IsRunning = false;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && !engine.Zapret.Running, "A lost tunnel switches winws2 off");

        // отключение останавливает sing-box и winws2; повторное подключение идёт без поиска
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && engine.Zapret.Running, "Setup: connected");
        await engine.DisconnectAsync();
        Check(!fake.IsRunning && !engine.Zapret.Running && engine.State == EngineState.Idle, "Disconnect stops sing-box and winws2");
        int before = fake.Started.Count;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && fake.Started.Count - before == 2 && engine.Zapret.Running && engine.Selected.Id == engine.Config.SelectedStrategyId,
            "Reconnecting with the saved pair needs only the probe and the tunnel, with winws2 on");

        // правила и программы доходят до сессии с адаптером
        string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
        engine.Config.PerAppProxy = true;
        engine.Config.ProxyApps = new List<string> { exe, Path.Combine(_data, "gone.exe") };
        engine.Config.ProxyIpv6 = false;
        engine.Config.ProxyDns = "9.9.9.9";
        SetPrivate(engine, "CompileRules", (Func<AppConfig, List<object>>)(config =>
            new List<object> { new Dictionary<string, object> { ["domain_suffix"] = new List<string> { "example.org" }, ["action"] = "reject" } }));
        fake.Started.Clear();
        await engine.ConnectAsync();
        var tun = fake.Started.Last();
        Check(tun.Tun && tun.AppPaths != null && tun.AppPaths.SequenceEqual(new[] { exe }) && tun.Rules.Count == 1 && !tun.Ipv6 && tun.Dns == "9.9.9.9",
            "Only existing programs, the rules and the options reach the tunnel session");
        Check(fake.Started.Where(s => !s.Tun).All(s => s.AppPaths == null && s.Rules.Count == 0), "A server check ignores rules and the program list");

        // правила не собрались (нет базы, неизвестная категория): подключения нет, объяснение остаётся
        SetPrivate(engine, "CompileRules", (Func<AppConfig, List<object>>)(config => throw new InvalidOperationException("geoip:xx: category not found")));
        await engine.DisconnectAsync();
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && !engine.Zapret.Running && engine.Detail.Contains("category not found"),
            "Broken routing rules stop the connection with a reason: " + engine.State + " " + engine.Detail);
        SetPrivate(engine, "CompileRules", (Func<AppConfig, List<object>>)(config => new List<object>()));

        // пустой выбор программ не превращается в «все программы»
        await engine.DisconnectAsync();
        engine.Config.ProxyApps = new List<string> { Path.Combine(_data, "gone.exe") };
        fake.Started.Clear();
        await engine.ConnectAsync();
        Check(fake.Started.Count == 0 && engine.State == EngineState.Idle && engine.Detail == L.T("apps.empty"), "Missing programs refuse to connect: " + engine.Detail);
        engine.Config.PerAppProxy = false;

        // время подключения - время первого запроса, а пинг берётся из полного замера
        var timed = ProxyEngine(out var timedFake);
        timed.Config.StopAfterWorking = 1;
        timedFake.Probe = s => new ProxyMeasure { Ok = true, FirstMs = 111 };
        timedFake.Measure = s => new ProxyMeasure { Ok = true, FirstMs = 222, PingMs = 33 };
        await timed.ConnectAsync();
        var timedResult = timed.Config.Results[timed.Selected.Id];
        Check(timed.State == EngineState.Connected && timedResult.ConnectMs == 111 && timedResult.PingMs == 33 && timedFake.Probes >= 2 && timedFake.Measures >= 2,
            "The connection time is that of the first request and the ping comes from the full measurement: " + timedResult.ConnectMs + " / " + timedResult.PingMs);
    }

    static async Task TestProxyModeFailuresAsync()
    {
        // сервер не отвечает: ни одна пара не проходит, причина записана, и после поиска ничего не остаётся включённым
        var engine = ProxyEngine(out var fake);
        fake.Measure = s => new ProxyMeasure { Error = "timeout" };
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.notFound") && !fake.IsRunning && !engine.Zapret.Running, "A dead server is not connected: " + engine.Detail);
        Check(engine.Strategies.Count == 2 && engine.Strategies.All(s => !engine.Config.Results[s.Id].Ok && engine.Config.Results[s.Id].ErrorText == L.T("err.proxyNoTraffic")) &&
              fake.Started.Count == 2 && fake.Started.All(s => !s.Tun), "Every pair is tested once, the failures are stored and the adapter is never started for a dead server: " + fake.Started.Count);
        Check(fake.Probes == 2 && fake.Measures == 0, "A pair whose first request fails is not measured any further: " + fake.Probes + " / " + fake.Measures);

        // sing-box не запустился
        engine = ProxyEngine(out fake);
        fake.StartResult = s => new Msg("err.singboxExited", "boom");
        await engine.ConnectAsync();
        Check(engine.Strategies.All(s => engine.Config.Results[s.Id].ErrorText == L.T("err.singboxExited", "boom")), "A start failure is reported as its own reason");

        // winws2 не запустился: пара не проходит со своей причиной, sing-box для неё не запускается
        engine = ProxyEngine(out fake);
        File.WriteAllText(engine.Zapret.Exe, "this is not a program"); // cmd не сможет её запустить
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && fake.Started.Count == 0 && engine.Strategies.All(s => !engine.Config.Results[s.Id].Ok && engine.Config.Results[s.Id].ErrorText.Contains("winws2")),
            "A pair whose winws2 does not start fails with that reason and sing-box is not started: " + string.Join(" | ", engine.Config.Results.Values.Select(r => r.ErrorText)));

        // winws2 не запустился при подключении с выбранной парой: понятная причина, ничего не остаётся включённым
        engine = ProxyEngine(out fake);
        engine.Config.StopAfterWorking = 1;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected, "Setup: connected");
        await engine.DisconnectAsync();
        File.WriteAllText(engine.Zapret.Exe, "this is not a program");
        fake.Started.Clear();
        engine.Config.Results.Clear(); // выбранная пара останется, а результатов не будет: подключение идёт с выбранной
        await engine.UseStrategyAsync(engine.Selected);
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.winwsFailed") && fake.Started.Count == 0 && !fake.IsRunning, "Connecting with a broken winws2 says so: " + engine.State + " " + engine.Detail);

        // сохранённая пара перестала работать: пробуются остальные проверенные, потом новый поиск; всё это называется своими словами
        engine = ProxyEngine(out fake);
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && engine.Config.Results.Values.Count(r => r.Ok && r.Confirmed) == 2, "Setup: connected, both pairs verified");
        var chosen = engine.Selected;
        await engine.DisconnectAsync();
        fake.Measure = s => new ProxyMeasure { Error = "timeout" };
        fake.Started.Clear();
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && engine.Detail == L.T("detail.notFound") && !fake.IsRunning && !engine.Zapret.Running && engine.Strategies.All(s => !engine.Config.Results[s.Id].Ok),
            "When the saved pair and the other verified one fail, the search runs again and nothing is left on: " + engine.State + " " + engine.Detail);
        // только выбранная пара умерла: подключение берёт другую проверенную
        engine = ProxyEngine(out fake);
        await engine.ConnectAsync();
        chosen = engine.Selected;
        await engine.DisconnectAsync();
        fake.Measure = s => engine.Zapret.RunningStrategyArgs() == chosen.Args.Trim() ? new ProxyMeasure { Error = "timeout" } : new ProxyMeasure { Ok = true, FirstMs = 200, PingMs = 50 };
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && engine.Selected != null && engine.Selected.Id != chosen.Id && engine.Zapret.RunningStrategyArgs() == engine.Selected.Args.Trim() && !engine.Config.Results[chosen.Id].Ok,
            "When the chosen pair stops passing, the other verified pair connects: " + engine.State + " / " + engine.Selected?.Name);

        // адаптер не поднялся: sing-box и winws2 остановлены
        engine = ProxyEngine(out fake);
        fake.Adapter = false;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && !engine.Zapret.Running, "Without the adapter nothing is left running");

        // адаптер поднялся, но трафик через него не идёт: sing-box останавливается, сеть возвращается, результат помечается
        engine = ProxyEngine(out fake);
        fake.TunnelOk = false;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && !engine.Zapret.Running && engine.Detail == L.T("detail.foundButFailed") && fake.Started.Last().Tun,
            "A dead adapter is removed instead of leaving the computer without a network: " + engine.State + " " + engine.Detail);

        // имя сервера не разрешается: причина у каждой пары своя, но ждать DNS заново для каждой не нужно
        engine = ProxyEngine(out fake);
        fake.Resolve = host => null;
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Idle && fake.Started.Count == 0 && fake.Resolved.Count == 1 && !fake.IsRunning && !engine.Zapret.Running &&
              engine.Strategies.All(s => engine.Config.Results[s.Id].ErrorText == L.T("err.proxyFailed", "cannot resolve proxy.example")),
            "A name that does not resolve is looked up once for all pairs: " + fake.Resolved.Count + " / " + string.Join(" | ", engine.Config.Results.Values.Select(r => r.ErrorText)));
        // а в следующей операции имя ищется заново: прежний отказ не должен её испортить
        fake.Resolve = host => "203.0.113.9";
        await engine.ConnectAsync();
        Check(engine.State == EngineState.Connected && fake.Resolved.Count == 2, "A name that resolves again is looked up again in the next operation: " + engine.State + " / " + fake.Resolved.Count);

        // ссылка неверна: ничего не запускается
        engine = ProxyEngine(out fake, "vless://bad");
        Check(engine.Strategies.Count == 0, "An invalid link gives no strategies");
        await engine.ConnectAsync();
        Check(fake.Started.Count == 0 && !engine.Zapret.Running && engine.State == EngineState.Idle && engine.Detail == L.T("detail.proxyInvalid"), "An invalid link stops before sing-box: " + engine.Detail);

        // сторонний VPN: так же, как в режиме WARP
        engine = ProxyEngine(out fake);
        SetPrivate(engine, "FindForeignVpns", (Func<List<string>>)(() => new List<string> { "happ-tun" }));
        await engine.SearchAsync(false);
        Check(fake.Started.Count == 0 && !engine.Zapret.Running && engine.Detail == L.T("detail.vpnOff"), "A search through another VPN is refused: " + engine.Detail);

        // подхват подключения после перезапуска Zarp: пара находится по работающему winws2
        engine = ProxyEngine(out fake);
        var adopted = engine.Strategies.Single(s => s.Id.StartsWith("t-disorder@"));
        var target = ZapretTarget.For("203.0.113.9", adopted.Profile);
        Check(await engine.Zapret.StartAsync(adopted, target) == null, "Setup: winws2 runs with the second pair");
        fake.IsRunning = true;
        fake.AdoptResult = new ProxySession { Profile = adopted.Profile, Port = 18080, User = "zarp", Password = "pw", Tun = true };
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Connected && engine.Config.SelectedStrategyId == adopted.Id && engine.Selected == adopted,
            "A running tunnel from the previous run is picked up with the pair whose winws2 is on: " + engine.State + " / " + engine.Selected?.Name);
        fake.IsRunning = false;
        await engine.MonitorAsync();
        Check(engine.State == EngineState.Unknown && !engine.Zapret.Running, "A tunnel found after a restart takes its winws2 with it when it is lost");
        // выбранная в настройках пара своего сервера важнее
        engine = ProxyEngine(out fake);
        Check(await engine.Zapret.StartAsync(adopted, target) == null, "Setup: winws2 runs with the second pair");
        engine.Config.SelectedStrategyId = engine.Strategies[0].Id;
        fake.IsRunning = true;
        fake.AdoptResult = new ProxySession { Profile = engine.Strategies[0].Profile, Port = 18080, User = "zarp", Password = "pw", Tun = true };
        await engine.RefreshStateAsync();
        Check(engine.Selected == engine.Strategies[0], "The pair chosen in the settings stays chosen");
        // нет ни выбранной пары, ни работающего winws2: найденное подключение показывается лучшей парой своего сервера по сохранённым результатам
        engine = ProxyEngine(out fake);
        var weak = engine.Strategies[0];
        var strong = engine.Strategies[1];
        engine.Config.Results[weak.Id] = new TestResult { StrategyId = weak.Id, Ok = true, Confirmed = true, ConnectMs = 900, PingMs = 90 };
        engine.Config.Results[strong.Id] = new TestResult { StrategyId = strong.Id, Ok = true, Confirmed = true, ConnectMs = 100, PingMs = 10 };
        fake.IsRunning = true;
        fake.AdoptResult = new ProxySession { Profile = strong.Profile, Port = 18080, User = "zarp", Password = "pw", Tun = true };
        await engine.RefreshStateAsync();
        Check(engine.Config.SelectedStrategyId == strong.Id, "Without any other hint the best verified pair of the server is shown: " + engine.Selected?.Name);
        // туннель жив, а winws2 нет: сообщается, что он не работает
        engine = ProxyEngine(out fake);
        fake.IsRunning = true;
        fake.AdoptResult = new ProxySession { Profile = engine.Strategies[0].Profile, Port = 18080, User = "zarp", Password = "pw", Tun = true };
        engine.Config.SelectedStrategyId = engine.Strategies[0].Id;
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Unknown && engine.Detail == L.T("detail.winwsFailed"), "A tunnel found without its winws2 is reported: " + engine.State + " " + engine.Detail);
        fake.IsRunning = false;
        engine = ProxyEngine(out fake);
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Idle && fake.Started.Count == 0, "Nothing running means disconnected");

        // sing-box, который не удаётся подхватить (потеряны сведения или сменился сервер), не остаётся работать втайне
        engine = ProxyEngine(out fake);
        fake.IsRunning = true;
        fake.AdoptResult = null;
        await engine.RefreshStateAsync();
        Check(engine.State == EngineState.Idle && !fake.IsRunning && fake.Stops > 0, "A leftover sing-box that cannot be taken over is stopped");

        // режим собственного сервера не нужен для WARP: без него warp-cli не вызывается
        Check(Catch(() => engine.Warp.Cli("status").GetAwaiter().GetResult()) is InvalidOperationException, "Setup: this engine has no WARP");
    }

    static void TestProxyModeWindows()
    {
        var engine = ProxyEngine(out var fake);
        using (var main = NewMain(engine))
        {
            var sub = GetPrivate<Label>(main, "_sub");
            var hint = GetPrivate<Label>(main, "_hint");
            Check(sub.Text == L.T("proxy.subtitle") && hint.Text == L.T("hint.proxyFirstRun"), "The window speaks of the server over zapret2, not WARP: " + sub.Text + " / " + hint.Text);
            Check(sub.Text.Contains("zapret2") && hint.Text.Contains("zapret2"), "Both texts name zapret2: it is part of the server mode");
            engine.Config.UseProxy = false;
            main.GetType().GetMethod("UpdateUi", PrivateInstance).Invoke(main, null);
            Check(sub.Text == L.T("main.subtitle") && hint.Text == L.T("hint.installWarp"), "Back to WARP texts");
        }
        engine.Config.UseProxy = true;
        engine.ReloadStrategies();
        using (var settings = NewForm("SettingsForm", engine))
        {
            PositionOffscreen(settings);
            settings.Show();
            Application.DoEvents();
            var list = GetPrivate<ListView>(settings, "_list");
            Check(list.Items.Count == 2 && list.Items.Cast<ListViewItem>().All(i => i.SubItems[2].Text == "Trojan") &&
                  list.Items[0].SubItems[1].Text == "TLS: split + Trojan: proxy.example:443" && list.Items[1].SubItems[1].Text == "TLS: disorder + Trojan: proxy.example:443",
                "The settings list shows the pairs of strategy and server");
            Check(list.Items[0].ToolTipText.Contains("proxy.example:443") && list.Items[0].ToolTipText.Contains("multisplit"), "The tip shows the server and the winws2 arguments: " + list.Items[0].ToolTipText);
            Check(GetPrivate<Control>(settings, "_filter").Visible && GetPrivate<Control>(settings, "_custom").Enabled,
                "The country filter and the custom strategies apply to a server too: they are its zapret2 strategies");
            Check(!GetPrivate<Control>(settings, "_restrict").Enabled && !GetPrivate<Control>(settings, "_isolate").Enabled, "Options that only concern WARP are off for a server");
            engine.Config.UseProxy = false;
            settings.GetType().GetMethod("UpdateButtons", PrivateInstance).Invoke(settings, null);
            Check(GetPrivate<Control>(settings, "_restrict").Enabled && GetPrivate<Control>(settings, "_isolate").Enabled, "And on again for WARP");
        }
    }
}

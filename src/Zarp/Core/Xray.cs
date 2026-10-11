using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Zarp.Core
{
    /// <summary>
    /// Xray-core (https://github.com/XTLS/Xray-core) - мост для серверов VLESS поверх XHTTP, которого в sing-box нет.
    /// Работает как локальный SOCKS5-вход на 127.0.0.1 с паролем: sing-box отправляет в него трафик адаптера, а Xray
    /// передаёт его серверу. Вшит в Zarp.exe, как sing-box, и запускается отдельным процессом; Zarp не линкуется с ним
    /// и не меняет его файлы (лицензия MPL-2.0, см. THIRD_PARTY_NOTICES.md). Без XHTTP в ссылке не распаковывается и не запускается.
    /// </summary>
    public sealed class Xray
    {
        public string Dir { get; }
        public string Exe => Path.Combine(Dir, "xray.exe");
        public string LogFile => Path.Combine(Dir, "xray.log");
        string ConfigFile => Path.Combine(Dir, "config.json");

        public Xray(string dir)
        {
            Dir = dir;
        }

        // ------------------------------------------------------------------ вшитый архив

        static byte[] EmbeddedZip()
        {
            using (var s = typeof(Xray).Assembly.GetManifestResourceStream("xray.zip"))
            {
                if (s == null) return null;
                var ms = new MemoryStream();
                s.CopyTo(ms);
                return ms.ToArray();
            }
        }

        static string _embeddedVersion;
        static string _embeddedHash;

        /// <summary>Версия Xray, вшитая в exe, или null, если exe собран без него.</summary>
        public static string EmbeddedVersion
        {
            get
            {
                if (_embeddedVersion != null) return _embeddedVersion.Length == 0 ? null : _embeddedVersion;
                _embeddedVersion = "";
                var data = EmbeddedZip();
                if (data == null) return null;
                using (var zip = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read))
                using (var r = new StreamReader(zip.GetEntry("version.txt").Open()))
                    _embeddedVersion = r.ReadToEnd().Trim();
                return _embeddedVersion;
            }
        }

        /// <summary>SHA-256 вшитого xray.exe: запускается только файл, совпадающий с ним.</summary>
        static string EmbeddedExeHash()
        {
            if (_embeddedHash != null) return _embeddedHash;
            using (var zip = new ZipArchive(new MemoryStream(EmbeddedZip()), ZipArchiveMode.Read))
            using (var s = zip.GetEntry("xray.exe").Open())
            using (var sha = SHA256.Create())
                return _embeddedHash = Hex(sha.ComputeHash(s));
        }

        static string Hex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));

        /// <summary>Версия установленного Xray (тег релиза) или null.</summary>
        public string Version
        {
            get
            {
                try { return File.ReadAllText(Path.Combine(Dir, "version.txt")).Trim(); }
                catch { return null; }
            }
        }

        public bool Installed => File.Exists(Exe) && Version != null;

        /// <summary>
        /// Положить xray.exe из вшитого архива в папку данных. Файл заменяется, если он отличается от вшитого
        /// (в том числе подменён): запускается всегда ровно тот двоичный файл, который лежит в Zarp.exe.
        /// Возвращает true, если файл записан.
        /// </summary>
        public bool ExtractEmbedded()
        {
            if (EmbeddedVersion == null) return false;
            string want = EmbeddedExeHash();
            if (File.Exists(Exe) && Version == EmbeddedVersion && HashOf(Exe) == want) return false;
            Stop(); // запущенный exe не перезаписать
            Directory.CreateDirectory(Dir);
            using (var zip = new ZipArchive(new MemoryStream(EmbeddedZip()), ZipArchiveMode.Read))
            {
                foreach (var e in zip.Entries.Where(e => e.Name.Length > 0 && e.Name != "version.txt"))
                {
                    try
                    {
                        e.ExtractToFile(Path.Combine(Dir, e.Name), true);
                    }
                    catch (IOException ex) when (Zapret.IsAntivirusError(ex))
                    {
                        throw new AntivirusBlockedException(L.T("err.avBlockedFile", e.Name), ex);
                    }
                }
            }
            File.WriteAllText(Path.Combine(Dir, "version.txt"), EmbeddedVersion); // последним - признак целостности
            Log.Write(L.T("log.xrayExtracted", EmbeddedVersion));
            return true;
        }

        static string HashOf(string file)
        {
            try
            {
                using (var s = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var sha = SHA256.Create())
                    return Hex(sha.ComputeHash(s));
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ проверка и запуск

        /// <summary>Проверить конфигурацию командой `xray run -test`: ничего не запускается и не меняется в системе.</summary>
        public async Task<RunResult> CheckAsync(string configJson, CancellationToken ct = default)
        {
            Directory.CreateDirectory(Dir);
            string file = Path.Combine(Dir, "check-" + Guid.NewGuid().ToString("N") + ".json");
            File.WriteAllText(file, configJson, new UTF8Encoding(false));
            try
            {
                return await ProcessUtil.RunAsync(Exe, "run -test -c \"" + file + "\"", 30000, ct).ConfigureAwait(false);
            }
            finally { try { File.Delete(file); } catch { } }
        }

        Process _shell;

        /// <summary>Сколько ждать, пока откроется порт моста. Меняется только в тестах: настоящий срок слишком долог для проверки отказа.</summary>
        internal int StartTimeoutMs = 25000;

        public bool Running
        {
            get
            {
                bool found = false;
                foreach (var p in FindOurProcesses()) { found = true; p.Dispose(); }
                return found;
            }
        }

        /// <summary>
        /// Запустить Xray с конфигурацией и дождаться, пока откроется SOCKS-вход.
        /// Возвращает null при успехе или описание ошибки (с хвостом журнала Xray).
        /// Файл конфигурации с UUID и паролем входа удаляется сразу после запуска.
        /// </summary>
        public async Task<Msg> StartAsync(string configJson, int waitPort, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            Stop();
            try
            {
                if (!Installed) return new Msg("err.xrayMissing");
                Directory.CreateDirectory(Dir);
                try { File.Delete(LogFile); } catch { }
                File.WriteAllText(ConfigFile, configJson, new UTF8Encoding(false));
                // Пока файл открыт на чтение с запретом записи, его нельзя подменить между проверкой и запуском.
                using (var locked = new FileStream(Exe, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (EmbeddedVersion != null)
                    {
                        using (var sha = SHA256.Create())
                            if (Hex(sha.ComputeHash(locked)) != EmbeddedExeHash())
                                return new Msg("err.xrayChanged");
                        locked.Position = 0;
                    }
                    // cmd нужен только для перенаправления вывода в файл: Xray не зависит от жизни окна Zarp.
                    var psi = new ProcessStartInfo(ProcessUtil.SystemExe("cmd.exe"),
                        "/d /s /c \"\"" + Path.GetFullPath(Exe) + "\" run -c config.json > xray.log 2>&1\"")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = Dir,
                    };
                    try { _shell = Process.Start(psi); }
                    catch (Exception e) { return new Msg("err.xrayStart", e.Message); }

                    for (int i = 0; i < 20 && !Running; i++)
                        await Task.Delay(100, ct).ConfigureAwait(false);
                }

                var clock = Stopwatch.StartNew();
                while (clock.ElapsedMilliseconds < StartTimeoutMs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Running) return Failure();
                    if (await PortOpenAsync(waitPort).ConfigureAwait(false))
                    {
                        try { File.Delete(ConfigFile); } catch { }
                        return null;
                    }
                    await Task.Delay(150, ct).ConfigureAwait(false);
                }
                Stop();
                return new Msg("err.xrayTimeout");
            }
            catch (OperationCanceledException) { Stop(); throw; }
            catch (Exception e) { Stop(); return new Msg("err.xrayStart", e.Message); }
            finally { if (!Running) { try { File.Delete(ConfigFile); } catch { } } }
        }

        /// <summary>Журнал Xray. Читается с разрешением записи: пока процесс жив, он держит файл открытым.</summary>
        public string ReadLog()
        {
            try
            {
                using (var file = new FileStream(LogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(file, Encoding.UTF8))
                    return reader.ReadToEnd();
            }
            catch { return ""; }
        }

        Msg Failure()
        {
            string log = ReadLog().Trim();
            Stop();
            return log.Length > 0 ? new Msg("err.xrayExited", Tail(log, 6)) : new Msg("err.xrayExitedSilent");
        }

        static string Tail(string text, int lines)
        {
            var l = StripAnsi(text).Split('\n');
            return string.Join("\n", l.Skip(Math.Max(0, l.Length - lines))).Trim();
        }

        static string StripAnsi(string text) => Regex.Replace(text, "\u001b\\[[0-9;]*m", "");

        static async Task<bool> PortOpenAsync(int port)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connect = client.ConnectAsync("127.0.0.1", port);
                    return await Task.WhenAny(connect, Task.Delay(300)).ConfigureAwait(false) == connect && client.Connected;
                }
            }
            catch { return false; }
        }

        public void Stop()
        {
            foreach (var p in FindOurProcesses())
            {
                try { p.Kill(); p.WaitForExit(3000); } catch { }
                p.Dispose();
            }
            // cmd-обёртка держит журнал открытым: без ожидания следующий запуск не сможет в него писать
            if (_shell != null)
            {
                try { if (!_shell.WaitForExit(3000)) _shell.Kill(); } catch { }
                _shell.Dispose();
                _shell = null;
            }
            // в журнале проверочного запуска есть адреса страниц и путь XHTTP (он бывает секретом): после остановки он не нужен
            try { File.Delete(LogFile); } catch { }
        }

        IEnumerable<Process> FindOurProcesses()
        {
            string exe = Path.GetFullPath(Exe);
            foreach (var p in Process.GetProcessesByName("xray"))
            {
                string path = ProcessUtil.GetProcessPath(p);
                if (path != null && ProcessUtil.SamePath(path, exe))
                    yield return p;
                else
                    p.Dispose();
            }
        }

        // Строка журнала: «2026/10/11 03:01:15.870104 [Info] [289985034] transport/internet/splithttp: failed to GET ...»
        static readonly Regex LogLine = new Regex(@"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(\.\d+)? \[(?<level>[A-Za-z]+)\] (\[\d+\] )?(?<text>.*)$", RegexOptions.Compiled);

        /// <summary>
        /// Последняя строка журнала о неудаче без метки времени, номера соединения и адресов страниц (в них путь XHTTP, а он
        /// может быть секретом), или null. Об ошибках Xray пишет на уровне Info, поэтому проверочный запуск идёт с ним.
        /// </summary>
        public string LastError()
        {
            try
            {
                string found = null;
                foreach (var raw in ReadLog().Split('\n'))
                {
                    var m = LogLine.Match(StripAnsi(raw).TrimEnd());
                    if (!m.Success) continue;
                    string level = m.Groups["level"].Value, text = m.Groups["text"].Value;
                    if (text.EndsWith(" started", StringComparison.Ordinal) && text.StartsWith("core: Xray ", StringComparison.Ordinal)) continue;
                    // «unexpected status 404» - так Xray сообщает о неверном пути XHTTP; об остальных отказах он пишет с «failed» или «error»
                    if (level == "Error" || level == "Warning" || (level == "Info" && Regex.IsMatch(text, "fail|error|refused|timeout|reset|denied|invalid|EOF|unexpected", RegexOptions.IgnoreCase)))
                        found = text;
                }
                if (found == null) return null;
                found = Regex.Replace(found, @"https?://[^\s""]+", "<url>");
                return found.Length > 300 ? found.Substring(0, 300) + "..." : found;
            }
            catch { return null; }
        }
    }
}

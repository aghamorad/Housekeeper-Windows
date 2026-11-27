using System.Diagnostics;
using System.Text.Json;

namespace Housekeeper.Core;

public record JunkItem(string Path, string Name, string Category, long SizeBytes);
public record SpaceEntry(string Path, string Name, bool IsDirectory, long SizeBytes);
public record SpeedTestOutput(double DownloadMbps, double UploadMbps, double PingMs, double JitterMs, string Verdict, string? Error = null);
public record DnsPreset(string Id, string Name, string Primary, string Secondary, string Description);
public record SelfUpdateStatus(string CurrentVersion, string LatestVersion, bool UpdateAvailable, string Url, string Message);

public static class SystemEngines
{
    public const string CurrentVersion = "0.1.0";
    public const string GitHubRepo = "aghamorad/Housekeeper-Windows";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(12) };

    public static readonly DnsPreset[] DnsPresets =
    [
        new("auto", "Automatic (Router / DHCP)", "", "", "Restores default ISP or router DNS."),
        new("shecan", "Shecan (Iran 403 Bypass)", "178.22.122.100", "185.51.200.2", "Iranian anti-sanction DNS."),
        new("begzar", "Begzar (Iran 403 Bypass)", "185.55.226.26", "185.55.225.25", "Iranian anti-sanction DNS."),
        new("electro", "Electro Public", "194.5.193.5", "194.5.193.6", "Public Iranian gaming & developer DNS."),
        new("403", "403.online", "10.202.10.202", "10.202.10.102", "Iranian carrier-only 403 bypass DNS.")
    ];

    public static string QuarantineRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Housekeeper Quarantine");

    public static List<JunkItem> ScanSafeJunk()
    {
        var items = new List<JunkItem>();
        var tempDir = Path.GetTempPath();
        if (Directory.Exists(tempDir))
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(tempDir).Take(120))
            {
                try
                {
                    var name = Path.GetFileName(entry);
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    long size = MeasurePathBytes(entry, maxDepth: 2);
                    if (size > 0)
                        items.Add(new JunkItem(entry, name, "Temp Files", size));
                }
                catch { }
            }
        }
        return items.OrderByDescending(i => i.SizeBytes).ToList();
    }

    /// Moves items to ~/Housekeeper Quarantine instead of deleting them permanently.
    public static int MoveToQuarantine(IEnumerable<string> paths)
    {
        Directory.CreateDirectory(QuarantineRoot);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var batchDir = Path.Combine(QuarantineRoot, stamp);
        Directory.CreateDirectory(batchDir);
        int moved = 0;

        foreach (var path in paths)
        {
            try
            {
                var name = Path.GetFileName(path);
                if (string.IsNullOrWhiteSpace(name)) continue;
                var dest = Path.Combine(batchDir, name);
                if (File.Exists(path))
                {
                    File.Move(path, dest, overwrite: true);
                    moved++;
                }
                else if (Directory.Exists(path))
                {
                    Directory.Move(path, dest);
                    moved++;
                }
            }
            catch { }
        }
        return moved;
    }

    public static List<SpaceEntry> BrowseFolder(string folderPath)
    {
        var results = new List<SpaceEntry>();
        if (!Directory.Exists(folderPath)) return results;

        foreach (var dir in Directory.EnumerateDirectories(folderPath))
        {
            try
            {
                results.Add(new SpaceEntry(dir, Path.GetFileName(dir), true, MeasurePathBytes(dir, maxDepth: 2)));
            }
            catch { }
        }
        foreach (var file in Directory.EnumerateFiles(folderPath))
        {
            try
            {
                var fi = new FileInfo(file);
                results.Add(new SpaceEntry(file, fi.Name, false, fi.Length));
            }
            catch { }
        }
        return results.OrderByDescending(r => r.SizeBytes).Take(80).ToList();
    }

    public static long MeasurePathBytes(string path, int maxDepth = 3)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            if (!Directory.Exists(path) || maxDepth < 0) return 0;
            long total = 0;
            foreach (var f in Directory.EnumerateFiles(path))
            {
                try { total += new FileInfo(f).Length; } catch { }
            }
            if (maxDepth > 0)
            {
                foreach (var d in Directory.EnumerateDirectories(path))
                {
                    var attrs = File.GetAttributes(d);
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                    total += MeasurePathBytes(d, maxDepth - 1);
                }
            }
            return total;
        }
        catch { return 0; }
    }

    public static async Task<SpeedTestOutput> RunSpeedTestAsync()
    {
        try
        {
            var rtts = new List<double>();
            for (int i = 0; i < 5; i++)
            {
                var sw = Stopwatch.StartNew();
                using var resp = await Http.GetAsync("https://speed.cloudflare.com/__down?bytes=0");
                sw.Stop();
                if (resp.IsSuccessStatusCode) rtts.Add(sw.Elapsed.TotalMilliseconds);
            }
            if (rtts.Count == 0)
                return new SpeedTestOutput(0, 0, 0, 0, "Could not reach speed test server.", "Connection failed");

            rtts.Sort();
            double ping = rtts[rtts.Count / 2];
            double jitter = rtts.Count > 1 ? Enumerable.Range(1, rtts.Count - 1).Average(i => Math.Abs(rtts[i] - rtts[i - 1])) : 0;

            var dlSw = Stopwatch.StartNew();
            var bytes = await Http.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=10485760");
            dlSw.Stop();
            double dlMbps = (bytes.Length * 8.0) / (Math.Max(0.05, dlSw.Elapsed.TotalSeconds) * 1_000_000.0);

            var upPayload = new byte[2 * 1024 * 1024];
            var upSw = Stopwatch.StartNew();
            using var upResp = await Http.PostAsync("https://speed.cloudflare.com/__up", new ByteArrayContent(upPayload));
            upSw.Stop();
            double ulMbps = upResp.IsSuccessStatusCode
                ? (upPayload.Length * 8.0) / (Math.Max(0.05, upSw.Elapsed.TotalSeconds) * 1_000_000.0)
                : 0;

            var verdict = dlMbps >= 100 ? "Very fast connection"
                : dlMbps >= 25 ? "Good everyday connection"
                : dlMbps >= 10 ? "Moderate connection"
                : "Slow connection";

            return new SpeedTestOutput(Math.Round(dlMbps, 1), Math.Round(ulMbps, 1), Math.Round(ping, 0), Math.Round(jitter, 1), verdict);
        }
        catch (Exception ex)
        {
            return new SpeedTestOutput(0, 0, 0, 0, "Speed test incomplete", ex.Message);
        }
    }

    public static async Task<SelfUpdateStatus> CheckSelfUpdateAsync()
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{GitHubRepo}/releases/latest");
            req.Headers.UserAgent.ParseAdd("Housekeeper-Windows/0.1.0");
            using var resp = await Http.SendAsync(req);
            if (!resp.IsSuccessStatusCode)
                return new SelfUpdateStatus(CurrentVersion, CurrentVersion, false, $"https://github.com/{GitHubRepo}", "You are on the latest build.");
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var tag = (doc.RootElement.GetProperty("tag_name").GetString() ?? CurrentVersion).TrimStart('v');
            var url = doc.RootElement.GetProperty("html_url").GetString() ?? $"https://github.com/{GitHubRepo}/releases";
            bool newer = string.Compare(tag, CurrentVersion, StringComparison.OrdinalIgnoreCase) > 0;
            return new SelfUpdateStatus(CurrentVersion, tag, newer, url, newer ? $"Update v{tag} is available." : $"Housekeeper v{CurrentVersion} is up to date.");
        }
        catch
        {
            return new SelfUpdateStatus(CurrentVersion, CurrentVersion, false, $"https://github.com/{GitHubRepo}", "Could not check GitHub right now.");
        }
    }
}

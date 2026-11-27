using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Housekeeper.Core;

namespace Housekeeper.Windows;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        int port = PickFreeLoopbackPort();
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        string baseUrl = $"http://127.0.0.1:{port}/?token={token}";

        var cts = new CancellationTokenSource();
        _ = Task.Run(() => RunLoopbackServerAsync(port, token, cts.Token));

        using var tray = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "Housekeeper for Windows — Made by Morad",
            Visible = true
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Housekeeper", null, (_, _) => OpenAppWindow(baseUrl));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Cloudflare Clean VPN", null, (_, _) => OpenAppWindow(baseUrl + "#vpn"));
        menu.Items.Add("Clean Up (Quarantine)", null, (_, _) => OpenAppWindow(baseUrl + "#clean"));
        menu.Items.Add("Space Lens", null, (_, _) => OpenAppWindow(baseUrl + "#space"));
        menu.Items.Add("Speed Test", null, (_, _) => OpenAppWindow(baseUrl + "#speed"));
        menu.Items.Add("DNS Switcher", null, (_, _) => OpenAppWindow(baseUrl + "#dns"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quit Housekeeper", null, (_, _) =>
        {
            cts.Cancel();
            tray.Visible = false;
            Application.Exit();
        });
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (_, _) => OpenAppWindow(baseUrl);

        OpenAppWindow(baseUrl);
        Application.Run();
    }

    private static int PickFreeLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static void OpenAppWindow(string url)
    {
        try
        {
            // Open in frameless Microsoft Edge App Mode (built into Windows 10/11)
            string[] edgePaths =
            [
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft", "Edge", "Application", "msedge.exe")
            ];
            var edge = edgePaths.FirstOrDefault(File.Exists);
            if (edge != null)
            {
                Process.Start(new ProcessStartInfo(edge, $"--app={url} --window-size=1120,760") { UseShellExecute = false });
                return;
            }
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
    }

    private static async Task RunLoopbackServerAsync(int port, string token, CancellationToken ct)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var html = LoadEmbeddedHtml();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var ctx = await listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(ctx, html, token), ct);
            }
            catch { break; }
        }
    }

    private static string LoadEmbeddedHtml()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream("Housekeeper.Windows.index.html")!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static async Task HandleRequestAsync(HttpListenerContext ctx, string html, string token)
    {
        try
        {
            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            if (path == "/" || path == "/index.html")
            {
                var bytes = Encoding.UTF8.GetBytes(html);
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
                return;
            }

            if (ctx.Request.Headers["X-HK-Token"] != token)
            {
                ctx.Response.StatusCode = 403;
                ctx.Response.Close();
                return;
            }

            object result = path switch
            {
                "/api/info" => new
                {
                    machine = Environment.MachineName,
                    os = Environment.OSVersion.VersionString,
                    arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
                    version = SystemEngines.CurrentVersion,
                    quarantine = SystemEngines.QuarantineRoot,
                    warpEndpoints = CloudflareVpnEngine.WarpEndpoints,
                    dnsPresets = SystemEngines.DnsPresets
                },
                "/api/warp" => await HandleWarpAsync(ctx),
                "/api/cf/verify" => await HandleCfVerifyAsync(ctx),
                "/api/cf/scan" => await CloudflareVpnEngine.ScanCleanIpsAsync(24, 443),
                "/api/clean/scan" => SystemEngines.ScanSafeJunk(),
                "/api/clean/quarantine" => await HandleQuarantineAsync(ctx),
                "/api/space" => SystemEngines.BrowseFolder(ctx.Request.QueryString["path"] ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
                "/api/speed" => await SystemEngines.RunSpeedTestAsync(),
                "/api/update" => await SystemEngines.CheckSelfUpdateAsync(),
                _ => new { error = "Unknown endpoint" }
            };

            var json = JsonSerializer.SerializeToUtf8Bytes(result, JsonOpts);
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.OutputStream.WriteAsync(json);
            ctx.Response.Close();
        }
        catch (Exception ex)
        {
            try
            {
                var err = JsonSerializer.SerializeToUtf8Bytes(new { error = ex.Message }, JsonOpts);
                ctx.Response.StatusCode = 500;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.OutputStream.WriteAsync(err);
                ctx.Response.Close();
            }
            catch { }
        }
    }

    private static async Task<object> HandleWarpAsync(HttpListenerContext ctx)
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.InputStream);
        var root = doc.RootElement;
        var ep = root.TryGetProperty("endpoint", out var e) ? e.GetString() ?? CloudflareVpnEngine.WarpEndpoints[0] : CloudflareVpnEngine.WarpEndpoints[0];
        var heavy = root.TryGetProperty("heavyJunk", out var h) && h.GetBoolean();
        return await CloudflareVpnEngine.GenerateAmneziaWarpAsync(ep, heavy, amnezia3x: true, registerOnline: true);
    }

    private static async Task<object> HandleCfVerifyAsync(HttpListenerContext ctx)
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.InputStream);
        var tok = doc.RootElement.GetProperty("token").GetString() ?? "";
        return await CloudflareVpnEngine.VerifyTokenAsync(tok);
    }

    private static async Task<object> HandleQuarantineAsync(HttpListenerContext ctx)
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.InputStream);
        var paths = doc.RootElement.GetProperty("paths").EnumerateArray().Select(x => x.GetString()!).ToList();
        int moved = SystemEngines.MoveToQuarantine(paths);
        return new { moved, quarantine = SystemEngines.QuarantineRoot };
    }
}

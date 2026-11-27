using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Housekeeper.Core;

public record CfAccountInfo(string AccountId, string AccountName, string? Subdomain, List<string> Workers);
public record CleanIpResult(string Ip, int Port, int LatencyMs, bool Reachable, string Quality);
public record WarpConfigResult(string ConfText, bool Registered, string Message);

public static class CloudflareVpnEngine
{
    private const string WarpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
    private const string WarpRegUrl = "https://api.cloudflareclient.com/v0a4005/reg";

    private const string QuicDisguiseI1 = "<b 0xc70000000108ce1bf31eec7d93360000449e227e4596ed7f75c4d35ce31880b4133107c822c6355b51f0d7c1bba96d5c210a48aca01885fed0871cfc37d59137d73b506dc013bb4a13c060ca5b04b7ae215af71e37d6e8ff1db235f9fe0c25cb8b492471054a7c8d0d6077d430d07f6e87a8699287f6e69f54263c7334a8e144a29851429bf2e350e519445172d36953e96085110ce1fb641e5efad42c0feb4711ece959b72cc4d6f3c1e83251adb572b921534f6ac4b10927167f41fe50040a75acef62f45bded67c0b45b9d655ce374589cad6f568b8475b2e8921ff98628f86ff2eb5bcce6f3ddb7dc89e37c5b5e78ddc8d93a58896e530b5f9f1448ab3b7a1d1f24a63bf981634f6183a21af310ffa52e9ddf5521561760288669de01a5f2f1a4f922e68d0592026bbe4329b654d4f5d6ace4f6a23b8560b720a5350691c0037b10acfac9726add44e7d3e880ee6f3b0d6429ff33655c297fee786bb5ac032e48d2062cd45e305e6d8d8b82bfbf0fdbc5ec09943d1ad02b0b5868ac4b24bb10255196be883562c35a713002014016b8cc5224768b3d330016cf8ed9300fe6bf39b4b19b3667cddc6e7c7ebe4437a58862606a2a66bd4184b09ab9d2cd3d3faed4d2ab71dd821422a9540c4c5fa2a9b2e6693d411a22854a8e541ed930796521f03a54254074bc4c5bca152a1723260e7d70a24d49720acc544b41359cfc252385bda7de7d05878ac0ea0343c77715e145160e6562161dfe2024846dfda3ce99068817a2418e66e4f37dea40a21251c8a034f83145071d93baadf050ca0f95dc9ce2338fb082d64fbc8faba905cec66e65c0e1f9b003c32c943381282d4ab09bef9b6813ff3ff5118623d2617867e25f0601df583c3ac51bc6303f79e68d8f8de4b8363ec9c7728b3ec5fcd5274edfca2a42f2727aa223c557afb33f5bea4f64aeb252c0150ed734d4d8eccb257824e8e090f65029a3a042a51e5cc8767408ae07d55da8507e4d009ae72c47ddb138df3cab6cc023df2532f88fb5a4c4bd917fafde0f3134be09231c389c70bc55cb95a779615e8e0a76a2b4d943aabfde0e394c985c0cb0376930f92c5b6998ef49ff4a13652b787503f55c4e3d8eebd6e1bc6db3a6d405d8405bd7a8db7cefc64d16e0d105a468f3d33d29e5744a24c4ac43ce0eb1bf6b559aed520b91108cda2de6e2c4f14bc4f4dc58712580e07d217c8cca1aaf7ac04bab3e7b1008b966f1ed4fba3fd93a0a9d3a27127e7aa587fbcc60d548300146bdc126982a58ff5342fc41a43f83a3d2722a26645bc961894e339b953e78ab395ff2fb854247ad06d446cc2944a1aefb90573115dc198f5c1efbc22bc6d7a74e41e666a643d5f85f57fde81b87ceff95353d22ae8bab11684180dd142642894d8dc34e402f802c2fd4a73508ca99124e428d67437c871dd96e506ffc39c0fc401f666b437adca41fd563cbcfd0fa22fbbf8112979c4e677fb533d981745cceed0fe96da6cc0593c430bbb71bcbf924f70b4547b0bb4d41c94a09a9ef1147935a5c75bb2f721fbd24ea6a9f5c9331187490ffa6d4e34e6bb30c2c54a0344724f01088fb2751a486f425362741664efb287bce66c4a544c96fa8b124d3c6b9eaca170c0b530799a6e878a57f402eb0016cf2689d55c76b2a91285e2273763f3afc5bc9398273f5338a06d>";

    public static readonly string[] WarpEndpoints =
    [
        "8.6.112.224:5279",
        "8.6.112.46:903",
        "8.6.112.206:3854",
        "8.6.112.31:859",
        "8.6.112.113:864",
        "8.6.112.121:500",
        "8.6.112.208:2408",
        "8.6.112.10:1701",
        "8.6.112.132:8854",
        "8.6.112.146:942",
        "188.114.96.1:2408",
        "188.114.97.1:2408",
        "188.114.98.1:2408",
        "188.114.99.1:2408",
        "188.114.96.1:500",
        "188.114.96.1:4500",
        "engage.cloudflareclient.com:2408"
    ];

    private static readonly string[] CfIpv4Prefixes =
    [
        "104.16.132", "104.16.248", "104.17.64", "104.17.148",
        "104.18.2", "104.18.26", "104.19.37", "104.19.196",
        "104.21.16", "104.21.48", "104.22.4", "104.22.58",
        "104.24.10", "104.26.8", "104.27.128", "162.159.135",
        "162.159.136", "162.159.138", "162.159.192", "162.159.193",
        "172.64.32", "172.64.80", "172.67.128", "172.67.180",
        "188.114.96", "188.114.97", "188.114.98", "188.114.99"
    ];

    private static readonly BigInteger P255 = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = new(121665);
    private static readonly BigInteger P255Minus2 = P255 - 2;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static string SanitizeToken(string raw)
    {
        var s = (raw ?? "").Trim().Trim('"', '\'');
        if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            s = s[7..];
        return s.Trim();
    }

    public static string GenerateNeutralWorkerName()
    {
        string[] adj = ["amber", "cedar", "maple", "linen", "pebble", "harbor", "meadow", "willow", "quartz", "copper"];
        string[] noun = ["notes", "journal", "studio", "garden", "lantern", "archive", "atelier", "gallery", "ledger", "canvas"];
        return $"{adj[RandomNumberGenerator.GetInt32(adj.Length)]}-{noun[RandomNumberGenerator.GetInt32(noun.Length)]}-{RandomNumberGenerator.GetInt32(10, 100)}";
    }

    // Pure C# RFC 7748 X25519
    private static BigInteger ModP(BigInteger x)
    {
        var r = x % P255;
        return r.Sign < 0 ? r + P255 : r;
    }

    public static byte[] X25519(byte[] scalarBytes, byte[] uBytes)
    {
        var k = new byte[32];
        Array.Copy(scalarBytes, k, 32);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        var kInt = new BigInteger(k, isUnsigned: true, isBigEndian: false);
        var uMasked = new byte[32];
        Array.Copy(uBytes, uMasked, 32);
        uMasked[31] &= 127;
        var x1 = new BigInteger(uMasked, isUnsigned: true, isBigEndian: false);

        var x2 = BigInteger.One;
        var z2 = BigInteger.Zero;
        var x3 = x1;
        var z3 = BigInteger.One;
        var swap = 0;

        for (int t = 254; t >= 0; t--)
        {
            int bit = (int)((kInt >> t) & 1);
            swap ^= bit;
            if (swap == 1)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }
            swap = bit;

            var a = ModP(x2 + z2);
            var aa = ModP(a * a);
            var b = ModP(x2 - z2);
            var bb = ModP(b * b);
            var e = ModP(aa - bb);
            var c = ModP(x3 + z3);
            var d = ModP(x3 - z3);
            var da = ModP(d * a);
            var cb = ModP(c * b);
            var nx3 = ModP((da + cb) * (da + cb));
            var nz3 = ModP(x1 * ModP((da - cb) * (da - cb)));
            var nx2 = ModP(aa * bb);
            var nz2 = ModP(e * ModP(aa + A24 * e));
            x3 = nx3; z3 = nz3; x2 = nx2; z2 = nz2;
        }

        if (swap == 1)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        var result = ModP(x2 * BigInteger.ModPow(z2, P255Minus2, P255));
        var raw = result.ToByteArray(isUnsigned: true, isBigEndian: false);
        var out32 = new byte[32];
        Array.Copy(raw, out32, Math.Min(32, raw.Length));
        return out32;
    }

    public static (string PrivB64, string PubB64) GenerateX25519KeyPair()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;
        var basePoint = new byte[32];
        basePoint[0] = 9;
        var pub = X25519(priv, basePoint);
        return (Convert.ToBase64String(priv), Convert.ToBase64String(pub));
    }

    public static async Task<WarpConfigResult> GenerateAmneziaWarpAsync(
        string endpoint,
        bool heavyJunk = false,
        bool amnezia3x = true,
        bool registerOnline = true)
    {
        var (privB64, pubB64) = GenerateX25519KeyPair();
        var v4 = "172.16.0.2";
        var peerKey = WarpPeerPublicKey;
        var registered = false;
        var msg = "Local AmneziaWG draft generated.";

        if (registerOnline)
        {
            try
            {
                var payload = JsonSerializer.Serialize(new
                {
                    key = pubB64,
                    install_id = "",
                    fcm_token = "",
                    tos = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    model = "PC",
                    serial_number = "",
                    locale = "en_US"
                });
                using var req = new HttpRequestMessage(HttpMethod.Post, WarpRegUrl);
                req.Headers.UserAgent.ParseAdd("okhttp/3.12.1");
                req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var resp = await Http.SendAsync(req);
                var body = await resp.Content.ReadAsStringAsync();
                if (resp.IsSuccessStatusCode)
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("config", out var cfg))
                    {
                        if (cfg.TryGetProperty("interface", out var iface) &&
                            iface.TryGetProperty("addresses", out var addrs) &&
                            addrs.TryGetProperty("v4", out var v4Prop) &&
                            !string.IsNullOrWhiteSpace(v4Prop.GetString()))
                        {
                            v4 = v4Prop.GetString()!;
                        }
                        if (cfg.TryGetProperty("peers", out var peers) && peers.GetArrayLength() > 0 &&
                            peers[0].TryGetProperty("public_key", out var pkProp) &&
                            !string.IsNullOrWhiteSpace(pkProp.GetString()))
                        {
                            peerKey = pkProp.GetString()!;
                        }
                    }
                    registered = true;
                    msg = "WARP key registered and ready for AmneziaVPN.";
                }
                else
                {
                    msg = $"Cloudflare WARP returned HTTP {(int)resp.StatusCode}. Retry once with internet.";
                }
            }
            catch (Exception ex)
            {
                msg = $"Could not reach WARP registration ({ex.Message}). Draft created — retry once with internet.";
            }
        }

        int jc = heavyJunk ? 5 : 3;
        int jmin = heavyJunk ? 10 : 1;
        int jmax = heavyJunk ? 40 : 3;

        var sb = new StringBuilder();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {privB64}");
        sb.AppendLine($"Address = {v4}/32");
        sb.AppendLine("DNS = 1.1.1.1");
        sb.AppendLine("MTU = 1280");
        sb.AppendLine($"Jc = {jc}");
        sb.AppendLine($"Jmin = {jmin}");
        sb.AppendLine($"Jmax = {jmax}");
        sb.AppendLine("S1 = 0");
        sb.AppendLine("S2 = 0");
        sb.AppendLine("H1 = 1");
        sb.AppendLine("H2 = 2");
        sb.AppendLine("H3 = 3");
        sb.AppendLine("H4 = 4");
        sb.AppendLine($"I1 = {QuicDisguiseI1}");
        if (amnezia3x)
        {
            sb.AppendLine("ContentPaddingAddition = 27-97");
            sb.AppendLine("MaxHandshakeAttempts = 18-26");
            sb.AppendLine("KeepaliveTimeout = 9-16");
            sb.AppendLine("RejectAfterTime = 171-196");
            sb.AppendLine("RekeyAfterTime = 116-131");
            sb.AppendLine("RekeyTimeout = 6-9");
            sb.AppendLine("RandomTrailers = on");
            sb.AppendLine("DisableCookies = on");
        }
        sb.AppendLine();
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey = {peerKey}");
        sb.AppendLine("AllowedIPs = 0.0.0.0/0");
        sb.AppendLine($"Endpoint = {endpoint.Trim()}");
        sb.AppendLine("PersistentKeepalive = 25");

        return new WarpConfigResult(sb.ToString(), registered, msg);
    }

    public static async Task<CfAccountInfo> VerifyTokenAsync(string rawToken)
    {
        var token = SanitizeToken(rawToken);
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Paste your Cloudflare API token first.");

        using var verifyDoc = await CfGetAsync("/user/tokens/verify", token);
        if (!verifyDoc.RootElement.TryGetProperty("success", out var ok) || !ok.GetBoolean())
            throw new InvalidOperationException("Cloudflare rejected this token. Check that it was copied completely.");

        using var accDoc = await CfGetAsync("/accounts?per_page=10", token);
        var arr = accDoc.RootElement.GetProperty("result");
        if (arr.GetArrayLength() == 0)
            throw new InvalidOperationException("No Cloudflare account found for this token.");

        var first = arr[0];
        var accountId = first.GetProperty("id").GetString()!;
        var accountName = first.TryGetProperty("name", out var nm) ? nm.GetString() ?? "Cloudflare Account" : "Cloudflare Account";

        string? subdomain = null;
        try
        {
            using var subDoc = await CfGetAsync($"/accounts/{accountId}/workers/subdomain", token);
            if (subDoc.RootElement.TryGetProperty("result", out var r) && r.TryGetProperty("subdomain", out var s))
                subdomain = s.GetString();
        }
        catch { }

        var workers = new List<string>();
        try
        {
            using var wDoc = await CfGetAsync($"/accounts/{accountId}/workers/scripts", token);
            if (wDoc.RootElement.TryGetProperty("result", out var list))
            {
                foreach (var item in list.EnumerateArray())
                {
                    if (item.TryGetProperty("id", out var idProp) && idProp.GetString() is string wid)
                        workers.Add(wid);
                }
            }
        }
        catch { }

        return new CfAccountInfo(accountId, accountName, subdomain, workers);
    }

    public static async Task DeleteWorkerAsync(string accountId, string rawToken, string workerName)
    {
        var token = SanitizeToken(rawToken);
        using var req = new HttpRequestMessage(HttpMethod.Delete, $"https://api.cloudflare.com/client/v4/accounts/{accountId}/workers/scripts/{workerName}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var resp = await Http.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Could not delete Worker (HTTP {(int)resp.StatusCode}).");
    }

    private static async Task<JsonDocument> CfGetAsync(string path, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.cloudflare.com/client/v4{path}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var resp = await Http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text);
    }

    public static List<string> SampleCandidateIps(int count)
    {
        var set = new HashSet<string>();
        var prefixes = CfIpv4Prefixes.OrderBy(_ => RandomNumberGenerator.GetInt32(1000)).ToArray();
        int idx = 0;
        while (set.Count < count)
        {
            var p = prefixes[idx % prefixes.Length];
            set.Add($"{p}.{RandomNumberGenerator.GetInt32(2, 250)}");
            idx++;
        }
        return set.ToList();
    }

    public static async Task<List<CleanIpResult>> ScanCleanIpsAsync(int count = 24, int port = 443)
    {
        var candidates = SampleCandidateIps(count);
        var sem = new SemaphoreSlim(8);
        var tasks = candidates.Select(async ip =>
        {
            await sem.WaitAsync();
            try { return await ProbeTlsIpAsync(ip, port); }
            finally { sem.Release(); }
        });
        var all = await Task.WhenAll(tasks);
        return all.Where(r => r.Reachable).OrderBy(r => r.LatencyMs).ToList();
    }

    private static async Task<CleanIpResult> ProbeTlsIpAsync(string ip, int port)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(2200);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ip, port, cts.Token);
            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "cloudflare.com" }, cts.Token);
            sw.Stop();
            int ms = Math.Max(1, (int)sw.ElapsedMilliseconds);
            var quality = ms <= 120 ? "Fast & Clean" : (ms <= 260 ? "Clean" : "Slow");
            return new CleanIpResult(ip, port, ms, true, quality);
        }
        catch
        {
            return new CleanIpResult(ip, port, 9999, false, "Blocked / Timed out");
        }
    }

    public static string BuildVlessLink(string workerHost, string uuid, string address, int port, string label)
    {
        var host = workerHost.Trim();
        var cleanUuid = uuid.Trim().ToLowerInvariant();
        var safeLabel = Uri.EscapeDataString(label.Replace(' ', '-'));
        return $"vless://{cleanUuid}@{address}:{port}?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=%2F%3Fed%3D2048#{safeLabel}";
    }
}

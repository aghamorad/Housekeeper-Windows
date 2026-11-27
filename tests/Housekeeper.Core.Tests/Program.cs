using Housekeeper.Core;

static void Assert(bool cond, string msg)
{
    if (!cond) throw new Exception($"FAIL: {msg}");
}

static byte[] FromHex(string hex) => Convert.FromHexString(hex);
static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

// 1. RFC 7748 X25519 vectors
var v1 = ToHex(CloudflareVpnEngine.X25519(
    FromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    FromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")));
Assert(v1 == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "X25519 vector 1");

var basePt = new byte[32]; basePt[0] = 9;
var alice = ToHex(CloudflareVpnEngine.X25519(
    FromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), basePt));
Assert(alice == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "X25519 Alice pubkey");

// 2. Token sanitization
Assert(CloudflareVpnEngine.SanitizeToken("  \"Bearer cfat_test123\" \n") == "cfat_test123", "Token sanitize");

// 3. Neutral worker names
for (int i = 0; i < 20; i++)
{
    var name = CloudflareVpnEngine.GenerateNeutralWorkerName();
    Assert(!name.Contains("vpn") && !name.Contains("proxy") && !name.Contains("bpb"), "Neutral name");
}

// 4. VLESS URI format
var vless = CloudflareVpnEngine.BuildVlessLink("amber-notes-42.ex.workers.dev", "044caab5-3190-4464-944e-709fe5924265", "104.18.2.55", 443, "HK Clean");
Assert(vless.StartsWith("vless://044caab5-3190-4464-944e-709fe5924265@104.18.2.55:443?"), "VLESS prefix");
Assert(vless.Contains("sni=amber-notes-42.ex.workers.dev"), "VLESS SNI");

// 5. Offline AmneziaWG WARP config with DarknessShade QUIC I1 + Amnezia 3.0/3.1
var warp = await CloudflareVpnEngine.GenerateAmneziaWarpAsync("8.6.112.224:5279", heavyJunk: false, amnezia3x: true, registerOnline: false);
Assert(warp.ConfText.Contains("Endpoint = 8.6.112.224:5279"), "WARP endpoint");
Assert(warp.ConfText.Contains("RandomTrailers = on"), "Amnezia 3.1");
Assert(warp.ConfText.Contains("ContentPaddingAddition = 27-97"), "Amnezia 3.0");

// 6. Candidate IPv4 sampling
var ips = CloudflareVpnEngine.SampleCandidateIps(24);
Assert(ips.Count == 24 && ips.All(ip => ip.Split('.').Length == 4), "IPv4 sample");

// 7. Quarantine move safety
var tmpFile = Path.Combine(Path.GetTempPath(), $"hk-test-{Guid.NewGuid()}.txt");
File.WriteAllText(tmpFile, "safe test");
int moved = SystemEngines.MoveToQuarantine([tmpFile]);
Assert(moved == 1 && !File.Exists(tmpFile), "Quarantine move");

Console.WriteLine("Housekeeper.Core.Tests: ALL 7 SUITES PASSED.");

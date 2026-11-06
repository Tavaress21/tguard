using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TGuard.Core.Ipc;

public static class Protocol
{
    public const string PipeName = "TGuard.Service.v1";
    public const string EventsPipeName = "TGuard.Events.v1";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
}

public sealed class Request
{
    public string Cmd { get; set; } = "";
    public JsonObject? Args { get; set; }
}

public sealed class Response
{
    public bool Ok { get; set; } = true;
    public string? Error { get; set; }
    public JsonNode? Data { get; set; }

    public static Response Success(object? data = null) =>
        new() { Data = data is null ? null : JsonSerializer.SerializeToNode(data, Protocol.Json) };

    public static Response Fail(string error) => new() { Ok = false, Error = error };

    public T? As<T>() => Data is null ? default : Data.Deserialize<T>(Protocol.Json);
}

public sealed class Notification
{
    public string Kind { get; set; } = "";
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    public JsonNode? Data { get; set; }
}

public sealed class ServiceStatus
{
    public string Version { get; set; } = "";
    public bool RealtimeEnabled { get; set; }
    public bool ProcessGuardActive { get; set; }
    public bool UsbProtection { get; set; }
    public bool RansomwareActive { get; set; }
    public int ProtectedFolders { get; set; }
    public bool EmailActive { get; set; }
    public int EmailAccounts { get; set; }
    public bool AccountLinked { get; set; }
    public bool AutoUpdate { get; set; }
    public int BadUrls { get; set; }
    public int WatchedFolders { get; set; }
    public int Signatures { get; set; }
    public int Rules { get; set; }
    public int QuarantineCount { get; set; }
    public int ThreatsLast30Days { get; set; }
    public DateTimeOffset? LastScan { get; set; }
    public DateTimeOffset? LastUpdate { get; set; }
    public ScanProgress? CurrentScan { get; set; }
}

public sealed class ScanProgress
{
    public string Id { get; set; } = "";
    public string Type { get; set; } = "";
    public bool Running { get; set; }
    public int FilesScanned { get; set; }
    public int Threats { get; set; }
    public string CurrentFile { get; set; } = "";
    public DateTimeOffset Started { get; set; }
    public DateTimeOffset? Finished { get; set; }
    public bool Cancelled { get; set; }
    public List<ThreatInfo> Found { get; set; } = new();

    public ScanProgress Snapshot()
    {
        lock (Found)
        {
            return new ScanProgress
            {
                Id = Id, Type = Type, Running = Running, FilesScanned = FilesScanned, Threats = Threats,
                CurrentFile = CurrentFile, Started = Started, Finished = Finished, Cancelled = Cancelled,
                Found = Found.ToList(),
            };
        }
    }
}

public sealed class ThreatInfo
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Verdict { get; set; } = "";
    public int Score { get; set; }
    public List<string> Reasons { get; set; } = new();
    public string Action { get; set; } = "";
}

public sealed class ServiceClient
{
    private readonly int _timeoutMs;

    public ServiceClient(int timeoutMs = 3000) => _timeoutMs = timeoutMs;

    public async Task<Response> SendAsync(string cmd, object? args = null, CancellationToken ct = default)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", Protocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(_timeoutMs, ct);
            var req = new Request { Cmd = cmd, Args = args is null ? null : JsonSerializer.SerializeToNode(args, Protocol.Json) as JsonObject };
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            await writer.WriteLineAsync(JsonSerializer.Serialize(req, Protocol.Json).AsMemory(), ct);
            var line = await reader.ReadLineAsync(ct);
            return line is null ? Response.Fail("no response") : JsonSerializer.Deserialize<Response>(line, Protocol.Json) ?? Response.Fail("invalid response");
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return Response.Fail("The TGuard service is not running.");
        }
    }

    public async Task ListenAsync(Action<Notification> onNotification, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", Protocol.EventsPipeName, PipeDirection.In, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(5000, ct);
                using var reader = new StreamReader(pipe, Encoding.UTF8);
                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line is null) break;
                    var n = JsonSerializer.Deserialize<Notification>(line, Protocol.Json);
                    if (n is not null) onNotification(n);
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception) { }
            try { await Task.Delay(3000, ct); } catch (OperationCanceledException) { return; }
        }
    }
}

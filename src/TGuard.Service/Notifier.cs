using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using TGuard.Core.Ipc;

namespace TGuard.Service;

public sealed class Notifier : BackgroundService
{
    private readonly ILogger<Notifier> _log;
    private readonly ConcurrentDictionary<Guid, Channel<string>> _subscribers = new();

    public Notifier(ILogger<Notifier> log) => _log = log;

    public void Publish(Notification n)
    {
        var line = JsonSerializer.Serialize(n, Protocol.Json);
        foreach (var ch in _subscribers.Values) ch.Writer.TryWrite(line);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = PipeFactory.Create(Protocol.EventsPipeName, PipeDirection.Out);
                await pipe.WaitForConnectionAsync(ct);
                var id = Guid.NewGuid();
                var ch = Channel.CreateBounded<string>(new BoundedChannelOptions(500) { FullMode = BoundedChannelFullMode.DropOldest });
                _subscribers[id] = ch;
                var connected = pipe;
                pipe = null;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var writer = new StreamWriter(connected, new UTF8Encoding(false)) { AutoFlush = true };
                        await foreach (var line in ch.Reader.ReadAllAsync(ct))
                            await writer.WriteLineAsync(line);
                    }
                    catch (Exception) { /* app fechada */ }
                    finally
                    {
                        _subscribers.TryRemove(id, out _);
                        await connected.DisposeAsync();
                    }
                }, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Notification channel error");
                await Task.Delay(1000, ct);
            }
            finally
            {
                if (pipe is not null) await pipe.DisposeAsync();
            }
        }
    }
}

internal static class PipeFactory
{
    public static NamedPipeServerStream Create(string name, PipeDirection dir)
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        // deny remote (network) access
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return NamedPipeServerStreamAcl.Create(name, dir, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, sec);
    }
}

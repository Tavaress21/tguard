using TGuard.Core.Storage;

namespace TGuard.Service;

/// <summary>Downloads new signatures and malicious URL lists every 6 hours.</summary>
public sealed class UpdateService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    private readonly ServiceState _state;
    private readonly ILogger<UpdateService> _log;
    private readonly Updater _updater = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UpdateService(ServiceState state, ILogger<UpdateService> log)
    {
        _state = state;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(2), ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            var st = _state.State;
            var due = st.LastUpdate is null || DateTimeOffset.Now - st.LastUpdate > Interval;
            // after a failed attempt (offline, server down) wait an hour before trying again
            var backoff = st.LastUpdateAttempt is not null && DateTimeOffset.Now - st.LastUpdateAttempt < TimeSpan.FromHours(1);
            if (_state.Settings.AutoUpdate && due && !backoff)
                await RunAsync(ct);
            try { await Task.Delay(TimeSpan.FromMinutes(15), ct); } catch (OperationCanceledException) { return; }
        }
    }

    public async Task<UpdateReport> RunAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var report = await _updater.RunAsync(_state.Engine, _state.Settings, ct);
            _state.State.LastUpdateAttempt = DateTimeOffset.Now;
            _state.State.Save();
            if (report.Success)
            {
                _state.State.LastUpdate = DateTimeOffset.Now;
                _state.State.Save();
            }
            _log.LogInformation("Update: sources={Sources} signatures+={Sigs} urls+={Urls} errors={Errors}",
                string.Join(",", report.Sources), report.SignaturesAdded, report.UrlsAdded, string.Join(" | ", report.Errors));
            return report;
        }
        finally { _gate.Release(); }
    }
}

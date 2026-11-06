using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class Scheduler : BackgroundService
{
    private readonly ServiceState _state;
    private readonly ScanManager _scans;
    private readonly ILogger<Scheduler> _log;

    public Scheduler(ServiceState state, ScanManager scans, ILogger<Scheduler> log)
    {
        _state = state;
        _scans = scans;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(10), ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            if (Schedule.IsQuickScanDue(_state.Settings, _state.State, DateTime.Now) && _scans.Current is not { Running: true })
            {
                _state.State.LastScheduledScan = DateOnly.FromDateTime(DateTime.Now);
                _state.State.Save();
                _log.LogInformation("Starting scheduled quick scan");
                _scans.Start("quick");
            }
            try { await Task.Delay(TimeSpan.FromMinutes(1), ct); } catch (OperationCanceledException) { return; }
        }
    }

}

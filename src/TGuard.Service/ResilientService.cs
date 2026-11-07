namespace TGuard.Service;

public abstract class ResilientService : BackgroundService
{
    private static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(15);
    private readonly ILogger _log;

    protected ResilientService(ILogger log) => _log = log;

    protected abstract Task LoopAsync(CancellationToken ct);

    protected sealed override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await LoopAsync(ct);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "{Service} failed, restarting in {Seconds}s", GetType().Name, RestartDelay.TotalSeconds);
            }

            try { await Task.Delay(RestartDelay, ct); }
            catch (OperationCanceledException) { return; }
        }
    }
}

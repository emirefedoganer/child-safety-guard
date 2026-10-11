using ChildSafetyGuard.Core.Enforcement;
using ChildSafetyGuard.Core.Notices;

namespace ChildSafetyGuard.Service;

/// <summary>Polls every few seconds so the notice appears moments after a blocked application is opened.</summary>
public sealed class BlockNoticeWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    private readonly BlockNoticeService _notices;
    private readonly ILogger<BlockNoticeWorker> _logger;

    public BlockNoticeWorker(BlockNoticeService notices, ILogger<BlockNoticeWorker> logger)
    {
        _notices = notices;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(PollInterval);
        var failures = 0;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    _notices.Tick();
                    failures = 0;
                }
                catch (Exception ex)
                {
                    // Log the first failure and then only occasionally, so a persistent problem cannot flood the Event Log.
                    failures++;
                    if (failures == 1 || failures % 100 == 0)
                    {
                        _logger.LogError(EventIds.WorkerError, ex, "Block notice check failed ({Failures} in a row).", failures);
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Service is stopping.
        }
    }
}

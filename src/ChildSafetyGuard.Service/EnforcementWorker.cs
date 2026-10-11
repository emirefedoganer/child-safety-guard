using System.Net.NetworkInformation;
using ChildSafetyGuard.Core.Enforcement;
using Microsoft.Extensions.Options;

namespace ChildSafetyGuard.Service;

/// <summary>
/// Runs the enforcement engine at startup, on a timer, and shortly after Windows reports a network address change.
/// Stopping the service does not remove firewall rules: the policy keeps protecting the device until the guardian
/// disables it with the CLI.
/// </summary>
public sealed class EnforcementWorker : BackgroundService
{
    private static readonly TimeSpan Debounce = TimeSpan.FromSeconds(5);

    private readonly EnforcementEngine _engine;
    private readonly IOptions<GuardOptions> _options;
    private readonly ILogger<EnforcementWorker> _logger;
    private readonly SemaphoreSlim _wake = new(0, 1);

    public EnforcementWorker(EnforcementEngine engine, IOptions<GuardOptions> options, ILogger<EnforcementWorker> logger)
    {
        _engine = engine;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(GuardOptions.MinimumIntervalSeconds, _options.Value.ReconcileIntervalSeconds));
        _logger.LogInformation(
            EventIds.ServiceStarted,
            "Child Safety Guard started. Policy is re-checked every {IntervalSeconds}s and after network changes.",
            (int)interval.TotalSeconds);

        NetworkAddressChangedEventHandler onNetworkChanged = (_, _) => SignalWake();
        NetworkChange.NetworkAddressChanged += onNetworkChanged;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                RunSafely();

                try
                {
                    var woken = await _wake.WaitAsync(interval, stoppingToken);
                    if (woken)
                    {
                        await Task.Delay(Debounce, stoppingToken);
                        while (_wake.CurrentCount > 0)
                        {
                            _wake.Wait(0);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= onNetworkChanged;
            _logger.LogInformation(EventIds.ServiceStopping, "Child Safety Guard is stopping. Firewall rules stay in place.");
        }
    }

    private void SignalWake()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // A run is already pending.
        }
    }

    private void RunSafely()
    {
        try
        {
            _engine.RunOnce();
        }
        catch (Exception ex)
        {
            // Never let one bad cycle take the service down; the next cycle retries.
            _logger.LogError(EventIds.WorkerError, ex, "Enforcement cycle failed unexpectedly.");
        }
    }
}

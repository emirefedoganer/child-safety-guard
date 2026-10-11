namespace ChildSafetyGuard.Service;

public sealed class GuardOptions
{
    public const int MinimumIntervalSeconds = 15;

    /// <summary>How often policy is re-applied and the network re-inspected, in addition to reacting to network changes.</summary>
    public int ReconcileIntervalSeconds { get; set; } = 60;
}

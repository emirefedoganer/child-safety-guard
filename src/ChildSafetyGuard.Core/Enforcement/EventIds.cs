using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Core.Enforcement;

/// <summary>Stable Windows Event Log event IDs, so guardians and tools can filter on them.</summary>
public static class EventIds
{
    public static readonly EventId ServiceStarted = new(1000, nameof(ServiceStarted));
    public static readonly EventId ServiceStopping = new(1001, nameof(ServiceStopping));
    public static readonly EventId EnforcementChanged = new(1100, nameof(EnforcementChanged));
    public static readonly EventId EnforcementUnchanged = new(1101, nameof(EnforcementUnchanged));
    public static readonly EventId NotConfigured = new(1102, nameof(NotConfigured));
    public static readonly EventId PolicyInvalid = new(2000, nameof(PolicyInvalid));
    public static readonly EventId StateUnreadable = new(2001, nameof(StateUnreadable));
    public static readonly EventId FirewallError = new(2002, nameof(FirewallError));
    public static readonly EventId ProtectedPathRefused = new(2003, nameof(ProtectedPathRefused));
    public static readonly EventId DetectionError = new(2004, nameof(DetectionError));
    public static readonly EventId Finding = new(3000, nameof(Finding));
    public static readonly EventId FindingWarning = new(3001, nameof(FindingWarning));
    public static readonly EventId WorkerError = new(9000, nameof(WorkerError));
}

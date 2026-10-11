using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Policy;

/// <summary>
/// Guardian-only policy changes. Every mutating method needs a live <see cref="GuardianSession"/>
/// and re-validates the whole policy before saving.
/// </summary>
public sealed class PolicyManager
{
    private readonly IStateStore _store;
    private readonly PolicyValidator _validator;
    private readonly TimeProvider _time;

    public PolicyManager(IStateStore store, PolicyValidator validator, TimeProvider time)
    {
        _store = store;
        _validator = validator;
        _time = time;
    }

    public AppState GetState() => _store.Load() ?? new AppState();

    public PolicyDocument GetPolicy() => GetState().Policy;

    public void SetEnforcement(GuardianSession session, bool enabled) =>
        Mutate(session, s => s with { Policy = s.Policy with { EnforcementEnabled = enabled } });

    public void AddOrUpdateApplication(GuardianSession session, BlockedApplication application) =>
        Mutate(session, s =>
        {
            var apps = s.Policy.BlockedApplications.Where(a => a.Id != application.Id).ToList();
            apps.Add(application);
            return s with { Policy = s.Policy with { BlockedApplications = apps } };
        });

    public bool RemoveApplication(GuardianSession session, string id)
    {
        var removed = false;
        Mutate(session, s =>
        {
            var apps = s.Policy.BlockedApplications.Where(a => a.Id != id).ToList();
            removed = apps.Count != s.Policy.BlockedApplications.Count;
            return s with { Policy = s.Policy with { BlockedApplications = apps } };
        });
        return removed;
    }

    public bool SetApplicationEnabled(GuardianSession session, string id, bool enabled)
    {
        var found = false;
        Mutate(session, s =>
        {
            var apps = s.Policy.BlockedApplications
                .Select(a =>
                {
                    if (a.Id != id)
                    {
                        return a;
                    }

                    found = true;
                    return a with { Enabled = enabled };
                })
                .ToList();
            return s with { Policy = s.Policy with { BlockedApplications = apps } };
        });
        return found;
    }

    public void SetTargetProfiles(GuardianSession session, IEnumerable<string> profileNames) =>
        Mutate(session, s => s with { Policy = s.Policy with { TargetProfiles = profileNames.ToList() } });

    public void SetWatchedProcesses(GuardianSession session, IEnumerable<string> processNames) =>
        Mutate(session, s => s with { Policy = s.Policy with { ExtraWatchedProcessNames = processNames.ToList() } });

    public void SetNotice(GuardianSession session, BlockNotice notice) =>
        Mutate(session, s => s with { Policy = s.Policy with { Notice = notice } });

    public void SetBaseline(GuardianSession session, NetworkSnapshot baseline) =>
        Mutate(session, s => s with { Baseline = baseline });

    private void Mutate(GuardianSession session, Func<AppState, AppState> change)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!session.IsValidAt(_time.GetUtcNow()))
        {
            throw new UnauthorizedAccessException("The guardian session has expired. Authenticate again.");
        }

        var state = _store.Load();
        if (state?.Guardian is null)
        {
            throw new InvalidOperationException("No guardian is configured. Run setup first.");
        }

        var updated = change(state);
        var errors = _validator.Validate(updated.Policy);
        if (errors.Count > 0)
        {
            throw new PolicyValidationException(errors);
        }

        _store.Save(updated);
    }
}

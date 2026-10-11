using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Detection;
using ChildSafetyGuard.Core.Firewall;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Network;
using ChildSafetyGuard.Core.Policy;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Core.Enforcement;

/// <summary>
/// One reconcile cycle: load the guardian's policy, make the managed Windows Firewall rules match it,
/// then look for configuration changes and known circumvention tools and report them.
/// </summary>
/// <remarks>
/// Fail-static: if the state cannot be read or the policy is invalid, existing firewall rules are left exactly
/// as they are. Only the product's own rules (name prefix <see cref="FirewallPlanner.NamePrefix"/>) are ever touched.
/// </remarks>
public sealed class EnforcementEngine
{
    private readonly IStateStore _store;
    private readonly IApplicationPathResolver _resolver;
    private readonly IFirewallGateway _firewall;
    private readonly INetworkInspector _inspector;
    private readonly IRuntimeInventory _inventory;
    private readonly IFindingSink _sink;
    private readonly PolicyValidator _validator;
    private readonly ILogger<EnforcementEngine> _logger;
    private readonly IReadOnlyList<KnownTool> _catalog;
    private readonly IAccountInspector? _accounts;

    private readonly HashSet<string> _reportedKeys = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public EnforcementEngine(
        IStateStore store,
        IApplicationPathResolver resolver,
        IFirewallGateway firewall,
        INetworkInspector inspector,
        IRuntimeInventory inventory,
        IFindingSink sink,
        PolicyValidator validator,
        ILogger<EnforcementEngine> logger,
        IReadOnlyList<KnownTool>? catalog = null,
        IAccountInspector? accounts = null)
    {
        _store = store;
        _resolver = resolver;
        _firewall = firewall;
        _inspector = inspector;
        _inventory = inventory;
        _sink = sink;
        _validator = validator;
        _logger = logger;
        _catalog = catalog ?? KnownToolCatalog.Default;
        _accounts = accounts;
    }

    public EnforcementReport RunOnce()
    {
        lock (_gate)
        {
            return RunLocked();
        }
    }

    private EnforcementReport RunLocked()
    {
        var problems = new List<string>();

        AppState? state;
        try
        {
            state = _store.Load();
        }
        catch (StateStoreException ex)
        {
            _logger.LogError(EventIds.StateUnreadable, ex, "The protected configuration could not be read; firewall rules were left unchanged.");
            return new EnforcementReport(false, false, 0, 0, new[] { "Configuration unreadable." }, Array.Empty<Finding>(), 0);
        }

        if (state?.Guardian is null)
        {
            _logger.LogDebug(EventIds.NotConfigured, "No guardian is configured yet; nothing to enforce.");
            return new EnforcementReport(false, false, 0, 0, problems, Array.Empty<Finding>(), 0);
        }

        var policy = state.Policy;
        var validationErrors = _validator.Validate(policy);
        if (validationErrors.Count > 0)
        {
            _logger.LogError(EventIds.PolicyInvalid, "The policy is invalid ({ErrorCount} problem(s)); firewall rules were left unchanged. First problem: {FirstProblem}", validationErrors.Count, validationErrors[0]);
            return new EnforcementReport(true, false, 0, 0, validationErrors, Array.Empty<Finding>(), 0);
        }

        var added = 0;
        var removed = 0;
        var enforced = false;
        try
        {
            (added, removed) = ReconcileFirewall(policy, problems);
            enforced = true;
        }
        catch (Exception ex)
        {
            problems.Add("Firewall reconciliation failed: " + ex.Message);
            _logger.LogError(EventIds.FirewallError, ex, "Firewall reconciliation failed; existing rules were left in place.");
        }

        var findings = CollectFindings(state, policy);
        var newFindings = ReportNewFindings(findings);

        if (added > 0 || removed > 0)
        {
            _logger.LogInformation(
                EventIds.EnforcementChanged,
                "Firewall rules reconciled: {Added} added, {Removed} removed. Enforcement is {State}.",
                added,
                removed,
                policy.EnforcementEnabled ? "on" : "off");
        }
        else
        {
            _logger.LogDebug(EventIds.EnforcementUnchanged, "Firewall rules already match the policy.");
        }

        return new EnforcementReport(true, enforced, added, removed, problems, findings, newFindings);
    }

    private (int Added, int Removed) ReconcileFirewall(PolicyDocument policy, List<string> problems)
    {
        IReadOnlyList<FirewallRuleSpec> desired = policy.EnforcementEnabled
            ? BuildDesiredRules(policy)
            : Array.Empty<FirewallRuleSpec>();

        var changes = FirewallReconciler.Plan(desired, _firewall.ListManagedRules());

        var added = 0;
        var removed = 0;
        var failedRemovals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in changes.Remove)
        {
            try
            {
                _firewall.RemoveRule(name);
                removed++;
            }
            catch (Exception ex)
            {
                failedRemovals.Add(name);
                problems.Add($"Could not remove firewall rule '{name}'.");
                _logger.LogError(EventIds.FirewallError, ex, "Could not remove firewall rule {RuleName}.", name);
            }
        }

        foreach (var spec in changes.Add)
        {
            if (failedRemovals.Contains(spec.Name))
            {
                continue; // do not stack a duplicate on top of a rule we failed to replace
            }

            try
            {
                _firewall.AddRule(spec);
                added++;
            }
            catch (Exception ex)
            {
                problems.Add($"Could not add firewall rule '{spec.Name}'.");
                _logger.LogError(EventIds.FirewallError, ex, "Could not add firewall rule {RuleName}.", spec.Name);
            }
        }

        return (added, removed);
    }

    private IReadOnlyList<FirewallRuleSpec> BuildDesiredRules(PolicyDocument policy)
    {
        var safe = new List<ResolvedApplication>();
        foreach (var app in _resolver.Resolve(policy))
        {
            var allowed = app.Paths.Where(p => !_validator.IsProtectedPath(p)).ToList();
            var refused = app.Paths.Count - allowed.Count;
            if (refused > 0)
            {
                _logger.LogWarning(
                    EventIds.ProtectedPathRefused,
                    "Refused to create {Count} rule(s) for {ApplicationId}: the path is a protected system, security or product location.",
                    refused,
                    app.Application.Id);
            }

            safe.Add(app with { Paths = allowed });
        }

        return FirewallPlanner.BuildDesiredRules(safe);
    }

    private IReadOnlyList<Finding> CollectFindings(AppState state, PolicyDocument policy)
    {
        var findings = new List<Finding>();

        if (policy.EnforcementEnabled && _accounts is not null)
        {
            try
            {
                findings.AddRange(ProfileSafetyChecker.Assess(policy.TargetProfiles, _accounts.GetProfiles(policy.TargetProfiles)));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(EventIds.DetectionError, ex, "Could not check the accounts targeted by the policy.");
            }
        }

        if (policy.EnforcementEnabled)
        {
            try
            {
                if (_firewall.AreAllProfilesEnabled() == false)
                {
                    findings.Add(new Finding(
                        "FIREWALL_DISABLED",
                        FindingSeverity.Warning,
                        "Windows Defender Firewall is turned off for at least one network profile",
                        "The blocking rules only take effect while the firewall is on for the active network profile. " +
                        "It may have been turned off by a person with administrator rights, or by a policy.",
                        "firewall",
                        new[] { "Profile state: at least one of Domain/Private/Public is off" }));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(EventIds.DetectionError, ex, "Could not determine the Windows Firewall state.");
            }
        }

        if (state.Baseline is not null)
        {
            try
            {
                findings.AddRange(NetworkChangeAnalyzer.Analyze(state.Baseline, _inspector.Capture()));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(EventIds.DetectionError, ex, "Network inspection failed.");
            }
        }

        try
        {
            findings.AddRange(CircumventionMatcher.Match(_inventory.Capture(), _catalog, policy.ExtraWatchedProcessNames));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(EventIds.DetectionError, ex, "Circumvention-tool detection failed.");
        }

        return findings;
    }

    private int ReportNewFindings(IReadOnlyList<Finding> findings)
    {
        // Forget findings that went away, so they are reported again if they come back.
        _reportedKeys.IntersectWith(findings.Select(f => f.Key));

        var count = 0;
        foreach (var finding in findings)
        {
            if (_reportedKeys.Add(finding.Key))
            {
                _sink.Report(finding);
                count++;
            }
        }

        return count;
    }
}

using System.Collections;
using System.Runtime.InteropServices;
using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Firewall;
using ChildSafetyGuard.Core.Models;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Windows Defender Firewall through the documented Windows Firewall with Advanced Security COM API
/// (HNetCfg.FwPolicy2 / INetFwPolicy2). Only rules whose name starts with <see cref="FirewallPlanner.NamePrefix"/>
/// are listed, added or removed.
/// </summary>
/// <remarks>
/// Requires administrator rights (the service runs as LocalSystem, the CLI is elevated). COM objects are
/// late-bound through <c>dynamic</c> to avoid a type-library dependency.
/// </remarks>
public sealed class WindowsFirewallGateway : IFirewallGateway
{
    private const int DirectionOut = 2;      // NET_FW_RULE_DIR_OUT
    private const int ActionBlock = 0;       // NET_FW_ACTION_BLOCK
    private const int ProfilesAll = 0x7FFFFFFF; // NET_FW_PROFILE2_ALL
    private static readonly int[] ProfileTypes = { 1, 2, 4 }; // NET_FW_PROFILE2_DOMAIN, PRIVATE, PUBLIC

    private readonly ILogger<WindowsFirewallGateway> _logger;

    public WindowsFirewallGateway(ILogger<WindowsFirewallGateway> logger)
    {
        _logger = logger;
    }

    public IReadOnlyList<ExistingFirewallRule> ListManagedRules()
    {
        dynamic policy = CreateObject("HNetCfg.FwPolicy2");
        try
        {
            var result = new List<ExistingFirewallRule>();
            foreach (dynamic rule in (IEnumerable)policy.Rules)
            {
                try
                {
                    string name = rule.Name ?? string.Empty;
                    if (!name.StartsWith(FirewallPlanner.NamePrefix, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    string program = rule.ApplicationName ?? string.Empty;
                    result.Add(new ExistingFirewallRule(
                        name,
                        program,
                        (bool)rule.Enabled,
                        (int)rule.Action == ActionBlock,
                        (int)rule.Direction == DirectionOut));
                }
                finally
                {
                    ReleaseCom((object)rule);
                }
            }

            return result;
        }
        finally
        {
            ReleaseCom((object)policy);
        }
    }

    public void AddRule(FirewallRuleSpec spec)
    {
        dynamic policy = CreateObject("HNetCfg.FwPolicy2");
        dynamic rule = CreateObject("HNetCfg.FWRule");
        try
        {
            rule.Name = spec.Name;
            rule.Description = spec.Description;
            rule.ApplicationName = spec.ProgramPath;
            rule.Direction = DirectionOut;
            rule.Action = ActionBlock;
            rule.Profiles = ProfilesAll;
            rule.Grouping = FirewallPlanner.GroupName;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
        finally
        {
            ReleaseCom((object)rule);
            ReleaseCom((object)policy);
        }
    }

    public void RemoveRule(string name)
    {
        if (!name.StartsWith(FirewallPlanner.NamePrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException("Refusing to remove a firewall rule this product does not own.", nameof(name));
        }

        dynamic policy = CreateObject("HNetCfg.FwPolicy2");
        try
        {
            policy.Rules.Remove(name);
        }
        finally
        {
            ReleaseCom((object)policy);
        }
    }

    public bool? AreAllProfilesEnabled()
    {
        try
        {
            dynamic policy = CreateObject("HNetCfg.FwPolicy2");
            try
            {
                foreach (var profile in ProfileTypes)
                {
                    bool enabled = policy.FirewallEnabled[profile];
                    if (!enabled)
                    {
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                ReleaseCom((object)policy);
            }
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            _logger.LogDebug(ex, "Could not read the Windows Firewall profile state.");
            return null;
        }
    }

    private static object CreateObject(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    private static void ReleaseCom(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }
}

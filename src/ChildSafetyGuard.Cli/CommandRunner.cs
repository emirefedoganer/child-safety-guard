using System.ServiceProcess;
using ChildSafetyGuard.Core;
using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Detection;
using ChildSafetyGuard.Core.Enforcement;
using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Network;
using ChildSafetyGuard.Core.Policy;
using ChildSafetyGuard.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Cli;

/// <summary>Guardian command-line tool. Every command needs an elevated prompt; every change also needs the guardian passphrase.</summary>
internal sealed class CommandRunner
{
    private readonly GuardianManager _guardian;
    private readonly PolicyManager _policy;
    private readonly EnforcementEngine _engine;
    private readonly INetworkInspector _inspector;
    private readonly IRuntimeInventory _inventory;
    private readonly IFirewallGateway _firewall;
    private readonly IAccountInspector _accounts;

    private CommandRunner(IServiceProvider services)
    {
        _guardian = services.GetRequiredService<GuardianManager>();
        _policy = services.GetRequiredService<PolicyManager>();
        _engine = services.GetRequiredService<EnforcementEngine>();
        _inspector = services.GetRequiredService<INetworkInspector>();
        _inventory = services.GetRequiredService<IRuntimeInventory>();
        _firewall = services.GetRequiredService<IFirewallGateway>();
        _accounts = services.GetRequiredService<IAccountInspector>();
    }

    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h" or "/?")
        {
            PrintHelp();
            return 0;
        }

        if (!WindowsElevation.IsAdministrator())
        {
            ConsoleIO.Error("Guardian commands need an elevated (Run as administrator) prompt.");
            return 3;
        }

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Warning));
        services.AddChildSafetyGuard(GuardPaths.DefaultDataDirectory);
        using var provider = services.BuildServiceProvider();

        try
        {
            return new CommandRunner(provider).Dispatch(args);
        }
        catch (StateStoreException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 4;
        }
        catch (PolicyValidationException ex)
        {
            ConsoleIO.Error("That change was rejected:");
            foreach (var error in ex.Errors)
            {
                ConsoleIO.Error("  - " + error);
            }

            return 5;
        }
        catch (UnauthorizedAccessException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 6;
        }
    }

    private int Dispatch(string[] args)
    {
        var rest = args.Skip(1).ToArray();
        return args[0].ToLowerInvariant() switch
        {
            "setup" => Setup(),
            "status" => Status(),
            "transparency" => Transparency(),
            "check" => Check(),
            "apply" => Apply("Applied."),
            "profiles" => ListProfiles(),
            "baseline" => Baseline(rest),
            "policy" => PolicyCommand(rest),
            "passphrase" => ChangePassphrase(),
            "recover" => Recover(),
            "teardown" => Teardown(),
            _ => Unknown(args[0]),
        };
    }

    private int Setup()
    {
        if (_guardian.IsInitialized)
        {
            ConsoleIO.Error("A guardian is already set up. Use 'csg passphrase' to change the passphrase.");
            return 1;
        }

        ConsoleIO.Info(TransparencyStatement.Text);
        ConsoleIO.Info(string.Empty);
        ConsoleIO.Info("Please read the statement above, ideally together with the person who uses this device.");
        if (!ConsoleIO.Confirm("Continue with setup?"))
        {
            return 1;
        }

        ConsoleIO.Info($"Choose a guardian passphrase ({GuardianManager.MinPassphraseLength}+ characters). Keep it away from the device user.");
        var passphrase = ConsoleIO.ReadSecret("Passphrase: ");
        if (passphrase != ConsoleIO.ReadSecret("Repeat passphrase: "))
        {
            ConsoleIO.Error("The passphrases do not match.");
            return 1;
        }

        string recoveryCode;
        try
        {
            recoveryCode = _guardian.Initialize(passphrase);
        }
        catch (ArgumentException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 1;
        }

        var session = _guardian.Authenticate(passphrase).Session!;
        _policy.SetBaseline(session, _inspector.Capture());

        ConsoleIO.Info(string.Empty);
        ConsoleIO.Info("Setup complete. The current network configuration was recorded as the baseline.");
        ConsoleIO.Info(string.Empty);
        ConsoleIO.Info("RECOVERY CODE (shown only once - write it down and keep it somewhere safe, offline):");
        ConsoleIO.Info("    " + recoveryCode);
        ConsoleIO.Info(string.Empty);
        ConsoleIO.Info("Next steps:");
        ConsoleIO.Info("  1. 'csg policy list'      review what will be blocked (Discord and Telegram are listed; nothing is enforced yet)");
        ConsoleIO.Info("  2. 'csg profiles'         see Windows profiles; 'csg policy target-profiles <name>' limits blocking to one");
        ConsoleIO.Info("  3. 'csg policy enable'    turn enforcement on");
        return 0;
    }

    private int Status()
    {
        var state = _policy.GetState();
        ConsoleIO.Info($"Guardian configured : {(state.Guardian is not null ? "yes" : "no")}");
        ConsoleIO.Info($"Enforcement         : {(state.Policy.EnforcementEnabled ? "ON" : "off")}");
        ConsoleIO.Info($"Service             : {ServiceStatus()}");
        ConsoleIO.Info($"Baseline recorded   : {(state.Baseline is null ? "no" : state.Baseline.CapturedAtUtc.ToLocalTime().ToString("g"))}");
        ConsoleIO.Info($"Managed fw rules    : {SafeRuleCount()}");
        ConsoleIO.Info($"Target profiles     : {(state.Policy.TargetProfiles.Count == 0 ? "(all)" : string.Join(", ", state.Policy.TargetProfiles))}");
        foreach (var app in state.Policy.BlockedApplications)
        {
            ConsoleIO.Info($"  - {app.Id,-14} {(app.Enabled ? "blocked " : "allowed ")} {app.DisplayName}");
        }

        PrintProfileWarnings();
        return 0;
    }

    private static int Transparency()
    {
        ConsoleIO.Info(TransparencyStatement.Text);
        return 0;
    }

    private int Check()
    {
        var state = _policy.GetState();
        var findings = new List<Finding>();

        if (state.Baseline is null)
        {
            ConsoleIO.Info("(No baseline recorded - skipping network comparison. Run 'csg baseline capture'.)");
        }
        else
        {
            findings.AddRange(NetworkChangeAnalyzer.Analyze(state.Baseline, _inspector.Capture()));
        }

        findings.AddRange(CircumventionMatcher.Match(_inventory.Capture(), KnownToolCatalog.Default, state.Policy.ExtraWatchedProcessNames));
        findings.AddRange(ProfileFindings());
        FindingPrinter.Print(findings);
        return 0;
    }

    private int Apply(string successMessage)
    {
        var report = _engine.RunOnce();
        if (!report.Configured)
        {
            ConsoleIO.Error("Nothing to apply: the guardian is not set up (or the configuration is unreadable).");
            return 1;
        }

        ConsoleIO.Info($"{successMessage} Firewall rules: +{report.RulesAdded} / -{report.RulesRemoved}.");
        foreach (var problem in report.Problems)
        {
            ConsoleIO.Error("  ! " + problem);
        }

        return report.Problems.Count == 0 ? 0 : 1;
    }

    private static int ListProfiles()
    {
        foreach (var profile in UserProfiles.Enumerate())
        {
            ConsoleIO.Info($"{profile.Name,-24} {profile.RootPath}");
        }

        return 0;
    }

    private int Baseline(string[] args)
    {
        switch (args.FirstOrDefault()?.ToLowerInvariant())
        {
            case "capture":
            {
                var session = RequireSession();
                if (session is null)
                {
                    return 2;
                }

                _policy.SetBaseline(session, _inspector.Capture());
                ConsoleIO.Info("Baseline recorded from the current network configuration.");
                return 0;
            }

            case "show":
            {
                var baseline = _policy.GetState().Baseline;
                if (baseline is null)
                {
                    ConsoleIO.Info("No baseline recorded.");
                    return 0;
                }

                ConsoleIO.Info($"Recorded {baseline.CapturedAtUtc.ToLocalTime():g}");
                foreach (var adapter in baseline.Adapters)
                {
                    ConsoleIO.Info($"  {adapter.Name} [{adapter.Kind}, {(adapter.IsUp ? "up" : "down")}] DNS: {(adapter.DnsServers.Count == 0 ? "-" : string.Join(", ", adapter.DnsServers))}");
                }

                return 0;
            }

            default:
                ConsoleIO.Error("Usage: csg baseline capture | show");
                return 1;
        }
    }

    private int PolicyCommand(string[] args)
    {
        var sub = args.FirstOrDefault()?.ToLowerInvariant();
        switch (sub)
        {
            case "list":
            {
                var policy = _policy.GetPolicy();
                ConsoleIO.Info($"Enforcement: {(policy.EnforcementEnabled ? "ON" : "off")}");
                ConsoleIO.Info($"Target profiles: {(policy.TargetProfiles.Count == 0 ? "(all)" : string.Join(", ", policy.TargetProfiles))}");
                foreach (var app in policy.BlockedApplications)
                {
                    ConsoleIO.Info($"{app.Id}  [{(app.Enabled ? "blocked" : "allowed")}]  {app.DisplayName}");
                    foreach (var pattern in app.PathPatterns)
                    {
                        ConsoleIO.Info("    " + pattern);
                    }
                }

                return 0;
            }

            case "enable":
            case "disable":
            {
                var exit = WithSession(s => _policy.SetEnforcement(s, sub == "enable"), $"Enforcement turned {(sub == "enable" ? "on" : "off")}.");
                if (exit == 0 && sub == "enable")
                {
                    PrintProfileWarnings();
                }

                return exit;
            }

            case "add" when args.Length >= 4:
                return WithSession(
                    s => _policy.AddOrUpdateApplication(s, new BlockedApplication(args[1], args[2], args.Skip(3).ToList())),
                    $"Application '{args[1]}' saved.");

            case "remove" when args.Length == 2:
                return WithSession(s =>
                {
                    if (!_policy.RemoveApplication(s, args[1]))
                    {
                        throw new InvalidOperationException($"No application with id '{args[1]}'.");
                    }
                }, $"Application '{args[1]}' removed.");

            case "toggle" when args.Length == 3 && args[2] is "on" or "off":
                return WithSession(s =>
                {
                    if (!_policy.SetApplicationEnabled(s, args[1], args[2] == "on"))
                    {
                        throw new InvalidOperationException($"No application with id '{args[1]}'.");
                    }
                }, $"Application '{args[1]}' is now {(args[2] == "on" ? "blocked" : "allowed")}.");

            case "target-profiles":
            {
                var exit = WithSession(s => _policy.SetTargetProfiles(s, args.Skip(1)), "Target profiles updated.");
                if (exit == 0)
                {
                    PrintProfileWarnings();
                }

                return exit;
            }

            case "notice" when args.Length == 1:
            {
                var notice = _policy.GetPolicy().Notice;
                ConsoleIO.Info("Title  : " + notice.Title);
                ConsoleIO.Info("Message: " + notice.Message);
                return 0;
            }

            case "notice" when args.Length == 3:
                return WithSession(s => _policy.SetNotice(s, new BlockNotice(args[1], args[2])), "Block notice updated.");

            case "watch":
                return WithSession(s => _policy.SetWatchedProcesses(s, args.Skip(1)), "Watched process names updated.");

            default:
                ConsoleIO.Error(
                    "Usage:\n" +
                    "  csg policy list\n" +
                    "  csg policy enable | disable\n" +
                    "  csg policy add <id> \"<Display Name>\" <exe-path-pattern> [...]\n" +
                    "  csg policy remove <id>\n" +
                    "  csg policy toggle <id> on|off\n" +
                    "  csg policy target-profiles [profile ...]     (none = all profiles)\n" +
                    "  csg policy notice [\"<title>\" \"<message>\"]   show or set the message shown when a blocked app is opened\n" +
                    "  csg policy watch [process-name ...]");
                return 1;
        }
    }

    private int ChangePassphrase()
    {
        if (!_guardian.IsInitialized)
        {
            ConsoleIO.Error("Run 'csg setup' first.");
            return 1;
        }

        var current = ConsoleIO.ReadSecret("Current passphrase: ");
        var next = ConsoleIO.ReadSecret("New passphrase: ");
        if (next != ConsoleIO.ReadSecret("Repeat new passphrase: "))
        {
            ConsoleIO.Error("The passphrases do not match.");
            return 1;
        }

        try
        {
            var result = _guardian.ChangePassphrase(current, next);
            return ReportAuthOutcome(result, "Passphrase changed.");
        }
        catch (ArgumentException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 1;
        }
    }

    private int Recover()
    {
        ConsoleIO.Info("Emergency recovery turns enforcement OFF, removes the firewall rules and sets a new passphrase.");
        var code = ConsoleIO.ReadSecret("Recovery code: ");
        var next = ConsoleIO.ReadSecret("New passphrase: ");
        if (next != ConsoleIO.ReadSecret("Repeat new passphrase: "))
        {
            ConsoleIO.Error("The passphrases do not match.");
            return 1;
        }

        try
        {
            var result = _guardian.Recover(code, next);
            if (ReportAuthOutcome(result.Auth, "Recovery accepted.") != 0)
            {
                return 2;
            }

            Apply("Firewall rules removed.");
            ConsoleIO.Info(string.Empty);
            ConsoleIO.Info("NEW RECOVERY CODE (shown only once):");
            ConsoleIO.Info("    " + result.NewRecoveryCode);
            ConsoleIO.Info("Enforcement is off. Turn it back on with 'csg policy enable' when you are ready.");
            return 0;
        }
        catch (ArgumentException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 1;
        }
    }

    private int Teardown()
    {
        var session = RequireSession();
        if (session is null)
        {
            return 2;
        }

        _policy.SetEnforcement(session, false);
        var exit = Apply("Enforcement turned off.");
        ConsoleIO.Info("All firewall rules created by this product are removed. You can now uninstall the service.");
        return exit;
    }

    private int WithSession(Action<GuardianSession> change, string successMessage)
    {
        var session = RequireSession();
        if (session is null)
        {
            return 2;
        }

        try
        {
            change(session);
        }
        catch (InvalidOperationException ex)
        {
            ConsoleIO.Error(ex.Message);
            return 1;
        }

        return Apply(successMessage);
    }

    private IReadOnlyList<Finding> ProfileFindings()
    {
        try
        {
            var requested = _policy.GetPolicy().TargetProfiles;
            return ProfileSafetyChecker.Assess(requested, _accounts.GetProfiles(requested));
        }
        catch (Exception ex)
        {
            ConsoleIO.Info("(Could not check the targeted Windows accounts: " + ex.Message + ")");
            return Array.Empty<Finding>();
        }
    }

    private void PrintProfileWarnings()
    {
        var findings = ProfileFindings();
        if (findings.Count > 0)
        {
            ConsoleIO.Info(string.Empty);
            FindingPrinter.Print(findings);
        }
    }

    private GuardianSession? RequireSession()
    {
        if (!_guardian.IsInitialized)
        {
            ConsoleIO.Error("The guardian is not set up. Run 'csg setup' first.");
            return null;
        }

        var result = _guardian.Authenticate(ConsoleIO.ReadSecret("Guardian passphrase: "));
        return ReportAuthOutcome(result, null) == 0 ? result.Session : null;
    }

    private static int ReportAuthOutcome(AuthResult result, string? successMessage)
    {
        switch (result.Status)
        {
            case AuthStatus.Success:
                if (successMessage is not null)
                {
                    ConsoleIO.Info(successMessage);
                }

                return 0;
            case AuthStatus.LockedOut:
                ConsoleIO.Error($"Too many failed attempts. Locked until {result.LockedUntilUtc!.Value.ToLocalTime():t}.");
                return 2;
            case AuthStatus.NotInitialized:
                ConsoleIO.Error("The guardian is not set up. Run 'csg setup' first.");
                return 2;
            default:
                ConsoleIO.Error($"Incorrect. {result.RemainingAttempts} attempt(s) left before a 15-minute lockout.");
                return 2;
        }
    }

    private static string ServiceStatus()
    {
        try
        {
            using var controller = new ServiceController(GuardPaths.ServiceName);
            return controller.Status.ToString();
        }
        catch (InvalidOperationException)
        {
            return "not installed";
        }
    }

    private string SafeRuleCount()
    {
        try
        {
            return _firewall.ListManagedRules().Count.ToString();
        }
        catch (Exception ex)
        {
            return "unavailable (" + ex.Message + ")";
        }
    }

    private static int Unknown(string command)
    {
        ConsoleIO.Error($"Unknown command '{command}'.");
        PrintHelp();
        return 1;
    }

    private static void PrintHelp()
    {
        ConsoleIO.Info(
            """
            csg - Child Safety Guard guardian tool (run from an elevated prompt)

              setup                  first-time setup: passphrase, recovery code, network baseline
              status                 show configuration and service state
              transparency           print what this software does and does not do
              check                  compare network with the baseline and look for known VPN/DPI tools (read-only)
              apply                  re-apply the policy to Windows Firewall now
              profiles               list Windows user profiles
              baseline capture|show  re-record or display the network baseline
              policy ...             list / enable / disable / add / remove / toggle / target-profiles / watch
              passphrase             change the guardian passphrase
              recover                emergency recovery with the recovery code
              teardown               turn enforcement off and remove all firewall rules (before uninstalling)
            """);
    }
}

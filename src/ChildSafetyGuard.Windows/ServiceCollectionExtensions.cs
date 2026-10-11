using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Enforcement;
using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Notices;
using ChildSafetyGuard.Core.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Windows;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the Windows implementations and the Core services. Requires logging to be registered by the host.</summary>
    public static IServiceCollection AddChildSafetyGuard(this IServiceCollection services, string dataDirectory)
    {
        services.AddSingleton(TimeProvider.System);

        services.AddSingleton<IStateStore>(sp => new DpapiStateStore(dataDirectory, sp.GetRequiredService<ILogger<DpapiStateStore>>()));
        services.AddSingleton<IFileSystemReader, WindowsFileSystemReader>();
        services.AddSingleton<IApplicationPathResolver, WindowsApplicationPathResolver>();
        services.AddSingleton<IFirewallGateway, WindowsFirewallGateway>();
        services.AddSingleton<INetworkInspector, WindowsNetworkInspector>();
        services.AddSingleton<IRuntimeInventory, WindowsRuntimeInventory>();
        services.AddSingleton<IAccountInspector, WindowsAccountInspector>();
        services.AddSingleton<IProcessLocator, WindowsProcessLocator>();
        services.AddSingleton<IBlockNoticeDisplay, WtsBlockNoticeDisplay>();
        services.AddSingleton<IFindingSink, LoggerFindingSink>();

        services.AddSingleton(new ProtectedLocations(new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            AppContext.BaseDirectory,
            dataDirectory,
        }));
        services.AddSingleton<PolicyValidator>();

        services.AddSingleton(sp => new GuardianManager(sp.GetRequiredService<IStateStore>(), sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<PolicyManager>();
        services.AddSingleton<BlockNoticeService>();
        services.AddSingleton(sp => new EnforcementEngine(
            sp.GetRequiredService<IStateStore>(),
            sp.GetRequiredService<IApplicationPathResolver>(),
            sp.GetRequiredService<IFirewallGateway>(),
            sp.GetRequiredService<INetworkInspector>(),
            sp.GetRequiredService<IRuntimeInventory>(),
            sp.GetRequiredService<IFindingSink>(),
            sp.GetRequiredService<PolicyValidator>(),
            sp.GetRequiredService<ILogger<EnforcementEngine>>(),
            accounts: sp.GetRequiredService<IAccountInspector>()));

        return services;
    }
}

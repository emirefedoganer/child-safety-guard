using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Policy;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Core.Notices;

/// <summary>
/// Shows the guardian-written notice when a blocked application is opened, so the device user learns <i>why</i> it will not
/// connect instead of staring at a spinner. Looks only at processes whose name matches a blocked executable, and only
/// shows the notice if the process really is one of the blocked files (a same-named program elsewhere is ignored).
/// </summary>
public sealed class BlockNoticeService
{
    /// <summary>A notice is shown at most once per application and Windows session within this time.</summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(2);

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    private readonly IStateStore _store;
    private readonly IApplicationPathResolver _resolver;
    private readonly IProcessLocator _processes;
    private readonly IBlockNoticeDisplay _display;
    private readonly PolicyValidator _validator;
    private readonly TimeProvider _time;
    private readonly ILogger<BlockNoticeService> _logger;

    private readonly Dictionary<string, DateTimeOffset> _lastShown = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _applicationByPath = new(StringComparer.OrdinalIgnoreCase);
    private string[] _processNames = Array.Empty<string>();
    private BlockNotice _notice = BlockNotice.Default;
    private DateTimeOffset _refreshAt = DateTimeOffset.MinValue;

    public BlockNoticeService(
        IStateStore store,
        IApplicationPathResolver resolver,
        IProcessLocator processes,
        IBlockNoticeDisplay display,
        PolicyValidator validator,
        TimeProvider time,
        ILogger<BlockNoticeService> logger)
    {
        _store = store;
        _resolver = resolver;
        _processes = processes;
        _display = display;
        _validator = validator;
        _time = time;
        _logger = logger;
    }

    /// <summary>One polling step. Returns how many notices were shown.</summary>
    public int Tick()
    {
        var now = _time.GetUtcNow();
        if (now >= _refreshAt)
        {
            Refresh(now);
        }

        if (_processNames.Length == 0)
        {
            return 0;
        }

        var shown = 0;
        foreach (var process in _processes.FindProcesses(_processNames))
        {
            if (process.SessionId <= 0 || process.ImagePath is null || !_applicationByPath.TryGetValue(process.ImagePath, out var applicationId))
            {
                continue; // session 0 is the services session: nobody to show anything to
            }

            var key = applicationId + ":" + process.SessionId;
            if (_lastShown.TryGetValue(key, out var last) && now - last < Cooldown)
            {
                continue;
            }

            _lastShown[key] = now;
            try
            {
                _display.Show(process.SessionId, _notice);
                shown++;
                _logger.LogInformation("Block notice shown for {ApplicationId} in session {SessionId}.", applicationId, process.SessionId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not show the block notice for {ApplicationId}.", applicationId);
            }
        }

        return shown;
    }

    private void Refresh(DateTimeOffset now)
    {
        _refreshAt = now + RefreshInterval;
        _applicationByPath.Clear();
        _processNames = Array.Empty<string>();

        AppState? state;
        try
        {
            state = _store.Load();
        }
        catch (StateStoreException)
        {
            return; // the enforcement engine already reports unreadable state
        }

        if (state?.Guardian is null || !state.Policy.EnforcementEnabled || _validator.Validate(state.Policy).Count > 0)
        {
            return;
        }

        _notice = state.Policy.Notice;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var application in _resolver.Resolve(state.Policy))
        {
            foreach (var path in application.Paths.Where(p => !_validator.IsProtectedPath(p)))
            {
                _applicationByPath[path] = application.Application.Id;
                names.Add(FileStem(path));
            }
        }

        _processNames = names.ToArray();
    }

    private static string FileStem(string path)
    {
        var name = path[(path.LastIndexOf('\\') + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[..dot] : name;
    }
}

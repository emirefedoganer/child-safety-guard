using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Core.Enforcement;

/// <summary>Writes findings to the configured logger (the Windows Event Log when hosted as the service).</summary>
public sealed class LoggerFindingSink : IFindingSink
{
    private readonly ILogger<LoggerFindingSink> _logger;

    public LoggerFindingSink(ILogger<LoggerFindingSink> logger)
    {
        _logger = logger;
    }

    public void Report(Finding finding)
    {
        var warning = finding.Severity == FindingSeverity.Warning;
        _logger.Log(
            warning ? LogLevel.Warning : LogLevel.Information,
            warning ? EventIds.FindingWarning : EventIds.Finding,
            "Finding {Code} ({Subject}): {Title}. {Explanation} Evidence: {Evidence}",
            finding.Code,
            finding.Subject,
            finding.Title,
            finding.Explanation,
            string.Join("; ", finding.Evidence));
    }
}

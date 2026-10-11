using System.Text.Json.Serialization;

namespace ChildSafetyGuard.Core.Models;

public enum FindingSeverity
{
    /// <summary>Worth knowing, usually benign.</summary>
    Info = 0,

    /// <summary>A change the guardian may want to look at.</summary>
    Notice = 1,

    /// <summary>A change that commonly undermines the configured restrictions.</summary>
    Warning = 2,
}

/// <summary>
/// An explainable observation. A finding says what was seen, why it might matter, and what it does
/// NOT prove. The product never punishes or acts automatically on a finding.
/// </summary>
public sealed record Finding(
    string Code,
    FindingSeverity Severity,
    string Title,
    string Explanation,
    string Subject,
    IReadOnlyList<string> Evidence)
{
    /// <summary>Stable identity used to avoid reporting the same observation every cycle.</summary>
    [JsonIgnore]
    public string Key => string.Join('|', Code, Subject, string.Join(';', Evidence.OrderBy(e => e, StringComparer.Ordinal)));
}

namespace ChildSafetyGuard.Core.Models;

/// <summary>Everything the product persists. Stored encrypted, locally, readable by Administrators/SYSTEM only.</summary>
public sealed record AppState
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;
    public GuardianRecord? Guardian { get; init; }
    public PolicyDocument Policy { get; init; } = PolicyDocument.CreateDefault();
    public NetworkSnapshot? Baseline { get; init; }
}

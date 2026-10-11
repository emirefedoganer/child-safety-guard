namespace ChildSafetyGuard.Core.Accounts;

/// <summary>A Windows user profile and whether its account is in the local Administrators group (null = could not be determined).</summary>
public sealed record ProfileAccount(string Name, bool? IsAdministrator);

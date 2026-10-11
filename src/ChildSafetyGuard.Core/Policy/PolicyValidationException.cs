namespace ChildSafetyGuard.Core.Policy;

public sealed class PolicyValidationException : Exception
{
    public PolicyValidationException(IReadOnlyList<string> errors)
        : base("Policy is invalid: " + string.Join(" ", errors))
    {
        Errors = errors;
    }

    public IReadOnlyList<string> Errors { get; }
}

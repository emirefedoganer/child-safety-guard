namespace ChildSafetyGuard.Core;

public sealed class StateStoreException : Exception
{
    public StateStoreException(string message) : base(message) { }
    public StateStoreException(string message, Exception inner) : base(message, inner) { }
}

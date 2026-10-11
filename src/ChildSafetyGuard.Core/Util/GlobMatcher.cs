namespace ChildSafetyGuard.Core.Util;

public static class GlobMatcher
{
    /// <summary>Case-insensitive match supporting '*' (any run) and '?' (any single character).</summary>
    public static bool IsMatch(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (p < pattern.Length &&
                     (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t])))
            {
                p++;
                t++;
            }
            else if (star != -1)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}

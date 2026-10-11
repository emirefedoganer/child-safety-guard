using System.Text;

namespace ChildSafetyGuard.Cli;

internal static class ConsoleIO
{
    public static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        var buffer = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                {
                    buffer.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                buffer.Append(key.KeyChar);
            }
        }

        Console.WriteLine();
        return buffer.ToString();
    }

    public static bool Confirm(string question)
    {
        Console.Write(question + " [y/N] ");
        var answer = Console.ReadLine();
        return answer is not null && answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
    }

    public static void Error(string message)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine(message);
        Console.ForegroundColor = previous;
    }

    public static void Info(string message) => Console.WriteLine(message);
}

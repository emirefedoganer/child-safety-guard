using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Notices;
using Microsoft.Extensions.Logging.Abstractions;

namespace ChildSafetyGuard.Core.Tests;

internal sealed class FakeProcessLocator : IProcessLocator
{
    public List<RunningProcess> Running { get; } = new();
    public List<string> RequestedNames { get; } = new();

    public IReadOnlyList<RunningProcess> FindProcesses(IReadOnlyCollection<string> processNames)
    {
        RequestedNames.AddRange(processNames);
        return Running.Where(p => processNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).ToList();
    }
}

internal sealed class FakeDisplay : IBlockNoticeDisplay
{
    public List<(int SessionId, BlockNotice Notice)> Shown { get; } = new();
    public bool Throw { get; set; }

    public void Show(int sessionId, BlockNotice notice)
    {
        if (Throw)
        {
            throw new InvalidOperationException("no such session");
        }

        Shown.Add((sessionId, notice));
    }
}

public class BlockNoticeServiceTests
{
    private const string DiscordExe = @"C:\Users\kid\AppData\Local\Discord\app-1.0.9002\Discord.exe";
    private const string DiscordUpdater = @"C:\Users\kid\AppData\Local\Discord\Update.exe";

    private sealed class Rig
    {
        public InMemoryStateStore Store { get; }
        public ManualTimeProvider Time { get; }
        public FakeProcessLocator Processes { get; } = new();
        public FakeDisplay Display { get; } = new();
        public BlockNoticeService Service { get; }

        public Rig(bool enforcementEnabled = true)
        {
            var (store, time, _, _) = TestData.Guarded();
            Store = store;
            Time = time;
            Store.Current = Store.Current! with { Policy = Store.Current.Policy with { EnforcementEnabled = enforcementEnabled } };
            var resolver = new FakeResolver();
            resolver.PathsByApplicationId["discord"] = new[] { DiscordExe, DiscordUpdater };
            Service = new BlockNoticeService(
                Store, resolver, Processes, Display, TestData.Validator(), Time, NullLogger<BlockNoticeService>.Instance);
        }

        public void Running(string name, string? path, int session) =>
            Processes.Running.Add(new RunningProcess(name, path, session));
    }

    [Fact]
    public void DefaultNotice_IsTheGuardiansQuestion()
    {
        Assert.Equal("GOTCHA!", BlockNotice.Default.Title);
        Assert.Equal("Bu uygulamayı kullanmak için annenden izin aldın mı?", BlockNotice.Default.Message);
    }

    [Fact]
    public void OpeningABlockedApplication_ShowsTheNotice_InThatSessionOnly()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 3);

        Assert.Equal(1, rig.Service.Tick());

        var (session, notice) = Assert.Single(rig.Display.Shown);
        Assert.Equal(3, session);
        Assert.Equal(BlockNotice.Default, notice);
    }

    [Fact]
    public void ASameNamedProgramElsewhere_IsIgnored()
    {
        var rig = new Rig();
        rig.Running("Update", @"C:\Users\kid\AppData\Local\Slack\Update.exe", session: 3);
        rig.Running("Discord", @"D:\Copies\Discord.exe", session: 3);
        rig.Running("Update", null, session: 3); // Windows would not reveal the path

        Assert.Equal(0, rig.Service.Tick());
        Assert.Empty(rig.Display.Shown);
    }

    [Fact]
    public void WhileEnforcementIsOff_NothingIsShown_AndNothingIsLookedAt()
    {
        var rig = new Rig(enforcementEnabled: false);
        rig.Running("Discord", DiscordExe, session: 3);

        Assert.Equal(0, rig.Service.Tick());
        Assert.Empty(rig.Processes.RequestedNames);
    }

    [Fact]
    public void OnlyTheNamesOfBlockedProgramsAreLookedUp()
    {
        var rig = new Rig();

        rig.Service.Tick();

        Assert.Equal(new[] { "Discord", "Update" }, rig.Processes.RequestedNames.Distinct().OrderBy(n => n));
    }

    [Fact]
    public void TheNotice_IsNotRepeatedWithinTheCooldown_ButIsShownAgainAfterIt()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 3);

        rig.Service.Tick();
        rig.Time.Advance(TimeSpan.FromSeconds(3));
        rig.Service.Tick();
        Assert.Single(rig.Display.Shown);

        rig.Time.Advance(BlockNoticeService.Cooldown);
        rig.Service.Tick();
        Assert.Equal(2, rig.Display.Shown.Count);
    }

    [Fact]
    public void EachWindowsSession_GetsItsOwnNotice()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 3);
        rig.Running("Discord", DiscordExe, session: 5);

        Assert.Equal(2, rig.Service.Tick());
        Assert.Equal(new[] { 3, 5 }, rig.Display.Shown.Select(s => s.SessionId).OrderBy(s => s));
    }

    [Fact]
    public void SessionZero_TheServicesSession_IsSkipped()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 0);

        Assert.Equal(0, rig.Service.Tick());
    }

    [Fact]
    public void ACustomNotice_IsUsed_AfterTheNextRefresh()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 3);
        rig.Store.Current = rig.Store.Current! with
        {
            Policy = rig.Store.Current.Policy with { Notice = new BlockNotice("Hei!", "Akşam konuşalım.") },
        };

        rig.Service.Tick();

        Assert.Equal("Hei!", Assert.Single(rig.Display.Shown).Notice.Title);
    }

    [Fact]
    public void ADisplayFailure_IsContained()
    {
        var rig = new Rig();
        rig.Display.Throw = true;
        rig.Running("Discord", DiscordExe, session: 3);

        Assert.Equal(0, rig.Service.Tick()); // no exception
    }

    [Fact]
    public void UnreadableOrMissingConfiguration_ShowsNothing()
    {
        var rig = new Rig();
        rig.Running("Discord", DiscordExe, session: 3);
        rig.Store.Unreadable = true;

        Assert.Equal(0, rig.Service.Tick());
    }
}

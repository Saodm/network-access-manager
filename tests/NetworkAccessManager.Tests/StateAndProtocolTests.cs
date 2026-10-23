using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;

namespace NetworkAccessManager.Tests;

public sealed class StateRepositoryTests
{
    [Fact]
    public void Missing_store_returns_empty_state_without_creating_file()
    {
        using var workspace = new TempWorkspace();
        var store = workspace.CreateStore();
        var read = store.ReadState();
        Assert.False(read.Existed);
        Assert.Empty(read.State.Rules);
        Assert.Empty(read.State.Tasks);
        Assert.Empty(read.State.Events);
        Assert.False(File.Exists(workspace.Paths.StateFilePath));
    }

    [Fact]
    public void Mutations_persist_and_increment_revision()
    {
        using var workspace = new TempWorkspace();
        var store = workspace.CreateStore();
        store.Mutate(state => state.Events.Add(new OperationHistoryEvent { Message = "first" }));
        store.Mutate(state => state.Events.Add(new OperationHistoryEvent { Message = "second" }));
        var read = store.ReadState();
        Assert.True(read.Existed);
        Assert.Equal(2, read.State.Revision);
        Assert.Equal(2, read.State.Events.Count);
        Assert.Equal("first", read.State.Events[0].Message);
    }

    [Fact]
    public void Corrupt_primary_recovers_from_backup()
    {
        using var workspace = new TempWorkspace();
        var store = workspace.CreateStore();
        store.Mutate(state => state.Events.Add(new OperationHistoryEvent { Message = "first" }));
        store.Mutate(state => state.Events.Add(new OperationHistoryEvent { Message = "second" }));
        Assert.True(File.Exists(workspace.Paths.StateBackupPath));
        File.WriteAllText(workspace.Paths.StateFilePath, "{ broken json");

        var read = store.ReadState();
        Assert.True(read.UsedBackup);
        Assert.NotNull(read.Warning);
        Assert.Contains("first", read.State.Events.Select(e => e.Message));
    }

    [Fact]
    public void Concurrent_mutations_are_serialized_across_threads()
    {
        using var workspace = new TempWorkspace();
        var store = workspace.CreateStore();
        Parallel.For(0, 20, i =>
        {
            store.Mutate(state => state.Events.Add(new OperationHistoryEvent { Message = i.ToString() }));
        });
        var read = store.ReadState();
        Assert.Equal(20, read.State.Events.Count);
        Assert.Equal(20, read.State.Revision);
    }

    [Fact]
    public void Helper_codec_roundtrips_unicode_request()
    {
        var request = new ElevatedRequest
        {
            UserSid = "S-1-5-21-测试",
            Actions =
            {
                new ElevatedAction
                {
                    ActionId = Guid.NewGuid().ToString("N"),
                    Kind = ElevatedActionKind.BlockNetworkAddress,
                    TargetKind = RuleTargetKind.NetworkAddress,
                    Target = "2001:db8::/32",
                    Directions = BlockDirections.Both
                }
            }
        };
        var encoded = HelperRequestCodec.Encode(request);
        Assert.DoesNotContain("=", encoded);
        var decoded = HelperRequestCodec.Decode(encoded);
        Assert.Equal(request.RequestId, decoded.RequestId);
        Assert.Equal("2001:db8::/32", decoded.Actions[0].Target);
        Assert.Equal(BlockDirections.Both, decoded.Actions[0].Directions);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-base64")]
    [InlineData("%%%")]
    public void Helper_codec_rejects_malformed_input(string input)
    {
        Assert.ThrowsAny<Exception>(() => HelperRequestCodec.Decode(input));
    }

    [Fact]
    public void Settings_roundtrip_and_clamp()
    {
        using var workspace = new TempWorkspace();
        var store = new SettingsStore(workspace.Paths);
        var settings = new UiSettings { RefreshIntervalSeconds = 1 };
        Assert.True(store.TrySave(settings, out var error), error);
        var loaded = store.Load();
        Assert.Equal(3, loaded.Settings.RefreshIntervalSeconds);
    }
}

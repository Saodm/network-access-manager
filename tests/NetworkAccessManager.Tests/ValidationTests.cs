using NetworkAccessManager.Core.Firewall;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Tests;

public sealed class FirewallRemoteAddressComparerTests
{
    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.0/24", true)]
    [InlineData("203.0.113.0/255.255.255.0", "203.0.113.0/24", true)]
    [InlineData("203.0.113.7/255.255.255.255", "203.0.113.7", true)]
    [InlineData("203.0.113.0/255.0.255.0", "203.0.113.0/24", false)]
    [InlineData("203.0.113.0/25", "203.0.113.0/24", false)]
    [InlineData("198.51.100.0/24", "203.0.113.0/24", false)]
    [InlineData("Any", "203.0.113.0/24", false)]
    [InlineData("203.0.113.0-203.0.113.255", "203.0.113.0/24", false)]
    [InlineData("203.0.113.0/33", "203.0.113.0/24", false)]
    [InlineData("2001:db8::/32", "2001:db8::/32", true)]
    [InlineData("2001:db8:0:0:0:0:0:0/32", "2001:db8::/32", true)]
    [InlineData("2001:db9::/32", "2001:db8::/32", false)]
    [InlineData("2001:db8::/ffff:ffff::", "2001:db8::/32", true)]
    public void Compares_normalized_windows_address_forms(string actual, string expected, bool shouldMatch)
    {
        Assert.Equal(shouldMatch, FirewallRemoteAddressComparer.Matches(actual, expected));
    }
}

public sealed class ProgramTargetValidatorTests
{
    [Fact]
    public void Existing_executable_is_accepted()
    {
        using var workspace = new TempWorkspace();
        var result = ProgramTargetValidator.Validate(workspace.DummyExePath);
        Assert.True(result.IsValid, result.Error);
        Assert.Equal(Path.GetFullPath(workspace.DummyExePath), result.NormalizedPath);
    }

    [Fact]
    public void Own_executable_is_rejected()
    {
        using var workspace = new TempWorkspace();
        var result = ProgramTargetValidator.Validate(workspace.DummyExePath, workspace.DummyExePath);
        Assert.False(result.IsValid);
        Assert.Contains("本工具自身", result.Error);
    }

    [Fact]
    public void Missing_file_is_rejected()
    {
        using var workspace = new TempWorkspace();
        var result = ProgramTargetValidator.Validate(Path.Combine(workspace.Root, "missing.exe"));
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Relative_path_is_rejected()
    {
        var result = ProgramTargetValidator.Validate(@"System32\where.exe");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Non_executable_file_is_rejected()
    {
        using var workspace = new TempWorkspace();
        var file = Path.Combine(workspace.Root, "not-an-exe.txt");
        File.WriteAllText(file, "test");
        var result = ProgramTargetValidator.Validate(file);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Paths_compare_case_insensitively()
    {
        Assert.True(ProgramTargetValidator.PathsEqual(@"C:\Windows\System32\where.exe", @"c:\windows\system32\WHERE.EXE"));
    }
}

public sealed class FirewallMetadataTests
{
    [Fact]
    public void Metadata_roundtrips_without_vertical_bar()
    {
        var created = DateTimeOffset.UtcNow;
        var source = FirewallRuleMetadata.Create(
            Guid.NewGuid().ToString("N"),
            FirewallDirection.Outbound,
            RuleTargetKind.Program,
            @"C:\程序 文件\示例 & 应用.exe",
            "S-1-5-21-1",
            created);
        var description = source.ToDescription();

        Assert.DoesNotContain("|", description);
        Assert.StartsWith(FirewallRuleMetadata.Prefix, description);
        Assert.True(FirewallRuleMetadata.TryParse(description, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(source.RuleId, parsed!.RuleId);
        Assert.Equal(source.Direction, parsed.Direction);
        Assert.Equal(source.TargetKind, parsed.TargetKind);
        Assert.Equal(source.Target, parsed.Target);
        Assert.Equal("S-1-5-21-1", parsed.OwnerSid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("anything")]
    [InlineData("NAMv1;id=bad;dir=Outbound;kind=Program;target=dGVzdA")]
    [InlineData("NAMv1;id=0123456789abcdef0123456789abcdef;dir=Sideways;kind=Program;target=dGVzdA")]
    [InlineData("NAMv1;id=0123456789abcdef0123456789abcdef;dir=Outbound;kind=Program")]
    public void Invalid_metadata_is_rejected(string? description)
    {
        Assert.False(FirewallRuleMetadata.TryParse(description, out _));
    }

    [Fact]
    public void Rule_name_is_deterministic_and_directional()
    {
        var id = Guid.NewGuid().ToString("N");
        var outbound = FirewallRuleMetadata.BuildRuleName(id, FirewallDirection.Outbound);
        var inbound = FirewallRuleMetadata.BuildRuleName(id, FirewallDirection.Inbound);
        Assert.StartsWith(FirewallConstants.RuleNamePrefix, outbound);
        Assert.EndsWith("_OUT", outbound);
        Assert.EndsWith("_IN", inbound);
        Assert.NotEqual(outbound, inbound);
    }
}

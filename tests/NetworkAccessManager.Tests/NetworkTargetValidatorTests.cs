using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Tests;

public sealed class NetworkTargetValidatorTests
{
    [Theory]
    [InlineData("192.0.2.10", "192.0.2.10", 32, false)]
    [InlineData("203.0.113.0/24", "203.0.113.0/24", 24, true)]
    [InlineData("203.0.113.77/24", "203.0.113.0/24", 24, true)]
    [InlineData("2001:db8::1", "2001:db8::1", 128, false)]
    [InlineData("2001:db8::/32", "2001:db8::/32", 32, true)]
    [InlineData("0.0.0.0/0", "0.0.0.0/0", 0, true)]
    [InlineData("::/0", "::/0", 0, true)]
    public void Valid_targets_are_normalized(string input, string expected, int prefix, bool isCidr)
    {
        var result = NetworkTargetValidator.Validate(input);
        Assert.True(result.IsValid, result.Error);
        Assert.Equal(expected, result.NormalizedTarget);
        Assert.Equal(prefix, result.PrefixLength);
        Assert.Equal(isCidr, result.IsCidr);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    [InlineData("example.com")]
    [InlineData("1.2.3")]
    [InlineData("999.1.1.1")]
    [InlineData("01.2.3.4")]
    [InlineData("1.2.3.4/33")]
    [InlineData("::1/129")]
    [InlineData("1.2.3.4:80")]
    [InlineData("http://1.2.3.4/")]
    [InlineData("1.2.3.4,5.6.7.8")]
    [InlineData("fe80::1%12")]
    [InlineData("::ffff:192.0.2.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("1.2.3.4/-1")]
    [InlineData("1.2.3.4/24/8")]
    [InlineData("1.2.3.4 / 24")]
    [InlineData("1.2.3.4.")]
    public void Invalid_targets_are_rejected(string input)
    {
        var result = NetworkTargetValidator.Validate(input);
        Assert.False(result.IsValid);
        Assert.NotNull(result.Error);
        Assert.Null(result.NormalizedTarget);
    }

    [Fact]
    public void Host_bits_are_normalized_with_warning()
    {
        var result = NetworkTargetValidator.Validate("198.51.100.199/24");
        Assert.True(result.IsValid);
        Assert.True(result.WasNormalized);
        Assert.Equal("198.51.100.0/24", result.NormalizedTarget);
        Assert.Contains("归一化", result.Warning);
    }

    [Fact]
    public void Broad_scope_is_flagged()
    {
        var result = NetworkTargetValidator.Validate("0.0.0.0/0");
        Assert.True(result.IsValid);
        Assert.True(result.IsBroadScope);
        Assert.Contains("全部", result.Warning);
    }

    [Fact]
    public void Loopback_and_multicast_are_flagged()
    {
        Assert.True(NetworkTargetValidator.Validate("127.0.0.0/8").IsLoopback);
        Assert.True(NetworkTargetValidator.Validate("239.1.2.3").IsMulticast);
        Assert.True(NetworkTargetValidator.Validate("ff02::1").IsMulticast);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("60")]
    [InlineData("10080")]
    public void Valid_durations_are_accepted(string input)
    {
        Assert.True(DurationValidator.TryParseMinutes(input, out var minutes, out _));
        Assert.InRange(minutes, 1, 10080);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("10081")]
    [InlineData("abc")]
    [InlineData("+5")]
    public void Invalid_durations_are_rejected(string input)
    {
        Assert.False(DurationValidator.TryParseMinutes(input, out _, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.99", true)]
    [InlineData("203.0.113.0/24", "203.0.114.1", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    public void Address_matcher_honors_cidr(string target, string address, bool expected)
    {
        Assert.Equal(expected, NetworkAddressMatcher.Matches(target, address));
    }
}

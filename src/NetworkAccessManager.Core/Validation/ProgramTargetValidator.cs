using System.Text.RegularExpressions;
using NetworkAccessManager.Core.Models;

namespace NetworkAccessManager.Core.Validation;

public sealed class ProgramTargetValidationResult
{
    public bool IsValid { get; init; }
    public string? NormalizedPath { get; init; }
    public string? Error { get; init; }
}

public static partial class ProgramTargetValidator
{
    private static readonly char[] InvalidPathChars = Path.GetInvalidPathChars();
    private static readonly char[] InvalidFileNameCharacters = Path.GetInvalidFileNameChars();

    public static ProgramTargetValidationResult Validate(string? path, string? ownExecutablePath = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new ProgramTargetValidationResult { IsValid = false, Error = "该进程没有可读取的可执行文件路径，不能按程序建立规则。" };

        var raw = path.Trim();
        if (raw.IndexOfAny(InvalidPathChars) >= 0 || raw.IndexOfAny(new[] { '"', '<', '>', '|', '*', '?' }) >= 0)
            return new ProgramTargetValidationResult { IsValid = false, Error = "可执行文件路径包含无效字符。" };
        try
        {
            var fileName = Path.GetFileName(raw);
            if (string.IsNullOrWhiteSpace(fileName) || fileName.IndexOfAny(InvalidFileNameCharacters) >= 0)
                return new ProgramTargetValidationResult { IsValid = false, Error = "可执行文件路径中的文件名包含无效字符。" };
        }
        catch
        {
            return new ProgramTargetValidationResult { IsValid = false, Error = "可执行文件路径格式无效。" };
        }
        if (raw.StartsWith(@"\\?\", StringComparison.Ordinal) || raw.StartsWith(@"\\.\", StringComparison.Ordinal))
            return new ProgramTargetValidationResult { IsValid = false, Error = "不支持设备路径或扩展长度前缀路径。" };
        if (!Path.IsPathFullyQualified(raw))
            return new ProgramTargetValidationResult { IsValid = false, Error = "必须使用可执行文件的完整绝对路径。" };

        string full;
        try
        {
            full = Path.GetFullPath(raw);
        }
        catch (Exception ex)
        {
            return new ProgramTargetValidationResult { IsValid = false, Error = $"路径无效：{ex.Message}" };
        }

        var root = Path.GetPathRoot(full);
        if (string.IsNullOrWhiteSpace(root) || root.StartsWith(@"\\", StringComparison.Ordinal))
            return new ProgramTargetValidationResult { IsValid = false, Error = "只支持本地磁盘上的程序，不支持网络或设备路径。" };
        if (!File.Exists(full))
            return new ProgramTargetValidationResult { IsValid = false, Error = "可执行文件已不存在或路径不可访问。" };
        if (!string.Equals(Path.GetExtension(full), ".exe", StringComparison.OrdinalIgnoreCase))
            return new ProgramTargetValidationResult { IsValid = false, Error = "程序防火墙规则的目标必须是 .exe 可执行文件。" };

        try
        {
            var attributes = File.GetAttributes(full);
            if ((attributes & FileAttributes.Directory) != 0)
                return new ProgramTargetValidationResult { IsValid = false, Error = "目标路径是目录，不是可执行文件。" };
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                return new ProgramTargetValidationResult { IsValid = false, Error = "目标路径是符号链接或重解析点，为免规则作用对象不明确，暂不支持。" };
        }
        catch (Exception ex)
        {
            return new ProgramTargetValidationResult { IsValid = false, Error = $"无法读取目标文件属性：{ex.Message}" };
        }

        if (!string.IsNullOrWhiteSpace(ownExecutablePath))
        {
            try
            {
                var ownFull = Path.GetFullPath(ownExecutablePath.Trim());
                if (string.Equals(full, ownFull, StringComparison.OrdinalIgnoreCase))
                    return new ProgramTargetValidationResult { IsValid = false, Error = "不能阻断本工具自身，否则将无法执行恢复和取消操作。" };
            }
            catch
            {
                // If the own path cannot be normalized we do not block based on this check.
            }
        }

        return new ProgramTargetValidationResult
        {
            IsValid = true,
            NormalizedPath = full
        };
    }

    public static string NormalizeForComparison(string path)
    {
        try
        {
            return Path.GetFullPath(path.Trim()).TrimEnd(Path.DirectorySeparatorChar);
        }
        catch
        {
            return path.Trim().TrimEnd(Path.DirectorySeparatorChar);
        }
    }

    public static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        return string.Equals(NormalizeForComparison(left), NormalizeForComparison(right), StringComparison.OrdinalIgnoreCase);
    }
}

public static class DurationValidator
{
    public const int MinMinutes = 1;
    public const int MaxMinutes = 7 * 24 * 60;

    public static bool TryParseMinutes(string? text, out int minutes, out string? error)
    {
        minutes = 0;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "请输入正整数分钟数。";
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.Any(c => c is < '0' or > '9'))
        {
            error = "分钟数只能是正整数，不能包含符号、空格或小数。";
            return false;
        }

        if (!int.TryParse(trimmed, out minutes) || minutes < MinMinutes || minutes > MaxMinutes)
        {
            error = $"分钟数必须在 {MinMinutes} 到 {MaxMinutes} 之间（最长 7 天）。";
            return false;
        }

        return true;
    }

    public static string DescribeDuration(int minutes)
    {
        if (minutes < 60) return $"{minutes} 分钟";
        var hours = minutes / 60;
        var rest = minutes % 60;
        if (rest == 0) return hours < 24 ? $"{hours} 小时" : $"{hours / 24} 天 {hours % 24} 小时";
        return $"{hours} 小时 {rest} 分钟";
    }
}

public static class DirectionText
{
    public static IReadOnlyList<FirewallDirection> ToFirewallDirections(this BlockDirections directions)
    {
        var result = new List<FirewallDirection>(2);
        if (directions.HasFlag(BlockDirections.Outbound)) result.Add(FirewallDirection.Outbound);
        if (directions.HasFlag(BlockDirections.Inbound)) result.Add(FirewallDirection.Inbound);
        return result;
    }

    public static string ToChinese(this BlockDirections directions) => directions switch
    {
        BlockDirections.Outbound => "仅出站",
        BlockDirections.Inbound => "仅入站",
        BlockDirections.Both => "入站和出站",
        _ => "未指定方向"
    };

    public static string ToShortChinese(this FirewallDirection direction) =>
        direction == FirewallDirection.Outbound ? "出站" : "入站";

    public static string DescribeRules(IEnumerable<FirewallDirection> directions)
    {
        var list = directions.Distinct().OrderBy(d => d).Select(d => d.ToShortChinese()).ToList();
        return list.Count == 0 ? "无" : string.Join("、", list);
    }
}

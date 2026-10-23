using System.Text;

namespace NetworkAccessManager.Core.Diagnostics;

public interface IAppLog
{
    void Info(string area, string message);
    void Warn(string area, string message);
    void Error(string area, string message, Exception? exception = null);
}

public sealed class NullAppLog : IAppLog
{
    public static readonly NullAppLog Instance = new();
    public void Info(string area, string message) { }
    public void Warn(string area, string message) { }
    public void Error(string area, string message, Exception? exception = null) { }
}

/// <summary>
/// Small thread-safe rolling text log. It intentionally writes one file per
/// process/day so the non-elevated UI and an elevated helper never share a
/// writable handle. Retention cleanup runs quietly at initialization.
/// </summary>
public sealed class FileAppLog : IAppLog
{
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly string _filePath;
    private readonly int _retentionDays;

    public FileAppLog(string directory, string processRole, int retentionDays = 14)
    {
        _directory = directory;
        _retentionDays = retentionDays;
        Directory.CreateDirectory(directory);
        var safeRole = string.Concat(processRole.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
        _filePath = Path.Combine(directory, $"{DateTime.Now:yyyyMMdd}-{safeRole}-{Environment.ProcessId}.log");
        TryCleanup();
    }

    public string LogDirectory => _directory;
    public string CurrentFile => _filePath;

    public void Info(string area, string message) => Write("INFO", area, message, null);
    public void Warn(string area, string message) => Write("WARN", area, message, null);
    public void Error(string area, string message, Exception? exception = null) => Write("ERROR", area, message, exception);

    private void Write(string level, string area, string message, Exception? exception)
    {
        try
        {
            var builder = new StringBuilder(256);
            builder.Append(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz"))
                .Append(" [").Append(level).Append(']')
                .Append(" [").Append(area).Append("] ")
                .Append(message.ReplaceLineEndings(" "));
            if (exception is not null)
            {
                builder.AppendLine();
                builder.Append(exception);
            }
            var line = builder.ToString();
            lock (_gate)
            {
                File.AppendAllText(_filePath, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch
        {
            // Logging must never bring down the application.
        }
    }

    private void TryCleanup()
    {
        try
        {
            var threshold = DateTime.Now.AddDays(-Math.Max(1, _retentionDays));
            foreach (var file in Directory.EnumerateFiles(_directory, "*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < threshold)
                        File.Delete(file);
                }
                catch
                {
                    // Another process may be using its own file; ignore.
                }
            }
        }
        catch
        {
            // Non-critical housekeeping only.
        }
    }
}

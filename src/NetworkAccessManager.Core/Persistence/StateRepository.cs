using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkAccessManager.Core.Diagnostics;

namespace NetworkAccessManager.Core.Persistence;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true) }
    };

    public static readonly JsonSerializerOptions CompactOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true) }
    };
}

public sealed class AppPaths
{
    public const string AppDirectoryName = "NetworkAccessManager";
    public const string DataDirectoryName = "data";

    public AppPaths(string rootDirectory)
    {
        RootDirectory = Path.GetFullPath(rootDirectory);
    }

    public string RootDirectory { get; }
    public string StateFilePath => Path.Combine(RootDirectory, "state.json");
    public string StateBackupPath => Path.Combine(RootDirectory, "state.backup.json");
    public string StateLockPath => Path.Combine(RootDirectory, "state.lock");
    public string SettingsFilePath => Path.Combine(RootDirectory, "settings.json");
    public string LogsDirectory => Path.Combine(RootDirectory, "logs");
    public string ResultsDirectory => Path.Combine(RootDirectory, "results");
    public string TempDirectory => Path.Combine(RootDirectory, "temp");

    /// <summary>
    /// The application uses a per-installation data directory by default so a
    /// portable tool can run without asking for profile permissions during
    /// read-only browsing. Every elevated helper uses exactly the same base
    /// directory next to the executable, which keeps scheduled tasks and the
    /// desktop UI on one state store. NAM_DATA_DIR is a developer/testing
    /// override and must be an absolute local path.
    /// </summary>
    public static AppPaths CreateDefault()
    {
        var overridePath = Environment.GetEnvironmentVariable("NAM_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            var trimmed = overridePath.Trim();
            if (!Path.IsPathFullyQualified(trimmed))
                throw new InvalidOperationException("NAM_DATA_DIR 必须是绝对路径。");
            return new AppPaths(trimmed);
        }

        var baseDirectory = string.IsNullOrWhiteSpace(AppContext.BaseDirectory)
            ? AppDomain.CurrentDomain.BaseDirectory
            : AppContext.BaseDirectory;
        return new AppPaths(Path.Combine(baseDirectory, DataDirectoryName));
    }

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(LogsDirectory);
        Directory.CreateDirectory(ResultsDirectory);
        Directory.CreateDirectory(TempDirectory);
    }

    public string ResultFilePath(string requestId) =>
        Path.Combine(ResultsDirectory, $"response-{RequireSafeId(requestId)}.json");

    private static string RequireSafeId(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("标识符格式无效。", nameof(value));
        return value;
    }
}

public sealed class StateStoreException : Exception
{
    public StateStoreException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// JSON state store with atomic replacement, a cross-process writer lock, a
/// last-known-good backup and bounded history. The desktop UI is a reader of
/// rule/task state; elevated helper actions are the only writers of those
/// records. The UI may append a local failure event through the same lock.
/// </summary>
public sealed class StateRepository
{
    private readonly AppPaths _paths;
    private readonly object _inProcessGate = new();
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(20);
    private const int MaxEvents = 5000;
    private const int EventRetentionDays = 365;

    public StateRepository(AppPaths paths)
    {
        _paths = paths;
    }

    public AppPaths Paths => _paths;

    public StoreReadResult ReadState()
    {
        lock (_inProcessGate)
        {
            return ReadStateCore();
        }
    }

    public T Mutate<T>(Func<AppState, T> mutator)
    {
        ArgumentNullException.ThrowIfNull(mutator);
        lock (_inProcessGate)
        {
            _paths.EnsureDirectories();
            using var lockHandle = AcquireWriterLock();
            var read = ReadStateCore();
            var state = read.State;
            state.SchemaVersion = 1;
            var result = mutator(state);
            state.Revision++;
            state.UpdatedUtc = DateTimeOffset.UtcNow;
            TrimEvents(state);
            WriteStateAtomic(state);
            return result;
        }
    }

    public void Mutate(Action<AppState> mutator) =>
        Mutate(state =>
        {
            mutator(state);
            return 0;
        });

    public void AppendEvent(OperationHistoryEvent historyEvent)
    {
        Mutate(state => state.Events.Add(historyEvent));
    }

    public bool TryAppendEvent(OperationHistoryEvent historyEvent, out string? error)
    {
        try
        {
            AppendEvent(historyEvent);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private StoreReadResult ReadStateCore()
    {
        if (!File.Exists(_paths.StateFilePath) && !File.Exists(_paths.StateBackupPath))
            return new StoreReadResult { State = new AppState(), Existed = false };

        Exception? primaryError = null;
        if (File.Exists(_paths.StateFilePath))
        {
            try
            {
                var json = ReadAllTextWithRetry(_paths.StateFilePath);
                var state = DeserializeState(json);
                return new StoreReadResult { State = state, Existed = true };
            }
            catch (Exception ex)
            {
                primaryError = ex;
            }
        }

        if (File.Exists(_paths.StateBackupPath))
        {
            try
            {
                var json = ReadAllTextWithRetry(_paths.StateBackupPath);
                var state = DeserializeState(json);
                var reason = primaryError is null
                    ? "主状态文件不存在，已使用上次备份。"
                    : $"主状态文件无法读取（{primaryError.Message}），已使用上次备份。最近的少量更改可能未恢复。";
                return new StoreReadResult
                {
                    State = state,
                    Existed = true,
                    UsedBackup = true,
                    Warning = reason
                };
            }
            catch (Exception backupError)
            {
                throw new StateStoreException(
                    $"状态数据损坏，主文件和备份均无法读取。主文件错误：{primaryError?.Message ?? "不存在"}；备份错误：{backupError.Message}",
                    backupError);
            }
        }

        throw new StateStoreException(
            $"状态数据无法读取：{primaryError?.Message ?? "找不到主状态文件"}",
            primaryError);
    }

    private static AppState DeserializeState(string json)
    {
        var state = JsonSerializer.Deserialize<AppState>(json, JsonDefaults.Options)
                    ?? throw new InvalidDataException("反序列化结果为空。");
        if (state.SchemaVersion > 1)
            throw new InvalidDataException($"数据版本 {state.SchemaVersion} 高于本程序支持的版本 1。");
        state.Rules ??= new List<ManagedRuleRecord>();
        state.Tasks ??= new List<ScheduledTaskRecord>();
        state.Events ??= new List<OperationHistoryEvent>();
        return state;
    }

    private static string ReadAllTextWithRetry(string path)
    {
        Exception? last = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
            catch (IOException ex) when (attempt < 5)
            {
                last = ex;
                Thread.Sleep(30 + attempt * 30);
            }
            catch (UnauthorizedAccessException ex) when (attempt < 5)
            {
                last = ex;
                Thread.Sleep(30 + attempt * 30);
            }
        }

        throw last ?? new IOException("无法读取状态文件。");
    }

    private FileStream AcquireWriterLock()
    {
        var started = DateTime.UtcNow;
        Exception? last = null;
        while (DateTime.UtcNow - started < LockTimeout)
        {
            try
            {
                return new FileStream(_paths.StateLockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None);
            }
            catch (IOException ex)
            {
                last = ex;
                Thread.Sleep(80);
            }
            catch (UnauthorizedAccessException ex)
            {
                last = ex;
                Thread.Sleep(80);
            }
        }

        throw new StateStoreException("无法取得状态数据写锁（可能有另一个高权限操作正在执行）。请稍后重试。", last);
    }

    private void WriteStateAtomic(AppState state)
    {
        var tempPath = Path.Combine(_paths.RootDirectory, $"state.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            var json = JsonSerializer.Serialize(state, JsonDefaults.Options);
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(true);
            }

            if (File.Exists(_paths.StateFilePath))
            {
                File.Replace(tempPath, _paths.StateFilePath, _paths.StateBackupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _paths.StateFilePath);
            }
        }
        catch (Exception ex)
        {
            throw new StateStoreException($"保存状态数据失败：{ex.Message}", ex);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
            }
            catch
            {
                // A stale temp file is harmless and ignored by readers.
            }
        }
    }

    private static void TrimEvents(AppState state)
    {
        var threshold = DateTimeOffset.UtcNow.AddDays(-EventRetentionDays);
        state.Events.RemoveAll(e => e.TimestampUtc < threshold);
        if (state.Events.Count > MaxEvents)
        {
            state.Events = state.Events
                .OrderByDescending(e => e.TimestampUtc)
                .Take(MaxEvents)
                .OrderBy(e => e.TimestampUtc)
                .ToList();
        }
    }
}

public sealed class SettingsStore
{
    private readonly AppPaths _paths;
    private readonly object _gate = new();
    private readonly IAppLog _log;

    public SettingsStore(AppPaths paths, IAppLog? log = null)
    {
        _paths = paths;
        _log = log ?? NullAppLog.Instance;
    }

    public (UiSettings Settings, string? Warning) Load()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_paths.SettingsFilePath))
                    return (new UiSettings(), null);
                var json = File.ReadAllText(_paths.SettingsFilePath);
                var settings = JsonSerializer.Deserialize<UiSettings>(json, JsonDefaults.Options) ?? new UiSettings();
                Normalize(settings);
                return (settings, null);
            }
            catch (Exception ex)
            {
                _log.Warn("Settings", $"读取设置失败，使用默认值：{ex.Message}");
                return (new UiSettings(), $"设置文件无法读取，已使用默认设置：{ex.Message}");
            }
        }
    }

    public bool TrySave(UiSettings settings, out string? error)
    {
        lock (_gate)
        {
            try
            {
                Normalize(settings);
                _paths.EnsureDirectories();
                var json = JsonSerializer.Serialize(settings, JsonDefaults.Options);
                var temp = _paths.SettingsFilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                File.WriteAllText(temp, json, new System.Text.UTF8Encoding(false));
                File.Move(temp, _paths.SettingsFilePath, overwrite: true);
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                _log.Error("Settings", "保存设置失败", ex);
                return false;
            }
        }
    }

    private static void Normalize(UiSettings settings)
    {
        settings.RefreshIntervalSeconds = Math.Clamp(settings.RefreshIntervalSeconds, 3, 120);
        settings.HistoryRetentionDays = Math.Clamp(settings.HistoryRetentionDays, 7, 3650);
    }
}

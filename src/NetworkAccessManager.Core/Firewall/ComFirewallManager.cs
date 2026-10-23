using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using NetworkAccessManager.Core.Models;
using NetworkAccessManager.Core.Native;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Persistence;
using NetworkAccessManager.Core.Security;
using NetworkAccessManager.Core.Validation;

namespace NetworkAccessManager.Core.Firewall;

public sealed class FirewallOperationException : Exception
{
    public FirewallOperationException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// All Windows Firewall access is via the supported firewall automation COM API
/// (HNetCfg.FwPolicy2). No global policy, service state or foreign rule is
/// touched. Only rules carrying this application's group and verifiable
/// metadata can be removed.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class ComFirewallManager : IFirewallManager
{
    private static readonly string[] ProfileNames = ["域", "专用", "公用"];

    public bool IsElevated => WindowsPrivilege.IsAdministrator();

    public FirewallAvailability GetAvailability() =>
        StaThreadRunner.Run(() =>
        {
            var availability = GetAvailabilityCore(out var policy);
            ReleaseCom((object?)policy);
            return availability;
        });

    public FirewallInspectionBatch InspectRules(IReadOnlyList<ManagedRuleRecord> records) =>
        StaThreadRunner.Run(() =>
        {
            var availability = GetAvailabilityCore(out var policy);
            var inspections = new Dictionary<string, FirewallRuleInspection>(StringComparer.OrdinalIgnoreCase);
            if (policy is null)
            {
                foreach (var record in records)
                    inspections[record.RuleId] = UnknownInspection(record, availability.Error ?? "无法读取 Windows 防火墙。");
                return new FirewallInspectionBatch
                {
                    Inspections = inspections,
                    Availability = availability,
                    CheckedUtc = DateTimeOffset.UtcNow
                };
            }

            try
            {
                Dictionary<string, ActualRule> actual;
                try
                {
                    actual = ReadAllRules((object)policy);
                }
                catch (Exception ex)
                {
                    foreach (var record in records)
                        inspections[record.RuleId] = UnknownInspection(record, $"读取防火墙规则失败：{ex.Message}");
                    return new FirewallInspectionBatch
                    {
                        Inspections = inspections,
                        Availability = new FirewallAvailability
                        {
                            IsAvailable = availability.IsAvailable,
                            IsCurrentProfileProtected = availability.IsCurrentProfileProtected,
                            CanReadRules = false,
                            IsAccessLimited = IsAccessDenied(ex),
                            StatusText = IsAccessDenied(ex) ? "读取受限（权限不足）" : "规则读取失败",
                            Error = IsAccessDenied(ex)
                                ? "当前权限无法读取 Windows 防火墙规则。实际规则状态未知；修改操作需要管理员授权。"
                                : ex.Message,
                            ProfilesSummary = availability.ProfilesSummary,
                            ManagedRuleCount = availability.ManagedRuleCount
                        },
                        CheckedUtc = DateTimeOffset.UtcNow
                    };
                }

                foreach (var record in records)
                {
                    inspections[record.RuleId] = actual.TryGetValue(record.FirewallRuleName, out var found)
                        ? InspectRecord(record, found)
                        : new FirewallRuleInspection
                        {
                            RuleId = record.RuleId,
                            FirewallRuleName = record.FirewallRuleName,
                            State = RuleInspectionState.Missing,
                            Exists = false,
                            Detail = "Windows 防火墙中找不到该受管规则，可能已被其他程序或用户删除。"
                        };
                }

                return new FirewallInspectionBatch
                {
                    Inspections = inspections,
                    Availability = availability,
                    CheckedUtc = DateTimeOffset.UtcNow
                };
            }
            finally
            {
                ReleaseCom((object)policy);
            }
        });

    public IReadOnlyList<FirewallRuleInspection> CreateRules(IReadOnlyList<RuleDefinition> definitions)
    {
        if (!IsElevated)
            throw new FirewallOperationException("创建防火墙规则需要管理员权限。");
        if (definitions.Count == 0) return Array.Empty<FirewallRuleInspection>();

        return StaThreadRunner.Run(() =>
        {
            dynamic policy;
            try
            {
                policy = CreatePolicy();
            }
            catch (Exception ex)
            {
                throw new FirewallOperationException($"无法打开 Windows 防火墙策略：{ex.Message}", ex);
            }

            var createdNames = new List<string>();
            try
            {
                var existing = ReadAllRules((object)policy);
                var duplicate = definitions.FirstOrDefault(d => existing.ContainsKey(d.FirewallRuleName));
                if (duplicate is not null)
                    throw new FirewallOperationException($"同名防火墙规则已存在：{duplicate.FirewallRuleName}，未做更改。");

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FwRule")
                               ?? throw new FirewallOperationException("系统未注册 Windows 防火墙规则 COM 组件 HNetCfg.FwRule。");

                foreach (var def in definitions)
                {
                    if (string.IsNullOrWhiteSpace(def.FirewallRuleName))
                        throw new FirewallOperationException("规则名称为空。");
                    dynamic rule = Activator.CreateInstance(ruleType)
                                   ?? throw new FirewallOperationException("无法创建 Windows 防火墙规则对象。");
                    try
                    {
                        rule.Name = def.FirewallRuleName;
                        rule.Description = def.Description;
                        rule.Grouping = FirewallConstants.ManagedGroup;
                        rule.Action = FirewallConstants.ActionBlock;
                        rule.Direction = (int)def.Direction;
                        rule.Enabled = true;
                        rule.Profiles = FirewallConstants.ProfileAll;
                        rule.Protocol = FirewallConstants.ProtocolAny;
                        if (def.TargetKind == RuleTargetKind.Program)
                            rule.ApplicationName = def.Target;
                        else
                            rule.RemoteAddresses = def.Target;

                        policy.Rules.Add(rule);
                        createdNames.Add(def.FirewallRuleName);
                    }
                    finally
                    {
                        ReleaseCom((object)rule);
                    }
                }

                var verified = ReadAllRules((object)policy);
                var results = new List<FirewallRuleInspection>(definitions.Count);
                var failures = new List<string>();
                foreach (var def in definitions)
                {
                    if (!verified.TryGetValue(def.FirewallRuleName, out var actual))
                    {
                        failures.Add($"{def.FirewallRuleName}: 创建后验证失败（规则未找到）");
                        continue;
                    }
                    var record = new ManagedRuleRecord
                    {
                        RuleId = def.RuleId,
                        FirewallRuleName = def.FirewallRuleName,
                        TargetKind = def.TargetKind,
                        Target = def.Target,
                        Direction = def.Direction,
                        Description = def.Description,
                        Status = ManagedRuleStatus.Active,
                        CreatedUtc = DateTimeOffset.UtcNow
                    };
                    var inspection = InspectRecord(record, actual);
                    if (inspection.State != RuleInspectionState.Verified)
                        failures.Add($"{def.FirewallRuleName}: {inspection.Detail}");
                    results.Add(inspection);
                }

                if (failures.Count > 0)
                    throw new FirewallOperationException("规则创建后验证未通过：" + string.Join("；", failures));

                return (IReadOnlyList<FirewallRuleInspection>)results;
            }
            catch (FirewallOperationException)
            {
                CleanupCreated((object)policy, createdNames);
                throw;
            }
            catch (Exception ex)
            {
                CleanupCreated((object)policy, createdNames);
                throw new FirewallOperationException($"创建 Windows 防火墙规则失败：{ex.Message}", ex);
            }
            finally
            {
                ReleaseCom((object)policy);
            }
        });
    }

    public void RemoveRule(string firewallRuleName, string expectedRuleId)
    {
        if (!IsElevated)
            throw new FirewallOperationException("删除防火墙规则需要管理员权限。");

        StaThreadRunner.Run(() =>
        {
            dynamic policy;
            try
            {
                policy = CreatePolicy();
            }
            catch (Exception ex)
            {
                throw new FirewallOperationException($"无法打开 Windows 防火墙策略：{ex.Message}", ex);
            }

            try
            {
                var actual = ReadAllRules((object)policy);
                if (!actual.TryGetValue(firewallRuleName, out var found))
                    throw new FirewallOperationException("目标规则已不存在，未执行删除。");

                if (!FirewallRuleMetadata.TryParse(found.Description, out var metadata) ||
                    metadata is null ||
                    !string.Equals(metadata.RuleId, expectedRuleId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(found.Grouping, FirewallConstants.ManagedGroup, StringComparison.Ordinal) ||
                    !firewallRuleName.StartsWith(FirewallConstants.RuleNamePrefix, StringComparison.Ordinal))
                {
                    throw new FirewallOperationException("同名规则的身份元数据与本工具登记不符，为安全起见拒绝删除。");
                }

                policy.Rules.Remove(firewallRuleName);
                var after = ReadAllRules((object)policy);
                if (after.ContainsKey(firewallRuleName))
                    throw new FirewallOperationException("Windows 防火墙未确认规则已删除。");
            }
            catch (FirewallOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new FirewallOperationException($"删除 Windows 防火墙规则失败：{ex.Message}", ex);
            }
            finally
            {
                ReleaseCom((object)policy);
            }
        });
    }

    public IReadOnlyList<string> FindManagedOrphanRuleNames(ISet<string> knownRuleNames) =>
        StaThreadRunner.Run(() =>
        {
            dynamic policy;
            try { policy = CreatePolicy(); }
            catch { return (IReadOnlyList<string>)Array.Empty<string>(); }
            try
            {
                var all = ReadAllRules((object)policy);
                return (IReadOnlyList<string>)all.Values
                    .Where(r => r.Name.StartsWith(FirewallConstants.RuleNamePrefix, StringComparison.Ordinal))
                    .Where(r => string.Equals(r.Grouping, FirewallConstants.ManagedGroup, StringComparison.Ordinal))
                    .Where(r => FirewallRuleMetadata.TryParse(r.Description, out _))
                    .Select(r => r.Name)
                    .Where(n => !knownRuleNames.Contains(n))
                    .ToList();
            }
            catch
            {
                return (IReadOnlyList<string>)Array.Empty<string>();
            }
            finally
            {
                ReleaseCom((object)policy);
            }
        });

    private FirewallAvailability GetAvailabilityCore(out dynamic? policy)
    {
        policy = null;
        dynamic localPolicy;
        try
        {
            localPolicy = CreatePolicy();
            policy = localPolicy;
        }
        catch (Exception ex)
        {
            var denied = IsAccessDenied(ex);
            return new FirewallAvailability
            {
                IsAvailable = false,
                IsCurrentProfileProtected = false,
                CanReadRules = false,
                IsAccessLimited = denied,
                StatusText = denied ? "读取受限（权限不足）" : "不可用",
                Error = denied
                    ? "当前权限无法读取 Windows 防火墙状态。规则实际状态未知；创建/解除操作会通过 UAC 由管理员辅助进程重新核对。"
                    : $"无法连接 Windows 防火墙：{ex.Message}",
                ProfilesSummary = "未知"
            };
        }

        try
        {
            var currentProfiles = ToInt(localPolicy.CurrentProfileTypes, 0);
            int ruleCount;
            try { ruleCount = ToInt(localPolicy.Rules.Count, 0); }
            catch (Exception ex)
            {
                var denied = IsAccessDenied(ex);
                return new FirewallAvailability
                {
                    IsAvailable = true,
                    IsCurrentProfileProtected = false,
                    CanReadRules = false,
                    IsAccessLimited = denied,
                    StatusText = denied ? "读取受限（权限不足）" : "可用（无法读取规则）",
                    Error = denied
                        ? "当前权限无法读取 Windows 防火墙规则；实际规则状态未知，修改操作需要管理员授权。"
                        : $"Windows 防火墙可用，但读取现有规则失败：{ex.Message}",
                    ProfilesSummary = DescribeProfiles(currentProfiles)
                };
            }

            var states = new List<(int Profile, bool Enabled)>();
            foreach (var profile in new[] { 1, 2, 4 })
            {
                if ((currentProfiles & profile) == 0) continue;
                bool enabled;
                try
                {
                    enabled = ReadFirewallEnabled((object)localPolicy, profile);
                }
                catch (Exception ex)
                {
                    var denied = IsAccessDenied(ex);
                    return new FirewallAvailability
                    {
                        IsAvailable = true,
                        IsCurrentProfileProtected = false,
                        CanReadRules = true,
                        IsAccessLimited = denied,
                        StatusText = denied ? "读取受限（权限不足）" : "可用（无法确认配置文件状态）",
                        Error = denied
                            ? "当前权限无法读取 Windows 防火墙配置文件状态。实际状态未知。"
                            : $"无法读取当前 Windows 防火墙启用状态：{ex.Message}",
                        ProfilesSummary = DescribeProfiles(currentProfiles),
                        ManagedRuleCount = CountManagedRuleNames((object)localPolicy)
                    };
                }
                states.Add((profile, enabled));
            }

            var hasCurrentProfile = currentProfiles != 0 && states.Count > 0;
            var allCurrentEnabled = hasCurrentProfile && states.All(s => s.Enabled);
            var profilesSummary = DescribeProfiles(currentProfiles, states);
            var statusText = !hasCurrentProfile
                ? "可用（当前网络配置文件未知）"
                : allCurrentEnabled
                    ? "Windows 防火墙可用 · 当前配置文件已启用"
                    : "Windows 防火墙可用 · 当前配置文件未启用";
            return new FirewallAvailability
            {
                IsAvailable = true,
                IsCurrentProfileProtected = allCurrentEnabled,
                CanReadRules = true,
                StatusText = statusText,
                Error = hasCurrentProfile && !allCurrentEnabled
                    ? "当前网络配置文件的 Windows 防火墙未启用，规则不会生效；本工具不会修改此全局设置。"
                    : null,
                ProfilesSummary = profilesSummary,
                ManagedRuleCount = CountManagedRuleNames((object)localPolicy)
            };
        }
        catch (Exception ex)
        {
            var denied = IsAccessDenied(ex);
            return new FirewallAvailability
            {
                IsAvailable = false,
                IsCurrentProfileProtected = false,
                CanReadRules = false,
                IsAccessLimited = denied,
                StatusText = denied ? "读取受限（权限不足）" : "不可用",
                Error = denied
                    ? "当前权限无法读取 Windows 防火墙状态。实际状态未知；修改操作会请求管理员授权。"
                    : $"Windows 防火墙状态读取失败：{ex.Message}",
                ProfilesSummary = "未知"
            };
        }
    }

    private static bool IsAccessDenied(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is UnauthorizedAccessException) return true;
            if (current.HResult == unchecked((int)0x80070005)) return true;
            if (current.Message.Contains("拒绝访问", StringComparison.OrdinalIgnoreCase) ||
                current.Message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) ||
                current.Message.Contains("E_ACCESSDENIED", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool ReadFirewallEnabled(object policyObject, int profile)
    {
        dynamic policy = policyObject;
        try
        {
            return Convert.ToBoolean(policy.FirewallEnabled[profile], CultureInfo.InvariantCulture);
        }
        catch
        {
            // Some COM interop paths expose parameterized properties only via late binding.
            var obj = (object)policy;
            var value = obj.GetType().InvokeMember(
                "FirewallEnabled",
                BindingFlags.GetProperty,
                binder: null,
                target: obj,
                args: new object[] { profile },
                culture: CultureInfo.InvariantCulture);
            return Convert.ToBoolean(value, CultureInfo.InvariantCulture);
        }
    }

    private static int CountManagedRuleNames(object policyObject)
    {
        dynamic policy = policyObject;
        try
        {
            var count = 0;
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    var name = Convert.ToString(rule.Name, CultureInfo.InvariantCulture);
                    if (name?.StartsWith(FirewallConstants.RuleNamePrefix, StringComparison.Ordinal) == true) count++;
                }
                catch
                {
                    // Keep the count best-effort; individual unreadable rules are ignored.
                }
            }
            return count;
        }
        catch
        {
            return 0;
        }
    }

    private static string DescribeProfiles(int currentProfiles)
    {
        if (currentProfiles == 0) return "当前网络配置文件未知";
        var names = new List<string>();
        if ((currentProfiles & 1) != 0) names.Add(ProfileNames[0]);
        if ((currentProfiles & 2) != 0) names.Add(ProfileNames[1]);
        if ((currentProfiles & 4) != 0) names.Add(ProfileNames[2]);
        return names.Count == 0 ? $"未知位掩码 {currentProfiles}" : $"当前配置文件：{string.Join("、", names)}";
    }

    private static string DescribeProfiles(int currentProfiles, IReadOnlyList<(int Profile, bool Enabled)> states)
    {
        if (currentProfiles == 0) return "当前网络配置文件未知";
        var names = states.Select(s =>
        {
            var name = s.Profile switch { 1 => ProfileNames[0], 2 => ProfileNames[1], 4 => ProfileNames[2], _ => $"未知({s.Profile})" };
            return $"{name}（防火墙{(s.Enabled ? "启用" : "关闭")}）";
        }).ToList();
        foreach (var profile in new[] { 1, 2, 4 })
        {
            if ((currentProfiles & profile) != 0 && states.All(s => s.Profile != profile))
            {
                var name = profile switch { 1 => ProfileNames[0], 2 => ProfileNames[1], 4 => ProfileNames[2], _ => profile.ToString() };
                names.Add($"{name}（状态未知）");
            }
        }
        return $"当前配置文件：{string.Join("、", names)}";
    }

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                   ?? throw new InvalidOperationException("系统未注册 Windows 防火墙策略 COM 组件 HNetCfg.FwPolicy2。");
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException("无法创建 Windows 防火墙策略对象。");
    }

    private static Dictionary<string, ActualRule> ReadAllRules(object policyObject)
    {
        dynamic policy = policyObject;
        var result = new Dictionary<string, ActualRule>(StringComparer.OrdinalIgnoreCase);
        foreach (dynamic rule in policy.Rules)
        {
            try
            {
                var name = Convert.ToString(rule.Name, CultureInfo.InvariantCulture);
                if (string.IsNullOrWhiteSpace(name)) continue;
                result[name] = new ActualRule(
                    name,
                    Convert.ToString(rule.Description, CultureInfo.InvariantCulture),
                    Convert.ToString(rule.Grouping, CultureInfo.InvariantCulture),
                    ToInt(rule.Direction, 0),
                    ToInt(rule.Action, -1),
                    Convert.ToBoolean(rule.Enabled, CultureInfo.InvariantCulture),
                    ToInt(rule.Profiles, 0),
                    ToInt(rule.Protocol, -1),
                    Convert.ToString(rule.ApplicationName, CultureInfo.InvariantCulture),
                    Convert.ToString(rule.RemoteAddresses, CultureInfo.InvariantCulture));
            }
            catch
            {
                // A rule can vanish while enumerating. It is not part of our
                // managed set and is omitted from this snapshot.
            }
        }
        return result;
    }

    private static FirewallRuleInspection InspectRecord(ManagedRuleRecord record, ActualRule actual)
    {
        var identicalIdentity =
            string.Equals(actual.Name, record.FirewallRuleName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(actual.Grouping, FirewallConstants.ManagedGroup, StringComparison.Ordinal) &&
            FirewallRuleMetadata.TryParse(actual.Description, out var metadata) &&
            metadata is not null &&
            string.Equals(metadata.RuleId, record.RuleId, StringComparison.OrdinalIgnoreCase) &&
            metadata.TargetKind == record.TargetKind &&
            metadata.Direction == record.Direction &&
            string.Equals(metadata.Target, record.Target, StringComparison.OrdinalIgnoreCase);

        var problems = new List<string>();
        if (!identicalIdentity)
            problems.Add("规则名称、分组或身份元数据与本工具登记不符");
        if (!actual.Enabled)
            problems.Add("规则已被禁用");
        if (actual.Action != FirewallConstants.ActionBlock)
            problems.Add($"动作不是阻断（实际 {actual.Action}）");
        if (actual.Direction != (int)record.Direction)
            problems.Add($"方向不一致（实际 {actual.Direction}）");
        if (actual.Profiles != FirewallConstants.ProfileAll)
            problems.Add($"配置文件范围被改变（实际 {actual.Profiles}）");
        if (actual.Protocol != FirewallConstants.ProtocolAny)
            problems.Add($"协议范围被改变（实际 {actual.Protocol}）");

        if (record.TargetKind == RuleTargetKind.Program)
        {
            if (!ProgramTargetValidator.PathsEqual(actual.ApplicationName, record.Target))
                problems.Add($"程序路径不一致（实际 {actual.ApplicationName ?? "未设置"}）");
        }
        else
        {
            if (!FirewallRemoteAddressComparer.Matches(actual.RemoteAddresses, record.Target))
                problems.Add($"远程地址不一致（实际 {actual.RemoteAddresses ?? "未设置"}）");
        }

        return new FirewallRuleInspection
        {
            RuleId = record.RuleId,
            FirewallRuleName = record.FirewallRuleName,
            State = problems.Count == 0 ? RuleInspectionState.Verified : RuleInspectionState.Mismatched,
            IdentityMatches = identicalIdentity,
            Exists = true,
            Detail = problems.Count == 0 ? "规则存在，属性与本工具登记一致。" : string.Join("；", problems) + "。",
            IsEnabled = actual.Enabled,
            Direction = actual.Direction,
            Action = actual.Action,
            ApplicationName = actual.ApplicationName,
            RemoteAddresses = actual.RemoteAddresses,
            Grouping = actual.Grouping,
            Description = actual.Description
        };
    }

    private static FirewallRuleInspection UnknownInspection(ManagedRuleRecord record, string reason) => new()
    {
        RuleId = record.RuleId,
        FirewallRuleName = record.FirewallRuleName,
        State = RuleInspectionState.Unknown,
        Detail = reason,
        IdentityMatches = false,
        Exists = false
    };

    private static void CleanupCreated(object policyObject, IReadOnlyList<string> createdNames)
    {
        dynamic policy = policyObject;
        foreach (var name in createdNames)
        {
            try { policy.Rules.Remove(name); }
            catch
            {
                // Best effort only; the verification failure is still reported.
            }
        }
    }

    private static int ToInt(object? value, int fallback)
    {
        try
        {
            return value is null ? fallback : Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }
        catch
        {
            return fallback;
        }
    }

    private static void ReleaseCom(object? value)
    {
        if (value is null) return;
        try
        {
            if (Marshal.IsComObject(value))
                Marshal.FinalReleaseComObject(value);
        }
        catch
        {
            // Never mask the operation result with a COM cleanup problem.
        }
    }

    private sealed record ActualRule(
        string Name,
        string? Description,
        string? Grouping,
        int Direction,
        int Action,
        bool Enabled,
        int Profiles,
        int Protocol,
        string? ApplicationName,
        string? RemoteAddresses);
}

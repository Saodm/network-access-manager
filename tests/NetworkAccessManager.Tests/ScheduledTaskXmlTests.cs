using System.Xml.Linq;
using NetworkAccessManager.Core.Operations;
using NetworkAccessManager.Core.Scheduling;
using NetworkAccessManager.Core.Security;

namespace NetworkAccessManager.Tests;

public sealed class ScheduledTaskXmlTests
{
    [Fact]
    public void Xml_contains_expected_one_shot_trigger_and_escapes_description()
    {
        var taskId = Guid.NewGuid().ToString("N");
        var name = TaskNamePolicy.ForTask(taskId);
        var exe = @"C:\Program Files\网络 & 工具\NetworkAccessManager.exe";
        var runAt = new DateTimeOffset(2026, 10, 23, 20, 30, 0, TimeSpan.Zero);
        var xml = ScheduledTaskXml.Build(name, exe, taskId, runAt, "说明 <test> & \"quoted\"");

        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        Assert.Equal(name, TaskNamePolicy.ForTask(taskId));
        Assert.Equal(exe, doc.Descendants(ns + "Command").Single().Value);
        Assert.Equal($"--execute-task={taskId}", doc.Descendants(ns + "Arguments").Single().Value);
        Assert.Equal("true", doc.Descendants(ns + "StartWhenAvailable").Single().Value);
        Assert.Equal("HighestAvailable", doc.Descendants(ns + "RunLevel").Single().Value);
        Assert.Equal("InteractiveToken", doc.Descendants(ns + "LogonType").Single().Value);
        Assert.Equal(WindowsPrivilege.CurrentUserSid(), doc.Descendants(ns + "UserId").Single().Value);
        var boundary = doc.Descendants(ns + "StartBoundary").Single().Value;
        Assert.Equal(runAt.ToLocalTime().ToString("yyyy-MM-dd'T'HH:mm:ss"), boundary);
        Assert.NotNull(doc.Descendants(ns + "TimeTrigger").SingleOrDefault());
        Assert.Null(doc.Descendants(ns + "BootTrigger").SingleOrDefault());
    }

    [Theory]
    [InlineData("NAM_Task_0123456789abcdef0123456789abcdef", true)]
    [InlineData("NAM_Task_0123456789ABCDEF0123456789ABCDEF", true)]
    [InlineData("NAM_Task_123", false)]
    [InlineData("Other_Task_0123456789abcdef0123456789abcdef", false)]
    [InlineData("NAM_Task_0123456789abcdef0123456789abcdef;calc.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Task_name_policy_is_strict(string? name, bool expected)
    {
        Assert.Equal(expected, TaskNamePolicy.IsValid(name));
    }

    [Fact]
    public void Xml_rejects_invalid_task_id()
    {
        var exe = Environment.ProcessPath!;
        Assert.Throws<ArgumentException>(() => ScheduledTaskXml.Build("NAM_Task_0123456789abcdef0123456789abcdef", exe, "not-a-guid", DateTimeOffset.UtcNow, "test"));
    }

    [Fact]
    public void Xml_rejects_shell_arguments_in_the_task_id()
    {
        var exe = Environment.ProcessPath!;
        Assert.Throws<ArgumentException>(() => ScheduledTaskXml.Build("NAM_Task_0123456789abcdef0123456789abcdef", exe, "x & calc.exe", DateTimeOffset.UtcNow, "test"));
    }
}

// SPDX-License-Identifier: MPL-2.0
// Synthetic compile-only dependencies. HostContext always traps; no real runner
// service, credentials, network, config or job can be entered by this harness.
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
namespace GitHub.DistributedTask.WebApi { }
namespace GitHub.Services.WebApi {
 public class AccessDeniedException:Exception { public int ErrorCode => 1; }
 public class RunnerNotFoundException:Exception { }
}
namespace GitHub.Runner.Common {
 public enum WellKnownDirectory { Root }
 public interface IHostContext { Tracing GetTrace(string name); void WritePerfCounter(string name); T GetService<T>(); string GetDirectory(WellKnownDirectory d); CancellationToken RunnerShutdownToken {get;} }
 public sealed class HostContext:IHostContext,IDisposable {
  public static int Constructed;
  public HostContext(string t) { Constructed++; throw new InvalidOperationException("HOST_CONTEXT_TRAP"); }
  public void Dispose() { throw new Exception("unexpected context dispose"); }
  public Tracing GetTrace(string n) => throw new Exception("unexpected trace");
  public void WritePerfCounter(string n) => throw new Exception("unexpected perf");
  public T GetService<T>() => throw new Exception("unexpected service");
  public string GetDirectory(WellKnownDirectory d) => throw new Exception("unexpected directory");
  public CancellationToken RunnerShutdownToken => throw new Exception("unexpected cancellation");
 }
 public sealed class Tracing { public void Info(string x) => throw new Exception("unexpected trace"); public void Error(Exception x) => throw new Exception("unexpected trace"); }
 public interface ITerminal { void WriteLine(string x); void WriteError(string x); }
 public static class Constants {
  public enum OSPlatform { Linux,OSX,Windows }
  public static class Runner { public static readonly OSPlatform Platform=OSPlatform.Linux; public const string PlatformArchitecture="X64";
   public static class ReturnCode { public const int Success=0,TerminatedError=1,RetryableError=2,RunnerVersionDeprecated=4; }
  }
  public static class Variables { public static class Actions { public const string ReturnVersionDeprecatedExitCode="SYNTHETIC_VERSION_EXIT"; } }
 }
 public class NonRetryableException:Exception { }
}
namespace GitHub.Runner.Sdk {
 public static class BuildConstants { public static class RunnerPackage { public static readonly string Version="1.2.3-synthetic",PackageName="synthetic"; } public static class Source { public static readonly string CommitHash="synthetic"; } }

 public static class IOUtil { public static void ValidateExecutePermission(string p) => throw new Exception("unexpected permission check"); }
 public static class StringUtil { public static bool ConvertToBoolean(string v) => throw new Exception("unexpected env conversion"); }
}
namespace GitHub.Runner.Listener {
 public sealed class CommandSettings { public CommandSettings(GitHub.Runner.Common.IHostContext c,string[] args) { throw new Exception("unexpected parsing"); } public List<string> Validate() => throw new Exception("unexpected validation"); public string GetCommandName() => throw new Exception("unexpected command"); }
 public interface IRunner { Task<int> ExecuteCommand(CommandSettings c); }
}

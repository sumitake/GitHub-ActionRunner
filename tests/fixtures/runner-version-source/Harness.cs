// SPDX-License-Identifier: MPL-2.0
using System;
using System.IO;
using System.Reflection;
using GitHub.Runner.Common;
public static class ContractHarness {
 public static int Main() {
  string root=Directory.GetParent(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location)).FullName;
  string envPath=Path.Combine(root,".env");
  const string sentinel="SYNTHETIC_STARTUP_CONTRACT_ENV";
  if(File.Exists(envPath)) throw new Exception("fixture refuses overwrite");
  File.WriteAllText(envPath,sentinel+"=touched\n");
  int failures=0;
  try {
   string[][] cases={new[]{"--version"},Array.Empty<string>(),new[]{"run"},new[]{"--version","extra"},new[]{"--Version"},new[]{"--commit"},new[]{"--help"},new[]{"--version","--help"}};
   foreach(var args in cases) {
    Environment.SetEnvironmentVariable(sentinel,null);HostContext.Constructed=0;
    var oldOut=Console.Out;var captured=new StringWriter();Console.SetOut(captured);
    int? code=null;Exception error=null;
    try { code=GitHub.Runner.Listener.Program.Main(args); }catch(Exception e){error=e;}
    finally {Console.SetOut(oldOut);}
    bool exact=args.Length==1&&args[0]=="--version";
    bool pass=exact
      ? code==0&&error==null&&captured.ToString()=="1.2.3-synthetic"+Environment.NewLine&&HostContext.Constructed==0&&Environment.GetEnvironmentVariable(sentinel)==null
      : code==null&&error is InvalidOperationException&&error.Message=="HOST_CONTEXT_TRAP"&&HostContext.Constructed==1&&Environment.GetEnvironmentVariable(sentinel)=="touched"&&captured.ToString()=="";
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{argv=args,pass,code,error=error?.Message,context_constructions=HostContext.Constructed,env_read=Environment.GetEnvironmentVariable(sentinel)!=null,runtime_framework=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}));
    if(!pass)failures++;
   }
  } finally { File.Delete(envPath);Environment.SetEnvironmentVariable(sentinel,null); }
  return failures==0?0:1;
 }
}

// Native boundary helpers shared by the Windows installer and disposable smoke.
using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class BrokerWindowsNative {
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct SidAttr { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct LsaAttrs { public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Descriptor, Quality; }
    [StructLayout(LayoutKind.Sequential)] struct LsaString { public ushort Length, Maximum; public IntPtr Buffer; }
    [DllImport("authz.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool AuthzInitializeResourceManager(uint flags, IntPtr a, IntPtr b, IntPtr c, string name, out IntPtr manager);
    [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzInitializeContextFromSid(uint flags, byte[] sid, IntPtr manager, IntPtr expiry, Luid id, IntPtr args, out IntPtr context);
    [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzGetInformationFromContext(IntPtr context, int kind, uint size, out uint needed, IntPtr buffer);
    [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
    [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr manager);
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LsaAttrs attrs, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
    [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
    static byte[] SidBytes(string text) { var sid = new SecurityIdentifier(text); var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); return bytes; }
    static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static string[] EffectiveSids(string user) {
        IntPtr manager=IntPtr.Zero, context=IntPtr.Zero, buffer=IntPtr.Zero;
        try {
            Check(AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "ssh-broker-installer", out manager));
            // Never silently fall back to incomplete directory-only group enumeration.
            Check(AuthzInitializeContextFromSid(0, SidBytes(user), manager, IntPtr.Zero, new Luid(), IntPtr.Zero, out context));
            uint needed; AuthzGetInformationFromContext(context, 2, 0, out needed, IntPtr.Zero);
            if (needed == 0) throw new InvalidOperationException("S4U group information unavailable");
            buffer=Marshal.AllocHGlobal(checked((int)needed));
            Check(AuthzGetInformationFromContext(context, 2, needed, out needed, buffer));
            int count=Marshal.ReadInt32(buffer), start=IntPtr.Size == 8 ? 8 : 4, stride=Marshal.SizeOf(typeof(SidAttr));
            var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase); result.Add(user);
            for(int i=0;i<count;i++) {
                var entry=(SidAttr)Marshal.PtrToStructure(IntPtr.Add(buffer,start+i*stride),typeof(SidAttr));
                result.Add(new SecurityIdentifier(entry.Sid).Value); // Include deny-only groups too.
            }
            return result.ToArray();
        } finally { if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer); if(context!=IntPtr.Zero)AuthzFreeContext(context); if(manager!=IntPtr.Zero)AuthzFreeResourceManager(manager); }
    }
    public static string[] AccountRights(string[] sids) {
        var attrs=new LsaAttrs(); attrs.Length=(uint)Marshal.SizeOf(typeof(LsaAttrs)); IntPtr policy;
        uint status=LsaOpenPolicy(IntPtr.Zero,ref attrs,0x800,out policy);
        if(status!=0)throw new Win32Exception((int)LsaNtStatusToWinError(status));
        var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { foreach(string sid in sids) {
            IntPtr rights=IntPtr.Zero; uint count;
            status=LsaEnumerateAccountRights(policy,SidBytes(sid),out rights,out count);
            if(status!=0) { uint error=LsaNtStatusToWinError(status); if(error==2)continue; throw new Win32Exception((int)error); }
            try { for(int i=0;i<count;i++) { var right=(LsaString)Marshal.PtrToStructure(IntPtr.Add(rights,i*Marshal.SizeOf(typeof(LsaString))),typeof(LsaString)); result.Add(Marshal.PtrToStringUni(right.Buffer,right.Length/2)); } }
            finally { if(rights!=IntPtr.Zero)LsaFreeMemory(rights); }
        } } finally { LsaClose(policy); }
        return result.ToArray();
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo { public int Size; public string Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public ushort Show,Reserved2; public IntPtr ReservedPtr,Input,Output,Error; }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public StartupInfo Startup; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread; public uint ProcessId,ThreadId; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint version,out IntPtr descriptor,out uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SecurityAttributes attrs,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr bytes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr service);
    public static string Quote(string arg) {
        var b=new StringBuilder("\""); int slashes=0;
        foreach(char c in arg) { if(c=='\\'){slashes++;continue;} if(c=='\"'){b.Append('\\',slashes*2+1);b.Append(c);}else{b.Append('\\',slashes);b.Append(c);} slashes=0; }
        b.Append('\\',slashes*2); return b.Append('"').ToString();
    }
    public sealed class Result { public int ExitCode; public byte[] Stdout,Stderr,Outcome; public long FirstOutputMilliseconds=-1,DurationMilliseconds; }
    static async Task Drain(FileStream source,MemoryStream sink,Result result,Stopwatch watch,bool track) {
        byte[] buffer=new byte[16384];
        try { int size; while((size=await source.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))!=0) {
            if(track && result.FirstOutputMilliseconds<0)result.FirstOutputMilliseconds=watch.ElapsedMilliseconds;
            // Keep an untrusted remote endpoint from exhausting the elevated smoke runner.
            if(sink.Length+size>32*1024*1024)throw new IOException("Smoke output limit exceeded");
            sink.Write(buffer,0,size);
        } } finally { Array.Clear(buffer,0,buffer.Length); source.Dispose(); }
    }
    static FileStream Stream(IntPtr handle,FileAccess access) { return new FileStream(new SafeFileHandle(handle,true),access,16384,false); }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateEvent(IntPtr attributes,bool manual,bool initial,string name);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    public static Result RunPrivate(string executable,string[] args,byte[] input,bool outcome,int timeoutSeconds) {
        return Run(executable,args,input,outcome,timeoutSeconds,null);
    }
    public static Result RunOutcomeProbe(string executable,string[] args,string variant,int timeoutSeconds) {
        return Run(executable,args,new byte[0],true,timeoutSeconds,variant);
    }
    static Result Run(string executable,string[] args,byte[] input,bool outcome,int timeoutSeconds,string variant) {
        var handles=new HashSet<IntPtr>(); IntPtr descriptor=IntPtr.Zero, list=IntPtr.Zero, values=IntPtr.Zero; ProcessInfo process=new ProcessInfo();
        var result=new Result(); var watch=Stopwatch.StartNew();
        try {
            string sid=WindowsIdentity.GetCurrent().User.Value; uint size;
            Check(ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+sid+"D:P(A;;GA;;;"+sid+")(A;;GA;;;SY)",1,out descriptor,out size));
            var attrs=new SecurityAttributes{Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,Inherit=true};
            IntPtr stdinRead,stdinWrite,stdoutRead,stdoutWrite,stderrRead,stderrWrite,outcomeRead,outcomeWrite;
            Check(CreatePipe(out stdinRead,out stdinWrite,ref attrs,0)); handles.Add(stdinRead);handles.Add(stdinWrite);
            Check(CreatePipe(out stdoutRead,out stdoutWrite,ref attrs,0));handles.Add(stdoutRead);handles.Add(stdoutWrite);
            Check(CreatePipe(out stderrRead,out stderrWrite,ref attrs,0));handles.Add(stderrRead);handles.Add(stderrWrite);
            Check(CreatePipe(out outcomeRead,out outcomeWrite,ref attrs,0));handles.Add(outcomeRead);handles.Add(outcomeWrite);
            foreach(IntPtr handle in new[]{stdinWrite,stdoutRead,stderrRead,outcomeRead})Check(SetHandleInformation(handle,1,0));
            IntPtr selectedOutcome=outcomeWrite;
            var inheritedList=new List<IntPtr>(new[]{stdinRead,stdoutWrite,stderrWrite,outcomeWrite});
            if(variant!=null) {
                if(variant=="readonly")selectedOutcome=CreateFile(executable,0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero);
                else if(variant=="event")selectedOutcome=CreateEvent(IntPtr.Zero,false,false,null);
                else if(variant=="process")selectedOutcome=OpenProcess(0x1000,false,checked((int)GetCurrentProcessId()));
                else throw new ArgumentException("Unknown outcome probe");
                Check(selectedOutcome!=IntPtr.Zero && selectedOutcome!=new IntPtr(-1));
                handles.Add(selectedOutcome);Check(SetHandleInformation(selectedOutcome,1,1));inheritedList.Add(selectedOutcome);
            }
            var inherited=inheritedList.ToArray();
            IntPtr bytes=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
            list=Marshal.AllocHGlobal(bytes); Check(InitializeProcThreadAttributeList(list,1,0,ref bytes));
            values=Marshal.AllocHGlobal(IntPtr.Size*inherited.Length); Marshal.Copy(inherited,0,values,inherited.Length);
            Check(UpdateProcThreadAttribute(list,0,new IntPtr(0x20002),values,new IntPtr(IntPtr.Size*inherited.Length),IntPtr.Zero,IntPtr.Zero));
            var command=new StringBuilder(Quote(executable));
            if(outcome)command.Append(" --outcome-handle ").Append(selectedOutcome.ToInt64());
            foreach(string arg in args)command.Append(' ').Append(Quote(arg));
            var startup=new StartupEx(); startup.Startup.Size=Marshal.SizeOf(typeof(StartupEx)); startup.Startup.Flags=0x100; startup.Startup.Input=stdinRead;startup.Startup.Output=stdoutWrite;startup.Startup.Error=stderrWrite;startup.Attributes=list;
            Check(CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,true,0x08080000,IntPtr.Zero,Path.GetDirectoryName(executable),ref startup,out process));
            foreach(IntPtr handle in inherited){CloseHandle(handle);handles.Remove(handle);}
            var output=new MemoryStream();var error=new MemoryStream();var status=new MemoryStream();
            var outTask=Drain(Stream(stdoutRead,FileAccess.Read),output,result,watch,true);handles.Remove(stdoutRead);
            var errTask=Drain(Stream(stderrRead,FileAccess.Read),error,result,watch,false);handles.Remove(stderrRead);
            var statusTask=Drain(Stream(outcomeRead,FileAccess.Read),status,result,watch,false);handles.Remove(outcomeRead);
            var stdin=Stream(stdinWrite,FileAccess.Write);handles.Remove(stdinWrite);
            var writer=Task.Run(delegate { using(stdin) { if(input!=null && input.Length>0)stdin.Write(input,0,input.Length); } });
            if(WaitForSingleObject(process.Process,checked((uint)timeoutSeconds*1000))!=0) { TerminateProcess(process.Process,125); throw new TimeoutException("Child deadline exceeded"); }
            uint code;Check(GetExitCodeProcess(process.Process,out code)); result.ExitCode=unchecked((int)code);
            // Bounded drain also detects descendants retaining inherited handles.
            if(!Task.WaitAll(new Task[]{outTask,errTask,statusTask},5000))throw new TimeoutException("Child output handles remain open");
            try { writer.GetAwaiter().GetResult(); } catch(IOException) { if(result.ExitCode==0)throw; }
            result.Stdout=output.ToArray();result.Stderr=error.ToArray();result.Outcome=status.ToArray();result.DurationMilliseconds=watch.ElapsedMilliseconds;
            output.Dispose();error.Dispose();status.Dispose();return result;
        } finally {
            if(process.Process!=IntPtr.Zero){TerminateProcess(process.Process,125);CloseHandle(process.Process);} if(process.Thread!=IntPtr.Zero)CloseHandle(process.Thread);
            foreach(IntPtr handle in handles)CloseHandle(handle);
            if(list!=IntPtr.Zero){DeleteProcThreadAttributeList(list);Marshal.FreeHGlobal(list);}if(values!=IntPtr.Zero)Marshal.FreeHGlobal(values);if(descriptor!=IntPtr.Zero)LocalFree(descriptor);
        }
    }
    public static bool DeniedProcessRead(int pid) {
        IntPtr handle=OpenProcess(0x10,false,pid);
        if(handle!=IntPtr.Zero){CloseHandle(handle);return false;}
        if(Marshal.GetLastWin32Error()!=5)throw new Win32Exception(Marshal.GetLastWin32Error()); return true;
    }
    public static bool DeniedTokenDuplicate(int pid) {
        IntPtr process=OpenProcess(0x1000,false,pid);Check(process!=IntPtr.Zero);
        try { IntPtr token; if(OpenProcessToken(process,2,out token)){CloseHandle(token);return false;} if(Marshal.GetLastWin32Error()!=5)throw new Win32Exception(Marshal.GetLastWin32Error());return true; }
        finally {CloseHandle(process);}
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugActiveProcess(int pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugActiveProcessStop(int pid);
    public static bool DeniedDebugger(int pid) {
        if(DebugActiveProcess(pid)) { DebugActiveProcessStop(pid); return false; }
        if(Marshal.GetLastWin32Error()!=5)throw new Win32Exception(Marshal.GetLastWin32Error()); return true;
    }
    public static bool DeniedServiceChange() {
        IntPtr manager=OpenSCManager(null,null,1);Check(manager!=IntPtr.Zero);
        try { foreach(uint access in new uint[]{2,0x10,0x20,0x40,0x100,0x10000,0x40000,0x80000}) {
            IntPtr service=OpenService(manager,"ssh-brokerd",access);
            if(service!=IntPtr.Zero){CloseServiceHandle(service);return false;}
            if(Marshal.GetLastWin32Error()!=5)throw new Win32Exception(Marshal.GetLastWin32Error());
        } return true; } finally {CloseServiceHandle(manager);}
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr attributes,uint creation,uint flags,IntPtr template);
    public static bool DeniedPathAccess(string path,uint access) {
        IntPtr handle=CreateFile(path,access,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);
        if(handle!=new IntPtr(-1)){CloseHandle(handle);return false;}
        if(Marshal.GetLastWin32Error()!=5)throw new Win32Exception(Marshal.GetLastWin32Error());return true;
    }
}

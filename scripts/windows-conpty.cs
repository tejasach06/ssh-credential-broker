using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// Runs in the unprivileged harness context. All terminal contents stay private;
// only observed acceptance booleans and a remote exit status leave this helper.
public static class BrokerConsoleSmoke {
    [StructLayout(LayoutKind.Sequential)] struct Coord { public short X, Y; public Coord(short x, short y) { X=x; Y=y; } }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct StartupInfo {
        public int Size; public string Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public ushort Show, Reserved2; public IntPtr ReservedPtr, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public StartupInfo Startup; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr attributes, uint size);
    [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(Coord size, IntPtr input, IntPtr output, uint flags, out IntPtr console);
    [DllImport("kernel32.dll")] static extern int ResizePseudoConsole(IntPtr console, Coord size);
    [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr bytes);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out ProcessInfo info);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    public sealed class Result { public bool Interactive, Resize, ControlC; public int ExitCode; public byte[] Transcript; }
    sealed class Capture {
        readonly object gate = new object();
        readonly StringBuilder text = new StringBuilder();
        bool failed;
        public void Append(byte[] buffer, int count) {
            lock(gate) {
                if(text.Length + count > 1024*1024) { failed=true; return; }
                text.Append(Encoding.UTF8.GetString(buffer,0,count));
            }
        }
        public bool Contains(string marker) { lock(gate) { return text.ToString().Contains(marker); } }
        public byte[] Snapshot() { lock(gate) { return Encoding.UTF8.GetBytes(text.ToString()); } }
        public bool Failed { get { lock(gate) { return failed; } } }
        public void Fail() { lock(gate) { failed=true; } }
        public void Clear() { lock(gate) { text.Clear(); } }
    }
    static void Check(bool success, string stage) {
        if(!success) throw new InvalidOperationException("ConPTY " + stage + " failed (Win32 " + Marshal.GetLastWin32Error() + ")");
    }
    static void HResult(int result, string stage) {
        if(result < 0) throw new InvalidOperationException("ConPTY " + stage + " failed (HRESULT " + result + ")");
    }
    static string Quote(string argument) {
        var quoted=new StringBuilder("\""); int slashes=0;
        foreach(char c in argument) {
            if(c=='\\') { slashes++; continue; }
            if(c=='\"') { quoted.Append('\\',slashes*2+1); quoted.Append(c); }
            else { quoted.Append('\\',slashes); quoted.Append(c); }
            slashes=0;
        }
        quoted.Append('\\',slashes*2); return quoted.Append('"').ToString();
    }
    static void Write(FileStream input, string text) {
        byte[] data=Encoding.UTF8.GetBytes(text);
        try { input.Write(data,0,data.Length); input.Flush(); }
        finally { Array.Clear(data,0,data.Length); }
    }
    static void Await(Capture capture, string marker, IntPtr process, int seconds, string stage, FileStream input=null, string probe=null) {
        var clock=Stopwatch.StartNew();
        long nextProbe=0;
        while(clock.ElapsedMilliseconds < (long)seconds*1000) {
            if(capture.Failed) throw new InvalidOperationException("ConPTY output capture failed");
            if(capture.Contains(marker)) return;
            if(WaitForSingleObject(process,0)==0) throw new InvalidOperationException("ConPTY child exited during " + stage);
            if(input!=null && clock.ElapsedMilliseconds>=nextProbe) {
                Write(input,probe);
                nextProbe=clock.ElapsedMilliseconds+250;
            }
            Thread.Sleep(20);
        }
        throw new TimeoutException("ConPTY " + stage + " timed out");
    }
    static void Close(ref IntPtr handle) {
        if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; }
    }

    public static Result Run(string executable, string[] arguments, int timeoutSeconds) {
        if(timeoutSeconds < 2 || timeoutSeconds > 120) throw new ArgumentOutOfRangeException("timeoutSeconds");
        IntPtr inputRead=IntPtr.Zero,inputWrite=IntPtr.Zero,outputRead=IntPtr.Zero,outputWrite=IntPtr.Zero;
        IntPtr console=IntPtr.Zero,list=IntPtr.Zero;
        bool listReady=false;
        ProcessInfo process=new ProcessInfo();
        FileStream input=null, output=null;
        Thread drain=null;
        var capture=new Capture();
        try {
            Check(CreatePipe(out inputRead,out inputWrite,IntPtr.Zero,0),"input pipe");
            Check(CreatePipe(out outputRead,out outputWrite,IntPtr.Zero,0),"output pipe");
            HResult(CreatePseudoConsole(new Coord(80,24),inputRead,outputWrite,0,out console),"creation");
            IntPtr bytes=IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
            if(bytes==IntPtr.Zero) throw new InvalidOperationException("ConPTY attribute sizing failed");
            list=Marshal.AllocHGlobal(bytes);
            Check(InitializeProcThreadAttributeList(list,1,0,ref bytes),"attribute initialization");
            listReady=true;
            // HPCON is the attribute value itself, not a pointer to a HANDLE slot.
            Check(UpdateProcThreadAttribute(list,0,new IntPtr(0x00020016),console,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"console attribute");
            var startup=new StartupEx();
            startup.Startup.Size=Marshal.SizeOf(typeof(StartupEx));
            startup.Attributes=list;
            var command=new StringBuilder(Quote(executable));
            foreach(string argument in arguments) command.Append(' ').Append(Quote(argument));
            output=new FileStream(new SafeFileHandle(outputRead,true),FileAccess.Read,4096,false);
            outputRead=IntPtr.Zero;
            FileStream outputStream=output;
            drain=new Thread(delegate() {
                byte[] buffer=new byte[4096];
                try { int count; while((count=outputStream.Read(buffer,0,buffer.Length))!=0) capture.Append(buffer,count); }
                catch(IOException) { capture.Fail(); }
                catch(ObjectDisposedException) { }
                finally { Array.Clear(buffer,0,buffer.Length); }
            });
            drain.IsBackground=true;
            drain.Start();
            string directory=Path.GetDirectoryName(executable);
            if(string.IsNullOrEmpty(directory)) directory=null;
            Check(CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,false,0x00080000,IntPtr.Zero,directory,ref startup,out process),"child creation");
            Close(ref inputRead); Close(ref outputWrite);
            input=new FileStream(new SafeFileHandle(inputWrite,true),FileAccess.Write,4096,false);
            inputWrite=IntPtr.Zero;
            // Assemble output markers remotely so echoed command text cannot satisfy a check.
            Write(input,"printf '\\n__BROKER_%s__\\n' 'PTY_READY'\r");
            Await(capture,"__BROKER_PTY_READY__",process.Process,timeoutSeconds,"interactive shell");
            Write(input,"printf '\\n__BROKER_SIZE_%s__\\n' \"$(stty size)\"\r");
            Await(capture,"__BROKER_SIZE_24 80__",process.Process,timeoutSeconds,"initial remote PTY size");
            HResult(ResizePseudoConsole(console,new Coord(112,37)),"resize");
            Await(capture,"__BROKER_SIZE_37 112__",process.Process,timeoutSeconds,"remote PTY resize",
                input,"printf '\\n__BROKER_SIZE_%s__\\n' \"$(stty size)\"\r");
            Write(input,"printf '\\n__BROKER_%s__\\n' 'SLEEP_STARTED'; sleep 30\r");
            Await(capture,"__BROKER_SLEEP_STARTED__",process.Process,timeoutSeconds,"foreground command");
            Thread.Sleep(250);
            Write(input,"\x03");
            // VINTR flushes pending typeahead. Probe until the shell has handled it;
            // sleep still running cannot satisfy this marker inside the 10s bound.
            Await(capture,"__BROKER_AFTER_CTRL_C__",process.Process,Math.Min(10,timeoutSeconds),"remote Ctrl-C",
                input,"printf '\\n__BROKER_%s__\\n' 'AFTER_CTRL_C'\r");
            Write(input,"exit 37\r");
            if(WaitForSingleObject(process.Process,checked((uint)timeoutSeconds*1000))!=0) throw new TimeoutException("ConPTY remote exit timed out");
            uint status; Check(GetExitCodeProcess(process.Process,out status),"exit status");
            if(status!=37) throw new InvalidOperationException("ConPTY remote exit status mismatch");
            return new Result { Interactive=true, Resize=true, ControlC=true, ExitCode=37, Transcript=capture.Snapshot() };
        } finally {
            if(process.Process!=IntPtr.Zero && WaitForSingleObject(process.Process,0)!=0) {
                TerminateProcess(process.Process,125);
                WaitForSingleObject(process.Process,5000);
            }
            if(input!=null) input.Dispose();
            Close(ref inputRead); Close(ref inputWrite); Close(ref outputWrite);
            // Keep output draining throughout pseudoconsole shutdown to avoid ConPTY deadlock.
            if(console!=IntPtr.Zero) ClosePseudoConsole(console);
            if(drain!=null && !drain.Join(5000)) { if(output!=null) output.Dispose(); drain.Join(1000); }
            if(output!=null) output.Dispose();
            Close(ref outputRead);
            if(listReady) DeleteProcThreadAttributeList(list);
            if(list!=IntPtr.Zero) Marshal.FreeHGlobal(list);
            Close(ref process.Thread); Close(ref process.Process);
            capture.Clear();
        }
    }
}

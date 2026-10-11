using System;
using System.Diagnostics;
using System.IO;
using System.Text;

static class Program
{
    static int Main(string[] args)
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(dir, "Start-VirusTotal-Tray.ps1");
        var arguments = new StringBuilder();
        arguments.Append("-STA -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ");
        arguments.Append(Quote(script));
        foreach (string arg in args)
        {
            arguments.Append(' ');
            arguments.Append(Quote(arg));
        }

        var start = new ProcessStartInfo();
        start.FileName = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        start.Arguments = arguments.ToString();
        start.WorkingDirectory = dir;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        Process.Start(start);
        return 0;
    }

    static string Quote(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}

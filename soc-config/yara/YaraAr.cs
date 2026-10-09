// Reponse active YARA pour l'agent Wazuh Windows (EQ13).
// L'agent Windows n'execute que des .exe : compiler sur DC01 avec PowerShell :
//   Add-Type -TypeDefinition (Get-Content YaraAr.cs -Raw) -OutputType ConsoleApplication -OutputAssembly <ossec-agent>/active-response/bin/yara.exe
using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;

public static class YaraAr {
    public static int Main() {
        string baseDir = @"C:\Program Files (x86)\ossec-agent";
        string log = Path.Combine(baseDir, @"active-response\active-responses.log");
        try {
            string input = Console.In.ReadLine();
            if (string.IsNullOrEmpty(input)) return 0;
            Match m = Regex.Match(input, "\"syscheck\"\\s*:\\s*\\{[^{}]*?\"path\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            if (!m.Success) return 0;
            string file = Regex.Unescape(m.Groups[1].Value);
            if (!File.Exists(file)) return 0;
            Thread.Sleep(1000);
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Path.Combine(baseDir, @"yara\yara64.exe");
            psi.Arguments = "-w \"" + Path.Combine(baseDir, @"yara\eq13.yar") + "\" \"" + file + "\"";
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.CreateNoWindow = true;
            using (Process p = Process.Start(psi)) {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(60000);
                foreach (string line in output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
                    int sp = line.IndexOf(' ');
                    if (sp <= 0) continue;
                    File.AppendAllText(log, "wazuh-yara: INFO - Scan result: " + line.Substring(0, sp) + " " + line.Substring(sp + 1) + Environment.NewLine);
                }
            }
        } catch (Exception e) {
            try { File.AppendAllText(log, "wazuh-yara: ERROR - " + e.Message.Replace("\r", " ").Replace("\n", " ") + Environment.NewLine); } catch { }
        }
        return 0;
    }
}

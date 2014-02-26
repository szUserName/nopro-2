using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;

// C:\Windows\Microsoft.NET\Framework\v3.5\Csc.exe /noconfig /nowarn:1701,1702 /errorreport:prompt /warn:4 /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Core.dll" /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Data.DataSetExtensions.dll" /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Data.dll /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.dll /reference:C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Xml.dll /reference:"C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Xml.Linq.dll" /reference:obj\Release\Interop.SHDocVw.dll /debug+ /debug:full /filealign:512 /nowin32manifest /optimize+ /out:obj\Release\Comb64.exe /target:exe Program.cs Properties\AssemblyInfo.cs
namespace ConsoleApplication1
{
    class EventHandlers
    {
        public void OnBeforeNavigate2(object sender, ref object URL,
                                      ref object Flags, ref object Target,
                                      ref object PostData, ref object Headers,
                                      ref bool Cancel)
        {
            // Console.WriteLine("BeforeNavigate2 fired!");
        }
        public void OnNavigateComplete2(object pDisp, ref object url)
        {
            var IE = (SHDocVw.InternetExplorer)pDisp;
            var whatever = (HtmlDocument)IE.Document;
            Console.WriteLine("THIS is INNERTEXT {0}", whatever.Body.InnerText);
        }
        public void OnTitleChange(String Text)
        {
            Console.WriteLine("Title changed to {0}", Text);
        }
        static public void navAgain(object BrowserObject)
        {
            var IE = (SHDocVw.InternetExplorer)BrowserObject;
            object Empty = 0;
            object browserFlags = 14; // no history, no read cache, no write cache
            object URL = "http://127.0.0.1/default.asp";
            object postData = 0;
            object postHeader = "Content-Type: application/x-www-form-urlencoded\r\n";
            //IE.Navigate2(ref URL, ref browserFlags, ref Empty, ref postData, ref postHeader);
            IE.Navigate2(ref URL, ref browserFlags, ref Empty, ref Empty, ref Empty);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            EventHandlers e = new EventHandlers();
            SHDocVw.InternetExplorer IE = new SHDocVw.InternetExplorer();

            //override BeforeNavigate2 event
            IE.BeforeNavigate2 += new SHDocVw.DWebBrowserEvents2_BeforeNavigate2EventHandler(e.OnBeforeNavigate2);
            IE.NavigateComplete2 += new SHDocVw.DWebBrowserEvents2_NavigateComplete2EventHandler(e.OnNavigateComplete2);
            IE.TitleChange += new SHDocVw.DWebBrowserEvents2_TitleChangeEventHandler(e.OnTitleChange);
            IE.Visible = false;
            while (true)
            {
                EventHandlers.navAgain(IE);
                System.Threading.Thread.Sleep(5000);
            }
            //IE.Quit();
        }
    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.IO;
using NetFwTypeLib;
using System.Text;
using System.Threading;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Management;
using Microsoft.Win32;
using PluginAPIs;
using System.Collections;
using System.Reflection;

namespace f2b_wsl
{
    public partial class Fail2BanService : ServiceBase
    {
        public Fail2BanService()
        {
            InitializeComponent();
            EventLog.BeginInit();
            if (!EventLog.SourceExists("Fail2BanWin"))
            {
                EventLog.CreateEventSource("Fail2BanWin", "Fail2BanWin");
            }
            EventLog.EndInit();
            EventLog.Source = "Fail2BanWin";
            EventLog.Log = "Fail2BanWin";
        }

        public enum LogIDs
        {
            Log_Starting = 0,
            Log_Notice_FoundF2B = 1,
            Log_Notice_Quit = 2,
            Log_Plugin_Activated = 3,
            Log_Plugin_Deactivated = 4,
            Log_Notice_PlainInfo = 5,

            Log_Error_Generic = 1000,
            Log_Error_ParseFile = 1001,
            Log_Error_NoF2BFound = 1002,
            Log_Error_NoPluginFound = 1003,
            Log_Error_Plugin = 1004
        }

        public enum LogCategories
        {
            Log_Info = 0,
            Log_Warning = 1,
            Log_Error = 2
        }

        private ArrayList plugins = new ArrayList();
        private Dictionary<string, Fail2BanEnv> F2BEnvPool = new Dictionary<string, Fail2BanEnv>();
        private Thread F2BEnvMonitorThread;

        protected override void OnStart(string[] args)
        {
            InitializePlugins();
            // Get fail2ban from wsl
            EventLog.WriteEntry("Service Fail2Ban Starting...", EventLogEntryType.Information, (int)LogIDs.Log_Starting, (short)LogCategories.Log_Info);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SID FROM Win32_UserAccount");
            ManagementObjectCollection collection = searcher.Get();
            foreach (ManagementBaseObject uInfo in collection.Cast<ManagementBaseObject>())
            {
                string uSID = (string)uInfo["SID"];
                int PFState;
                var PFListKey = Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("Microsoft").OpenSubKey("Windows NT").OpenSubKey("CurrentVersion").OpenSubKey("ProfileList");
                try
                {
                    PFState = (int)PFListKey.OpenSubKey(uSID).GetValue("State");
                }
                catch (Exception)
                { continue; }
                if (PFState == 0)
                {
                    string LxssPath = (string)PFListKey.OpenSubKey(uSID).GetValue("ProfileImagePath") + @"\AppData\Local\lxss\rootfs\etc\fail2ban";
                    if (Directory.Exists(LxssPath))
                    {
                        EventLog.WriteEntry("Found fail2ban under dir:" + LxssPath, EventLogEntryType.Information, (int)LogIDs.Log_Starting, (short)LogCategories.Log_Info);
                        F2BEnvPool.Add(LxssPath, new Fail2BanEnv(LxssPath));
                    }
                }
            }
            // if no fail2ban install found
            if (F2BEnvPool.Count == 0)
            {
                EventLog.WriteEntry("No valid fail2ban installation found. Service Stopping.", EventLogEntryType.Error, (int)LogIDs.Log_Error_NoF2BFound, (short)LogCategories.Log_Error);
                Stop();
            }
            else
            {
                F2BEnvMonitorThread = new Thread(F2BEnvMonitor);
                F2BEnvMonitorThread.Start();
            }
        }

        private void InitializePlugins()
        {
            if (!Directory.Exists(System.AppDomain.CurrentDomain.BaseDirectory + @"\Plugins\"))
                Directory.CreateDirectory(System.AppDomain.CurrentDomain.BaseDirectory + @"\Plugins\");
            DirectoryInfo pluginAssemblyDir = new DirectoryInfo(System.AppDomain.CurrentDomain.BaseDirectory + @"\Plugins\");
            FileInfo[] pluginFiles = pluginAssemblyDir.GetFiles("*.dll");
            if (pluginFiles.Length <= 0)
            {
                EventLog.WriteEntry("No plugins found.", EventLogEntryType.Information, (int)LogIDs.Log_Error_NoPluginFound, (short)LogCategories.Log_Info);
                return;
            }
            foreach (FileInfo pluginFile in pluginFiles)
            {
                ArrayList FailedRegisterPluginList = new ArrayList();
                try
                {
                    Assembly pluginAsm = Assembly.LoadFile(pluginFile.FullName);
                    Type[] types = pluginAsm.GetTypes();
                    foreach (Type t in types)
                    {
                        if (t == null || !t.IsClass || !t.IsPublic || t.IsAbstract || t.GetInterface("IPluginEvent") == null)
                            continue;
                        plugins.Add(pluginAsm.CreateInstance(t.FullName));
                    }
                    foreach (IPlugin WaitForRegPlugin in plugins)
                    {
                        if (WaitForRegPlugin.RegisterPlugin(EventLog))
                        {
                            WaitForRegPlugin.OnLoad();
                            EventLog.WriteEntry("Load Plugin " + pluginFile.Name + " Successful. ", EventLogEntryType.Information, (int)LogIDs.Log_Plugin_Activated, (short)LogCategories.Log_Info);
                        }
                        else
                        {
                            FailedRegisterPluginList.Add(WaitForRegPlugin);
                        }
                    }
                    foreach(IPlugin FailedPlugin in FailedRegisterPluginList)
                    {
                        plugins.Remove(FailedPlugin);
                    }
                }
                catch (Exception e)
                {
                    EventLog.WriteEntry("Load Plugin " + pluginFile.Name + " Failed." + e.Message, EventLogEntryType.Warning, (int)LogIDs.Log_Error_Plugin, (short)LogCategories.Log_Warning);
                }
            }
        }

        protected override void OnStop()
        {
            foreach(IPlugin WaitForStopPlugin in plugins)
            {
                WaitForStopPlugin.OnDestroy();
            }
            EventLog.WriteEntry("Service Stopped.", EventLogEntryType.Information, (int)LogIDs.Log_Notice_Quit, (short)LogCategories.Log_Info);
        }

        private void F2BEnvMonitor()
        {
            // monitor all Fail2BanEnv to see if thread aborted or not.
            // auto restart these threads.
            while (true)
            {
                Thread.Sleep(10000);
                foreach(IPlugin WaitForCallPlugin in plugins)
                {
                    WaitForCallPlugin.TriggerEvent(this, new PluginEventArgs() { EventSource = "test", EventTextContent = "DemoPluginTest", EventType = "test" });
                    DumpPlugins();
                }
            }
        }

        private void DumpPlugins()
        {
            string tmpString = "";
            foreach(IPlugin plugin in plugins)
            {
                tmpString += string.Format("{0}: ver. {1}; \r\nDescription:{2} \r\n", new string[] {
                    plugin.PluginName,
                    plugin.PluginVersion.ToString(),
                    plugin.PluginDescription
               });
            }
            EventLog.WriteEntry(tmpString, EventLogEntryType.Information, (int)LogIDs.Log_Notice_PlainInfo, (short)LogCategories.Log_Info);
        }
    }
}

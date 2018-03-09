#region "License Declearation"
/*
    fail2ban-wsl: a tool to port fail2ban into windows environment
    Copyright (C) 2018 mingl0280

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Contact: mingl0280@gmail.com for more information.
*/
#endregion
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.IO;
using System.Threading;
using System.Management;
using Microsoft.Win32;
using PluginAPIs;
using System.Collections;
using System.Reflection;
using static PluginAPIs.EventLogEnums;

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

        private ArrayList plugins = new ArrayList();
        public Dictionary<string, Fail2BanEnv> F2BEnvPool = new Dictionary<string, Fail2BanEnv>();
        private Thread F2BEnvMonitorThread;

        public ArrayList Plugins { get => plugins; set => plugins = value; }

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
                        F2BEnvPool.Add(LxssPath, new Fail2BanEnv(LxssPath, this));
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
            // Plugin initialize and add to valid plugin list
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
                        Plugins.Add(pluginAsm.CreateInstance(t.FullName));
                    }
                    foreach (IPlugin WaitForRegPlugin in Plugins)
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
                        Plugins.Remove(FailedPlugin);
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
            foreach(IPlugin WaitForStopPlugin in Plugins)
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
                foreach(KeyValuePair<string, Fail2BanEnv> EnvItem in F2BEnvPool)
                {
                    var env = EnvItem.Value;
                    
                    if (env.GetThreadStatus() != System.Threading.ThreadState.Running)
                    {
                        env.StartMonitorThread();
                    }
                }
                Thread.Sleep(10000);/*
                foreach(IPlugin WaitForCallPlugin in plugins)
                {
                    //WaitForCallPlugin.RaiseAfterBadIPDetected( this, new PluginEventArgs() { EventSource = "test", EventTextContent = "DemoPluginTest", EventType = "test" });
                    DumpPlugins();
                }*/
            }
        }

        private void DumpPlugins()
        {
            string tmpString = "";
            foreach(IPlugin plugin in Plugins)
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

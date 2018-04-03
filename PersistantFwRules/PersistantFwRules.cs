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
using PluginAPIs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using NetFwTypeLib;
using System.ServiceProcess;
using static PluginAPIs.EventLogEnums;
using System.IO;
using System.Timers;

namespace PersistantFwRules
{
    public class PersistantFwRules : IPlugin
    {
        public PersistantFwRules() : base("PersistantFwRules", new Version(1, 0, 0), "Persistant Firewall Rules") { }

        private static Type FwPolicy2Types = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        private static Type FwRuleTypes = Type.GetTypeFromProgID("HNetCfg.FwRule");
        private static INetFwPolicy2 FwPolicy;
        private static INetFwRule FwRule;
        private static object FwAccessLocker = new object();
        private static object FwStackLocker = new object();
        private static object FwIOLocker = new object();
        private static string PersistantRulesFileName = AppDomain.CurrentDomain.BaseDirectory + "\\PersistantRules.txt";
        private static Dictionary<string, int> PersistantCounter = new Dictionary<string, int>();
        private int MaxRegisterTimes = 3;
        private bool ignoreEventInput = false;
        private Timer DumpTimer = new Timer(60 * 60 * 1000); //Dump bad IP list every hour
        

        private enum FwEventIDs
        {
            IPAdded = 2040,
            IPRemoved = 2041,
            IPDuplicate = 2042,
            IPNotExist = 2043,
            IPListSet = 2044
        }

        public override void OnDestroy()
        {
            DumpBadIPList();
            DumpTimer.Stop();
            _logger.WriteEntry("Plugin Destroyed" + _pluginName, EventLogEntryType.Warning, (int)LogIDs.Log_Plugin_Deactivated, (short)LogCategories.Log_Info);
        }

        public override void OnLoad()
        {
            lock (FwAccessLocker)
            {
                FwPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicy2Types);
                try
                {
                    FwRule = FwPolicy.Rules.Item("F2BPersistantAutoRule");
                }
                catch (Exception)
                {
                    if (FwRule == null)
                    {
                        FwRule = (INetFwRule)Activator.CreateInstance(FwRuleTypes);
                        FwRule.Name = "F2BPersistantAutoRule";
                        FwRule.Description = "Fail2Ban for WSL auto rule (Persistant)";
                        FwRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                        FwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                        FwRule.Enabled = false;
                        FwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                        FwRule.Grouping = "F2BAuto";
                        FwRule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
                        FwPolicy.Rules.Add(FwRule);
                    }
                }
            }
            _logger.WriteEntry("F2B Persistant Firewall Settings Initialized.", EventLogEntryType.Information, (int)LogIDs.Log_Plugin_Activated, (short)LogCategories.Log_Info);
            if (!File.Exists(PersistantRulesFileName))
            {
                File.Create(PersistantRulesFileName).Close();
            }
            ReadExistingPersistantRules();
            DumpTimer.Start();
            _logger.WriteEntry("F2B Firewall Plugin Initialized.", EventLogEntryType.Information, (int)LogIDs.Log_Plugin_Activated, (short)LogCategories.Log_Info);
        }

        private void ReadExistingPersistantRules()
        {
            StreamReader sr = new StreamReader(PersistantRulesFileName);
            lock (FwIOLocker)
            {
                while (!sr.EndOfStream)
                {
                    string inputline = sr.ReadLine();
                    string[] data = inputline.Split(',');
                    if (data[0] == "IP")
                        continue;
                    PersistantCounter.Add(data[0], Convert.ToInt32(data[1]));
                }
                foreach (var PersistantItem in PersistantCounter)
                {
                    if (PersistantItem.Value > MaxRegisterTimes)
                        AddFwBadIP(PersistantItem.Key);
                }
            }
            sr.Close();
            sr.Dispose();
        }

        public override bool RegisterPlugin(EventLog logger)
        {
            OnBadIPDetected += PersistantFwRules_OnBadIPDetected;
            EnvStartInitialize += PersistantFwRules_EnvStartInitialize;
            EnvEndInitialize += PersistantFwRules_EnvEndInitialize;
            DumpTimer.Elapsed += DumpTimer_Elapsed;
            _logger = logger;
            if (!CheckWinFwStatus())
                return false;
            return true;
        }

        private void DumpTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            DumpBadIPList();
        }

        private void PersistantFwRules_EnvStartInitialize(object sender, EventArgs args)
        {
            ignoreEventInput = true;
        }

        private void PersistantFwRules_EnvEndInitialize(object sender, EventArgs args)
        {
            DumpBadIPList();
            ignoreEventInput = false;
        }

        private void DumpBadIPList()
        {
            lock (FwIOLocker)
            {
                FileStream fs = new FileStream(PersistantRulesFileName, FileMode.Truncate);
                fs.Close();
                fs.Dispose();
                StreamWriter sw = new StreamWriter(PersistantRulesFileName);
                sw.AutoFlush = true;
                sw.WriteLine("IP,BlockTimes");
                foreach (var PersistantItem in PersistantCounter)
                {
                    sw.WriteLine(PersistantItem.Key + "," + PersistantItem.Value.ToString());
                }
                sw.Flush();
                sw.Close();
                sw.Dispose();
            }
        }

        private void PersistantFwRules_OnBadIPDetected(object sender, PluginEventArgs args)
        {
            lock (FwStackLocker)
            {
                if (ignoreEventInput)
                    return;
                if (args.EventTextContent.StartsWith("+"))
                {
                    var datastr = args.EventTextContent.Substring(1);
                    if (PersistantCounter.ContainsKey(datastr))
                        PersistantCounter[datastr]++;
                    else
                        PersistantCounter.Add(datastr, 1);
                    if (PersistantCounter[datastr] > MaxRegisterTimes)
                        AddFwBadIP(datastr);
                }
            }
        }


        /// <summary>
        /// check if windows firewall is started or not. It will attempt to start the windows firewall if not started.
        /// </summary>
        /// <returns>True = started, False = not started.</returns>
        private bool CheckWinFwStatus()
        {
            ServiceController ctrl = new ServiceController("mpssvc");
            if (ctrl.Status != ServiceControllerStatus.Running && ctrl.Status != ServiceControllerStatus.StartPending)
            {
                try
                {
                    ctrl.Start();
                    ctrl.WaitForStatus(ServiceControllerStatus.Running, new TimeSpan(0, 0, 5));
                    _logger.WriteEntry("Windows Firewall Starting", EventLogEntryType.Warning, (int)LogIDs.Log_Notice_DependencyStarting, (short)LogCategories.Log_Info);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.WriteEntry(ex.Message, EventLogEntryType.Error, (int)LogIDs.Log_Error_Generic, (short)LogCategories.Log_Error);
                    return false;
                }
            }
            else
            {
                _logger.WriteEntry("Windows Firewall OK", EventLogEntryType.Information, (int)LogIDs.Log_Notice_PlainInfo, (short)LogCategories.Log_Info);
                return true;
            }

        }

        /// <summary>
        /// Add a bad ip to firewall
        /// </summary>
        /// <param name="IPAddr">ip address string</param>
        private void AddFwBadIP(string IPAddr)
        {
            if (!FwRule.RemoteAddresses.Contains(IPAddr))
            {
                if (string.IsNullOrEmpty(FwRule.RemoteAddresses) || FwRule.RemoteAddresses == "*")
                {
                    FwRule.RemoteAddresses = IPAddr;
                    FwRule.Enabled = true;
                }
                else
                {
                    FwRule.RemoteAddresses += "," + IPAddr;
                }
                _logger.WriteEntry("Persistant Firewall rule added for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPAdded, (short)LogCategories.Log_Info);
            }
            else
            {
                //_logger.WriteEntry("Firewall rule duplicate for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPDuplicate, (short)LogCategories.Log_Info); // Don't want too much duplicated info
            }
        }

    }
}

#define DIRECT
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
using System.Diagnostics;
using NetFwTypeLib;
using System.ServiceProcess;
using static PluginAPIs.EventLogEnums;
using System.Collections.Generic;
using System.Linq;

namespace FirewallPolicyPlugin
{
    public class FirewallPolicyModifier : IPlugin
    {
        public FirewallPolicyModifier() : base("WinFirewallModifier", new Version(1, 0, 0), "A plugin to modify windows firewall rules") { }

        private static Type FwPolicy2Types = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        private static Type FwRuleTypes = Type.GetTypeFromProgID("HNetCfg.FwRule");
        private static INetFwPolicy2 FwPolicy;
        private static INetFwRule FwRule;
        private static object FwAccessLocker = new object();
        private static object FwStackLocker = new object();
        private static object FwRedirectLock = new object();
        private static bool RedirectWrite = false;
        private static Dictionary<string, int> CachedFwItems = new Dictionary<string, int>();

        public override void OnDestroy()
        {
            _logger.WriteEntry("Plugin Destroyed" + _pluginName, EventLogEntryType.Warning, (int)LogIDs.Log_Plugin_Deactivated, (short)LogCategories.Log_Info);
        }

        private enum FwEventIDs
        {
            IPAdded = 2010,
            IPRemoved = 2011,
            IPDuplicate = 2012,
            IPNotExist = 2013,
            IPListSet = 2014
        }

        public override void OnLoad()
        {
            lock (FwAccessLocker)
            {
                FwPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicy2Types);
                try
                {
                    FwRule = FwPolicy.Rules.Item("F2BAutoRule");
                }
                catch (Exception)
                {
                    if (FwRule == null)
                    {
                        FwRule = (INetFwRule)Activator.CreateInstance(FwRuleTypes);
                        FwRule.Name = "F2BAutoRule";
                        FwRule.Description = "Fail2Ban for WSL auto rule";
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
            _logger.WriteEntry("F2B Firewall Plugin Initialized.", EventLogEntryType.Information, (int)LogIDs.Log_Plugin_Activated, (short)LogCategories.Log_Info);
        }

        public override bool RegisterPlugin(EventLog logger)
        {
            EnvStartInitialize += FirewallPolicyModifier_EnvStartInitialize;
            EnvEndInitialize += FirewallPolicyModifier_EnvEndInitialize;
            OnBadIPDetected += FirewallPolicyModifier_OnBadIPDetected;
            _logger = logger;
            if (!CheckWinFwStatus())
                return false;
            return true;
        }

        private void FirewallPolicyModifier_EnvEndInitialize(object sender, EventArgs args)
        {
            lock (FwRedirectLock)
            {
                RedirectWrite = false;
                WriteAllCached();
            }
        }

        private void FirewallPolicyModifier_EnvStartInitialize(object sender, EventArgs args)
        {
            lock (FwRedirectLock)
            {
                RedirectWrite = true;
            }

        }

        private void WriteAllCached()
        {
            lock (FwAccessLocker)
            {
                if (CachedFwItems.Count > 0)
                {
                    SetFwBadIPs(CachedFwItems);
                    CachedFwItems.Clear();
                }
            }
        }

        private void FirewallPolicyModifier_OnBadIPDetected(object sender, PluginEventArgs args)
        {
#if DIRECT
            lock (FwStackLocker)
            {
                if (args.EventTextContent.StartsWith("+"))
                {
                    if (RedirectWrite == true)
                    {
                        try
                        {
                            CachedFwItems.Add(args.EventTextContent.Substring(1), 1);
                        }
                        catch (Exception) { }
                    }
                    else
                    {
                        AddFwBadIP(args.EventTextContent.Substring(1));
                        return;
                    }
                }
                if (args.EventTextContent.StartsWith("-"))
                {
                    if (RedirectWrite == true)
                    {
                        try
                        {
                            CachedFwItems.Remove(args.EventTextContent.Substring(1));
                        }
                        catch (Exception) { }
                    }
                    else
                    {
                        RemoveFwBadIP(args.EventTextContent.Substring(1));
                    }
                }
            }
#else
            lock (FwStackLocker)
            {

                string BadIPEventText = args.EventTextContent;
                string BadIP = BadIPEventText.Substring(1);
                if (!FwRuleStack.ContainsKey(BadIP))
                {
                    FwRuleStack.Add(BadIP, new Stack<int>());
                }
                if (args.EventTextContent.StartsWith("+"))
                {
                    FwRuleStack[BadIP].Push(1);

                    //AddFwBadIP(args.EventTextContent.Substring(1));
                    return;
                }
                if (args.EventTextContent.StartsWith("-"))
                {
                    try
                    {
                        FwRuleStack[BadIP].Pop();
                    }
                    catch (Exception) { }

                    //RemoveFwBadIP(args.EventTextContent.Substring(1));
                }
            }


            SetFwBadIPs();
#endif
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
            System.Threading.Thread.MemoryBarrier();
            lock (FwAccessLocker)
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
                    _logger.WriteEntry("Firewall rule added for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPAdded, (short)LogCategories.Log_Info);
                }
                else
                {
                    //_logger.WriteEntry("Firewall rule duplicate for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPDuplicate, (short)LogCategories.Log_Info); // Don't want too much duplicated info
                }
            }
        }

        /// <summary>
        /// Remove a bad ip from firewall
        /// </summary>
        /// <param name="IPAddr">ip address string</param>
        private void RemoveFwBadIP(string IPAddr)
        {
            lock (FwAccessLocker)
            {
                if (FwRule.RemoteAddresses.Contains(IPAddr))
                {
                    List<string> IPAddrList = new List<string>();
                    IPAddrList.AddRange(FwRule.RemoteAddresses.Split(','));
                    IPAddrList.RemoveAll(x => x.Contains(IPAddr));
                    string AfterRmAddrs = "";
                    if (IPAddrList.Count < 1)
                    {
                        FwRule.Enabled = false;
                        FwRule.RemoteAddresses = "*";
                    }
                    else
                    {
                        foreach (string item in IPAddrList)
                        {
                            AfterRmAddrs += "," + item;
                        }
                        AfterRmAddrs = AfterRmAddrs.Trim(',');
                        FwRule.RemoteAddresses = AfterRmAddrs;
                    }
                    _logger.WriteEntry("Firewall rule removed for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPRemoved, (short)LogCategories.Log_Info);
                }
                else
                {
                    _logger.WriteEntry("Firewall rule not exist for removal: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPNotExist, (short)LogCategories.Log_Info);
                }
            }
        }
        #region "StackFwIPProcess"
#if !DIRECT
        private static Dictionary<string, Stack<int>> FwRuleStack;
#endif
        protected void SetFwBadIPs(Dictionary<string, int> FwRuleStack)
        {
            string FwBadIPStr = "";
            lock (FwAccessLocker)
            {
                lock (FwStackLocker)
                {
                    List<string> IPAddrList = new List<string>();
                    IPAddrList.AddRange(FwRule.RemoteAddresses.Replace("/255.255.255.255","").Split(','));
                    IPAddrList.AddRange(FwRuleStack.Keys);
                    List<string> DeDupedList = IPAddrList.Distinct().ToList();
                    foreach (var BadIPStr in DeDupedList)
                    {
                        if (BadIPStr != "*")
                        FwBadIPStr += BadIPStr + @"/255.255.255.255,";
                    }
                    FwBadIPStr = FwBadIPStr.Trim(',');
                    
                    if (string.IsNullOrEmpty(FwBadIPStr) || string.IsNullOrWhiteSpace(FwBadIPStr))
                    {
                        FwRule.RemoteAddresses = "*";
                        FwRule.Enabled = false;
                        _logger.WriteEntry("Firewall blocked IP list is empty.", EventLogEntryType.Warning, (int)FwEventIDs.IPListSet, (short)LogCategories.Log_Warning);
                    }
                    else
                    {
                        FwRule.Enabled = true;
                        FwRule.RemoteAddresses = FwBadIPStr;
                        _logger.WriteEntry("Firewall blocked IP addresses set to: \r\n" + FwBadIPStr, EventLogEntryType.Warning, (int)FwEventIDs.IPListSet, (short)LogCategories.Log_Warning);
                    }
                }
            }
        }

        #endregion
#if DEBUG
        public void RaiseBIPDeteacted(string IPAddr)
        {
            FirewallPolicyModifier_OnBadIPDetected(null, new PluginEventArgs() { EventSource = "", EventTextContent = IPAddr, EventType = "Det" });
        }
#endif
    }
}

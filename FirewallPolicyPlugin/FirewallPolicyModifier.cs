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

        public override void OnDestroy()
        {
            _logger.WriteEntry("Plugin Destroyed" + _pluginName, EventLogEntryType.Warning, (int)LogIDs.Log_Plugin_Deactivated, (short)LogCategories.Log_Info);
        }

        private enum FwEventIDs
        {
            IPAdded = 2010,
            IPRemoved = 2011,
            IPDuplicate = 2012,
            IPNotExist = 2013
        }

        public override void OnLoad()
        {
            lock (FwAccessLocker)
            {
                FwPolicy = (INetFwPolicy2)Activator.CreateInstance(FwPolicy2Types);
                try
                {
                    FwRule = FwPolicy.Rules.Item("F2BAutoRule");
                }catch(Exception)
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
            OnBadIPDetected += FirewallPolicyModifier_OnBadIPDetected;
            _logger = logger;
            if (!CheckWinFwStatus())
                return false;
            return true;
        }

        private void FirewallPolicyModifier_OnBadIPDetected(object sender, PluginEventArgs args)
        {
            if (args.EventTextContent.StartsWith("+"))
            {
                AddFwBadIP(args.EventTextContent.Substring(1));
                return;
            }
            if (args.EventTextContent.StartsWith("-"))
            {
                RemoveFwBadIP(args.EventTextContent.Substring(1));
            }
        }

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

        protected void AddFwBadIP(string IPAddr)
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
                _logger.WriteEntry("Firewall rule duplicate for IP: " + IPAddr, EventLogEntryType.Warning, (int)FwEventIDs.IPDuplicate, (short)LogCategories.Log_Info);
            }
        }

        protected void RemoveFwBadIP(string IPAddr)
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
                    foreach(string item in IPAddrList)
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

#if DEBUG
        public void RaiseBIPDeteacted(string IPAddr)
        {
            FirewallPolicyModifier_OnBadIPDetected(null, new PluginEventArgs() { EventSource = "", EventTextContent = IPAddr, EventType ="Det" });
        }
#endif 
    }
}

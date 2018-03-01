using PluginAPIs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PluginDemo
{
    public class ClassDemo : IPlugin
    {
        private enum DemoPluginEventIDs
        {
            Plugin_Called = 2000,
            Plugin_OnLoad = 2001,
            Plugin_OnDestroy = 2002
        }

        public ClassDemo() : base("DemoPlugin", new Version(1, 0, 1), "This is a demo plugin") { }
        
        public override void OnDestroy()
        {
            OnPluginCalled -= ClassDemo_OnPluginCalled;
            _logger.WriteEntry("This plugin is under OnDestroy event.", EventLogEntryType.Information, (int)DemoPluginEventIDs.Plugin_OnDestroy);
        }

        public override void OnLoad()
        {
            _logger.WriteEntry("This plugin is under OnLoad event.", EventLogEntryType.Information, (int)DemoPluginEventIDs.Plugin_OnLoad);
        }

        public override bool RegisterPlugin(EventLog logger)
        {
            try
            {
                OnPluginCalled += ClassDemo_OnPluginCalled;
                _logger = logger;
                return true;
            }catch(Exception)
            {
                return false;
            }
        }

        private void ClassDemo_OnPluginCalled(object sender, PluginEventArgs args)
        {
            _logger.WriteEntry("This plugin is called by host program.\r\n" + args.EventSource + "\r\n" + args.EventTextContent + "\r\n" + args.EventType, EventLogEntryType.Information, (int)DemoPluginEventIDs.Plugin_Called);
        }
        
    }
}

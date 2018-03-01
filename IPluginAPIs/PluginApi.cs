using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PluginAPIs
{
    public interface IPluginEvent
    {
        event OnPluginCalledDelegate OnPluginCalled;

        void TriggerEvent(object sender, PluginEventArgs args);
    }

    public delegate void OnPluginCalledDelegate(object sender, PluginEventArgs args);


    public abstract class IPlugin : IPluginEvent
    {
        public event OnPluginCalledDelegate OnPluginCalled;

        protected EventLog _logger;
        public abstract bool RegisterPlugin(EventLog logger);
        public abstract void OnLoad();
        public abstract void OnDestroy();

        public string PluginName => _pluginName;
        public Version PluginVersion=>_pluginVersion;
        public string PluginDescription =>_pluginDescription;

        protected string _pluginName;
        protected Version _pluginVersion;
        protected string _pluginDescription;

        protected IPlugin(string name, Version ver, string desc = "")
        {
            if (string.IsNullOrEmpty(name) || desc == null || ver == null)
            {
                throw new InvalidOperationException("Constructor parameters cannot be null!");
            }
            _pluginDescription = desc;
            _pluginName = name;
            _pluginVersion = ver;
        }
      
        public void TriggerEvent(object sender, PluginEventArgs args)
        {
            OnPluginCalled?.Invoke(sender, args);
        }
    }

    public class PluginEventArgs: EventArgs
    {
        public string EventSource;
        public string EventType;
        public string EventTextContent;
    }
}

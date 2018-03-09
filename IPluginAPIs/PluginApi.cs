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
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PluginAPIs
{
    public interface IPluginEvent
    {
        event AfterBadIPDetectedDelegate AfterBadIPDetected;
        event OnBadIPDetectedDelegate OnBadIPDetected;

        void RaiseAfterBadIPDetected(object sender, PluginEventArgs args);
        void RaiseOnBadIPDetected(object sender, PluginEventArgs args);
    }

    public delegate void AfterBadIPDetectedDelegate(object sender, PluginEventArgs args);
    public delegate void OnBadIPDetectedDelegate(object sender, PluginEventArgs args);


    public abstract class IPlugin : IPluginEvent
    {
        public event AfterBadIPDetectedDelegate AfterBadIPDetected;
        /// <summary>
        /// This delegate happens when an record detected by the mainprogram.
        /// </summary>
        public event OnBadIPDetectedDelegate OnBadIPDetected;

        protected EventLog _logger;
        /// <summary>
        /// Process plugin event registration, link event log
        /// </summary>
        /// <param name="logger">Event log provider (called by the main program)</param>
        /// <returns>If the registration succeed.</returns>
        public abstract bool RegisterPlugin(EventLog logger);
        /// <summary>
        /// Process plugin initialize
        /// </summary>
        public abstract void OnLoad();
        /// <summary>
        /// Process plugin destroy
        /// </summary>
        public abstract void OnDestroy();

        public string PluginName => _pluginName;
        public Version PluginVersion => _pluginVersion;
        public string PluginDescription => _pluginDescription;

        protected string _pluginName;
        protected Version _pluginVersion;
        protected string _pluginDescription;

        /// <summary>
        /// Plugin Initializer, load plugin information.
        /// </summary>
        /// <param name="name">Plugin Name</param>
        /// <param name="ver">Plugin Version</param>
        /// <param name="desc">Plugin Description (can be empty)</param>
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

        /// <summary>
        /// Trigger after a bad IP address item is detected.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public void RaiseOnBadIPDetected(object sender, PluginEventArgs args)
        {
            OnBadIPDetected?.Invoke(sender, args);
        }

        /// <summary>
        /// Not used currently. 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public void RaiseAfterBadIPDetected(object sender, PluginEventArgs args)
        {
            AfterBadIPDetected?.Invoke(sender, args);
        }
        
    }

    public class PluginEventArgs : EventArgs
    {
        public string EventSource;
        public string EventType;
        public string EventTextContent;
    }
}

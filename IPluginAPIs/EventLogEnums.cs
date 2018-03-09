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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PluginAPIs
{
    public class EventLogEnums
    {
        public enum LogCategories
        {
            Log_Info = 0,
            Log_Warning = 1,
            Log_Error = 2
        }
        public enum LogIDs
        {
            Log_Starting = 0,
            Log_Notice_FoundF2B = 1,
            Log_Notice_Quit = 2,
            Log_Plugin_Activated = 3,
            Log_Plugin_Deactivated = 4,
            Log_Notice_PlainInfo = 5,
            Log_Notice_DependencyStarting = 6,
            Log_Error_Generic = 1000,
            Log_Error_ParseFile = 1001,
            Log_Error_NoF2BFound = 1002,
            Log_Error_NoPluginFound = 1003,
            Log_Error_Plugin = 1004
        }
    }
}

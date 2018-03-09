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
using System.Diagnostics;
using f2b_wsl;
using FirewallPolicyPlugin;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace f2b_utest
{
    [TestClass]
    public class UnitTest_EnvInit
    {
        [TestMethod]
        public void TestMethod_FwPlugin()
        {
            FirewallPolicyModifier fwp = new FirewallPolicyModifier();
            EventLog eLog = new EventLog();
            eLog.BeginInit();
            if (!EventLog.SourceExists("Fail2BanWin"))
            {
                EventLog.CreateEventSource("Fail2BanWin", "Fail2BanWin");
            }
            eLog.EndInit();
            eLog.Source = "Fail2BanWin";
            eLog.Log = "Fail2BanWin";
            fwp.RegisterPlugin(eLog);
            fwp.OnLoad();

            fwp.RaiseBIPDeteacted("+212.2.2.2");
            fwp.RaiseBIPDeteacted("+123.12.2.34");
            fwp.RaiseBIPDeteacted("-212.2.2.2");

            fwp.RaiseBIPDeteacted("-123.12.2.34");
        }
    }
    
}

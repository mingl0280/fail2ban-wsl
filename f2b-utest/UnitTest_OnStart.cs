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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using f2b_wsl;

namespace f2b_utest
{
    [TestClass]
    public class UnitTest_OnStart
    {
        [TestMethod]
        public void TestMethod_OnStart()
        {
            MockOnStart mos = new MockOnStart();
            mos._OnStart(new string[] {""});
            var F2BEnv = mos.F2BEnvPool[@"C:\Users\mingl\AppData\Local\lxss\rootfs\etc\fail2ban"];
            Assert.AreEqual(F2BEnv.DummyFileDirectory, @"C:\Users\mingl\AppData\Local\lxss\rootfs\tmp\fail2ban");
            Assert.AreEqual(F2BEnv.DummyFileName, "fail2ban.dummy");

        }
    }

    public class MockOnStart : Fail2BanService
    {
        public void _OnStart(string[] args)
        {
            base.OnStart(args);
        }
    }
}

using System;
using f2b_wsl;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace f2b_utest
{
    [TestClass]
    public class UnitTest_EnvChange
    {
        [TestMethod]
        public void TestMethodFileChanged()
        {
            MockOnStart mos = new MockOnStart();
            mos._OnStart(new string[] { "" });
            Fail2BanEnv fEnv = mos.F2BEnvPool[@"C:\Users\mingl\AppData\Local\lxss\rootfs\etc\fail2ban"];
            fEnv.ChangeHandleTestMethod(@"C:\Users\mingl\AppData\Local\lxss\rootfs\tmp\fail2ban\fail2ban.dummy");
            
        }
    }
}

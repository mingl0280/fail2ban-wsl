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

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using f2b_wsl;
using System.IO;

namespace f2b_utest
{
    [TestClass]
    public class UnitTest_LineParser
    {
        private static string NormalCommentLine = @"#       journalmatch. See https://github.com/fail2ban/fail2ban/issues/959#issuecomment-74901200";
        private static string NonCommentLineWithKeyValuePair = @"failregex = ^%(__line_prefix)s( error:)?\s*client <HOST>#\S+( \([\S.]+\))?: (view (internal|external): )?query(?: \(cache\))? '.*' denied\s*$";
        private static string NonCommentLineWithoutKey = @"^%(__line_prefix)s( error:)?\s*client <HOST>#\S+( \([\S.]+\))?: zone transfer '\S+/AXFR/\w+' denied\s*$";
        private static string EmptyLine = "";
        private static string SpaceLine = "                                              ";
        private static string ErrorLine = "aaaa;;;bbb";
        private static string EmptyKeyError = "=bklkjl";
        private static string SpaceKeyError = "        = jlkjlkjlsd";
        

        [TestMethod]
        public void TestMethod_LineParser()
        {
            ConfigLineParser clp = new ConfigLineParser();
            clp.TryParseLine(NormalCommentLine);
            Assert.AreEqual(clp.Comment, NormalCommentLine);
            Assert.AreEqual(clp.Key, "");
            Assert.AreEqual(clp.Value, "");
            clp.TryParseLine(NonCommentLineWithKeyValuePair);
            Assert.AreEqual(clp.Key, "failregex");
            Assert.AreEqual(clp.Value, @"^%(__line_prefix)s( error:)?\s*client <HOST>#\S+( \([\S.]+\))?: (view (internal|external): )?query(?: \(cache\))? '.*' denied\s*$");
            Assert.AreEqual(clp.Comment, "");
            clp.TryParseLine(NonCommentLineWithoutKey, "failregex");
            Assert.AreEqual(clp.Value, NonCommentLineWithoutKey);
            Assert.AreEqual(clp.Comment, "");
            Assert.AreEqual(clp.Key, "failregex");
            clp.TryParseLine(EmptyLine);
            Assert.AreEqual(clp.Key, "");
            Assert.AreEqual(clp.Value, "");
            Assert.AreEqual(clp.Comment, "");
            clp.TryParseLine(SpaceLine);
            Assert.AreEqual(clp.Key, "");
            Assert.AreEqual(clp.Value, "");
            Assert.AreEqual(clp.Comment, "");
            Assert.ThrowsException<InvalidDataException>(() => clp.TryParseLine(EmptyKeyError));
            Assert.ThrowsException<InvalidDataException>(() => clp.TryParseLine(SpaceKeyError));
            Assert.ThrowsException<InvalidDataException>(() => clp.TryParseLine(ErrorLine));
        }
    }
}

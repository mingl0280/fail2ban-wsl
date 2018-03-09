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

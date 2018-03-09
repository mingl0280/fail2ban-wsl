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
using System.Collections.Generic;
using System.IO;

namespace f2b_wsl
{
    public class ConfigFile
    {
        private List<string> _sections;
        private Dictionary<string, Dictionary<string, string>> _items;
        private Dictionary<string, string> _vars;

        /// <summary>
        /// <localize>
        /// <zh-CHS>
        /// 配置文件的段
        /// </zh-CHS>
        /// <en>Configuration file sections</en>
        /// </localize>
        /// </summary>
        public List<string> Sections => _sections;
        ///
        /// <summary>
        ///<localize>
        /// <zh-CHS>配置文件项，基于每个配置段的</zh-CHS>
        /// <en>Configuration file items based on sections</en>
        /// </localize>
        /// </summary>
        public Dictionary<string, Dictionary<string, string>> Items => _items;

        public ConfigFile(FileInfo FilePath)
        {
            // read each line and throw to ConfigLineParser
            // if before: create new ConfigFile, use as initiate values to this file, read file.
            // if after: read this file, create new ConfigFile, override existing values.
        }
    }
    /*
    public class ConfItemPool
    {
        private Dictionary<string, Dictionary<string, List<string>>> _confItemRecord = new Dictionary<string, Dictionary<string, List<string>>>();
        public string Check(string ConfType, string Key)
        {
            //if (_confItemRecord[ConfType][Key].Count) //stucked here.
        }
        public string 
    }*/
}

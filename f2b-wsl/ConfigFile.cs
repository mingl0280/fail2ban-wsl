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

    public class ConfItemPool
    {
        private Dictionary<string, Dictionary<string, List<string>>> _confItemRecord = new Dictionary<string, Dictionary<string, List<string>>>();
        public string Check(string ConfType, string Key)
        {
            if (_confItemRecord[ConfType][Key].Count) //stucked here.
        }
        public string 
    }
}

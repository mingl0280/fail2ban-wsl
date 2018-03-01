using System.Collections.Generic;
using System.IO;

namespace f2b_wsl
{
    public class Fail2BanEnv
    {
        private string _f2bDirectoryString;
        private DirectoryInfo _f2bDirInfo;
        private List<string> _pluginList;
        private List<string> _jails;
        private List<string> _actions;
        private Dictionary<string, string> _filters = new Dictionary<string, string>();
        private List<FileSystemWatcher> logWatchers = new List<FileSystemWatcher>();

        public string F2bDirectoryString { get => _f2bDirectoryString; set => _f2bDirectoryString = value; }
        public List<string> PluginList { get => _pluginList; set => _pluginList = value; }
        public List<string> Jails { get => _jails; set => _jails = value; }
        public List<string> Actions { get => _actions; set => _actions = value; }

        public Fail2BanEnv(string BaseDirectory)
        {
            _f2bDirectoryString = BaseDirectory;
            _f2bDirInfo = new DirectoryInfo(BaseDirectory);
            InitJails();
        }

        private void InitJails()
        {

        }

        private void InitWatchers()
        {

        }

    }
}

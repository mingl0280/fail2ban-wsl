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
using PluginAPIs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using static PluginAPIs.EventLogEnums;

namespace f2b_wsl
{
    public class Fail2BanEnv : IDisposable
    {
        private string _f2bDirectoryString;
        private DirectoryInfo _f2bDirInfo;
        private List<string> _pluginList;
        private string _dummyFileDirectory, _dummyFileName;
        private Dictionary<string, string> _filters = new Dictionary<string, string>();
        private List<FileSystemWatcher> logWatchers = new List<FileSystemWatcher>();
        private Thread monitorThread;
        private FileSystemWatcher Fail2BanDummyFileWatcher;
        private Fail2BanService _parentService;
        private List<string> IOFile = new List<string>();
        private object IOLock = new object();
        private List<string> CachedDummyFileContent = new List<string>();
        private string CachedDummyFile = "";
        private bool disposedValue = false;
        private static object FwStateLocker = new object();
        private bool _running = true;

        public string F2bDirectoryString { get => _f2bDirectoryString; set => _f2bDirectoryString = value; }
        public List<string> PluginList { get => _pluginList; set => _pluginList = value; }
        public string DummyFileDirectory { get => _dummyFileDirectory; set => _dummyFileDirectory = value; }
        public string DummyFileName { get => _dummyFileName; set => _dummyFileName = value; }

        /// <summary>
        /// Initialize an environment and monitor
        /// </summary>
        /// <param name="BaseDirectory">Environment Base Directory</param>
        /// <param name="ParentService"></param>
        public Fail2BanEnv(string BaseDirectory, Fail2BanService ParentService)
        {
            _f2bDirectoryString = BaseDirectory;
            _f2bDirInfo = new DirectoryInfo(BaseDirectory);
            _parentService = ParentService;
            InitJails();
        }

        public System.Threading.ThreadState GetThreadStatus()
        {
            return (monitorThread == null) ? System.Threading.ThreadState.Unstarted : monitorThread.ThreadState;
        }

        public void StartMonitorThread()
        {
            monitorThread = new Thread(DummyMonitor);
            //monitorThread.Start();
        }

        public void StopThisEnv()
        {
            Fail2BanDummyFileWatcher.EnableRaisingEvents = false;
            monitorThread.Abort();
        }

        private void DummyMonitor()
        {
            while (_running)
            {
                Thread.Sleep(1000);
                Thread.Yield();
            }
        }

        private void InitJails()
        {
            StreamReader sr = new StreamReader(_f2bDirectoryString + @"\action.d\dummy-wsl.conf");

            while (!sr.EndOfStream)
            {
                string confline = sr.ReadLine();
                if (confline.StartsWith("actionban"))
                {
                    string[] SplitedStrings = confline.Split(new char[] { '>' }, StringSplitOptions.RemoveEmptyEntries);
                    string DummyFilePath = SplitedStrings[SplitedStrings.Length - 1].Trim();
                    int LastSlashIndex = DummyFilePath.LastIndexOf('/');
                    DummyFileDirectory = _f2bDirectoryString.Replace(@"\etc\fail2ban", DummyFilePath.Substring(0, LastSlashIndex).Replace(@"/", @"\"));
                    DummyFileName = DummyFilePath.Substring(LastSlashIndex + 1);
                    _parentService.EventLog.WriteEntry("Environment Dummy Operation File Found: " + DummyFileDirectory + @" \ " + DummyFileName, EventLogEntryType.Information, (int)LogIDs.Log_Notice_PlainInfo, (short)LogCategories.Log_Info);
                    break;
                }
            }
            sr.Close();
            sr.Dispose();
            try
            {
                Fail2BanDummyFileWatcher = new FileSystemWatcher(DummyFileDirectory + @"\");
                Fail2BanDummyFileWatcher.Changed += Fail2BanDummyFileWatcher_Changed;
                Fail2BanDummyFileWatcher.Deleted += Fail2BanDummyFileWatcher_Deleted;
                Thread.Sleep(5000);
#if DEBUG
                Thread.Sleep(5000);
#endif
                Fail2BanDummyFileWatcher.EnableRaisingEvents = true;

            }
            catch (Exception e)
            {
                _parentService.EventLog.WriteEntry("FSW init failed.\r\n" + e.Message + "\r\n" + e.StackTrace, EventLogEntryType.Error, (int)LogIDs.Log_Error_ParseFile, (short)LogCategories.Log_Error);
                throw new Exception("Forece Quit - Env not init properly.");
            }
            foreach (IPlugin plugin in _parentService.Plugins)
            {
                plugin.RaiseBeginInitialize(this, new EventArgs());
            }
            Thread.MemoryBarrier();
            FileContentChangeHandle(DummyFileDirectory + "\\" + DummyFileName);
            foreach (IPlugin plugin in _parentService.Plugins)
            {
                plugin.RaiseEndInitialize(this, new EventArgs());
            }
            Thread.MemoryBarrier();
        }

        private void Fail2BanDummyFileWatcher_Deleted(object sender, FileSystemEventArgs e)
        {
            lock (IOLock)
            {
                if (IOFile.Contains(e.FullPath) || e.ChangeType != WatcherChangeTypes.Changed || e.Name != DummyFileName)
                    return;
                foreach (string content in CachedDummyFileContent)
                {
                    foreach (IPlugin plugin in _parentService.Plugins)
                    {
                        plugin.RaiseOnBadIPDetected(this, new PluginEventArgs() { EventSource = _f2bDirectoryString, EventTextContent = "-" + content.Substring(1), EventType = "ClearBadIPs" });
                    }
                }
                CachedDummyFileContent.Clear();
            }
        }

        private void Fail2BanDummyFileWatcher_Changed(object sender, FileSystemEventArgs e)
        {
            lock (IOLock)
            {
                //_parentService.EventLog.WriteEntry(e.Name + "\r\n" + DummyFileName, EventLogEntryType.Information, (int)LogIDs.Log_Notice_PlainInfo, (short)LogCategories.Log_Info);
                if (IOFile.Contains(e.FullPath) || e.ChangeType != WatcherChangeTypes.Changed || e.Name != DummyFileName)
                    return;
                FileContentChangeHandle(e.FullPath);
            }
        }
#if DEBUG
        public void ChangeHandleTestMethod(string i)
        { FileContentChangeHandle(i); }
#endif

        private void FileContentChangeHandle(string filePath)
        {
            StreamReader sr;
            FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            sr = new StreamReader(fs);

            string tmpFile = sr.ReadToEnd();
            //Thread safe(for multiple events happening at one time)
            lock (FwStateLocker)
            {
                if (tmpFile == CachedDummyFile)
                {
                    sr.Close();
                    sr.Dispose();
                    return;
                }
                else
                {
                    if (tmpFile.Length < CachedDummyFile.Length)
                        CachedDummyFile = "";
                    sr.BaseStream.Seek(0, SeekOrigin.Begin);
                }

                //Only send new content to plugins
                string DifferentPart = (string.IsNullOrEmpty(CachedDummyFile) || string.IsNullOrWhiteSpace(CachedDummyFile)) ? tmpFile : tmpFile.Replace(CachedDummyFile, "");
                string[] DifferentRowsArray = DifferentPart.Split('\n');
                foreach (string DiffRowContent in DifferentRowsArray)
                {
                    if ((string.IsNullOrEmpty(DiffRowContent) || DiffRowContent.Length < 7))
                    { continue; }
                    foreach (IPlugin plugin in _parentService.Plugins)
                    {
                        plugin.RaiseOnBadIPDetected(this, new PluginEventArgs() { EventSource = _f2bDirectoryString, EventTextContent = DiffRowContent, EventType = "NewBadIPEvent" });
                    }
                }
                CachedDummyFile = tmpFile;
            }
            sr.Close();
            sr.Dispose();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Fail2BanDummyFileWatcher.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

    }
}

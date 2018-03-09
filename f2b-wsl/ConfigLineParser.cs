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
using System.IO;

namespace f2b_wsl
{
    public class ConfigLineParser
    {
        private string _key;
        private string _value;
        private string _comment;

        public ConfigLineParser()
        {
            _key = "";
            _value = "";
            _comment = "";
        }

        public string Key { get => _key; }
        public string Value { get => _value;  }
        public string Comment { get => _comment; }

        public void TryParseLine(string LineContent, string LineKey = "")
        {
            _key = "";
            _value = "";
            _comment = "";
            if (LineContent.StartsWith("#"))
            {
                _comment = LineContent;
                return;
            }
            LineContent = LineContent.Trim();
            if (string.IsNullOrEmpty(LineContent))
                return;

            if (LineKey != "")
            {
                _key = LineKey;
                _value = LineContent;
            }
            else
            {
                if (LineContent.Contains("="))
                {
                    string[] KeyValueSplited = LineContent.Split(new char[] { '=' }, 2);
                    if (KeyValueSplited[0].Trim() == "")
                        throw new InvalidDataException("Key is empty.");
                    _key = KeyValueSplited[0].Trim();
                    _value = KeyValueSplited[1].Trim();
                }
                else
                {
                    throw new InvalidDataException("Invalid line input.");
                }
            }
        }
    }
}

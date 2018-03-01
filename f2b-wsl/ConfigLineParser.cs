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

namespace AlexPilotti.FTPS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text.RegularExpressions;
    using Common;

    /// <summary>
    /// Based on Adarsh's code: http://blogs.msdn.com/adarshk/archive/2004/09/15/230177.aspx
    /// </summary>
    internal static class DirectoryListParser
    {
        enum EDirectoryListingStyle { UnixStyle, WindowsStyle, Unknown }

        const string UNIX_SYM_LINK_PATH_SEPARATOR = " -> ";

        public static IList<DirectoryListItem> GetDirectoryList(string dataString)
        {
            try
            {
                var myListArray = new List<DirectoryListItem>();
                var dataRecords = dataString.Split('\n');
                var directoryListStyle = GuessDirectoryListingStyle(dataRecords);
                foreach (var s in dataRecords)
                {
                    if (directoryListStyle != EDirectoryListingStyle.Unknown && s != "")
                    {
                        var f = new DirectoryListItem {Name = ".."};
                        switch (directoryListStyle)
                        {
                            case EDirectoryListingStyle.UnixStyle:
                                f = ParseDirectoryListItemFromUnixStyleRecord(s);
                                break;
                            case EDirectoryListingStyle.WindowsStyle:
                                f = ParseDirectoryListItemFromWindowsStyleRecord(s);
                                break;
                        }
                        if (!(f == null || f.Name == "." || f.Name == ".."))
                        {
                            myListArray.Add(f);
                        }
                    }
                }
                return myListArray;
            }
            catch (Exception ex)
            {
                throw new FTPException("Unable to parse the directory list", ex);
            }
        }

        private static DirectoryListItem ParseDirectoryListItemFromWindowsStyleRecord(string record)
        {
            //Assuming the record style as
            // 02-03-04  07:46PM       <DIR>          Append
            var f = new DirectoryListItem();
            var processStr = record.Trim();
            var dateStr = processStr.Substring(0, 8);
            processStr = processStr.Substring(8, processStr.Length - 8).Trim();
            var timeStr = processStr.Substring(0, 7);
            processStr = processStr.Substring(7, processStr.Length - 7).Trim();
            f.CreationTime = DateTime.Parse(dateStr + " " + timeStr, CultureInfo.GetCultureInfo("en-US"));
            if (processStr.Substring(0, 5) == "<DIR>")
            {
                f.IsDirectory = true;
                processStr = processStr.Substring(5, processStr.Length - 5).Trim();
            }
            else
            {
                f.IsDirectory = false;

                var i = processStr.IndexOf(' ');
                f.Size = ulong.Parse(processStr.Substring(0, i));

                processStr = processStr.Substring(i + 1);
            }
            f.Name = processStr;  //Rest is name   
            return f;
        }

        private static EDirectoryListingStyle GuessDirectoryListingStyle(string[] recordList)
        {
            foreach (var s in recordList)
            {
                if (s.Length > 10
                 && Regex.IsMatch(s.Substring(0, 10), "(-|d)(-|r)(-|w)(-|x)(-|r)(-|w)(-|x)(-|r)(-|w)(-|x)"))
                {
                    return EDirectoryListingStyle.UnixStyle;
                }

                if (s.Length > 8
                    && Regex.IsMatch(s.Substring(0, 8), "[0-9][0-9]-[0-9][0-9]-[0-9][0-9]"))
                {
                    return EDirectoryListingStyle.WindowsStyle;
                }
            }
            return EDirectoryListingStyle.Unknown;
        }

        private static DirectoryListItem ParseDirectoryListItemFromUnixStyleRecord(string record)
        {
            //Assuming record style as
            // dr-xr-xr-x   1 owner    group               0 Nov 25  2002 user

            // Mac OS X - tnftpd returns the total on the first line
            if (record.ToLower().StartsWith("total "))
                return null;

            var f = new DirectoryListItem();
            var processStr = record.Trim();
            f.Flags = processStr.Substring(0, 9);
            f.IsDirectory = f.Flags[0] == 'd';
            // Note: there is no way to determine here if the symlink refers to a dir or a file
            f.IsSymLink = f.Flags[0] == 'l';                
            processStr = processStr.Substring(11).Trim();
            CutSubstringFromStringWithTrim(ref processStr, " ", 0);   //skip one part
            f.Owner = CutSubstringFromStringWithTrim(ref processStr, " ", 0);
            f.Group = CutSubstringFromStringWithTrim(ref processStr, " ", 0);
            f.Size = ulong.Parse(CutSubstringFromStringWithTrim(ref processStr, " ", 0));  
            
            var creationTimeStr = CutSubstringFromStringWithTrim(ref processStr, " ", 8);
            var dateFormat = creationTimeStr.IndexOf(':') < 0 ? "MMM dd yyyy" : "MMM dd H:mm";

            // Some servers (e.g.: Mac OS X 10.5 - tnftpd) return days < 10 without a leading 0 
            if (creationTimeStr[4] == ' ')
                creationTimeStr = creationTimeStr.Substring(0, 4) + "0" + creationTimeStr.Substring(5);

            f.CreationTime = DateTime.ParseExact(creationTimeStr, dateFormat, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.AllowWhiteSpaces);

            if (f.IsSymLink && processStr.IndexOf(UNIX_SYM_LINK_PATH_SEPARATOR, StringComparison.Ordinal) > 0)
            {
                f.Name = CutSubstringFromStringWithTrim(ref processStr, UNIX_SYM_LINK_PATH_SEPARATOR, 0);
                f.SymLinkTargetPath = processStr;
            }
            else
                f.Name = processStr;   //Rest of the part is name
            return f;
        }

        private static string CutSubstringFromStringWithTrim(ref string s, string str, int startIndex)
        {
            var pos1 = s.IndexOf(str, startIndex, StringComparison.Ordinal);
            var retString = s.Substring(0, pos1);
            s = s.Substring(pos1 + str.Length).Trim();
            return retString;
        }
    }
}

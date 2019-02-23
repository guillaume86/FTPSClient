namespace AlexPilotti.FTPS.Client
{
    using System.IO;
    using System.Text;

    /// <summary>
    ///     Path helper
    /// </summary>
    public static class PathCheck
    {
        static char replacementChar = '_';

        /// <summary>
        /// Replaces all invalid characters found in the provided name
        /// </summary>
        /// <param name="fileName">A file name without directory information</param>
        /// <returns></returns>
        public static string GetValidLocalFileName(string fileName)
        {
            return ReplaceAllChars(fileName, Path.GetInvalidFileNameChars(), replacementChar);
        }

        private static string ReplaceAllChars(string str, char[] oldChars, char newChar)
        {
            var sb = new StringBuilder(str);
            foreach (var c in oldChars)
                sb.Replace(c, newChar);
            return sb.ToString();
        }
    }
}

namespace  AlexPilotti.FTPS.Client
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Security.Authentication;

    /// <summary>
    ///     The transfer mode
    /// </summary>
    public enum ETransferMode
    {
        /// <summary>
        /// 
        /// </summary>
        ASCII,
        /// <summary>
        /// 
        /// </summary>
        Binary
    }

    /// <summary>
    ///     The text encoding
    /// </summary>
    public enum ETextEncoding
    {
        /// <summary>
        /// 
        /// </summary>
        ASCII,
        /// <summary>
        /// 
        /// </summary>
        // ReSharper disable InconsistentNaming
        UTF8
        // ReSharper restore InconsistentNaming
    }

    /// <summary>
    ///     An FTP command acknowledgement or response
    /// </summary>
    public class FTPReply
    {
        /// <summary>
        ///     The response code
        /// </summary>
        public int Code { get; set; }

        /// <summary>
        ///     The response message
        /// </summary>
        public string Message { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            return string.Format("{0} {1}", Code, Message);
        }
    }

    /// <summary>
    ///     A single record from a dir or ls command
    /// </summary>
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class DirectoryListItem
    {
        /// <summary>
        ///     The size in bytes
        /// </summary>
        public ulong Size { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public string SymLinkTargetPath { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public string Flags { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public string Owner { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public string Group { get; set; }

        /// <summary>
        ///     True if the item is a directory
        /// </summary>
        public bool IsDirectory { get; set; }

        /// <summary>
        ///     True if the item is a symbolic link
        /// </summary>
        public bool IsSymLink { get; set; }

        /// <summary>
        ///     The item name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     The time the item was created
        /// </summary>
        public DateTime CreationTime { get; set; }
    }

    /// <summary>
    /// Encapsulates the SSL/TLS algorithms connection information.
    /// </summary>
    public class SslInfo
    {
        /// <summary>
        ///     ?
        /// </summary>
        public SslProtocols SslProtocol { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public CipherAlgorithmType CipherAlgorithm { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public int CipherStrength { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public HashAlgorithmType HashAlgorithm { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public int HashStrength { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public ExchangeAlgorithmType KeyExchangeAlgorithm { get; set; }

        /// <summary>
        ///     ?
        /// </summary>
        public int KeyExchangeStrength { get; set; }


        /// <inheritdoc />
        public override string ToString()
        {
            return SslProtocol + ", " +
                   CipherAlgorithm + " (" + CipherStrength + " bit), " +
                   KeyExchangeAlgorithm + " (" + KeyExchangeStrength + " bit), " +
                   HashAlgorithm + " (" + HashStrength + " bit)";
        }
    }

    /// <inheritdoc />
    public class LogCommandEventArgs : EventArgs
    {
        /// <inheritdoc />
        public LogCommandEventArgs(string commandText)
        {
            CommandText = commandText;
        }

        /// <summary>
        ///     The text of the command
        /// </summary>
        public string CommandText { get; }
    }

    /// <inheritdoc />
    public class LogServerReplyEventArgs : EventArgs
    {
        /// <inheritdoc />
        public LogServerReplyEventArgs(FTPReply serverReply)
        {
            ServerReply = serverReply;
        }

        /// <summary>
        ///     The server reply
        /// </summary>
        public FTPReply ServerReply { get; }
    }
}
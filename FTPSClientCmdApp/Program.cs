/*
 *  Copyright 2008 Alessandro Pilotti
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA 
 */

namespace AlexPilotti.FTPS.Client.ConsoleApp
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Reflection;
    using System.Security.Cryptography.X509Certificates;
    using Common;
    using Plossum;
    using Plossum.CommandLine;

    enum EInvalidSslCertificateHandling { Refuse, Accept, Prompt }
    enum Ex509CertificateExportFormats { Cert, SerializedCert, Pkcs12 }

    internal static class Program
    {
        private static readonly Options _options = new Options();
        private static IList<string> _commandArguments;
        const string PROGRAM_NAME = "ftps";
        const string LOG_DATE_TIME_FORMAT = "yyyy-MM-ddTHH:mm:ss.fffffffK";

        private static int _consoleFormatWidth = 80;
        // Needed to show progress during a file transfer
        private static int _lastCharPos;

        // Set during multiple file transfers
        private static int _filesTransferredCount;

        private static readonly Stopwatch _watch = new Stopwatch();

        private static StreamWriter _swLog;

        static int Main()
        {
            var retVal = -1;

            SetConsoleFormatWidth();

            try
            {
                var parser = new CommandLineParser(_options);
                parser.AddAssignmentCharacter(':', OptionStyles.All);

                IList<string> additionalErrors;
                ParseArguments(parser, out additionalErrors);

                if (_options.helpCmd || parser.HasErrors || additionalErrors.Count > 0)
                    ShowHelpInfoAndErrors(parser, additionalErrors, !_options.helpCmd);
                else
                {
                    if (!_options.noCopyrightInfo)
                        ShowHeader();

                    DoCommands();

                    retVal = 0;
                }                
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("ERROR: " + ex.Message);

                if (_options.verbose && ex.InnerException != null)
                    Console.Error.WriteLine("Inner exception: " + ex.InnerException);
            }

            return retVal;
        }

        private static void SetConsoleFormatWidth()
        {
            try
            {
                _consoleFormatWidth = Console.WindowWidth - 1;
            }
            catch (Exception)
            {
                _consoleFormatWidth = 80;
            } 
        }

        private static void DoCommands()
        {
            try
            {
                using (var client = new FtpsClient())
                {
                    InitLogFile(client);

                    DoConnect(client);

                    if (_options.listDirCmd)
                        DoList(client);

                    if (_options.getCmd)
                        DoGet(client);

                    if (_options.putCmd)
                        DoPut(client);

                    if (_options.deleteFileCmd)
                        DoDeleteFile(client);

                    if (_options.renameFileCmd)
                        DoRenameFile(client);

                    if (_options.makeDirCmd)
                        DoMakeDir(client);

                    if (_options.removeDirCmd)
                        DoRemoveDir(client);

                    if (_options.putUniqueFileCmd)
                        DoPutUniqueFile(client);

                    if (_options.putAppendFileCmd)
                        DoAppendFile(client);

                    if (_options.sysCmd)
                        DoSys(client);

                    if (_options.expCertCmd)
                        DoExportSslServerCert(client);

                    if (_options.featuresCmd)
                        DoFeatures(client);

                    if (_options.customCmd)
                        DoCustomCommand(client);

                    if (_options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Command completed");
                    }
                }
            }
            finally
            {
                if (_swLog != null)
                {
                    _swLog.Close();
                    _swLog = null;
                }
            }
        }

        private static void InitLogFile(FtpsClient client)
        {
            if (_options.logFileName != null)
            {
                _swLog = new StreamWriter(_options.logFileName);
                client.LogCommand += client_LogCommand;
                client.LogServerReply += client_LogServerReply;
            }
        }

        static void client_LogCommand(object sender, LogCommandEventArgs args)
        {
            if (_options.logFileTimeStamps)
                _swLog.WriteLine(DateTime.Now.ToString(LOG_DATE_TIME_FORMAT));

            // Hide password
            var cmdText = args.CommandText;
            if (cmdText.StartsWith("PASS "))
                cmdText = "PASS ********";

            _swLog.WriteLine(cmdText);
        }

        static void client_LogServerReply(object sender, LogServerReplyEventArgs args)
        {
            if (_options.logFileTimeStamps)
                _swLog.WriteLine(DateTime.Now.ToString(LOG_DATE_TIME_FORMAT));
            _swLog.WriteLine("{0} {1}", args.ServerReply.Code, args.ServerReply.Message);
        }

        private static void DoCustomCommand(FtpsClient client)
        {
            var reply = client.SendCustomCommand(_commandArguments[0]);

            Console.WriteLine("Server reply: " + reply);
        }

        private static void DoFeatures(FtpsClient client)
        {
            var features = client.GetFeatures();

            Console.WriteLine();

            if(features == null)
                Console.WriteLine("The FEAT command is not supported by the server");
            else
            {                
                Console.WriteLine("Features:");
                Console.WriteLine();

                foreach (var feature in features)
                    Console.WriteLine(feature);                
            }            
        }

        private static void DoExportSslServerCert(FtpsClient client)
        {
            if (client.SslSupportCurrentMode == ESSLSupportMode.ClearText)
                throw new Exception("The FTP connection is not encrypted");

            var cert = client.RemoteCertificate;
            if (cert == null)
                throw new Exception("No remote SSL/TLS X.509 certificate available");

            var exportX509ContentType = X509ContentType.Cert;
            switch (_options.sslCertExportFormat)
            {
                case Ex509CertificateExportFormats.Cert:
                    exportX509ContentType = X509ContentType.Cert;
                    break;
                case Ex509CertificateExportFormats.SerializedCert:
                    exportX509ContentType = X509ContentType.SerializedCert;
                    break;
                case Ex509CertificateExportFormats.Pkcs12:
                    exportX509ContentType = X509ContentType.Pkcs12;
                    break;
            }

            var exportedCert = cert.Export(exportX509ContentType);

            using (Stream s = File.Create(_commandArguments[0]))
                s.Write(exportedCert, 0, exportedCert.Length);
        }

        private static void ShowHelpInfoAndErrors(CommandLineParser parser, IList<string> additionalErrors, bool showErrors)
        {
            ShowHeader();

            Console.WriteLine();
            Console.WriteLine("Usage: " + PROGRAM_NAME + " [options] <command> [command specific arguments]");
            Console.WriteLine();
            Console.WriteLine();

            if (showErrors)
            {
                if (parser.HasErrors)
                    Console.WriteLine(parser.UsageInfo.GetErrorsAsString(_consoleFormatWidth));

                if (additionalErrors.Count > 0)
                    WriteAdditionalErrors(additionalErrors);

                Console.WriteLine();
            }
            
            Console.WriteLine(parser.UsageInfo.GetOptionsAsString(_consoleFormatWidth));

            ShowUsageSamples();
        }

        private static void ShowUsageSamples()
        {
            Console.WriteLine();
            Console.WriteLine("QUICK USAGE SAMPLES:");
            Console.WriteLine();
            Console.WriteLine("* Show the directory contents of a remote directory using anonymous");
            Console.WriteLine("  authentication on standard FTP (without SSL/TLS):");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -ssl ClearText -l /pub");
            Console.WriteLine();
            Console.WriteLine("* Connect to the server using SSL/TLS during authentication or");
            Console.WriteLine("  clear text mode (standard FTP) if FTPS is not supported:");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -U alex -l /pub");
            Console.WriteLine();
            Console.WriteLine("* Download a remote file using control and data channel SSL/TLS encryption:");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -U alex -ssl All -g /remote/path/somefile.txt /local/path/");
            Console.WriteLine();
            Console.WriteLine("* Upload a local file with a control channel encrypted");
            Console.WriteLine("  during authentication only:");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -U alex -ssl CredentialsRequired -p /local/path/somefile.txt /remote/path/");
            Console.WriteLine();
            Console.WriteLine("* Recursively download a whole directory tree:");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -r -g /remote/path/* \local\path\");
            Console.WriteLine();
            Console.WriteLine("* Implicit FTPS on port 21:");
            Console.WriteLine();
            Console.WriteLine(PROGRAM_NAME + @" -h ftp.yourserver.com -port 21 -ssl Implicit -U alex -l");
            Console.WriteLine();
            Console.WriteLine("ADDITIONAL INFO AND HELP: http://www.codeplex.com/ftps");
        }

        private static void ShowHeader()
        {
            Console.WriteLine("Alex FTPS version " + GetAssemblyVersion());
            Console.WriteLine("Copyright (C) Alessandro Pilotti 2008-2009");
            Console.WriteLine();
            Console.WriteLine("http://www.codeplex.com/ftps");
            Console.WriteLine("info@pilotti.it");
            Console.WriteLine();
            Console.WriteLine("This is free software, you may use it under the terms of");            
            Console.WriteLine("the LGPL license <http://www.gnu.org/copyleft/lesser.html>");            
        }

        private static string GetAssemblyVersion()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }

        private static void ParseArguments(CommandLineParser parser, out IList<string> additionalErrors)
        {            
            parser.Parse();

            additionalErrors = new List<string>();

            // Get the arguments left off by the parser
            _commandArguments = new List<string>();

            if (!parser.HasErrors)
            {
                PerformAdditionalCommandLineValidation(parser, additionalErrors);
                // The remaining arguments are the valid command parameters
                ((List<string>) _commandArguments).AddRange(parser.RemainingArguments);
            }
        }

        private static void WriteAdditionalErrors(IList<string> additionalErrors)
        {
            var indentWidth = 3;

            Console.WriteLine("Errors:");
            foreach (var message in additionalErrors)
                Console.WriteLine(StringFormatter.FormatInColumns(indentWidth, 1, new ColumnInfo(1, "*"),
                                  new ColumnInfo(_consoleFormatWidth - 1 - indentWidth - 1, message)));            
        }

        private static void PerformAdditionalCommandLineValidation(CommandLineParser parser, IList<string> additionalErrors)
        {
            var messageTemplate = "Wrong arguments number supplied for the \"{0}\" command.\r\n" + 
                                     "Usage: " + PROGRAM_NAME + " [options] {1}";

            if (_options.listDirCmd && parser.RemainingArguments.Count > 1)
                additionalErrors.Add(string.Format(messageTemplate, "list", "[remoteDir]"));           

            if(_options.getCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "get", "<remoteFile|remoteFilePattern> [localDir|localFile]"));

            if (_options.putCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "put", "<localFile|localFilePattern> [remoteDir|remoteFile]"));

            if (_options.deleteFileCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "delete", "<remoteFile>"));

            if (_options.renameFileCmd && parser.RemainingArguments.Count != 2)
                additionalErrors.Add(string.Format(messageTemplate, "rename", "<fromRemoteFile> <toRemoteFile>"));

            if (_options.makeDirCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "mkdir", "<remoteDir>"));

            if (_options.removeDirCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "rmdir", "<remoteDir>"));

            if (_options.putUniqueFileCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "putUnique", "<localFile> [remoteDir]"));

            if (_options.putAppendFileCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "putAppend", "<localFile> [remoteDir|remoteFile]"));

            if (_options.sysCmd && parser.RemainingArguments.Count > 0)
                additionalErrors.Add(string.Format(messageTemplate, "sys", ""));

            if (_options.expCertCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "exportSslServerCert", "<certFileName>"));

            if (_options.featuresCmd && parser.RemainingArguments.Count > 0)
                additionalErrors.Add(string.Format(messageTemplate, "features", ""));

            if (_options.customCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "custom", "<customFTPCommand>"));
        }

        private static void DoSys(FtpsClient client)
        {
            var systemInfo = client.GetSystem();
            Console.WriteLine("Remote system: \"" + systemInfo + "\"");
        }

        private static void DoDeleteFile(FtpsClient client)
        {
            client.DeleteFile(NormalizeRemotePath(_commandArguments[0]));
        }

        private static void DoRenameFile(FtpsClient client)
        {
            client.RenameFile(NormalizeRemotePath(_commandArguments[0]), 
                              NormalizeRemotePath(_commandArguments[1]));
        }

        private static void DoPutUniqueFile(FtpsClient client)
        {
            var localPathName = _commandArguments[0];

            if(_commandArguments.Count > 1)
            {
                var remoteDirName = NormalizeRemotePath(_commandArguments[1]);
                client.SetCurrentDirectory(remoteDirName);
            }

            string remoteFileName;
            client.PutUniqueFile(localPathName, out remoteFileName, TransferCallback);            

            Console.WriteLine("Unique file uploaded. File name: \"" + remoteFileName + "\"");
        }

        private static void DoAppendFile(FtpsClient client)
        {
            var localPathName = _commandArguments[0];
            var remotePathName = GetRemotePathName(localPathName);
            client.AppendFile(localPathName, remotePathName, TransferCallback);            
        }

        private static void DoMakeDir(FtpsClient client)
        {
            client.MakeDir(NormalizeRemotePath(_commandArguments[0]));
        }

        private static void DoRemoveDir(FtpsClient client)
        {
            client.RemoveDir(NormalizeRemotePath(_commandArguments[0]));
        }

        private static void DoConnect(FtpsClient client)
        {
            WriteCredentialsEncryptionWarning();

            CheckPassword();

            var port = _options.port;
            if (port == 0)
                port = (_options.SslRequestSupportMode & ESSLSupportMode.Implicit) == ESSLSupportMode.Implicit ? 990 : 21;

            NetworkCredential credential = null;
            if (!string.IsNullOrEmpty(_options.UserName))
                credential = new NetworkCredential(_options.UserName, _options.password);

            X509Certificate x509ClientCert = null;
            if (_options.sslClientCertPath != null)
                x509ClientCert = X509Certificate.CreateFromCertFile(_options.sslClientCertPath);

            client.Connect(_options.hostName, port,
                           credential,
                           _options.SslRequestSupportMode,
                           ValidateTestServerCertificate,
                           x509ClientCert, 
                           _options.sslMinKeyExchangeAlgStrength, 
                           _options.sslMinCipherAlgStrength,
                           _options.sslMinHashAlgStrength,
                           _options.timeout * 1000,
                           _options.useCtrlEndPointAddressForData,
                           _options.dataConnectionMode);

            // client.Connect already sets binary by default
            if (_options.transferMode != ETransferMode.Binary)
                client.SetTransferMode(_options.transferMode);

            WriteConnectionInfo(client);

            WriteSslStatus(client);
        }

        private static void WriteConnectionInfo(FtpsClient client)
        {
            if (_options.verbose)
            {
                Console.WriteLine();
                Console.WriteLine("Banner message:");
                Console.WriteLine();
                Console.WriteLine(client.BannerMessage);
                Console.WriteLine();

                Console.WriteLine("Welcome message:");
                Console.WriteLine();
                Console.WriteLine(client.WelcomeMessage);
                Console.WriteLine();

                Console.WriteLine("Text encoding: " + client.TextEncoding);
                Console.WriteLine("Transfer mode: " + client.TransferMode);
            }
        }

        private static void WriteCredentialsEncryptionWarning()
        {
            if (_options.UserName != null && (_options.SslRequestSupportMode & ESSLSupportMode.CredentialsRequired) != ESSLSupportMode.CredentialsRequired)
            {
                Console.WriteLine();

                Console.WriteLine((_options.SslRequestSupportMode & ESSLSupportMode.CredentialsRequested) != ESSLSupportMode.CredentialsRequested ? "WARNING: Credentials will be sent in clear text" : "WARNING: Credentials might be sent in clear text");
                Console.WriteLine("Please see the \"ssl\" option for details");
            }
        }

        private static void WriteSslStatus(FtpsClient client)
        {
            if (_options.verbose)
            {
                string sslSupportDesc = null;

                if ((client.SslSupportCurrentMode & ESSLSupportMode.CredentialsRequested) == ESSLSupportMode.CredentialsRequested)
                    sslSupportDesc = "Credentials";
                if ((client.SslSupportCurrentMode & ESSLSupportMode.ControlChannelRequested) == ESSLSupportMode.ControlChannelRequested)
                    sslSupportDesc += ", Commands";

                if ((client.SslSupportCurrentMode & ESSLSupportMode.DataChannelRequested) == ESSLSupportMode.DataChannelRequested)
                {
                    if (sslSupportDesc != null)
                        sslSupportDesc += ", ";
                    sslSupportDesc += "Data";
                }

                if (sslSupportDesc == null)
                    sslSupportDesc = "None";

                Console.WriteLine();
                Console.WriteLine("SSL/TLS support: " + sslSupportDesc);

                var sslInfo = client.SslInfo;
                if (sslInfo != null)
                {
                    Console.WriteLine("SSL/TLS Info: " + sslInfo);
                }
            }
        }

        private static void DoGet(FtpsClient client)
        {
            var remotePathPattern = _commandArguments[0];
            
            if (IsWildCardPath(remotePathPattern))
                DoWildCardGet(client, remotePathPattern);
            else
                DoSingleFileGet(client, remotePathPattern);
        }

        private static void DoSingleFileGet(FtpsClient client, string remotePathName)
        {
            string localPathName = null;
            string localDirName = null;
            if (_commandArguments.Count > 1)
            {
                if (Directory.Exists(_commandArguments[1]))
                    localDirName = _commandArguments[1];
                else
                    localPathName = _commandArguments[1];

            }
            else
                localDirName = Directory.GetCurrentDirectory();

            if (localPathName == null)
            {                
                var remoteFileName = Path.GetFileName(remotePathName);
                localPathName = Path.Combine(localDirName ?? throw new InvalidOperationException($"{nameof(localDirName)} cannot be null"), 
                    remoteFileName ?? throw new InvalidOperationException($"{nameof(remoteFileName)} cannot be null"));
            }

            client.GetFile(remotePathName, localPathName, TransferCallback);
        }

        private static void DoWildCardGet(FtpsClient client, string remotePathPattern)
        {
            var remoteDirName = NormalizeRemotePath(Path.GetDirectoryName(remotePathPattern));
            var remoteFilePattern = Path.GetFileName(remotePathPattern);

            _filesTransferredCount = 0;

            var localDirName = _commandArguments.Count > 1 ? _commandArguments[1] : Directory.GetCurrentDirectory();

            client.GetFiles(remoteDirName, localDirName, remoteFilePattern, EPatternStyle.Wildcard, _options.recursive, TransferCallback);

            Console.WriteLine();
            if (_filesTransferredCount > 0)
                Console.WriteLine("Downloaded files: {0}", _filesTransferredCount);
            else
                Console.Error.WriteLine("WARNING: No files downloaded");            
        }

        private static bool IsWildCardPath(string pathName)
        {
            return pathName.Contains("*") || pathName.Contains("?");
        }

        private static void DoPut(FtpsClient client)
        {
            var localPathPattern = _commandArguments[0];            

            if (IsWildCardPath(localPathPattern))
                DoWildCardPut(client, localPathPattern);
            else
                DoSingleFilePut(client, localPathPattern);            
        }

        private static void DoWildCardPut(FtpsClient client, string localPathPattern)
        {
            var localDirName = Path.GetDirectoryName(localPathPattern);
            var localFilePattern = Path.GetFileName(localPathPattern);

            _filesTransferredCount = 0;

            string remoteDirName = null;
            if (_commandArguments.Count > 1)
                remoteDirName = NormalizeRemotePath(_commandArguments[1]);

            client.PutFiles(localDirName, remoteDirName, localFilePattern, EPatternStyle.Wildcard, _options.recursive, TransferCallback);

            Console.WriteLine();
            if (_filesTransferredCount > 0)
                Console.WriteLine("Uploaded files: {0}", _filesTransferredCount);
            else
                Console.Error.WriteLine("WARNING: No files uploaded");            
        }

        private static void DoSingleFilePut(FtpsClient client, string localPathName)
        {
            var remotePathName = GetRemotePathName(localPathName);
            client.PutFile(localPathName, remotePathName, TransferCallback);
        }

        private static string GetRemotePathName(string localPathName)
        {
            string remotePathName;
            var localFileName = Path.GetFileName(localPathName);
            if (_commandArguments.Count > 1)
            {
                var str = NormalizeRemotePath(_commandArguments[1]);

                if (str.EndsWith("/"))
                    remotePathName = str + localFileName;
                else
                    remotePathName = str;
            }
            else
                remotePathName = localFileName;
            return remotePathName;
        }

        /// <summary>
        /// Replaces the "\" path separator with "/"
        /// </summary>
        /// <param name="remotePath"></param>
        /// <returns></returns>
        private static string NormalizeRemotePath(string remotePath)
        {
            return remotePath != null ? remotePath.Replace("\\", "/") : null;
        }

        private static void DoList(FtpsClient client)
        {
            var remoteDirName = _commandArguments.Count > 0 ? NormalizeRemotePath(_commandArguments[0]) : client.GetCurrentDirectory();

            Console.WriteLine();
            Console.WriteLine("Remote directory: " + remoteDirName);

            // Get the dirList before the WriteLine in order to avoid writing an empty newline in case of exceptions
            var dirList = client.GetDirectoryListUnparsed(remoteDirName);
            Console.WriteLine();
            Console.WriteLine(dirList);
        }

        private static bool ValidateTestServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var certOk = false;

            if (sslPolicyErrors == SslPolicyErrors.None)
                certOk = true;
            else
            {
                Console.Error.WriteLine();
                
                if((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate chain errors");

                if((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate name mismatch");

                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate not available");                

                if (_options.sslInvalidServerCertHandling == EInvalidSslCertificateHandling.Accept)
                    certOk = true;
            }

            if (!certOk || _options.verbose)
            {
                Console.WriteLine();
                Console.WriteLine("SSL/TLS Server certificate details:");
                Console.WriteLine();
                Console.WriteLine(Utility.GetCertificateInfo(certificate));
            }

            if (!certOk && _options.sslInvalidServerCertHandling == EInvalidSslCertificateHandling.Prompt)
            {                
                certOk = Utility.ConsoleConfirm("Accept invalid server certificate? (Y/N)");                
            }

            return certOk;
        }

        private static void CheckPassword()
        {
            if (_options.UserName != null && _options.password == null)
            {
                Console.WriteLine();
                Console.Write("Password: ");
                _options.password = Utility.ReadConsolePassword();
                Console.WriteLine();
            }
        }

        private static void TransferCallback(FtpsClient sender, ETransferActions action, string localObjectName, string remoteObjectName, ulong fileTransmittedBytes, ulong? fileTransferSize, ref bool cancel)
        {
            switch (action)
            {
                case ETransferActions.FileDownloaded:
                case ETransferActions.FileUploaded:
                    OnFileTransferCompleted(fileTransmittedBytes, fileTransferSize);                    
                    break;
                case ETransferActions.FileDownloadingStatus:
                case ETransferActions.FileUploadingStatus:
                    OnFileTransferStatus(action, localObjectName, remoteObjectName, fileTransmittedBytes, fileTransferSize);
                    break;
                case ETransferActions.RemoteDirectoryCreated:
                    if (_options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Remote directory created: " + remoteObjectName);                        
                    }
                    break;
                case ETransferActions.LocalDirectoryCreated:
                    if (_options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Local directory created: " + localObjectName);                        
                    }
                    break;
            }
        }

        private static void OnFileTransferStatus(ETransferActions action, string localObjectName, string remoteObjectName, ulong fileTransmittedBytes, ulong? fileTransferSize)
        {
            if (fileTransmittedBytes == 0)
            {
                // Download / upload start

                _watch.Reset();
                _watch.Start();

                _lastCharPos = 0;

                Console.WriteLine();

                if (action == ETransferActions.FileDownloadingStatus)
                {
                    Console.WriteLine("Source (remote): " + remoteObjectName);
                    Console.WriteLine("Dest (local): " + localObjectName);
                }
                else
                {
                    Console.WriteLine("Source (local): " + localObjectName);
                    Console.WriteLine("Dest (remote): " + remoteObjectName);
                }

                Console.Write("File Size: ");
                if (fileTransferSize != null)
                {
                    Console.WriteLine(fileTransferSize.Value.ToString("N0") + " Byte");
                    Console.WriteLine();
                    Console.WriteLine("0%".PadRight(_consoleFormatWidth - 4, ' ') + "100%");
                }
                else
                    Console.WriteLine("Unknown");
            }
            else if (fileTransferSize != null)
            {
                // Download / upload progress

                var charPos = (int)(fileTransmittedBytes * (ulong)_consoleFormatWidth / fileTransferSize);

                if (charPos - _lastCharPos > 0)
                {
                    Console.Write(new String('.', charPos - _lastCharPos));
                    _lastCharPos = charPos;
                }
            }
        }

        private static void OnFileTransferCompleted(ulong fileTransmittedBytes, ulong? fileTransferSize)
        {
            _watch.Stop();

            _filesTransferredCount++;

            if (fileTransferSize != null)
            {
                Console.WriteLine();

                if (fileTransferSize != fileTransmittedBytes)
                {
                    Console.Error.WriteLine("WARNING: Declared transfer file size ({0:N0}) differs from the transferred bytes count ({1:N0})",
                                      fileTransferSize.Value, fileTransmittedBytes);                    
                }
            }

            double kBs = 0;
            if (_watch.ElapsedMilliseconds > 0)
                kBs = fileTransmittedBytes / 1.024D / _watch.ElapsedMilliseconds;

            Console.WriteLine("Elapsed time: " + Utility.FormatTimeSpan(_watch.Elapsed) + " - Average rate: " + kBs.ToString("N02") + " KB/s");
        }
    }
}

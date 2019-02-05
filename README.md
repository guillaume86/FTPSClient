# FTPSClient
Extension of Alex's FTPS client, forked from [luck02](https://github.com/luck02/FTPSClient) and recompiled for .net4.7.2 so it works as a netstandard reference. I will probably add an overload for RemoveDir() that does a recursive delete soon.

Original project: https://ftps.codeplex.com/

Protocols set to:
SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls

luck02's Package at:
https://www.nuget.org/packages/AlexFTPSv2

Tested with Azure FTPS.

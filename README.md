# FTPSClient
Extension of Alex's FTPS client, forked from [luck02](https://github.com/luck02/FTPSClient) and recompiled for .net4.7.2 so it works as a netstandard reference. 

Release/Packaging build status: [![Build status](https://ci.appveyor.com/api/projects/status/f2v7bjngjqbhxfey?svg=true)](https://ci.appveyor.com/project/StingyJack/ftpsclient)

This package is available at ...(coming soon)

Original project: https://ftps.codeplex.com/

luck02's Package at:
https://www.nuget.org/packages/AlexFTPSv2



Tested as working with Azure FTPS for uploading new WebJobs as of Feb 2019

Protocols set to:
SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls

Planned updates

- Add an overload for RemoveDir() that does a recursive delete.

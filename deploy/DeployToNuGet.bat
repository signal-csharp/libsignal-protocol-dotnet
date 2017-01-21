REM Use this to deploy a new version of libtextsecure-uwp to NuGet. Note that you first have to set your API key
REM (which you can find by signing into NuGet.org and looking at your account page) by running this command:
REM NuGet.exe setApiKey 00000-0000-0000-0000-000000 (replace with your key)

nuget push ..\..\libsignal-protocol-dotnet.*.nupkg

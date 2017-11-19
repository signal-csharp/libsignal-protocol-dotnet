dotnet clean
dotnet restore
dotnet build
dotnet test libsignal-protocol-dotnet-tests\libsignal-protocol-dotnet-tests.csproj
if not "%errorlevel%"=="0" exit 1
dotnet pack --include-symbols --include-source
rem nuget push libsignal-protocol-dotnet\bin\Debug\libsignal-protocol-dotnet.2.5.3.2.nupkg -SymbolSource https://www.myget.org/F/signal-csharp/symbols/api/v2/packag
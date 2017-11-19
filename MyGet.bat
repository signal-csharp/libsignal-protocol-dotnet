dotnet clean
dotnet restore
dotnet build
dotnet test libsignal-protocol-dotnet-tests\libsignal-protocol-dotnet-tests.csproj
if not "%errorlevel%"=="0" exit 1
dotnet pack --include-symbols --include-source

dotnet clean
dotnet restore
dotnet build
dotnet test libsignal-protocol-dotnet-tests\libsignal-protocol-dotnet-tests.csproj
dotnet pack --include-symbols --include-source

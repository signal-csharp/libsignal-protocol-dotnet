dotnet clean
dotnet restore
nuget restore
dotnet build
dotnet pack --include-symbols --include-source
rem dotnet test
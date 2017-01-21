setlocal
rem SET PATH=%PATH%;%USERPROFILE%\.nuget\packages\Google.ProtocolBuffers\2.4.1.555\tools
ProtoGen -namespace="libsignal.state" -umbrella_classname="StorageProtos" -nest_classes=true -output_directory="../state/" LocalStorageProtocol.proto
ProtoGen -namespace="libsignal.protocol" -umbrella_classname="SignalProtos" -nest_classes=true -output_directory="../protocol/" WhisperTextProtocol.proto
ProtoGen -namespace="libsignal.fingerprint" -umbrella_classname="FingerprintProtos" -nest_classes=true -output_directory="../fingerprint/" FingerprintProtocol.proto

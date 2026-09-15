# Biz.Bizadm.KMS.Credentials.Runtime.osx

내부 구현 패키지입니다. **직접 참조하지 마세요.**

macOS Keychain(`keychain`) 기반 OS 자격 증명 구현입니다. 이 구현은 `Biz.Bizadm.KMS.Credentials` facade 패키지의 `runtimes/osx/lib/net10.0` 자산으로 포함됩니다.

```csharp
IOsKekCredentialStore creds = OsKekCredentialProvider.CreateForCurrentOs();
```

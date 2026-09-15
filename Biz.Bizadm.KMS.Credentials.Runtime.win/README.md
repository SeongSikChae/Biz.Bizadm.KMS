# Biz.Bizadm.KMS.Credentials.Runtime.win

내부 구현 패키지입니다. **직접 참조하지 마세요.**

Windows Credential Manager(`wincredman`) 기반 OS 자격 증명 구현입니다. 이 구현은 `Biz.Bizadm.KMS.Credentials` facade 패키지의 `runtimes/win/lib/net10.0` 자산으로 포함됩니다.

```csharp
IOsKekCredentialStore creds = OsKekCredentialProvider.CreateForCurrentOs();
```

# Biz.Bizadm.KMS.Protect.Runtime.osx

내부 구현 패키지입니다. **직접 참조하지 마세요.**

macOS Keychain(`keychain`) 기반 OS 자격 증명 구현입니다. 소비자는 [`Biz.Bizadm.KMS.Protect`](https://www.nuget.org/packages/Biz.Bizadm.KMS.Protect)만 참조하면 NuGet RID restore가 이 패키지를 가져옵니다.

```csharp
IOsKekCredentialStore creds = OsKekCredentialProvider.CreateForCurrentOs();
```

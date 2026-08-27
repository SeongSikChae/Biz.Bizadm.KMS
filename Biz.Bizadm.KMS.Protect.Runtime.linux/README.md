# Biz.Bizadm.KMS.Protect.Runtime.linux

내부 구현 패키지입니다. **직접 참조하지 마세요.**

Linux Secret Service(`secretservice`) 기반 OS 자격 증명 구현입니다. 소비자는 [`Biz.Bizadm.KMS.Protect`](https://www.nuget.org/packages/Biz.Bizadm.KMS.Protect)만 참조하면 NuGet RID restore가 이 패키지를 가져옵니다.

헤드리스 환경에서는 프로세스 시작 전에 `GCM_CREDENTIAL_STORE=gpg` 등을 설정할 수 있습니다.

```csharp
IOsKekCredentialStore creds = OsKekCredentialProvider.CreateForCurrentOs();
```

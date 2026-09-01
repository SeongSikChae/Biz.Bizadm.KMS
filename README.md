# Biz.Bizadm.KMS

Key Management System 라이브러리. 공통 `ICipher` 아래에 KEK wrap/unwrap용 `IKekCipher`와 데이터 암·복호화용 `IDekCipher`를 두고, 소프트웨어·TPM·Azure Key Vault 백엔드를 제공한다.

대상 프레임워크: `net10.0`

## 계층

```text
ICipher
├── IKekCipher                       # 키 물질 wrap/unwrap (DEK 보호)
│   ├── AesGcmKekCipher              # 소프트웨어 AES-GCM
│   ├── TpmKekCipher                 # TPM AES-256-CFB
│   └── AzureKeyVaultKekCipher       # Azure Key Vault RSA-OAEP wrap
├── IKekManager                      # KEK 버전 관리·DEK re-wrap
│   ├── AesGcmKekManager
│   ├── TpmKekManager
│   └── AzureKeyVaultKekManager
└── IDekCipher                       # 데이터 암·복호화
    └── AesGcmDekCipher              # AES-GCM (DEK는 envelope로 보관)
```

`AesGcmKekCipher`와 `AesGcmDekCipher`는 `AbstractAesGcmCipher`를 공유한다. 출력 형식은 `nonce(12) || cipher || tag(16)`.

```csharp
public interface ICipher : IDisposable
{
    byte[] Encrypt(byte[] plain);
    Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default);
    byte[] Decrypt(byte[] encrypted);
    Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default);
}

public interface IKekCipher : ICipher
{
    string KeyId { get; }
}
public interface IDekCipher : ICipher { }
```

## IKekManager

KEK 버전 레지스트리와 DEK re-wrap 오케스트레이션을 담당한다. 호스트 앱은 개별 `IKekCipher`보다 Manager를 권장 진입점으로 사용한다.

| Manager | Rotate API |
|---|---|
| `AesGcmKekManager` | `Rotate(IKekCredentialProvider, byte[] newSalt, int iterationCount)` |
| `AzureKeyVaultKekManager` | `RotateAsync(CancellationToken)` |
| `TpmKekManager` | `Rotate(FileInfo newKekBlobFile)` |

공통 API: `Current`, `Resolve(keyId)`, `RewrapDek(envelope)`, `RewrapDekFile(dekFile)`, `Release(keyId)`.

로테이션 후 이전 KEK는 registry에 남아 아직 re-wrap되지 않은 DEK도 처리할 수 있다. 모든 DEK re-wrap이 끝나면 `Release(oldKeyId)`로 이전 KEK를 해제한다. `Current`는 `Release`할 수 없다.

```csharp
using AesGcmKekManager manager = AesGcmKekManager.Create(credentialProvider, salt, iterations);
using AesGcmDekCipher dek = AesGcmDekCipher.Create(manager.Current, new FileInfo("dek.bin"));

string oldKeyId = manager.Current.KeyId;
manager.Rotate(newCredential, newSalt, iterations);
manager.RewrapDekFile(new FileInfo("dek.bin"));
manager.Release(oldKeyId);
```

## KEK Rotation과 DEK envelope

**KEK rotation**은 DEK 평문을 바꾸지 않고 wrap만 새 KEK로 교체한다. **DEK rotation**(데이터 재암호화)은 별도 작업이다.

`IKekCipher.KeyId` 형식:

| 구현 | KeyId |
|---|---|
| `AesGcmKekCipher` | `aesgcm:{SHA256(derivedKey)}` |
| `AzureKeyVaultKekCipher` | `azurekv:{keyName}:{version}` |
| `TpmKekCipher` | `tpm:{SHA256(kekPublic)}` |

wrap된 DEK는 **envelope 포맷**(breaking change)으로 저장한다. raw ciphertext는 더 이상 읽지 않는다.

| 필드 | 크기 | 설명 |
|---|---|---|
| Magic | 4 | `KDEK` |
| Version | 1 | `1` |
| KeyIdLength | 2 | UTF-8 KeyId 길이 |
| KeyId | variable | wrap에 사용된 KEK KeyId |
| WrappedKeyLength | 4 | ciphertext 길이 |
| WrappedKey | variable | KEK로 wrap된 DEK |

저수준 re-wrap: `targetKek.RewrapDek(sourceKek, wrappedDek)` 또는 `AesGcmDekCipher.Rewrap(source, target, dekFile)`.

로컬 AES·TPM 구현의 `*Async`는 동기 경로를 `Task.FromResult`로 감싼다. Azure Key Vault 구현은 SDK 비동기 API를 그대로 사용한다.

KEK 생성에 쓰는 패스워드는 `IKekCredentialProvider`로 주입한다. `Create`가 `GetPassword()`로 받은 뒤 사용 후 `ZeroMemory`한다.

```csharp
public interface IKekCredentialProvider
{
    byte[] GetPassword();
    Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default);
}
```

| 구현 | 저장소 |
|---|---|
| `AzureKeyVaultKekCredentialProvider` | Azure Key Vault Secret (없으면 32바이트 시크릿 생성) |
| `OsKekCredentialProvider` (`Biz.Bizadm.KMS.Protect`) | OS 자격 증명 금고 (RID별 runtime) |

그 외는 호스트 앱이 `IKekCredentialProvider`를 구현한다.

## Protect (OS 자격 증명, RID runtime 패키지)

소비자는 **`Biz.Bizadm.KMS.Protect`**만 참조한다. NuGet이 RID에 맞는 내부 구현 패키지를 가져온다 (직접 참조하지 않음).

| 패키지 | 용도 |
|---|---|
| `Biz.Bizadm.KMS.Protect` | 퍼사드 / `IOsKekCredentialStore` / `OsKekCredentialProvider` |
| `Biz.Bizadm.KMS.Protect.Runtime.win` | Windows Credential Manager (`wincredman`) |
| `Biz.Bizadm.KMS.Protect.Runtime.osx` | macOS Keychain (`keychain`) |
| `Biz.Bizadm.KMS.Protect.Runtime.linux` | Linux Secret Service (`secretservice`) |

```csharp
IOsKekCredentialStore creds = OsKekCredentialProvider.CreateForCurrentOs();
creds.StorePassword("secret"u8);
using AesGcmKekCipher kek = AesGcmKekCipher.Create(creds, salt, iterations);
```

Linux 헤드리스에서는 프로세스 시작 전에 `GCM_CREDENTIAL_STORE=gpg` 등을 설정할 수 있다.

## IKekCipher

구현체는 키 저장 방식만 다르고, 호출부는 동일하다. 대량 데이터 암호화가 아니라 **DEK wrap** 용도를 전제로 한다.

| 구현 | 키 | 알고리즘 | 출력 |
|---|---|---|---|
| `AesGcmKekCipher` | PBKDF2-SHA256으로 유도 | AES-256-GCM (`System.Security.Cryptography`) | `nonce(12) \|\| cipher \|\| tag(16)` |
| `TpmKekCipher` | TPM 내부 AES-256 키 (SRK 자식) | TPM `EncryptDecrypt` AES-256-CFB | `iv(16) \|\| cipher` |
| `AzureKeyVaultKekCipher` | Key Vault RSA-4096 (Wrap/Unwrap) | RSA-OAEP-256 (`CryptographyClient`) | wrap된 키 바이트 |

## AesGcmKekCipher

소프트웨어 KEK. BouncyCastle을 쓰지 않으며 .NET `AesGcm` + `Rfc2898DeriveBytes.Pbkdf2`를 사용한다.

- 생성: `AesGcmKekCipher.Create(IKekCredentialProvider, salt, iterationCount)` → 32바이트 키
- 로테이션: `AesGcmKekCipher.CreateRotated(IKekCredentialProvider, newSalt, iterationCount)`
- `KeyId`: `aesgcm:{SHA256(derivedKey)}` — 패스워드·salt·iteration 변경 시 함께 바뀐다
- `AesGcm` 인스턴스는 `ObjectPool`로 재사용 (`AbstractAesGcmCipher`)
- AEAD이므로 변조 시 `AuthenticationTagMismatchException`
- `Decrypt` 실패 시 평문 버퍼를 `ZeroMemory`로 지운 뒤 예외를 다시 던진다

## AesGcmDekCipher

DEK로 데이터를 암·복호화한다. DEK 자체는 `IKekCipher`로 wrap되어 envelope 파일 또는 바이트로 보관된다.

- `Create(IKekCipher, FileInfo)` — 파일이 있으면 envelope 로드, 없으면 32바이트 DEK를 생성·wrap 후 원자적 저장
- `Create(IKekCipher, byte[] envelope)` — envelope 바이트에서 생성 (`cipher.KeyId`와 envelope KeyId 일치 검증)
- `Rewrap(sourceKek, targetKek, FileInfo|byte[])` — KEK rotation 후 DEK re-wrap
- 파일 저장은 temp 파일 기록 후 `File.Move`로 원자적으로 반영한다. 경쟁으로 파일이 이미 생기면 기존 파일을 다시 로드한다.
- `Dispose` 시 DEK 키를 `ZeroMemory`한다 (`AbstractAesGcmCipher`)

## AzureKeyVaultKekCipher

Azure Key Vault RSA 키로 DEK를 wrap/unwrap한다. `Azure.Security.KeyVault.Keys` + `Azure.Identity`의 `TokenCredential`을 사용한다.

생성: `AzureKeyVaultKekCipher.CreateAsync(Uri vaultUri, TokenCredential credential, string keyName, string? version = null, CancellationToken)`.

- `version`을 지정하면 해당 버전 로드(unwrap용). null이면 최신 버전(wrap용).
- `RotateAsync()` — 동일 keyName으로 새 RSA 키 버전 import 후 새 인스턴스 반환
- `KeyId`: `azurekv:{keyName}:{version}`

- 지정한 이름의 RSA-4096 키를 로드하고, 없으면 WrapKey/UnwrapKey 전용으로 생성한다.
- 409(충돌)·soft-delete된 키가 있으면 재조회 또는 recover 후 사용한다.
- `Encrypt`/`EncryptAsync` → `WrapKey(RsaOaep256)`, `Decrypt`/`DecryptAsync` → `UnwrapKey(RsaOaep256)`
- 키 물질은 Vault에만 있고 로컬에 내려오지 않는다.

```csharp
using AzureKeyVaultKekCipher kek = await AzureKeyVaultKekCipher.CreateAsync(
    vaultUri, credential, "my-kek-key");
using AesGcmDekCipher dek = AesGcmDekCipher.Create(kek, new FileInfo("dek.bin"));
```

## AzureKeyVaultKekCredentialProvider

Azure Key Vault Secret에 보관한 32바이트 패스워드를 `IKekCredentialProvider`로 제공한다. `AesGcmKekCipher` 등과 함께 쓴다.

- 생성: `new AzureKeyVaultKekCredentialProvider(Uri vaultUri, TokenCredential credential, string secretName)`
- Secret이 없으면 랜덤 32바이트를 Base64로 저장한 뒤 재조회한다. 동시 생성·soft-delete는 cipher와 같이 재조회/recover로 처리한다.
- `GetPassword` / `GetPasswordAsync` 모두 지원한다. 반환 바이트는 호출부가 사용 후 `ZeroMemory`해야 한다.

## TpmKekCipher

TPM 2.0에 KEK를 두고 암·복호화한다. TSS.Net (`Microsoft.TSS`) 사용.

생성: `TpmKekCipher.Create(Tpm2Device device, IKekCredentialProvider credentialProvider, FileInfo kekBlobFile)`. 디바이스 연결은 호출부가 한다.

- `Rotate(FileInfo newKekBlobFile)` — 동일 SRK 아래 새 KEK blob 생성
- `KeyId`: `tpm:{SHA256(kekPublic)}`
- `Dispose` 시 TPM 핸들(SRK·KEK)만 flush한다. **`Tpm2Device`는 닫지 않는다** — TSS.Net `Tpm2.Dispose()`가 device까지 Dispose하기 때문에, 공유 device를 쓰는 Rotate·`Release` 시나리오에서 연결이 끊기지 않도록 의도적으로 생략했다. device `Close`/`Dispose`는 호출부 책임이다.

### 키 계층

1. **SRK** — Owner 계층 `CreatePrimary`. RSA-2048 storage parent (restricted decrypt). `password`의 SHA-256을 unique에 넣어 동일 패스워드면 같은 SRK가 나온다.
2. **KEK** — SRK 아래 AES-256-CFB 대칭키. 없으면 생성 후 blob 저장, 있으면 blob에서 `Load`.

기존 RSA-OAEP KEK 경로는 소스에 주석으로 남아 있다. RSA blob과 AES blob은 호환되지 않으므로 알고리즘을 바꾸면 blob을 다시 만들어야 한다.

### Blob (`TpmKekBlob`)

파일 매직 `TKEK`, version `1`, TPM `TpmPublic` / `TpmPrivate` 직렬화. 개인키 물질은 SRK로 wrap된 채 디스크에 저장되고, 같은 SRK(같은 password)로만 Load된다.

`FileInfo.Exists`는 캐시되므로 생성·로드 경로는 `Refresh()` 후 존재 여부를 본다.

### AES-256-CFB

TPM 2.0은 GCM을 지원하지 않아 CFB를 쓴다.

- Encrypt: 랜덤 IV 16바이트 + `EncryptDecrypt`(encrypt)
- Decrypt: IV 분리 후 `EncryptDecrypt`(decrypt)
- 인증 태그 없음. 변조되어도 TPM이 성공하고 다른 평문을 반환할 수 있다.

일부 Windows 실물 TPM은 export 규제 등으로 `EncryptDecrypt`를 막아 두기도 한다. 이 환경의 TBS 테스트에서는 AES-CFB 라운드트립이 통과했다.

## TPM 디바이스

`TpmKekCipher`는 `Tpm2Device`만 받는다. 연결은 호출부가 한다.

### `SwtpmTpmDevice` (`Cipher.Tpm.Device`)

Rocky Linux **swtpm** TCP용. Microsoft `TcpTpmDevice`(mssim handshake)와는 프로토콜이 다르다.

- 명령 포트: raw TPM 프레임 (기본 `2321`)
- `not-need-init`이면 control `CMD_INIT` 불필요
- `startup-clear`가 없으면 `Connect()`에서 `TPM2_Startup(SU_CLEAR)` (이미 started면 `TPM_RC_INITIALIZE` 무시)

예시:

```bash
swtpm socket \
    --tpm2 \
    --tpmstate dir=/swtpm \
    --server type=tcp,port=2321,bindaddr=0.0.0.0 \
    --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
    --flags not-need-init \
    --daemon
```

`disconnect`가 없으면 연결을 유지한다. 한 연결에서 명령을 직렬 처리하므로 `TpmKekCipher` 동시 호출은 하지 않는다.

### Windows `TbsDevice`

로컬 TPM (TBS). TSS.Net의 `TbsDevice` + `Connect()`. 현재 `TpmKekCipher`는 AES-256-CFB `EncryptDecrypt` 경로를 사용한다.

## 테스트

자동 테스트(CI / `dotnet test`):

```bash
dotnet test --filter "TestCategory!=Manual"
```

- `AesGcmKekCipherTests`
- `AesGcmKekCipherPerformanceTests`
- `AesGcmDekCipherTests`
- `WrappedDekEnvelopeTests`
- `KekCipherExtensionsTests`
- `AesGcmKekManagerTests`

수동 테스트: `[TestCategory("Manual")]`만 붙인다 (`[Ignore]` 없음). CI에서는 위 필터로 제외하고, Visual Studio Test Explorer에서는 해당 클래스를 선택해 바로 실행한다. Run All에서 Manual까지 빼려면 검색창에 `-Trait:"Manual"`을 쓴다.

TPM 기능·성능 테스트는 디바이스별 파생 클래스로 나뉜다. 공통 시나리오는 추상 베이스에 두고, 디바이스 연결만 오버라이드한다. 자격 증명은 테스트용 `FixedPasswordCredentialProvider`를 쓴다.

| 클래스 | 베이스 | 대상 |
|---|---|---|
| `TpmKekCipherTbsDeviceTests` | `TpmKekCipherDeviceTests` | Windows TBS (`[OSCondition(Windows)]`) |
| `TpmKekCipherTbsDevicePerformanceTests` | `TpmKekCipherDevicePerformanceTests` | TBS 성능 (횟수·지연 한도를 하드웨어에 맞춤) |
| `AzureKeyVaultKekCipherTests` | — | Key Vault RSA wrap·Rotate (`[OSCondition(Windows)]`, 환경 변수·클라이언트 인증서 필요) |
| `AzureKeyVaultKekCipherPerformanceTests` | — | Key Vault RSA wrap 성능 (`[OSCondition(Windows)]`) |
| `AzureKeyVaultKekManagerTests` | — | Manager Rotate + re-wrap (`[OSCondition(Windows)]`) |
| `AzureKeyVaultKekCredentialProviderTests` | — | Key Vault Secret 패스워드 (`[OSCondition(Windows)]`) |

Azure 수동 테스트 환경 변수: `AZURE_KEY_VAULT_URL`, `AZURE_TENANTID`, `AZURE_CLIENT_ID`, `AZURE_KEY_VAULT_THUMBPRINT`(CurrentUser\My 인증서).

테스트 blob은 `%TEMP%\kms-tpm-kek-*.blob` / `kms-tpm-kek-perf-*.blob`에 만들었다가 종료 시 삭제한다.

TBS AES 기능 테스트는 이 환경에서 18건 통과했다. 원격 swtpm용 TCP 테스트 클래스는 제거했으며, swtpm 검증이 필요하면 `SwtpmTpmDevice`로 동일 베이스를 파생하면 된다.

## 성능 참고 (실측)

측정 대상은 **32바이트 DEK wrap/unwrap 라운드트립**(`Encrypt` + `Decrypt`)이다. 성능 테스트는 `Biz.Bizadm.KMSTest`에 있으며, 아래 수치는 이 저장소를 개발한 Windows 환경(`net10.0`)에서 `dotnet test --logger "console;verbosity=detailed"`로 재현할 수 있다.

### `AesGcmKekCipher` (소프트웨어 AES-256-GCM)

테스트: `AesGcmKekCipherPerformanceTests` (CI 포함)

| 항목 | 값 |
|---|---|
| 동시성 | `degree = ProcessorCount × 2` (본 환경 32) |
| 처리량 | 40,000 ops, p50 ≈ **0.001ms**, p95 ≈ **0.002ms**, ≈ **2.2×10⁷ ops/s** |
| 할당 | ≈ **144 bytes/roundtrip** (관리 힙) |

DEK wrap 용도로는 사실상 CPU-bound이며 서브밀리초다.

### `TpmKekCipher` (Windows 실물 TPM, AES-256-CFB)

테스트: `TpmKekCipherTbsDevicePerformanceTests` (`[TestCategory("Manual")]`, `[OSCondition(Windows)]`)

| 항목 | 값 |
|---|---|
| 디바이스 | `TbsDevice` + `Connect()` (로컬 TPM) |
| 처리량 | 20 ops 순차, p50 ≈ **31ms**, p95 ≈ **32ms**, ≈ **32 ops/s** |
| 할당 | ≈ **340KiB/roundtrip** (TSS.Net 마샬링; `secondGrowth=0`으로 누수는 관측되지 않음) |

TPM은 소프트웨어 KEK 대비 **약 3만 배** 느리지만, DEK wrap처럼 저빈도 호출에는 실사용 가능한 수준이다. 동일 연결에서 동시 호출은 하지 않는다.

### `AzureKeyVaultKekCipher` (Key Vault RSA-OAEP-256)

테스트: `AzureKeyVaultKekCipherPerformanceTests` (`[TestCategory("Manual")]`, `[OSCondition(Windows)]`)

| 항목 | 값 |
|---|---|
| 인증 | 클라이언트 인증서 (`AZURE_KEY_VAULT_*` 환경 변수) |
| 처리량 | 30 ops 순차, p50 ≈ **46ms**, p95 ≈ **274ms**, p99 ≈ **414ms**, ≈ **12 ops/s** |
| 할당 | ≈ **28KiB/roundtrip** (HTTPS·SDK 버퍼) |

Key Vault HTTPS 왕복이 지배적이며, 리전·네트워크에 따라 변동한다. 키 물질은 Vault에만 존재한다.

### 비교 요약

| 구현 | p50 (wrap+unwrap) | 상대 처리량 | 비고 |
|---|---|---|---|
| `AesGcmKekCipher` | ≈ 0.001ms | 기준 (최고) | 로컬 CPU, 동시 처리 가능 |
| `AzureKeyVaultKekCipher` | ≈ 46ms | ≈ 1/46,000 | HTTPS + RSA, 네트워크 bound |
| `TpmKekCipher` (Win TPM) | ≈ 31ms | ≈ 1/30,000 | TBS 직렬, 할당 큼 |

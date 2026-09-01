# Biz.Bizadm.KMS

Key Management System 라이브러리. 공통 `ICipher` 아래에 KEK wrap/unwrap용 `IKekCipher`와 데이터 암·복호화용 `IDekCipher`를 두고, 소프트웨어·TPM·Azure Key Vault·PKCS#11 HSM 백엔드를 제공한다.

대상 프레임워크: `net10.0`

## 계층

```text
ICipher
├── IKekCipher                       # 키 물질 wrap/unwrap (DEK 보호)
│   ├── AesGcmKekCipher              # 소프트웨어 AES-GCM
│   ├── TpmKekCipher                 # TPM AES-256-CFB / RSA-OAEP-256
│   ├── AzureKeyVaultKekCipher       # Azure Key Vault RSA-OAEP wrap
│   └── Pkcs11KekCipher              # PKCS#11 HSM RSA-OAEP wrap (별도 패키지)
├── IKekManager                      # KEK 버전 관리·DEK re-wrap
│   ├── AesGcmKekManager
│   ├── TpmKekManager
│   ├── AzureKeyVaultKekManager
│   └── Pkcs11KekManager
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

| Manager | Rotate API | LoadKey API |
|---|---|---|
| `AesGcmKekManager` | `Rotate(IKekCredentialProvider, byte[] newSalt, int iterationCount)` | `LoadKey(IKekCredentialProvider, byte[] salt, int iterationCount)` |
| `AzureKeyVaultKekManager` | `RotateAsync(CancellationToken)` | `LoadKeyAsync(string version, CancellationToken)` |
| `TpmKekManager` | `Rotate(FileInfo newKekBlobFile)` | `LoadKey(FileInfo kekBlobFile)` |
| `Pkcs11KekManager` | `Rotate(string newKeyLabel)` | `LoadKey(string keyLabel)` |

공통 API: `Current`, `Resolve(keyId)`, `RewrapDek(envelope)`, `RewrapDekFile(dekFile)`, `Release(keyId)`.

로테이션 후 이전 KEK는 registry에 남아 아직 re-wrap되지 않은 DEK도 처리할 수 있다. 프로세스 재시작 등으로 registry가 비어 있으면 `LoadKey`로 envelope에 기록된 old KEK를 다시 올린다. `LoadKey`는 **Current를 바꾸지 않고** registry에만 등록한다. 모든 DEK re-wrap이 끝나면 `Release(oldKeyId)`로 이전 KEK를 해제한다. `Current`는 `Release`할 수 없다.

동일 `KeyId`로 `Rotate`/`LoadKey`를 호출하면 `InvalidOperationException`이 발생하고, 등록에 실패한 cipher는 즉시 `Dispose`된다. `RewrapDekAsync`/`RewrapDekFileAsync`는 lock 밖에서 await하므로, 비동기 re-wrap 진행 중에는 `Release`/`Dispose`를 호출하지 않는다.

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
| `Pkcs11KekCipher` | `pkcs11:{SHA256(modulus\|\|exponent)}` |

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

로컬 AES·TPM·PKCS#11 구현의 `*Async`는 동기 경로를 `Task.FromResult`로 감싼다. Azure Key Vault 구현은 SDK 비동기 API를 그대로 사용한다.

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
| `TpmKekCipher` | TPM 내부 KEK (SRK 자식) | AES-256-CFB(기본) 또는 RSA-OAEP-256 | AES: `iv(16) \|\| cipher` / RSA: `keySize/8` 바이트 |
| `AzureKeyVaultKekCipher` | Key Vault RSA-4096 (Wrap/Unwrap) | RSA-OAEP-256 (`CryptographyClient`) | wrap된 키 바이트 |
| `Pkcs11KekCipher` | HSM RSA-4096 (토큰 영구 키) | RSA-OAEP-256 (`C_WrapKey`/`C_UnwrapKey`) | wrap된 키 바이트 |

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
- `RotateAsync()` — Key Vault에서 동일 keyName으로 새 RSA 키 버전(`CreateRsaKeyAsync`) 생성 후 새 인스턴스 반환
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

## PKCS#11 HSM (`Biz.Bizadm.KMS.Pkcs11`)

Thales Luna·nCipher·SoftHSM2 등 PKCS#11 호환 HSM으로 DEK를 wrap/unwrap한다. 메인 `Biz.Bizadm.KMS`와 별도 NuGet 패키지이며, `Pkcs11Interop`를 사용한다.

> **검증 범위:** 현재 `Pkcs11KekCipher`·`Pkcs11KekManager`는 **SoftHSM 2.5.0(소프트웨어 에뮬레이터)** Manual 테스트만 수행했다. Thales Luna·nCipher·AWS CloudHSM 등 **실물 HSM에서는 아직 검증되지 않았다.** 프로덕션 투입 전에는 대상 HSM에서 `Pkcs11KekOptions`(wrap 메커니즘·RSA 키 크기)를 벤더 권장값에 맞춰 별도 Manual 테스트 클래스를 추가하는 것을 권장한다.

소비자는 **`Biz.Bizadm.KMS` + `Biz.Bizadm.KMS.Pkcs11`**을 참조한다. cryptoki DLL/SO 경로는 호스트가 런타임에 지정한다.

```csharp
using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Pkcs11.Cipher;

using Pkcs11LibraryContext context = Pkcs11LibraryContext.Create(
    @"C:\SoftHSM2\lib\softhsm2-x64.dll",
    slotId: 0,
    pinProvider);
using Pkcs11KekManager manager = Pkcs11KekManager.Create(context, "my-kek-label");
using AesGcmDekCipher dek = AesGcmDekCipher.Create(manager.Current, new FileInfo("dek.bin"));

string oldKeyId = manager.Current.KeyId;
manager.Rotate("my-kek-label-v2");
manager.RewrapDekFile(new FileInfo("dek.bin"));
manager.Release(oldKeyId);
```

### `Pkcs11LibraryContext`

- PKCS#11 라이브러리 로드, 슬롯 선택, USER PIN 로그인(`IKekCredentialProvider`)
- RW 세션 1개 + `SemaphoreSlim`으로 HSM 호출 직렬화 (동시 호출 금지)
- `Pkcs11KekManager`가 컨텍스트 수명을 관리한다. Cipher만 단독 사용 시 호출부가 `Dispose`한다.

### `Pkcs11KekCipher`

- 생성: `Pkcs11KekCipher.Create(context, keyLabel, createIfMissing: true)`
- HSM에서 `CKA_LABEL`로 RSA 키 쌍을 찾고, 없으면 RSA-4096을 생성한다.
- `Encrypt`/`Decrypt` — DEK(32바이트)를 일시 AES 객체로 만든 뒤 RSA-OAEP-256으로 `C_WrapKey`/`C_UnwrapKey`
- `Rotate(newKeyLabel)` — HSM에 새 RSA 키 쌍 생성 후 새 인스턴스 반환
- `KeyId`: `pkcs11:{SHA256(modulus||exponent)}`
- `Pkcs11KekOptions`로 OAEP 메커니즘·RSA 키 크기를 벤더에 맞게 조정할 수 있다.
- KEK 개인키 물질은 HSM 밖으로 나오지 않는다.

### SoftHSM2 로컬 설정 예시

```bash
# Linux 예시
export SOFTHSM2_CONF=$HOME/softhsm2.conf
softhsm2-util --init-token --slot 0 --label "kms-test" --pin 1234 --so-pin 0000

# 키 확인
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
```

Windows portable 예시 (`SOFTHSM2_CONF`·`PATH` 설정 후):

```powershell
$base = "C:\path\to\SoftHSM2"
$env:SOFTHSM2_CONF = "$base\etc\softhsm2.conf"
$env:PATH = "$base\bin;$base\lib;" + $env:PATH
& "$base\bin\softhsm2-util.exe" --init-token --slot 0 --label "kms-test" --pin 1234 --so-pin 00000000
```

수동 테스트 환경 변수:

| 변수 | 예시 | 비고 |
|---|---|---|
| `PKCS11_LIBRARY_PATH` | `...\lib\softhsm2-x64.dll` | 64비트 .NET |
| `PKCS11_PIN` | `1234` | `--init-token` 시 지정한 USER PIN |
| `PKCS11_SLOT_ID` | `1590757401` | 생략 가능 — 초기화된 토큰 슬롯 자동 탐색 |

**SoftHSM 2.5.0 Manual 테스트 프로파일:** `Pkcs11KekCipher` 기본값(RSA-OAEP-256)은 SoftHSM 2.5.0에서 `CKR_ARGUMENTS_BAD`가 날 수 있다. 테스트는 `SoftHsmPkcs11TestProfile`로 **CKM_RSA_PKCS + RSA-2048** 옵션을 주입한다. 프로덕션 HSM 검증은 벤더별로 별도 프로파일·Manual 테스트 클래스를 추가한다.

```powershell
$env:PKCS11_LIBRARY_PATH = "C:\path\to\SoftHSM2\lib\softhsm2-x64.dll"
$env:PKCS11_PIN = "1234"
dotnet test --filter "FullyQualifiedName~SoftHsm"
```

## TpmKekCipher

TPM 2.0에 KEK를 두고 암·복호화한다. TSS.Net (`Microsoft.TSS`) 사용.

생성: `TpmKekCipher.Create(Tpm2Device device, IKekCredentialProvider credentialProvider, FileInfo kekBlobFile, TpmKekOptions? options = null)`. 디바이스 연결은 호출부가 한다.

- `Rotate(FileInfo newKekBlobFile, TpmKekOptions? options = null)` — 동일 SRK 아래 새 KEK blob 생성
- `KeyId`: `tpm:{SHA256(kekPublic)}`
- `Dispose` 시 TPM 핸들(SRK·KEK)만 flush한다. **`Tpm2Device`는 닫지 않는다** — TSS.Net `Tpm2.Dispose()`가 device까지 Dispose하기 때문에, 공유 device를 쓰는 Rotate·`Release` 시나리오에서 연결이 끊기지 않도록 의도적으로 생략했다. device `Close`/`Dispose`는 호출부 책임이다.

### Wrap 모드 (`TpmKekOptions`)

보안 우선(KEK wrap 무결성·변조 검출)이면 **`RsaOaep256`**을 권장한다. `Aes256Cfb`는 성능 우선 모드로 **인증 태그가 없으며** wrap된 DEK 변조를 검출하지 못한다(README AES-CFB 섹션 참고).

| 모드 | KEK 타입 | wrap 알고리즘 | 출력 |
|---|---|---|---|
| `Aes256Cfb` (기본) | TPM AES-256 대칭키 | `EncryptDecrypt` AES-256-CFB | `iv(16) \|\| cipher` |
| `RsaOaep256` (보안 권장) | TPM RSA 비대칭키 (기본 2048비트) | `RsaEncrypt` / `RsaDecrypt` OAEP-SHA256 | `keySize/8` 바이트 |

기존 blob을 로드할 때는 `TpmPublic.type`으로 모드를 자동 감지한다 (`Symcipher` → AES, `Rsa` → RSA-OAEP). AES blob과 RSA blob은 호환되지 않으므로 모드를 바꾸려면 새 blob을 만들어야 한다.

```csharp
var rsaOptions = new TpmKekOptions { WrapMode = TpmKekWrapMode.RsaOaep256 };
using TpmKekCipher kek = TpmKekCipher.Create(device, creds, kekBlobFile, rsaOptions);
```

### 키 계층

1. **SRK** — Owner 계층 `CreatePrimary`. RSA-2048 storage parent (restricted decrypt). `password`의 SHA-256을 `unique`에 넣어 동일 패스워드면 같은 SRK가 나온다. SRK `authValue`는 `HMAC-SHA256(password, "Biz.Bizadm.KMS.Tpm.Srk")`로 유도한다.
2. **KEK** — SRK 아래 대칭(AES-256-CFB) 또는 비대칭(RSA-OAEP) 키. `authValue`는 `HMAC-SHA256(password, "Biz.Bizadm.KMS.Tpm.Kek")`. blob이 없으면 `TpmKekOptions.WrapMode`에 따라 생성 후 저장, 있으면 blob에서 `Load`. Create·Load·Encrypt/Decrypt는 TSS.Net handle auth로 자동 인증한다.

패스워드는 `Create` 시 1회만 `GetPassword()`로 받고 authValue 유도 후 즉시 `ZeroMemory`한다. 인스턴스 수명 동안 TPM handle auth가 유지되므로 매 연산마다 password를 다시 넣지 않는다.

### Blob (`TpmKekBlob`)

파일 매직 `TKEK`, version `1`, TPM `TpmPublic` / `TpmPrivate` 직렬화. 개인키 물질은 SRK로 wrap된 채 디스크에 저장되고, 올바른 password(SRK·KEK authValue + SRK unique)로만 Load된다.

`FileInfo.Exists`는 캐시되므로 생성·로드 경로는 `Refresh()` 후 존재 여부를 본다.

### AES-256-CFB (기본)

TPM 2.0은 GCM을 지원하지 않아 CFB를 쓴다.

- Encrypt: 랜덤 IV 16바이트 + `EncryptDecrypt`(encrypt)
- Decrypt: IV 분리 후 `EncryptDecrypt`(decrypt)
- 인증 태그 없음. 변조되어도 TPM이 성공하고 다른 평문을 반환할 수 있다.

일부 Windows 실물 TPM은 export 규제 등으로 `EncryptDecrypt`를 막아 두기도 한다. 이 환경의 TBS 테스트에서는 AES-CFB 라운드트립이 통과했다.

### RSA-OAEP-256

- Encrypt: `RsaEncrypt`(OAEP-SHA256) — DEK(32바이트)를 직접 wrap
- Decrypt: `RsaDecrypt`(OAEP-SHA256)
- OAEP 패딩으로 변조 시 복호화가 실패한다 (`TpmException`)
- RSA-2048 기준 최대 평문 ~190바이트 (DEK 32바이트에 충분)

## TPM 디바이스

`TpmKekCipher`는 `Tpm2Device`만 받는다. 연결은 호출부가 한다.

Windows에서는 TSS.Net `TbsDevice` + `Connect()`로 로컬 TPM(TBS)에 연결한다. `TpmKekCipher`는 기본 AES-256-CFB 또는 `TpmKekOptions`로 RSA-OAEP-256을 선택할 수 있다.

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

TPM 기능·성능 테스트는 디바이스별 파생 클래스로 나뉜다. PKCS#11도 동일하게 추상 베이스(`Pkcs11KekCipherDeviceTests`)에 공통 시나리오를 두고, SoftHSM 연결만 파생 클래스에서 구현한다. 자격 증명은 테스트용 `FixedPasswordCredentialProvider`를 쓴다.

| 클래스 | 베이스 | 대상 |
|---|---|---|
| `TpmKekCipherAesTbsDeviceTests` | `TpmKekCipherDeviceTests` | Windows TBS AES-256-CFB (`[OSCondition(Windows)]`) |
| `TpmKekCipherRsaOaepTbsDeviceTests` | `TpmKekCipherDeviceTests` | Windows TBS RSA-OAEP-256 (`[OSCondition(Windows)]`) |
| `TpmKekCipherAesTbsDevicePerformanceTests` | `TpmKekCipherDevicePerformanceTests` | TBS AES 성능 (횟수·지연 한도를 하드웨어에 맞춤) |
| `TpmKekCipherRsaOaepTbsDevicePerformanceTests` | `TpmKekCipherDevicePerformanceTests` | TBS RSA-OAEP 성능 |
| `AzureKeyVaultKekCipherTests` | — | Key Vault RSA wrap·Rotate (`[OSCondition(Windows)]`, 환경 변수·클라이언트 인증서 필요) |
| `AzureKeyVaultKekCipherPerformanceTests` | — | Key Vault RSA wrap 성능 (`[OSCondition(Windows)]`) |
| `AzureKeyVaultKekManagerTests` | — | Manager Rotate + re-wrap (`[OSCondition(Windows)]`) |
| `AzureKeyVaultKekCredentialProviderTests` | — | Key Vault Secret 패스워드 (`[OSCondition(Windows)]`) |
| `Pkcs11KekCipherSoftHsmTests` | `Pkcs11KekCipherDeviceTests` | SoftHSM2 (`SoftHsmPkcs11TestProfile`, CKM_RSA_PKCS) |
| `Pkcs11KekManagerSoftHsmTests` | `Pkcs11KekManagerDeviceTests` | Manager Rotate + re-wrap |
| `Pkcs11KekCipherSoftHsmPerformanceTests` | — | SoftHSM2 wrap 성능 (`[TestCategory("Manual")]`) |

Azure 수동 테스트 환경 변수: `AZURE_KEY_VAULT_URL`, `AZURE_TENANTID`, `AZURE_CLIENT_ID`, `AZURE_KEY_VAULT_THUMBPRINT`(CurrentUser\My 인증서).

PKCS#11(SoftHSM) 수동 테스트 환경 변수: `PKCS11_LIBRARY_PATH`, `PKCS11_PIN`. `PKCS11_SLOT_ID`는 생략 가능.

`Pkcs11KekCipher` 관련 Manual 테스트는 **SoftHSM 2.5.0만** 대상이다. 실물 HSM용 테스트 클래스는 아직 없다.

테스트 blob은 `%TEMP%\kms-tpm-kek-*.blob` / `kms-tpm-kek-perf-*.blob`에 만들었다가 종료 시 삭제한다.

TBS AES 기능 테스트는 이 환경에서 18건 통과했다.

### swtpm Manual 테스트 (`SwtpmTpmDevice`)

Rocky Linux **swtpm** TCP 검증용 어댑터는 `Biz.Bizadm.KMSTest/Cipher/Tpm/Device/SwtpmTpmDevice.cs`에 있다. Microsoft `TcpTpmDevice`(mssim handshake)와는 프로토콜이 다르다. swtpm 검증이 필요하면 `TpmKekCipherDeviceTests`를 파생하고 이 디바이스로 `Tpm2Device`를 연결하면 된다.

- 명령 포트: raw TPM 프레임 (기본 `2321`)
- `not-need-init`이면 control `CMD_INIT` 불필요
- `startup-clear`가 없으면 `Connect()`에서 `TPM2_Startup(SU_CLEAR)` (이미 started면 `TPM_RC_INITIALIZE` 무시)

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

### `TpmKekCipher` — AES-256-CFB (Windows 실물 TPM)

테스트: `TpmKekCipherAesTbsDevicePerformanceTests` (`[TestCategory("Manual")]`, `[OSCondition(Windows)]`)

| 항목 | 값 |
|---|---|
| 디바이스 | `TbsDevice` + `Connect()` (로컬 TPM) |
| 처리량 | 20 ops 순차, p50 ≈ **31ms**, p95 ≈ **47ms**, ≈ **33 ops/s** |
| 할당 | ≈ **340KiB/roundtrip** (TSS.Net 마샬링; `secondGrowth=0`으로 누수는 관측되지 않음) |

### `TpmKekCipher` — RSA-OAEP-256 (Windows 실물 TPM)

테스트: `TpmKekCipherRsaOaepTbsDevicePerformanceTests` (`[TestCategory("Manual")]`, `[OSCondition(Windows)]`)

| 항목 | 값 |
|---|---|
| 디바이스 | `TbsDevice` + `Connect()` (로컬 TPM), RSA-2048 KEK |
| 처리량 | 20 ops 순차, p50 ≈ **47ms**, p95 ≈ **61ms**, ≈ **21 ops/s** |
| 할당 | ≈ **387KiB/roundtrip** (TSS.Net 마샬링; `secondGrowth=0`으로 누수는 관측되지 않음) |

동일 TPM·동일 32바이트 DEK 기준으로 RSA-OAEP는 AES-CFB 대비 p50 약 **1.5배** 느리다. TPM은 소프트웨어 KEK 대비 **약 3만 배** 느리지만, DEK wrap처럼 저빈도 호출에는 실사용 가능한 수준이다. 동일 연결에서 동시 호출은 하지 않는다.

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
| `TpmKekCipher` AES-256-CFB | ≈ 31ms | ≈ 1/30,000 | TBS 직렬, 할당 큼 |
| `TpmKekCipher` RSA-OAEP-256 | ≈ 47ms | ≈ 1/47,000 | 동일 TPM에서 AES 대비 ≈1.5× 느림, 변조 시 실패 |
| `AzureKeyVaultKekCipher` | ≈ 46ms | ≈ 1/46,000 | HTTPS + RSA, 네트워크 bound |
| `Pkcs11KekCipher` (SoftHSM 2.5.0) | ≈ 2.4ms (CKM_RSA_PKCS) | — | `Pkcs11KekCipherSoftHsmPerformanceTests` (Manual). **에뮬레이터 수치이며 실물 HSM과 무관** |

# Biz.Bizadm.KMS.NetFramework

독립 .NET Framework 4.8 KMS 구현입니다. 공통 `ICipher` 아래에 KEK wrap/unwrap용 `IKekCipher`와 데이터 암·복호화용 `IDekCipher`를 두고, 소프트웨어·Windows Credential Manager·TPM·Azure Key Vault·PKCS#11 HSM 백엔드를 **단일 NuGet 패키지**로 제공합니다.

대상 프레임워크: `net48`  
네임스페이스: `Biz.Bizadm.KMS.NetFramework.Cipher` (+ `.Tpm`, `.Pkcs11`)

개념(KEK/DEK envelope, rotation, KeyId)과 암호문·envelope 형식은 net10 `Biz.Bizadm.KMS`와 맞춥니다. 자세한 설계·성능 수치는 저장소 루트 [README.md](../README.md)를 참고하세요.

## 설치

```xml
<PackageReference Include="Biz.Bizadm.KMS.NetFramework" Version="1.0.0-net48" />
```

별도 `Biz.Bizadm.KMS.Pkcs11` / `Biz.Bizadm.KMS.Credentials` 패키지는 **없습니다**. PKCS#11과 Windows Credential 구현이 이 패키지에 포함됩니다.

## net10 대비 차이

| 항목 | net10 (`Biz.Bizadm.KMS`) | net48 (`Biz.Bizadm.KMS.NetFramework`) |
|---|---|---|
| 패키징 | 본체 + 선택 Pkcs11 / Credentials | **단일 패키지** |
| AES-GCM | .NET `AesGcm` | **BouncyCastle** (`AbstractAesGcmCipher`) |
| OS 자격 증명 | RID별 Credentials 런타임 (win/linux/osx) | **Windows Credential Manager만** |
| PKCS#11 | 별도 NuGet | 동일 어셈블리 |
| Manager | `IKekManager` / 공통 베이스 | 타입별 sealed manager (공통 베이스 없음) |
| 관계 | — | **독립 포트**(멀티타깃 TFM이 아님) |

## 계층

```text
ICipher
├── IKekCipher
│   ├── AesGcmKekCipher
│   ├── TpmKekCipher
│   ├── AzureKeyVaultKekCipher
│   └── Pkcs11KekCipher
├── AesGcmKekManager / TpmKekManager / AzureKeyVaultKekManager / Pkcs11KekManager
└── IDekCipher
    └── AesGcmDekCipher
```

## 사용 예제

### 소프트웨어 KEK + DEK

```csharp
using Biz.Bizadm.KMS.NetFramework.Cipher;

IWindowsKekCredentialStore creds = WindowsCredentialManagerKekCredentialProvider.Create();
creds.StorePassword(passwordBytes);

using AesGcmKekManager manager = AesGcmKekManager.Create(creds, salt, iterations);
using AesGcmDekCipher dek = AesGcmDekCipher.CreateFromFile(manager.Current, "dek.bin");

byte[] cipher = dek.Encrypt(plain);
byte[] roundtrip = dek.Decrypt(cipher);

string oldKeyId = manager.Current.KeyId;
manager.Rotate(newCreds, newSalt, iterations);
manager.RewrapDekFile("dek.bin");
manager.Release(oldKeyId);
```

### Azure / TPM / PKCS#11 (요약)

| Manager | Create | Rotate | LoadKey |
|---|---|---|---|
| `AzureKeyVaultKekManager` | `CreateAsync(vaultUri, credential, keyName, version?)` | `RotateAsync()` | `LoadKeyAsync(version)` |
| `TpmKekManager` | `Create(device, creds, kekBlobFile, options?)` | `Rotate(newKekBlobFile, options?)` | `LoadKey(kekBlobFile, options?)` |
| `Pkcs11KekManager` | `Create(context, keyLabel, …)` | `Rotate(newKeyLabel, options?)` | `LoadKey(keyLabel, options?)` |

TPM wrap 모드·SoftHSM 옵션·Azure Key Vault 동작은 루트 README의 해당 절을 따릅니다. SoftHSM 2.5.0 Manual 테스트는 net10과 같이 **CKM_RSA_PKCS + RSA-2048** 프로파일을 사용합니다.

## Envelope / KeyId 호환

wrap된 DEK는 **KDEK v1** envelope(`KDEK` magic)로 저장합니다. KeyId 형식도 net10과 동일합니다.

| 구현 | KeyId |
|---|---|
| `AesGcmKekCipher` | `aesgcm:{SHA256(derivedKey)}` |
| `AzureKeyVaultKekCipher` | `azurekv:{keyName}:{version}` |
| `TpmKekCipher` | `tpm:{SHA256(kekPublic)}` |
| `Pkcs11KekCipher` | `pkcs11:{SHA256(modulus\|\|exponent)}` |

Windows Credential 기본값(`Biz.Bizadm.KMS` / `bizadm-kms://kek` / `default`)도 net10과 공유하므로 동일 머신에서 OS 항목을 같이 쓸 수 있습니다.

### net10 교차 검증

`Biz.Bizadm.KMS.NetFramework.Tests`의 Interop 헬퍼(`InteropNet10` / `InteropNet48`)로 검증합니다.

| 범위 | 분류 | 테스트 |
|---|---|---|
| AES-GCM wire (`nonce\|\|cipher\|\|tag`) | CI | `RuntimeSetupTests` |
| PBKDF2 KeyId · KDEK envelope · wrap/unwrap/rewrap | CI | `CrossCompatTests` |
| Windows Credential store/get 공유 | CI (Windows) | `CrossCompatTests` |
| Azure / TPM / PKCS#11 SoftHSM wrap 교차 | Manual | `CrossCompatManualTests` |

Manual 교차는 unwrap 후 DEK 평문 일치가 성공 기준입니다(RSA wrap 암호문 바이트 동일성은 요구하지 않음).

## FeatureSupport

`FeatureSupport`로 net48에서 의도적으로 지원·미지원인 기능을 선언합니다. Unsupported 호출은 `UnsupportedFeatureException`을 던집니다.

| Feature | Status |
|---|---|
| `SoftwareAesGcm` | Supported |
| `SoftwareKekDek` | Supported |
| `KdeKEnvelope` | Supported |
| `WindowsCredentials` | Supported |
| `AzureKeyVault` | Supported |
| `Tpm` | Supported |
| `Pkcs11` | Supported |
| `LinuxMacOsCredentials` | **Unsupported** |

## 테스트

프로젝트: `Biz.Bizadm.KMS.NetFramework.Tests` (`net48`, MSTest)

```bash
dotnet test Biz.Bizadm.KMS.NetFramework.Tests --filter "TestCategory!=Manual"
```

수동 테스트(`[TestCategory("Manual")]`):

| 테스트 | 필요 환경 |
|---|---|
| `AzureKeyVaultTests` | `AZURE_KEY_VAULT_URL`, `AZURE_TENANTID`, `AZURE_CLIENT_ID`, `AZURE_KEY_VAULT_THUMBPRINT` |
| `Pkcs11BackendTests` (SoftHSM) | `PKCS11_LIBRARY_PATH`, `PKCS11_SLOT_ID`, `PKCS11_PIN` |
| `TpmBackendTests` | Windows 로컬 TPM (TBS) |
| `CrossCompatManualTests` (Azure/TPM/PKCS#11) | 위와 동일 환경 변수·디바이스 |

## 상세 문서

로테이션 흐름, TPM AES-CFB vs RSA-OAEP, SoftHSM 설정, 성능 참고 등은 저장소 루트 [README.md](../README.md)(net10 기준 서술)를 참고하되, 패키지 참조·네임스페이스·자격 증명 API는 이 문서를 우선합니다.

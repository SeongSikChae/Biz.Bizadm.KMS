# Biz.Bizadm.KMS

Key Management System 라이브러리. KEK(Key Encryption Key)로 평문을 wrap/unwrap하는 `IKekCipher`와, 소프트웨어·TPM 백엔드를 제공한다.

대상 프레임워크: `net10.0`

## IKekCipher

```csharp
public interface IKekCipher : IDisposable
{
    byte[] Encrypt(byte[] plain);
    byte[] Decrypt(byte[] encrypted);
}
```

구현체는 키 저장 방식만 다르고, 호출부는 동일하다. 대량 데이터 암호화가 아니라 **DEK wrap** 용도를 전제로 한다.

| 구현 | 키 | 알고리즘 | 출력 |
|---|---|---|---|
| `AesGcmKekCipher` | PBKDF2-SHA256으로 유도 | AES-256-GCM (`System.Security.Cryptography`) | `nonce(12) \|\| cipher \|\| tag(16)` |
| `TpmKekCipher` | TPM 내부 AES-256 키 (SRK 자식) | TPM `EncryptDecrypt` AES-256-CFB | `iv(16) \|\| cipher` |

## AesGcmKekCipher

소프트웨어 KEK. BouncyCastle을 쓰지 않으며 .NET `AesGcm` + `Rfc2898DeriveBytes.Pbkdf2`를 사용한다.

- 생성자: `(password, salt, iterationCount)` → 32바이트 키
- `AesGcm` 인스턴스는 `ObjectPool`로 재사용
- AEAD이므로 변조 시 `AuthenticationTagMismatchException`
- `Decrypt` 실패 시 평문 버퍼를 `ZeroMemory`로 지운 뒤 예외를 다시 던진다

## TpmKekCipher

TPM 2.0에 KEK를 두고 암·복호화한다. TSS.Net (`Microsoft.TSS`) 사용.

생성자: `(Tpm2Device device, byte[] password, FileInfo kekBlobFile)`. 디바이스 연결은 호출부가 한다.

### 키 계층

1. **SRK** — Owner 계층 `CreatePrimary`. RSA-2048 storage parent (restricted decrypt). `password`의 SHA-256을 unique에 넣어 동일 패스워드면 같은 SRK가 나온다.
2. **KEK** — SRK 아래 AES-256-CFB 대칭키. 없으면 생성 후 blob 저장, 있으면 blob에서 `Load`.

기존 RSA-OAEP KEK 경로는 소스에 주석으로 남아 있다. RSA blob과 AES blob은 호환되지 않으므로 알고리즘을 바꾸면 blob을 다시 만들어야 한다.

### Blob (`TpmKekBlob`)

파일 매직 `TKEK`, version `1`, TPM `TpmPublic` / `TpmPrivate` 직렬화. 개인키 물질은 SRK로 wrap된 채 디스크에 저장되고, 같은 SRK(같은 password)로만 Load된다.

`FileInfo.Exists`는 캐시되므로 생성자는 `Refresh()` 후 존재 여부를 본다.

### AES-256-CFB

TPM 2.0은 GCM을 지원하지 않아 CFB를 쓴다.

- Encrypt: 랜덤 IV 16바이트 + `EncryptDecrypt`(encrypt)
- Decrypt: IV 분리 후 `EncryptDecrypt`(decrypt)
- 인증 태그 없음. 변조되어도 TPM이 성공하고 다른 평문을 반환할 수 있다.

일부 Windows 실물 TPM은 export 규제 등으로 `EncryptDecrypt`를 막아 두기도 한다. 이 환경의 TBS 테스트에서는 AES-CFB 라운드트립이 통과했다.

## TPM 디바이스

`TpmKekCipher`는 `Tpm2Device`만 받는다. 연결은 호출부가 한다.

### `SwtpmTpmDevice`

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

로컬 TPM (TBS). TSS.Net의 `TbsDevice` + `Connect()`. RSA 연산은 swtpm보다 훨씬 느리고, AES-CFB는 칩이 명령을 허용하면 실사용 가능한 수준이다.

## 테스트

자동 테스트(CI / `dotnet test`):

```bash
dotnet test --filter "TestCategory!=Manual"
```

- `AesGcmKekCipherTests`
- `AesGcmKekCipherPerformanceTests`

수동 테스트: `[TestCategory("Manual")]`만 붙인다 (`[Ignore]` 없음). CI에서는 위 필터로 제외하고, Visual Studio Test Explorer에서는 해당 클래스를 선택해 바로 실행한다. Run All에서 Manual까지 빼려면 검색창에 `-Trait:"Manual"`을 쓴다.

TPM 기능·성능 테스트는 디바이스별 파생 클래스로 나뉜다. 공통 시나리오는 추상 베이스에 두고, 디바이스 연결만 오버라이드한다.

| 클래스 | 베이스 | 대상 |
|---|---|---|
| `TpmKekCipherTbsDeviceTests` | `TpmKekCipherDeviceTests` | Windows TBS (`[OSCondition(Windows)]`) |
| `TpmKekCipherTbsDevicePerformanceTests` | `TpmKekCipherDevicePerformanceTests` | TBS 성능 (횟수·지연 한도를 하드웨어에 맞춤) |

테스트 blob은 `%TEMP%\kms-tpm-kek-*.blob` / `kms-tpm-kek-perf-*.blob`에 만들었다가 종료 시 삭제한다.

TBS AES 기능 테스트는 이 환경에서 18건 통과했다. 원격 swtpm용 TCP 테스트 클래스는 제거했으며, swtpm 검증이 필요하면 `SwtpmTpmDevice`로 동일 베이스를 파생하면 된다.

## 성능 참고 (실측)

swtpm AES 이전 RSA-OAEP 기준 원격 TCP: p50 ≈ 11ms, ≈ 91 ops/s. 소프트웨어 AES-GCM은 서브밀리초.

Windows 실물 TPM RSA-2048은 보통 한 자릿수 이상 느리다 (칩 내부 개인키 연산 + TBS). AES-CFB로 바꾼 이유는 이 지연을 줄이기 위함이다.

TSS.Net 마샬링으로 라운드트립당 할당이 크다(RSA 시절 약 376KiB). 누수(`secondGrowth=0`)와는 별개다.

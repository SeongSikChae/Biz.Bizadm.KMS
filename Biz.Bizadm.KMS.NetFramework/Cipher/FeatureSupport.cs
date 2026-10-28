namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Declares net48 feature verification status for the independent implementation.
/// </summary>
public enum FeatureVerificationStatus
{
    Supported,
    Unsupported,
    Unverified
}

/// <summary>
/// Central registry of net48 feature support decisions.
/// </summary>
public static class FeatureSupport
{
    public static FeatureVerificationStatus SoftwareAesGcm => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus SoftwareKekDek => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus KdeKEnvelope => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus WindowsCredentials => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus AzureKeyVault => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus Tpm => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus Pkcs11 => FeatureVerificationStatus.Supported;

    public static FeatureVerificationStatus LinuxMacOsCredentials => FeatureVerificationStatus.Unsupported;

    /// <summary>
    /// Throws when a feature is intentionally unsupported on net48.
    /// </summary>
    public static void ThrowIfUnsupported(string feature, FeatureVerificationStatus status, string reason)
    {
        if (status == FeatureVerificationStatus.Unsupported)
            throw new UnsupportedFeatureException(feature, reason);
    }
}

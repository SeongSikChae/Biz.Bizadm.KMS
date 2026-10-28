namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Signals that a cryptographic backend is intentionally unavailable in this target.
/// </summary>
public sealed class UnsupportedFeatureException : NotImplementedException
{
    public UnsupportedFeatureException(string feature, string reason)
        : base($"Feature '{feature}' is not implemented for .NET Framework 4.8: {reason}")
    {
        if (string.IsNullOrWhiteSpace(feature)) throw new ArgumentException("A feature name is required.", nameof(feature));
        if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("A reason is required.", nameof(reason));
    }
}

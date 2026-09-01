namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// KEK 버전 레지스트리와 DEK re-wrap 오케스트레이션을 담당한다.
    /// </summary>
    public interface IKekManager : IDisposable
    {
        /// <summary>
        /// wrap에 사용할 현재(최신) KEK.
        /// </summary>
        IKekCipher Current { get; }

        /// <summary>
        /// 등록된 모든 KeyId.
        /// </summary>
        IReadOnlyCollection<string> KnownKeyIds { get; }

        /// <summary>
        /// KeyId에 해당하는 KEK를 반환한다.
        /// </summary>
        /// <param name="keyId">조회할 KeyId.</param>
        /// <returns>해당 KEK.</returns>
        /// <exception cref="KeyNotFoundException">등록되지 않은 KeyId인 경우.</exception>
        IKekCipher Resolve(string keyId);

        /// <summary>
        /// envelope의 KeyId로 source KEK를 찾아 Current로 re-wrap한다.
        /// </summary>
        /// <param name="envelope">직렬화된 DEK envelope.</param>
        /// <returns>새 envelope 바이트.</returns>
        byte[] RewrapDek(byte[] envelope);

        /// <summary>
        /// envelope의 KeyId로 source KEK를 찾아 Current로 비동기 re-wrap한다.
        /// </summary>
        /// <param name="envelope">직렬화된 DEK envelope.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>새 envelope 바이트.</returns>
        Task<byte[]> RewrapDekAsync(byte[] envelope, CancellationToken cancellationToken = default);

        /// <summary>
        /// DEK 파일을 envelope 파싱 후 re-wrap하고 원자적으로 갱신한다.
        /// </summary>
        /// <param name="dekFile">DEK envelope 파일.</param>
        void RewrapDekFile(FileInfo dekFile);

        /// <summary>
        /// DEK 파일을 envelope 파싱 후 비동기 re-wrap하고 원자적으로 갱신한다.
        /// </summary>
        /// <param name="dekFile">DEK envelope 파일.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        Task RewrapDekFileAsync(FileInfo dekFile, CancellationToken cancellationToken = default);

        /// <summary>
        /// 더 이상 unwrap에 필요 없는 KEK를 registry에서 제거하고 Dispose한다.
        /// </summary>
        /// <param name="keyId">해제할 KEK의 KeyId.</param>
        /// <exception cref="KeyNotFoundException">등록되지 않은 KeyId인 경우.</exception>
        /// <exception cref="InvalidOperationException"><see cref="Current"/> KEK를 해제하려는 경우.</exception>
        void Release(string keyId);
    }
}

using Neo;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using System;
using System.Numerics;

namespace SeraphID
{
    /// <summary>
    /// Issuer Trust Status Flag
    /// </summary>
    public enum IssuerStatus
    {
        NotTrusted = 0,
        Trusted = 1
    }

    /// <summary>
    /// SeraphID Trust Anchor Smart Contract Template
    /// </summary>
    public class RootOfTrust : SmartContract
    {
        private static readonly string ROT_NAME = "Seraph Trust Anchor Template";
        private static readonly UInt160 OWNER = "NVbCf5RXFmWNjJakueHAu4wnFzzBd5gjbE".ToScriptHash();

        /// <summary>
        /// Get RootofTrust name
        /// </summary>
        public static string Name()
        {
            return ROT_NAME;
        }

        /// <summary>
        /// Checks if given issuer-schema pair is trusted
        /// </summary>
        /// <param name="issuerDID">issuerDID (string)</param>
        /// <param name="schemaName">the schema name</param>
        public static bool IsTrusted(string issuerDID, string schemaName)
        {
            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            IssuerStatus status = ByteArray2IssuerStatus((byte[])issuerTrustList.Get(schemaName));
            return status == IssuerStatus.Trusted;
        }

        /// <summary>
        /// Registers an issuer-schema pair.
        /// </summary>
        /// <param name="issuerDID">issuer ID</param>
        /// <param name="schemaName">the schema name</param>
        public static bool RegisterIssuer(string issuerDID, string schemaName)
        {
            if (!Runtime.CheckWitness(OWNER)) throw new Exception("Only SmartContract owner can call this operation");
            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            byte[] trusted = IssuerStatus2ByteArray(IssuerStatus.Trusted);
            issuerTrustList.Put(schemaName, (ByteString)trusted);
            return true;
        }

        /// <summary>
        /// Deactivates a trusted issuer-schema pair
        /// </summary>
        /// <param name="issuerDID">issuerDID (string)</param>
        /// <param name="schemaName">schemaName (string)</param>
        public static bool DeactivateIssuer(string issuerDID, string schemaName)
        {
            if (!Runtime.CheckWitness(OWNER)) throw new Exception("Only SmartContract owner can call this operation");
            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            IssuerStatus status = ByteArray2IssuerStatus((byte[])issuerTrustList.Get(schemaName));

            if (status == IssuerStatus.NotTrusted) throw new Exception("No such issuer-schema pair registered");

            issuerTrustList.Delete(schemaName);

            return true;
        }

        /// <summary>
        /// Helper method to serialize IssuerStatus
        /// </summary>
        /// <param name="value">ClaimStatus</param>
        /// <returns>Serialized ClaimStatus</returns>
        private static byte[] IssuerStatus2ByteArray(IssuerStatus value) => ((BigInteger)(int)value).ToByteArray();

        /// <summary>
        /// Helper method to deserialize bytes to IssuerStatus
        /// </summary>
        /// <param name="value">Serialized ClaimStatus</param>
        /// <returns>Deserialized ClaimStatus</returns>
        private static IssuerStatus ByteArray2IssuerStatus(byte[] value)//changed
        {
            if (value == null || value.Length == 0) return IssuerStatus.NotTrusted;
            return (IssuerStatus)(int)value.ToBigInteger();
        }
    }
}

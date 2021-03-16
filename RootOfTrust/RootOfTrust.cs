/// Copyright (c) 2019 Swisscom Blockchain AG
/// Licensed under MIT License

using Neo;
using Neo.Cryptography.ECC;
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
        private static readonly string TRUST_ANCHOR_NAME = "Seraph Trust Anchor Template";
        private static readonly ECPoint ISSUER_DEFAULT_PUBLIC_KEY = (ECPoint)"033e26d8947eb55a24f16abaf4f6db5aff6e2285676815877a32c0cd83440e68a5".HexToBytes();
        private static readonly UInt160 OWNER = "NVbCf5RXFmWNjJakueHAu4wnFzzBd5gjbE".ToScriptHash();

        /// <summary>
        /// Get RootofTrust name
        /// </summary>
        public static string Name()
        {
            return TRUST_ANCHOR_NAME;
        }

        /// <summary>
        /// Checks if given issuer-schema pair is trusted
        /// </summary>
        /// <param name="args">issuerDID (string), schemaName (string)</param>
        public static bool IsTrusted(string issuerDID, string schemaName)
        {
            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            IssuerStatus status = ByteArray2IssuerStatus((byte[])issuerTrustList.Get(schemaName));
            return status == IssuerStatus.Trusted;
        }

        /// <summary>
        /// Registers an issuer-schema pair.
        /// </summary>
        /// <param name="args">issuerDID (string), schemaName (string)</param>
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
        /// <param name="args">issuerDID (string), schemaName (string)</param>
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
        /// Get public key list
        /// </summary>
        /// <param name="args">schemaName (string)</param>
        public static ECPoint[] PublicKey()
        {
            ECPoint[] publicKeyList = Recovery.GetPublicKeys(ISSUER_DEFAULT_PUBLIC_KEY);
            return publicKeyList;
        }

        /// <summary>
        /// Set recovery
        /// </summary>
        /// <param1 name="args">recoveryList (byte[]), pubKeyIndex (BigInteger), message (byte[]), signature (byte[])</param>
        /// <param2 name="args">recoveryList (byte[]), recoveryIndexes (BigInteger[]), message (byte[]), signatures (byte[][])</param>
        public static bool SetRecovery(byte[] recoveryList, BigInteger[] recoveryIndexes, byte[] message, byte[][] signatures)
        {
            object[] newArgs = new object[5];
            newArgs[0] = ISSUER_DEFAULT_PUBLIC_KEY;
            newArgs[1] = (RecoveryList)StdLib.Deserialize((ByteString)recoveryList);
            newArgs[2] = recoveryIndexes;
            newArgs[3] = message;
            newArgs[4] = signatures;
            return Recovery.SetRecovery(newArgs);
        }

        /// <summary>
        /// Add a new public key
        /// </summary>
        /// <param name="args">addedPubKey (ECPoint), recoveryIndexes (BigInteger[]), message (byte[]), signature (byte[][])</param>
        public static bool AddKeyByRecovery(ECPoint addedPubKey, BigInteger[] recoveryIndexes, byte[] message, byte[][] signature)
        {
            object[] newArgs = new object[5];
            newArgs[0] = ISSUER_DEFAULT_PUBLIC_KEY;
            newArgs[1] = addedPubKey;
            newArgs[2] = recoveryIndexes;
            newArgs[3] = message;
            newArgs[4] = signature;
            return Recovery.AddKeyByRecovery(newArgs);
        }

        /// <summary>
        /// Remove a new public key
        /// </summary>
        /// <param name="args">removedPubKey (ECPoint), recoveryIndexes (BigInteger[]), message (byte[]), signature (byte[][])</param>
        public static bool RemoveKeyByRecovery(ECPoint removedPubKey, BigInteger[] recoveryIndexes, byte[] message, byte[][] signature)
        {
            object[] newArgs = new object[5];
            newArgs[0] = ISSUER_DEFAULT_PUBLIC_KEY;
            newArgs[1] = removedPubKey;
            newArgs[2] = recoveryIndexes;
            newArgs[3] = message;
            newArgs[4] = signature;
            return Recovery.RemoveKeyByRecovery(newArgs);
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

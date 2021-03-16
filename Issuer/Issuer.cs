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
    /// Claim Status Flag
    /// </summary>
    public enum ClaimStatus
    {
        Nonexistent = 0,
        Valid = 1,
        Revoked = 2
    }

    /// <summary>
    /// SeraphID Issuer Smart Contract Template
    /// </summary>
    public class Issuer : SmartContract
    {
        private static readonly string ISSUER_NAME = "Seraph Issuer Template";
        private static readonly ECPoint ISSUER_DEFAULT_PUBLIC_KEY = (ECPoint)"02e3729c717dd45a40400f91419e2663b404831f94c7cc4d68ecba642cd8dfd176".HexToBytes();//changed

        private static StorageMap schema => Storage.CurrentContext.CreateMap(nameof(schema));
        private static StorageMap claims => Storage.CurrentContext.CreateMap(nameof(claims));

        private static readonly UInt160 OWNER = "NXJTCgwFDeboGmxAYNMaJcddHjwtwNoUkZ".ToScriptHash();//changed

        /// <summary>
        /// Get issuer name
        /// </summary>
        public static string Name()
        {
            ECPoint a = new ECPoint();
            return ISSUER_NAME;
        }

        /// <summary>
        /// Get public key list
        /// </summary>
        public static ECPoint[] GetPublicKeys()
        {
            ECPoint[] publicKeyList = Recovery.GetPublicKeys(ISSUER_DEFAULT_PUBLIC_KEY);
            return publicKeyList;
        }

        /// <summary>
        /// Gets a schemas definition given its name
        /// </summary>
        /// <param name="schemaName">schemaName (string)</param>
        public static string GetSchemaDetails(string schemaName)
        {
            string schemaDefinition = schema.Get(schemaName);
            if (schemaDefinition == null) throw new Exception("Schema does not exist");
            return schemaDefinition;
        }

        /// <summary>
        /// Registers a schema given a schema definition
        /// </summary>
        /// <param name="args">schemaName (string), schemaDefinition (string)</param>
        public static bool RegisterSchema(string schemaName, string schemaDefinition)
        {
            if (!Runtime.CheckWitness(OWNER)) throw new Exception("Only SmartContract owner can call this operation");

            string existingDefinition = schema.Get(schemaName);

            if (existingDefinition != null) throw new Exception("Schema already exists");
            schema.Put(schemaName, schemaDefinition);

            //StorageMap revokableSchemas = Storage.CurrentContext.CreateMap(REVOKABLE_SCHEMAS_MAP);
            //revokableSchemas.Put(schemaName, (byte[])args[2]);
            return true;
        }

        /// <summary>
        /// Inject a claim into the smart contract
        /// </summary>
        /// <param name="args">claimID (string)</param>
        public static bool InjectClaim(string id)
        {
            if (!Runtime.CheckWitness(OWNER)) throw new Exception("Only SmartContract owner can call this operation");

            ClaimStatus status = ByteArray2ClaimStatus((byte[])claims.Get(id));

            if (status != ClaimStatus.Nonexistent) throw new Exception("Claim already exists");

            claims.Put(id, (ByteString)ClaimStatus2ByteArray(ClaimStatus.Valid));

            return true;
        }

        /// <summary>
        /// Revoke a claim given a claimID
        /// </summary>
        /// <param name="args">claimID (string)</param>
        public static bool RevokeClaim(string id)
        {
            if (!Runtime.CheckWitness(OWNER)) throw new Exception("Only SmartContract owner can call this operation");

            ClaimStatus status = ByteArray2ClaimStatus((byte[])claims.Get(id));

            if (status == ClaimStatus.Nonexistent) throw new Exception("Claim does not exist");
            if (status == ClaimStatus.Revoked) return true;

            claims.Put(id, (ByteString)ClaimStatus2ByteArray(ClaimStatus.Revoked));
            return true;
        }

        /// <summary>
        /// Check if claim is revoked
        /// </summary>
        /// <param name="args">claimID (string)</param>
        public static bool IsValidClaim(string id)
        {
            ClaimStatus status = ByteArray2ClaimStatus((byte[])claims.Get(id));
            return status == ClaimStatus.Valid;
        }

        /// <summary>
        /// Set recovery
        /// </summary>
        /// <param1 name="args">threshold(BigInteger), members(ECPoint[]), pubKeyIndex (BigInteger), message (byte[]), signature (byte[])</param>
        /// <param2 name="args">threshold(BigInteger), members(ECPoint[]), recoveryIndexes (BigInteger[]), message (byte[]), signatures (byte[][])</param>
        public static bool SetRecovery(BigInteger threshold, ECPoint[] members, object index, object message, object signature)
        {
            object[] newArgs = new object[5];
            newArgs[0] = ISSUER_DEFAULT_PUBLIC_KEY;
            RecoveryList recoveryList = new RecoveryList()
            {
                threshold = threshold,
                members = members
            };
            newArgs[1] = recoveryList;
            newArgs[2] = index;
            newArgs[3] = message;
            newArgs[4] = signature;
            return Recovery.SetRecovery(newArgs);
        }

        /// <summary>
        /// Add a new public key
        /// </summary>
        /// <param name="args">addedPubKey (byte[]), recoveryIndexes (BigInteger[]), message (byte[]), signature (byte[][])</param>
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
        /// Helper method to serialize ClaimStatus
        /// </summary>
        /// <param name="value">ClaimStatus</param>
        /// <returns>Serialized ClaimStatus</returns>
        private static byte[] ClaimStatus2ByteArray(ClaimStatus value) => ((BigInteger)(int)value).ToByteArray();

        /// <summary>
        /// Helper method to deserialize bytes to ClaimStatus
        /// </summary>
        /// <param name="value">Serialized ClaimStatus</param>
        /// <returns>Deserialized ClaimStatus</returns>
        private static ClaimStatus ByteArray2ClaimStatus(byte[] value)
        {
            if (value == null || value.Length == 0) return ClaimStatus.Nonexistent;
            return (ClaimStatus)(int)value.ToBigInteger();
        }
    }
}

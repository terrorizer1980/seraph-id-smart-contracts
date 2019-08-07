/// Copyright (c) 2019 Swisscom Blockchain AG
/// Licensed under MIT License

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
        /// <summary>
        /// Main entrypoint of the smart contract
        /// </summary>
        /// <param name="operation">The method to be invoked</param>
        /// <param name="args">Arguments specific to the method</param>
        /// <returns>Result object</returns>
        public static object Main(string operation, object[] args)
        {
            if (operation == "Name") return TRUST_ANCHOR_NAME;
            if (operation == "IsTrusted") return IsTrusted(args);
            if (operation == "RegisterIssuer") return RegisterIssuer(args);
            if (operation == "DeactivateIssuer") return DeactivateIssuer(args);
            else return Result(false, "Invalid operation: " + operation);
        }

        private static readonly string TRUST_ANCHOR_NAME = "SeraphID Trust Anchor Template";
        private static readonly byte[] OWNER = "AK2nJJpJr6o664CWJKi1QRXjqeic2zRp8y".ToScriptHash();

        /// <summary>
        /// Checks if given issuer-schema pair is trusted
        /// </summary>
        /// <param name="args">issuerDID (string), schemaName (string)</param>
        private static object[] IsTrusted(params object[] args){
            if (args.Length != 2) return Result(false, "Incorrect number of parameters");

            string issuerDID = (string)args[0];
            string schemaName = (string)args[1];

            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);

            IssuerStatus status = ByteArray2IssuerStatus(issuerTrustList.Get(schemaName));

            return Result(true, status == IssuerStatus.Trusted);
	    }

        /// <summary>
        /// Registers an issuer-schema pair.
        /// </summary>
        /// <param name="args">issuerDID (string), schemaName (string)</param>
        private static object[] RegisterIssuer(params object[] args){
            if (args.Length != 2) return Result(false, "Incorrect number of parameters");
            if (!Runtime.CheckWitness(OWNER)) return Result(false, "Only SmartContract owner can call this operation");

            string issuerDID = (string)args[0];
            string schemaName = (string)args[1];

            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            issuerTrustList.Put(schemaName, IssuerStatus2ByteArray(IssuerStatus.Trusted));

            return Result(true, true);
        }

        /// <summary>
        /// Deactivates a trusted issuer-schema pair
        /// </summary>
        /// <param name="args">issuerDID (string), schemaName (string)</param>
        private static object[] DeactivateIssuer(params object[] args){
            if (args.Length != 2) return Result(false, "Incorrect number of parameters");
            if (!Runtime.CheckWitness(OWNER)) return Result(false, "Only SmartContract owner can call this operation");

            string issuerDID = (string)args[0];
            string schemaName = (string)args[1];

            StorageMap issuerTrustList = Storage.CurrentContext.CreateMap(issuerDID);
            IssuerStatus status = ByteArray2IssuerStatus(issuerTrustList.Get(schemaName));

            if (status == IssuerStatus.NotTrusted) return Result(false, "No such issuer-schema pair registered");

            issuerTrustList.Delete(schemaName);

            return Result(true, true);

        }

        /// <summary>
        /// Helper method to serialize IssuerStatus
        /// </summary>
        /// <param name="value">ClaimStatus</param>
        /// <returns>Serialized ClaimStatus</returns>
        private static byte[] IssuerStatus2ByteArray(IssuerStatus value) => ((BigInteger)(int)value).AsByteArray();

        /// <summary>
        /// Helper method to deserialize bytes to IssuerStatus
        /// </summary>
        /// <param name="value">Serialized ClaimStatus</param>
        /// <returns>Deserialized ClaimStatus</returns>
        private static IssuerStatus ByteArray2IssuerStatus(byte[] value) => value == null || value.Length == 0 ? IssuerStatus.NotTrusted : (IssuerStatus)(int)value.AsBigInteger();


        /// <summary>
        /// Helper method to deserialize bytes to string
        /// </summary>
        /// <param name="data">Serialized string</param>
        /// <returns>Deserialized string</returns>
        private static string Bytes2String(byte[] data) => data == null || data.Length == 0 ? null : data.AsString();

        /// <summary>
        /// Helper method for unified smart contract return format
        /// </summary>
        /// <param name="success">Indicates wether an error has occured during execution</param>
        /// <param name="result">The result or error message</param>
        /// <returns>Object containing the parameters</returns>
        private static object[] Result(bool success, object result) => new object[] { success, result };
    }
}

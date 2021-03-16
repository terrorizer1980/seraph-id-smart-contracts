using Neo.Cryptography.ECC;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using System;
using System.Numerics;

namespace SeraphID
{
    public class RecoveryList
    {
        public BigInteger threshold;
        public ECPoint[] members;
    }

    public class Recovery
    {
        private static readonly byte[] PUBLICKEYLIST = "publicKeyList".ToByteArray();
        private static readonly byte[] RECOVERYLIST = "recoveryList".ToByteArray();

        /// <summary>
        /// Get public key list, if no public key stored then return input default public Key
        /// </summary>
        /// <param name="defaultPubKey">the default public key</param>
        public static ECPoint[] GetPublicKeys(ECPoint defaultPubKey)
        {
            ECPoint[] publicKeyList = GetStoredPublicKeys();
            if (publicKeyList.Length == 0) publicKeyList = new ECPoint[] { defaultPubKey };
            return publicKeyList;
        }

        /// <summary>
        /// Get public key list
        /// </summary>
        public static ECPoint[] GetStoredPublicKeys()
        {
            byte[] publicKeyBs = (byte[])Storage.Get(Storage.CurrentContext, PUBLICKEYLIST);
            ECPoint[] publicKeyList = null;
            if (publicKeyBs != null && publicKeyBs.Length > 0)
            {
                publicKeyList = StdLib.Deserialize((ByteString)publicKeyBs) as ECPoint[];
            }
            return publicKeyList ?? new ECPoint[0];
        }

        /// <summary>
        /// Set public key list
        /// </summary>
        /// <param name="newPubKeyList">the new public key list</param>
        private static void SetPublicKeys(ECPoint[] newPubKeyList)
        {
            Storage.Put(Storage.CurrentContext, PUBLICKEYLIST, StdLib.Serialize(newPubKeyList));
        }

        /// <summary>
        /// Get recovery list
        /// </summary>
        public static RecoveryList GetRecovery()
        {
            byte[] recoveryListBs = (byte[])Storage.Get(Storage.CurrentContext, RECOVERYLIST);
            RecoveryList currentRecoveryList = null;
            if (recoveryListBs != null && recoveryListBs.Length > 0)
            {
                currentRecoveryList = (RecoveryList)StdLib.Deserialize((ByteString)recoveryListBs);
            }
            return currentRecoveryList;
        }

        /// <summary>
        /// Set recovery list
        /// </summary>
        /// <param name="recoveryList">the recovery list</param>
        private static void SetRecovery(RecoveryList recoveryList)
        {
            Storage.Put(Storage.CurrentContext, RECOVERYLIST, StdLib.Serialize(recoveryList));
        }

        /// <summary>
        /// Set recovery
        /// </summary>
        /// <param name="args[0]">the default public key</param>
        /// <param name="args[1]">the recovery list</param>
        /// <param name="args[2]">the index (BigInteger) of the signature for initializing or indexes (BigInteger[]) of signatures for updating in the recovery list</param>
        /// <param name="args[3]">the signed message</param>
        /// <param name="args[4]">the signature (byte[]) for initializing or signatures (byte[][]) for updating</param>
        public static bool SetRecovery(params object[] args)
        {
            if (args == null || args.Length != 5) throw new Exception("Illegal input argument amount");
            RecoveryList recoveryList = (RecoveryList)args[1];
            if (!IsLegalRecoveryList(recoveryList))
            {
                throw new Exception("Illegal recoveryList");
            }
            RecoveryList currentRecoveryList = GetRecovery();
            if (currentRecoveryList == null || currentRecoveryList.members.Length == 0)//initialization
            {
                BigInteger pubKeyIndex = (BigInteger)args[2];
                ECPoint[] currentPubKeys = GetPublicKeys((ECPoint)args[0]);
                if (pubKeyIndex >= currentPubKeys.Length) throw new Exception("Illegal pubKeyIndex");
                ECPoint pubKey = currentPubKeys[(int)pubKeyIndex];
                byte[] message = (byte[])args[3];
                byte[] signature = (byte[])args[4];
                if (!CryptoLib.VerifyWithECDsa((ByteString)message, pubKey, (ByteString)signature, NamedCurve.secp256r1)) throw new Exception("Signature verification failed");
            }
            else//modification
            {
                BigInteger[] recoveryIndexes = (BigInteger[])args[2];
                if (recoveryIndexes == null || currentRecoveryList.threshold > recoveryIndexes.Length) throw new Exception("Illegal recoveryIndexes");
                ECPoint[] pubKeys = new ECPoint[recoveryIndexes.Length];
                ECPoint[] members = currentRecoveryList.members;
                for (int i = 0; i < recoveryIndexes.Length; i++)
                {
                    int index = (int)recoveryIndexes[i];
                    if (index < 0 || index >= members.Length) throw new Exception("Illegal pubKeyIndex");
                    pubKeys[i] = members[index];
                }
                byte[] message = (byte[])args[3];
                byte[][] signatures = (byte[][])args[4];
                if (signatures.Length != pubKeys.Length) throw new Exception("signatures and pubKeys are not the same length.");
                if (!CheckMultisig(message, pubKeys, signatures)) throw new Exception("Signature verification failed");
            }
            SetRecovery(recoveryList);
            return true;
        }

        /// <summary>
        /// Add a new public key
        /// </summary>
        /// <param name="args[0]">the default public key</param>
        /// <param name="args[1]">the public key to be added</param>
        /// <param name="args[2]">the index (BigInteger) of the signature for initializing or indexes (BigInteger[]) of signatures for updating in the recovery list</param>
        /// <param name="args[3]">the signed message</param>
        /// <param name="args[4]">the signature (byte[]) for initializing or signatures (byte[][]) for updating</param>
        public static bool AddKeyByRecovery(params object[] args)
        {
            if (args == null || args.Length != 5) throw new Exception("Illegal input argument amount");
            ECPoint addedPubKey = (ECPoint)args[1];
            byte[] addedPubKeyBs = (byte[])addedPubKey;
            if ((addedPubKeyBs).Equals((byte[])(ECPoint)args[0])) throw new Exception("Default pubkey cannot be added");
            RecoveryList currentRecoveryList = GetRecovery();
            if (currentRecoveryList == null || currentRecoveryList.members.Length == 0)
            {
                throw new Exception("Recovery has not been defined");
            }
            BigInteger[] recoveryIndexes = (BigInteger[])args[2];
            if (recoveryIndexes == null || currentRecoveryList.threshold > recoveryIndexes.Length) throw new Exception("Illegal recoveryIndexes");
            ECPoint[] pubKeys = new ECPoint[recoveryIndexes.Length];
            ECPoint[] members = currentRecoveryList.members;
            for (int i = 0; i < recoveryIndexes.Length; i++)
            {
                int index = (int)recoveryIndexes[i];
                if (index < 0 || index >= members.Length) throw new Exception("Illegal pubKeyIndex");
                pubKeys[i] = members[index];
            }
            byte[] message = (byte[])args[3];
            byte[][] signatures = (byte[][])args[4];
            if (signatures.Length != pubKeys.Length) throw new Exception("signatures and pubKeys are not the same length.");
            if (!CheckMultisig(message, pubKeys, signatures)) throw new Exception("Signature verification failed");
            ECPoint[] pubKeyList = GetStoredPublicKeys();
            foreach (byte[] key in pubKeyList)
            {
                if (key.Equals(addedPubKeyBs)) throw new Exception("Added pubkey already exists.");
            }
            ECPoint[] newPubKeyList = new ECPoint[pubKeyList.Length + 1];
            for (int i = 0; i < pubKeyList.Length; i++)
            {
                newPubKeyList[i] = pubKeyList[i];
            }
            newPubKeyList[newPubKeyList.Length - 1] = addedPubKey;
            SetPublicKeys(newPubKeyList);
            return true;
        }

        /// <summary>
        /// Remove a new public key
        /// </summary>
        /// <param name="args[0]">the default public key</param>
        /// <param name="args[1]">the public key to be removed</param>
        /// <param name="args[2]">the index (BigInteger) of the signature for initializing or indexes (BigInteger[]) of signatures for updating in the recovery list</param>
        /// <param name="args[3]">the signed message</param>
        /// <param name="args[4]">the signature (byte[]) for initializing or signatures (byte[][]) for updating</param>
        public static bool RemoveKeyByRecovery(params object[] args)
        {
            if (args == null || args.Length != 5) throw new Exception("Illegal input argument amount");
            ECPoint removedPubKey = (ECPoint)args[1];
            byte[] removedPubKeyBs = (byte[])removedPubKey;
            if (removedPubKeyBs.Equals((byte[])(ECPoint)args[0])) throw new Exception("Default pubkey cannot be removed");
            RecoveryList currentRecoveryList = GetRecovery();
            if (currentRecoveryList == null || currentRecoveryList.members.Length == 0)
            {
                throw new Exception("Recovery has not been defined");
            }
            BigInteger[] recoveryIndexes = (BigInteger[])args[2];
            if (recoveryIndexes == null || currentRecoveryList.threshold > recoveryIndexes.Length) throw new Exception("Illegal recoveryIndexes");
            ECPoint[] pubKeys = new ECPoint[recoveryIndexes.Length];
            ECPoint[] members = currentRecoveryList.members;
            for (int i = 0; i < recoveryIndexes.Length; i++)
            {
                int index = (int)recoveryIndexes[i];
                if (index < 0 || index >= members.Length) throw new Exception("Illegal pubKeyIndex");
                pubKeys[i] = members[index];
            }
            byte[] message = (byte[])args[3];
            byte[][] signatures = (byte[][])args[4];
            if (signatures.Length != pubKeys.Length) throw new Exception("signatures and pubKeys are not the same length.");
            if (!CheckMultisig(message, pubKeys, signatures)) throw new Exception("Signature verification failed");
            ECPoint[] pubKeyList = GetStoredPublicKeys();
            if (pubKeyList == null || pubKeyList.Length == 0) throw new Exception("No public key to delete");
            int removedIndex = -1;
            for (int i = 0; i < pubKeyList.Length; i++)
            {
                if (((byte[])pubKeyList[i]).Equals(removedPubKeyBs)) removedIndex = i;
            }
            if (removedIndex == -1) throw new Exception("Public key to delete does not exist in current public key list");
            ECPoint[] newPubKeyList = new ECPoint[pubKeyList.Length - 1];
            int p = 0, q = 0;
            while (p < pubKeyList.Length)
            {
                if (p == removedIndex)
                {
                    p += 1;
                    continue;
                }
                newPubKeyList[q] = pubKeyList[p];
                p += 1;
                q += 1;
            }
            SetPublicKeys(newPubKeyList);
            return true;
        }

        /// <summary>
        /// Returns true if input recoveryList is legal
        /// </summary>
        /// <param name="recoveryList">the recovery list</param>
        public static bool IsLegalRecoveryList(RecoveryList recoveryList)
        {
            ECPoint[] members = recoveryList.members;
            int threshold = (int)recoveryList.threshold;
            int num = members == null ? 0 : members.Length;
            if (threshold > num || threshold < 0) return false;
            if (num > 0 && threshold == 0) return false;
            return true;
        }

        private static bool CheckMultisig(byte[] message, ECPoint[] pubkeys, byte[][] signatures)
        {
            int m = signatures.Length, n = pubkeys.Length;
            if (n == 0 || m == 0 || m > n) throw new ArgumentException();
            try
            {
                for (int i = 0, j = 0; i < m && j < n;)
                {
                    if (CryptoLib.VerifyWithECDsa((ByteString)message, pubkeys[j], (ByteString)signatures[i], NamedCurve.secp256r1))
                        i++;
                    j++;
                    if (m - i > n - j)
                        return false;
                }
            }
            catch (ArgumentException)
            {
                return false;
            }
            return true;
        }
    }
}

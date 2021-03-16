using Neo.SmartContract.Framework;

namespace SeraphID
{
    public class BasicMethods
    {
        /// <summary>
        /// Helper method to deserialize bytes to string
        /// </summary>
        /// <param name="data">Serialized string</param>
        /// <returns>Deserialized string</returns>
        public static string Bytes2String(byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            return data.ToByteString();
        }

        /*/// <summary>
        /// Helper method for unified smart contract return format
        /// </summary>
        /// <param name="success">Indicates whether an error has occured during execution</param>
        /// <param name="result">The result or error message</param>
        /// <returns>Object containing the parameters</returns>
        public static object[] Result(bool success, object result) => new object[] { success, result };*/
    }
}
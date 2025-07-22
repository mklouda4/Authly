using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Serialization;

namespace Authly.Extension
{
    /// <summary>
    /// Extension methods for object manipulation, serialization, and conversion
    /// </summary>
    public static class ObjectExtensions
    {
        /// <summary>
        /// Wraps an item in a completed Task
        /// </summary>
        /// <typeparam name="T">Type of the item</typeparam>
        /// <param name="item">Item to wrap</param>
        /// <returns>Completed task containing the item</returns>
        public static Task<T> ToTaskResult<T>(this T item)
               => Task.FromResult(item);

        /// <summary>
        /// Performs equality comparison between two objects
        /// </summary>
        /// <param name="a">First object</param>
        /// <param name="b">Second object</param>
        /// <returns>True if objects are equal, false otherwise</returns>
        public static bool Eq(this object a, object b)
        {
            if (a != null && b != null)
            {
                if (a.GetType() == b.GetType())
                    return a.Equals(b);
            }
            else if (a == null && b == null)
                return true;
            return false;
        }

        /// <summary>
        /// Serializes an object to JSON string
        /// </summary>
        /// <param name="data">Object to serialize</param>
        /// <returns>JSON string or null if data is null</returns>
        public static string? Serialize(this object data) => data == null ? null : JsonSerializer.Serialize(data);

        /// <summary>
        /// Serializes an object to JSON string with custom options
        /// </summary>
        /// <param name="data">Object to serialize</param>
        /// <param name="options">JSON serializer options</param>
        /// <returns>JSON string or null if data is null</returns>
        public static string? Serialize(this object data, JsonSerializerOptions options) => data == null ? null : JsonSerializer.Serialize(data, options);

        /// <summary>
        /// Deserializes JSON string to specified type
        /// </summary>
        /// <typeparam name="T">Target type</typeparam>
        /// <param name="data">JSON string to deserialize</param>
        /// <returns>Deserialized object or default value</returns>
        public static T? Deserialize<T>(this string data)
        {
            if (string.IsNullOrEmpty(data))
                return default;
            return JsonSerializer.Deserialize<T>(data);
        }

        /// <summary>
        /// Deserializes JSON string to specified type with custom options
        /// </summary>
        /// <typeparam name="T">Target type</typeparam>
        /// <param name="data">JSON string to deserialize</param>
        /// <param name="options">JSON serializer options</param>
        /// <returns>Deserialized object or default value</returns>
        public static T? Deserialize<T>(this string data, JsonSerializerOptions options)
        {
            if (string.IsNullOrEmpty(data))
                return default;
            return JsonSerializer.Deserialize<T>(data, options);
        }

        /// <summary>
        /// Deserializes byte array to specified type
        /// </summary>
        /// <typeparam name="T">Target type</typeparam>
        /// <param name="data">Byte array to deserialize</param>
        /// <returns>Deserialized object</returns>
        public static T? Deserialize<T>(this byte[] data) => data.FromBytes().Deserialize<T>();

        /// <summary>
        /// Converts byte array to UTF-8 string
        /// </summary>
        /// <param name="data">Byte array to convert</param>
        /// <returns>UTF-8 string or null if data is null</returns>
        public static string? FromBytes(this byte[] data) => data == null ? null : Encoding.UTF8.GetString(data);

        /// <summary>
        /// Converts object to byte array via JSON serialization
        /// </summary>
        /// <param name="data">Object to convert</param>
        /// <returns>Byte array representation</returns>
        public static byte[] ToBytes(this object data) => data.Serialize().ToBytes();

        /// <summary>
        /// Converts string to UTF-8 byte array
        /// </summary>
        /// <param name="data">String to convert</param>
        /// <returns>UTF-8 byte array or empty array if data is null</returns>
        public static byte[] ToBytes(this string data) => data == null ? [] : Encoding.UTF8.GetBytes(data);

        /// <summary>
        /// Serializes object to XML string
        /// </summary>
        /// <typeparam name="T">Type of object to serialize</typeparam>
        /// <param name="data">Object to serialize</param>
        /// <returns>XML string representation</returns>
        public static string ToXml<T>(this T data)
        {
            XmlSerializer serializer = new(typeof(T));
            using StringWriter stringWriter = new();
            serializer.Serialize(stringWriter, data);
            return stringWriter.ToString();
        }

        /// <summary>
        /// Computes MD5 hash of byte array
        /// </summary>
        /// <param name="data">Byte array to hash</param>
        /// <returns>MD5 hash as hexadecimal string</returns>
        public static string ToMD5Hash(this byte[] data)
        {
            byte[] hashBytes = MD5.HashData(data);

            StringBuilder sb = new();
            foreach (byte b in hashBytes)
            {
                _ = sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Creates a deep copy of an object using JSON serialization
        /// </summary>
        /// <typeparam name="T">Type of object to copy</typeparam>
        /// <param name="obj">Object to copy</param>
        /// <returns>Deep copy of the object</returns>
        public static T DeepCopy<T>(this T obj)
        {
            var json = JsonSerializer.Serialize(obj);
            return JsonSerializer.Deserialize<T>(json);
        }
    }
}

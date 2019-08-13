using System;
using System.Text;
using System.Security.Cryptography;

namespace SimpleEncryptionPassword
{
    internal class PreCrypte
    {
        public static string HashingPassword(string pass)
        {
            if (pass == null || pass == "") throw new ArgumentNullException("Error, faild to hash! Password should not be empty");
            var hash = HashSHA(pass, SaltCreate());
            return hash;
        }

        public static string HashingPassword(string pass, string salt)
        {
            if (pass == null || pass == "") throw new ArgumentNullException("Error, faild to hash! Password should not be empty");
            if (salt == null || salt == "") throw new ArgumentNullException("Error, faild to hash! Salt should not be empty");
            var hash = HashSHA(pass, salt);
            return hash;
        }

        private static string SaltCreate()
        {
            var crypto = new RNGCryptoServiceProvider();
            var saltArr = new byte[16];
            crypto.GetBytes(saltArr);

            return Convert.ToBase64String(saltArr);
        }

        /// <summary>
        /// This is method hashed and return hash with salt teamwise
        /// </summary>
        /// <param name="pass"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private static string HashSHA(string pass, string salt)
        {
            if (pass == null) throw new ArgumentNullException("text for encrypt not input");
            if (salt == null) throw new ArgumentNullException("salt is empty string");

            var bytePass = Encoding.UTF8.GetBytes(pass + salt);
            SHA512 sha = new SHA512Managed();
            var hash = sha.ComputeHash(bytePass);

            return Convert.ToBase64String(hash) + ":" + salt;
        }

        /// <summary>
        /// Takes hash from a decrypted password
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        private static string GetHashWithoutSalt(string hash)
        {
            if (hash == null) throw new ArgumentNullException("the hash must not be empty");
            string[] splitHash = hash.Split(':');
            return splitHash[0];
        }

        /// <summary>
        /// Takes salt from a decrypted password
        /// </summary>
        /// <param name="encPass"></param>
        /// <returns></returns>
        public static string GetSalt(string encPass)
        {
            if (encPass == null) throw new ArgumentNullException("the password must not be empty");
            string[] splitPass = encPass.Split(':');
            return splitPass[1];
        }

        public static bool IsHashEquals(string hash1, string hash2)
        {
            if ((hash1 == null) || (hash2 == null)) throw new ArgumentNullException("the hash must not be empty to match");
            return GetHashWithoutSalt(hash1).Equals(GetHashWithoutSalt(hash2));
        }

        public string Base64Encode(string text)
        {
            var textByte = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(textByte);
        }

        public string Base64Decode(string text)
        {
            var textByte = Convert.FromBase64String(text);
            return Encoding.UTF8.GetString(textByte);
        }
    }
}

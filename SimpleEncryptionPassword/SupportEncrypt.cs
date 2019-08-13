using System;
using System.Security.Cryptography;
using System.IO;

namespace SimpleEncryptionPassword
{
    public class SupportEncrypt
    {
        private byte[] myIV = null;     //it is not secret, it should adds to cipher password
        private byte[] myKey = null;

        public SupportEncrypt()
        {

        }

        public string EncryptPassword(string password)
        {
            if (password == null || password == "") throw new ArgumentNullException("password for encrypte shold not be empty");
            var hash = PreCrypte.HashingPassword(password);
            var cipher = AddIVtoCipher(Encrypte(hash), Convert.ToBase64String(myIV));
            return cipher;
        }

        private string AddIVtoCipher(string pass, string IV)
        {
            if (pass == null || pass == "") throw new ArgumentNullException("when added IV to the password, it not be empty ");
            if (IV == null || IV == "") throw new ArgumentNullException("when added IV to the password, IV not be empty");
            return pass + ":" + IV;
        }

        private string Encrypte(string pass)
        {
            if (pass == null) throw new ArgumentNullException("password must don't be empty");
            byte[] encrypted;

            using (AesManaged aes = new AesManaged())
            {
                aes.GenerateIV();
                aes.GenerateKey();
                myIV = aes.IV;          //it should set to ...
                myKey = aes.Key;        //it should set to DB
                Console.WriteLine("IV = " + Convert.ToBase64String(aes.IV) + "\nKey = " + Convert.ToBase64String(aes.Key));
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(pass);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            var returnCrypte = Convert.ToBase64String(encrypted);
            return returnCrypte;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pass1">This is the password stored in the database</param>
        /// <param name="pass2">This is the password to compare</param>
        /// <returns></returns>
        public bool IsEncryptedPasswordEqual(string pass1, string pass2)
        {
            if (pass1 == null || pass2 == null) throw new ArgumentNullException("the passwords must not be empty to match");
            //TODO: need to revision required
            var hash1 = DecryptPass(pass1);
            var salt = PreCrypte.GetSalt(hash1);
            var hash2 = PreCrypte.HashingPassword(pass2, salt);
            return hash1.Equals(hash2);
        }

        public string DecryptPass(string password)
        {
            if (password == null || password == "") throw new ArgumentNullException("Error, failed to decrypt password");
            var temp = password.Split(':');
            var pass = temp[0];
            var IV = temp[1];
            var decriptPassword = Decrypt(pass, IV, Convert.ToBase64String(myKey));
            return decriptPassword;
        }

        private string Decrypt(string password, string IV, string Key)
        {
            string plaintText = null;
            using (AesManaged aes = new AesManaged())
            {
                aes.IV = Convert.FromBase64String(IV);
                aes.Key = myKey; 
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(password)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecript = new StreamReader(csDecrypt))
                        {
                            plaintText = srDecript.ReadToEnd();
                        }
                    }
                }
            }
            return plaintText;
        }

        /// <summary>
        /// This is method return IV for save it anywere, with target will use whan to need Decrypte this password
        /// </summary>
        /// <returns></returns>
        public byte[] GetIV()
        {
            if (myIV == null || myIV.Length == 0)
            {
                throw new Exception("IV did not create yeat");                
            }
            return myIV;
        }

        /// <summary>
        /// This is method return Key for save it anywere, with target will use whan to need Decrypte this password
        /// </summary>
        /// <returns></returns>
        public byte[] GetKey()
        {
            if (myKey == null || myKey.Length==0)
            {
                throw new Exception("Key for Encripted did not create yeat");
            }
            return myKey;
        }
    }
}

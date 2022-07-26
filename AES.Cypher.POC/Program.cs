using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES.Cypher.POC
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("Welcome to the Aes Encryption Test tool");
			Console.WriteLine("Please enter the text that you want to encrypt:");
			string plainText = Console.ReadLine();


			//for (int i = 0; i < 5; i++)
			//{
			string cipherText = EncryptDataWithAes(plainText, out string keyBase64, out string vectorBase64,
				out string cipherTextBase64);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine("Here is the cipher text:");
			Console.WriteLine(cipherTextBase64);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine("Here is the Aes key in Base64:");
			Console.WriteLine(keyBase64);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine("Here is the Aes IV in Base64:");
			Console.WriteLine(vectorBase64);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine("Here is the Aes IV and cipher text combined as Base64:");
			Console.WriteLine(cipherText);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine();
			Console.WriteLine("Decryption");
			Console.WriteLine("--------------------------------------------------------------");

			string plainTextDecrypt = DecryptDataWithAes(cipherText, keyBase64, vectorBase64);

			Console.WriteLine("--------------------------------------------------------------");
			Console.WriteLine("Here is the decrypted data:");
			Console.WriteLine(plainTextDecrypt);
			//}
			Console.ReadLine();
		}

		private static string EncryptDataWithAes(string plainText, out string keyBase64, out string vectorBase64, out string cipherTextBase64)
		{
			using (Aes aesAlgorithm = Aes.Create())
			{
				Console.WriteLine($"Aes Cipher Mode : {aesAlgorithm.Mode}");
				Console.WriteLine($"Aes Padding Mode: {aesAlgorithm.Padding}");
				Console.WriteLine($"Aes Key Size : {aesAlgorithm.KeySize}");
				Console.WriteLine($"Aes Block Size : {aesAlgorithm.BlockSize}");

				//set the parameters with out keyword
				keyBase64 = Convert.ToBase64String(aesAlgorithm.Key);
				vectorBase64 = Convert.ToBase64String(aesAlgorithm.IV);

				// Create encryptor object
				ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor();

				byte[] encryptedData;

				//Encryption will be done in a memory stream through a CryptoStream object
				using (MemoryStream ms = new MemoryStream())
				{
					using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter sw = new StreamWriter(cs))
						{
							sw.Write(plainText);
						}

						encryptedData = ms.ToArray();
					}
				}

				cipherTextBase64 = Convert.ToBase64String(encryptedData);

				byte[] mergedArray = aesAlgorithm.IV.Concat(encryptedData).ToArray();
				//Console.WriteLine($"length of byte array: {mergedArray.Length} {aesAlgorithm.IV.Length}");
				return Convert.ToBase64String(mergedArray);

				//return Convert.ToBase64String(encryptedData);
			}
		}

		private static string DecryptDataWithAes(string cipherText, string keyBase64, string vectorBase64)
		{
			using (Aes aesAlgorithm = Aes.Create())
			{
				byte[] cipher = Convert.FromBase64String(cipherText);

				aesAlgorithm.Key = Convert.FromBase64String(keyBase64);
				aesAlgorithm.IV = cipher.Take(16).ToArray();

				//Console.WriteLine($"Aes Cipher Mode : {aesAlgorithm.Mode}");
				//Console.WriteLine($"Aes Padding Mode: {aesAlgorithm.Padding}");
				//Console.WriteLine($"Aes Key Size : {aesAlgorithm.KeySize}");
				//Console.WriteLine($"Aes Block Size : {aesAlgorithm.BlockSize}");

				// Create decryptor object
				ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();


				//Decryption will be done in a memory stream through a CryptoStream object
				using (MemoryStream ms = new MemoryStream(cipher.Skip(16).ToArray()))
				{
					using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader sr = new StreamReader(cs))
						{
							return sr.ReadToEnd();
						}
					}
				}
			}
		}

		private string GetHMAC(string text, string key)
		{
			key = key ?? "";

			using (var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
			{
				var hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(text));
				return Convert.ToBase64String(hash);
			}

		}
	}
}

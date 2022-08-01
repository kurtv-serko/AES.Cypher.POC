// See https://aka.ms/new-console-template for more information

using System.Security.Cryptography;

Console.WriteLine("Welcome to the Aes Encryption Test tool");
Console.WriteLine("Please enter the text that you want to encrypt:");
string plainText = Console.ReadLine();
string privateKey = "BPVhmLB5ZBlVB6uwGCnmIl7xJugawDHk6ARum0EfHms=";

//for (int i = 0; i < 5; i++)
//{
string cipherText = EncryptDataWithAes(plainText, privateKey, out string keyBase64, out string vectorBase64,
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
Console.WriteLine("Here is the Aes IV, cipher text and version combined:");

var versionedValue = "sv1:" + cipherText;

Console.WriteLine(versionedValue);

Console.WriteLine("--------------------------------------------------------------");
Console.WriteLine("Url encoded");

var encodedValue = Uri.EscapeDataString(versionedValue);

Console.WriteLine(encodedValue);

Console.WriteLine("--------------------------------------------------------------");
Console.WriteLine();
Console.WriteLine("Decryption");
Console.WriteLine("--------------------------------------------------------------");

// remove url encoding and version
var cypherTextToDecrypt = Uri.UnescapeDataString(cipherText);

Console.WriteLine("Unescaped string");
Console.WriteLine(cypherTextToDecrypt);
var plainTextDecrypt = DecryptDataWithAes(cypherTextToDecrypt, keyBase64);

Console.WriteLine("--------------------------------------------------------------");
Console.WriteLine("Here is the decrypted data:");
Console.WriteLine(plainTextDecrypt);
//}
Console.ReadLine();

static string EncryptDataWithAes(string plainText, string privateKey, out string keyBase64, out string vectorBase64,
	out string cipherTextBase64)
{
	using (Aes aesAlgorithm = Aes.Create())
	{
		aesAlgorithm.Key = Convert.FromBase64String(privateKey);
		
		// Console.WriteLine($"Aes Cipher Mode : {aesAlgorithm.Mode}");
		// Console.WriteLine($"Aes Padding Mode: {aesAlgorithm.Padding}");
		// Console.WriteLine($"Aes Key Size : {aesAlgorithm.KeySize}");
		// Console.WriteLine($"Aes Block Size : {aesAlgorithm.BlockSize}");

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

static string DecryptDataWithAes(string cipherText, string keyBase64)
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
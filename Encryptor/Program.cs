using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class FileEncryptionUtility
{
    static void Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.WriteLine("Usage: FileEncryptionUtility <operation> <directory> <password>");
            return;
        }

        string operation = args[0];
        string directory = args[1];
        string password = args[2];

        if (operation != "encrypt" && operation != "decrypt")
        {
            Console.WriteLine("Invalid operation. Use 'encrypt' or 'decrypt'.");
            return;
        }

        foreach (string file in Directory.GetFiles(directory))
        {
            string outputFile = file;
            

            if (operation == "encrypt" || operation== "e" )
            {
                outputFile = outputFile + ".enc";
                EncryptFile(file, outputFile, password);
            }
            else
            {
                outputFile = outputFile.Replace(".enc", "");
                DecryptFile(file, outputFile, password);
            }
        }
    }

    static void EncryptFile(string inputFile, string outputFile, string password)
    {
        using (Aes aes = Aes.Create())
        {
            using (Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(password, aes.IV))
            {
                aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);

                using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    outputStream.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                    {
                        inputStream.CopyTo(cryptoStream);
                    }
                }
            }
        }
    }

    static void DecryptFile(string inputFile, string outputFile, string password)
    {
        using (Aes aes = Aes.Create())
        {
            using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
            {
                byte[] iv = new byte[aes.IV.Length];
                inputStream.Read(iv, 0, iv.Length);

                using (Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(password, iv))
                {
                    aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);
                    aes.IV = iv;

                    using (CryptoStream cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
        }
    }
}

// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
using System;
using System.Windows;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Diagnostics;

namespace FileIntegrityChecker
{

    public partial class MainWindow : Window
    {
        private string selectedFilePath;
        private byte[] originalHash;
        private byte[] aesKey;

        public MainWindow()
        {
            //Window_Loaded();
            InitializeComponent();
        }

        private bool RunCheckExecutable()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "Hash.exe"; 
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;

                    process.Start();
                    process.WaitForExit();

                    int exitCode = process.ExitCode;

                    // Возвращаем true при успешном выполнении (exit code 0), иначе false
                    if (exitCode == 0)
                    {
                        return true;
                    }
                    else
                    {
                        MessageBox.Show($"Ошибка выполнения check.exe. Код завершения: {exitCode}");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при запуске check.exe: {ex.Message}");
                return false;
            }
        }

        private void Window_Loaded()
        {
            if (!RunCheckExecutable())
            {
                Application.Current.Shutdown();
            }
        }
        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                selectedFilePath = openFileDialog.FileName;
                FilePathTextBox.Text = selectedFilePath;

                
                originalHash = ComputeFileHash(selectedFilePath);
                OriginalHashTextBox.Text = BitConverter.ToString(originalHash).Replace("-", "");
            }
        }

        private void SetIntegrityControlButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath) || !File.Exists(selectedFilePath))
            {
                MessageBox.Show("Выберите действительный файл.");
                return;
            }

            
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                aesKey = aes.Key;

                
                SaveKeyToConfig(selectedFilePath, aesKey);

                
                byte[] iv;
                byte[] encryptedHash = EncryptHash(originalHash, out iv);

                
                SaveHashToConfig(selectedFilePath, encryptedHash, iv);

                MessageBox.Show("Контроль целостности установлен. Хэш сохранен.");

                Array.Clear(aesKey, 0, aesKey.Length);
            }
        }

        private void VerifyIntegrityButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath) || !File.Exists(selectedFilePath))
            {
                MessageBox.Show("Выберите действительный файл.");
                return;
            }


            byte[] encryptedHash = LoadHashFromConfig(selectedFilePath, out byte[] iv);

            byte[] aesKey = LoadKeyFromConfig(selectedFilePath);

            byte[] decryptedHash = DecryptHash(encryptedHash, aesKey, iv);

            byte[] currentHash = ComputeFileHash(selectedFilePath);

            if (CompareByteArrays(decryptedHash, currentHash))
            {
                MessageBox.Show("Файл не изменен. Хэш совпадает.");
            }
            else
            {
                MessageBox.Show("Файл изменен. Восстановление необходимо.");

                File.Copy(selectedFilePath + ".bak", selectedFilePath, true);

                MessageBox.Show("Файл успешно восстановлен.");
            }

            Array.Clear(aesKey, 0, aesKey.Length);
        }

        private void CreateBackupButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath) || !File.Exists(selectedFilePath))
            {
                MessageBox.Show("Выберите действительный файл.");
                return;
            }
            string backupFilePath = selectedFilePath + ".bak";
            File.Copy(selectedFilePath, backupFilePath, true);

            MessageBox.Show($"Резервная копия создана: {backupFilePath}");
        }

        private byte[] ComputeFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return sha256.ComputeHash(stream);
                }
            }
        }

        private void SaveKeyToConfig(string filePath, byte[] key)
        {
            File.WriteAllBytes(filePath + ".key", key);

            SetFileAttributesHidden(filePath + ".key");

            Array.Clear(key, 0, key.Length);
        }

        private void SaveHashToConfig(string filePath, byte[] encryptedHash, byte[] iv)
        {
            File.WriteAllBytes(filePath + ".hash", encryptedHash);
            File.WriteAllBytes(filePath + ".iv", iv);

            SetFileAttributesHidden(filePath + ".hash");
            SetFileAttributesHidden(filePath + ".iv");

            Array.Clear(encryptedHash, 0, encryptedHash.Length);
            Array.Clear(iv, 0, iv.Length);
        }

        private byte[] LoadKeyFromConfig(string filePath)
        {

            SetFileAttributesNormal(filePath + ".key");

            byte[] key = File.ReadAllBytes(filePath + ".key");

            Array.Clear(key, 0, key.Length);

            return key;
        }

        private byte[] LoadHashFromConfig(string filePath, out byte[] iv)
        {

            SetFileAttributesNormal(filePath + ".hash");
            SetFileAttributesNormal(filePath + ".iv");

            iv = File.ReadAllBytes(filePath + ".iv");
            return File.ReadAllBytes(filePath + ".hash");
        }

        private void SetFileAttributesHidden(string filePath)
        {
            if (File.Exists(filePath))
            {
                File.SetAttributes(filePath, File.GetAttributes(filePath) | FileAttributes.Hidden);
            }
        }

        private void SetFileAttributesNormal(string filePath)
        {
            if (File.Exists(filePath))
            {
                File.SetAttributes(filePath, File.GetAttributes(filePath) & ~FileAttributes.Hidden);
            }
        }

        private byte[] EncryptHash(byte[] hash, out byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                iv = aes.IV;

                aes.Key = aesKey;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(hash, 0, hash.Length);
                    }
                    return ms.ToArray();
                }
            }
        }

        private byte[] DecryptHash(byte[] encryptedHash, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream(encryptedHash))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (BinaryReader reader = new BinaryReader(cryptoStream))
                        {
                            return reader.ReadBytes(encryptedHash.Length);
                        }
                    }
                }
            }
        }

        private bool CompareByteArrays(byte[] array1, byte[] array2)
        {
            if (array1 == null || array2 == null || array1.Length != array2.Length)
            {
                return false;
            }

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}

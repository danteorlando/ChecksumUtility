using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ChecksumUtility
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static readonly BitmapImage redX = new BitmapImage(new Uri("RedX.png", UriKind.Relative));
        private static readonly BitmapImage greenCheck = new BitmapImage(new Uri("Green_Check.png", UriKind.Relative));

        public MainWindow()
        {
            InitializeComponent();
        }

        private void button_file_Click(object sender, RoutedEventArgs e)
        {
            // Create OpenFileDialog 
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                //textBox.Text = filename;
                fileValue.Content = filename;

                MD5 md5 = MD5.Create();
                SHA1 sha1 = SHA1.Create();
                SHA256 sha256 = SHA256.Create();
                SHA384 sha384 = SHA384.Create();
                SHA512 sha512 = SHA512.Create();
                Crc32 crc32 = new Crc32();
                string crc32Hash = "";

                using (var stream = File.OpenRead(filename))
                {
                    //md5Value.Content = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    md5Value.Text = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    stream.Seek(0, SeekOrigin.Begin);

                    sha256Value.Content = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    stream.Seek(0, SeekOrigin.Begin);

                    sha1Value.Content = BitConverter.ToString(sha1.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    stream.Seek(0, SeekOrigin.Begin);

                    sha384Value.Content = BitConverter.ToString(sha384.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    stream.Seek(0, SeekOrigin.Begin);

                    sha512Value.Content = BitConverter.ToString(sha512.ComputeHash(stream)).Replace("-", string.Empty).ToLower().Trim();
                    stream.Seek(0, SeekOrigin.Begin);

                    foreach (byte b in crc32.ComputeHash(stream))
                    {
                        //crc32Hash += b.ToString("x2").ToLower();
                        crc32Hash += b.ToString("d").ToLower().Trim();
                    }
                    crc32Value.Content = crc32Hash;
                }

            }
        }
        private void button_verify_Click(object sender, RoutedEventArgs e)
        {
            String key = textBox.Text.ToLower().Trim();
            if (!String.IsNullOrEmpty(key))
            {
                if (key.Equals(md5Value.Text))
                {
                    img_md5.Source = greenCheck;
                    img_sha1.Source = redX;
                    img_sha256.Source = redX;
                    img_sha384.Source = redX;
                    img_sha512.Source = redX;
                    img_crc32.Source = redX;
                }
                else if (key.Equals(sha1Value.Content))
                {
                    img_md5.Source = redX;
                    img_sha1.Source = greenCheck;
                    img_sha256.Source = redX;
                    img_sha384.Source = redX;
                    img_sha512.Source = redX;
                    img_crc32.Source = redX;
                }
                else if (key.Equals(sha256Value.Content))
                {
                    img_md5.Source = redX;
                    img_sha1.Source = redX;
                    img_sha256.Source = greenCheck;
                    img_sha384.Source = redX;
                    img_sha512.Source = redX;
                    img_crc32.Source = redX;
                }
                else if (key.Equals(sha384Value.Content))
                {
                    img_md5.Source = redX;
                    img_sha1.Source = redX;
                    img_sha256.Source = redX;
                    img_sha384.Source = greenCheck;
                    img_sha512.Source = redX;
                    img_crc32.Source = redX;
                }
                else if (key.Equals(sha512Value.Content))
                {
                    img_md5.Source = redX;
                    img_sha1.Source = redX;
                    img_sha256.Source = redX;
                    img_sha384.Source = redX;
                    img_sha512.Source = greenCheck;
                    img_crc32.Source = redX;
                }
                else if (key.Equals(crc32Value.Content))
                {
                    img_md5.Source = redX;
                    img_sha1.Source = redX;
                    img_sha256.Source = redX;
                    img_sha384.Source = redX;
                    img_sha512.Source = redX;
                    img_crc32.Source = greenCheck;
                }
                else
                {
                    img_md5.Source = redX;
                    img_sha1.Source = redX;
                    img_sha256.Source = redX;
                    img_sha384.Source = redX;
                    img_sha512.Source = redX;
                    img_crc32.Source = redX;

                }
            }
            else
            {
                img_md5.Source = redX;
                img_sha1.Source = redX;
                img_sha256.Source = redX;
                img_sha384.Source = redX;
                img_sha512.Source = redX;
                img_crc32.Source = redX;
            }
        }
    }
}

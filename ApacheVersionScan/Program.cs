using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Xml;

namespace ApacheVersionScan
{
    class Program
    {
        static void Main(string[] args)
        {
            // Обработка порта

            Console.WriteLine("Введите номер порта, где запущен сервер Apache");
            Console.ForegroundColor = ConsoleColor.Blue;
            string portString = Console.ReadLine();
            Console.ResetColor();

            if (!int.TryParse(portString, out var port) || port < 0 || port > 65535)
            {
                ShowWarning("Порт должен быть числом в диапазоне от 0 до 65535");
                return;
            }

            // Запуск Nmap

            var pathAssembly = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var scriptNmap = Path.Combine(pathAssembly, "http-apache404-H3.nse");

            string requestNmap = $"nmap -sV --script {scriptNmap} -p{port} 127.0.0.1 --oX 8081.xml";

            using (Process nmapProcess = new Process())
            {
                try
                {
                    nmapProcess.StartInfo.FileName = "nmap.exe";
                    nmapProcess.StartInfo.Arguments = requestNmap;

                    nmapProcess.Start();
                    nmapProcess.WaitForExit();

                    if (nmapProcess.ExitCode != 0)
                        return;
                }
                catch
                {
                    ShowWarning("Отсутствует Nmap.exe");
                    return;
                }

            }

            //Работа с xml файлом полученным в результате сканирования
            //(получение из файла название продукта и его версию) 

            XmlDocument doc = new XmlDocument();
            doc.Load("8081.xml");
            XmlElement? xRoot = doc.DocumentElement;
            XmlNodeList? serviceNode = xRoot?.SelectNodes("//nmaprun/host/ports/port/service");

            var stringProduct = "";
            var stringVersion = "";

            if (serviceNode == null)
            {
                DeleteFileXml();
                return;
            }

            foreach (XmlNode node in serviceNode)
            {
                var product = node.SelectSingleNode("@product");
                var version = node.SelectSingleNode("@version");

                if (product == null || version == null)
                {
                    ShowWarning($"На данном порту - {port} не запущен Apache ");
                    DeleteFileXml();
                    return;
                }

                stringProduct = product.Value.ToUpper();
                stringVersion = version.Value.ToUpper();

                if (string.IsNullOrWhiteSpace(stringProduct) || string.IsNullOrWhiteSpace(stringVersion) || !stringProduct.Contains("APACHE"))
                {
                    ShowWarning($"На данном порту - {port} запущен другой сервер");
                    DeleteFileXml();
                    return;
                }
            }

            // Запись в БД

            using (ApacheContext db = new ApacheContext())
            {
                try
                {
                    var apache = new Apache { ScanDate = DateTime.Now, Product = stringProduct, Version = stringVersion };
                    db.Apaches.Add(apache);
                    db.SaveChanges();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Объект успешно сохранен");
                    Console.ResetColor();
                }
                catch
                {
                    ShowWarning("Не удалось записать в БД");
                }
            }

            DeleteFileXml();
        }

        //Удаление файла

        static private void DeleteFileXml()
        {
            var pathAssembly = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var pathFileXml = Path.Combine(pathAssembly, "8081.xml");
            File.Delete(pathFileXml);
        }

        static private void ShowWarning(string warn)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine();
            Console.WriteLine(warn);
            Console.ResetColor();
        }
    }
}

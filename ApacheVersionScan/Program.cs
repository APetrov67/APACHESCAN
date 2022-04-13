using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml;

namespace ApacheVersionScan
{
    class Program
    {
        const string IP_REGEX = @"\d{3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";

        static void Main(string[] args)
        {
            //Обработка Хоста

            Console.WriteLine("Введите адресс ХОСТА, если адресс не введен будет использоваться localhost");                
            Console.ForegroundColor = ConsoleColor.Blue;
            string IPhostString = Console.ReadLine();
            Console.ResetColor();

            if (string.IsNullOrWhiteSpace(IPhostString))
            {
                IPhostString = "localhost";
            } 
            else if(!Regex.IsMatch(IPhostString, IP_REGEX))
            {
                ShowWarning("НЕ является IP адресом");
                return;            
            }
            

            // Обработка диапазона портов

            Console.WriteLine("Введите диапазон портов для сканирования, либо конкретный порт, либо будут сканироваться 8080-8090");
            Console.ForegroundColor = ConsoleColor.Blue;
            string portRangeString = Console.ReadLine();
            Console.ResetColor();

            if(!TryParsePort(portRangeString, out var port1, out var port2))
            {
                ShowWarning("Не удалось распознать диапазон портов");
                return;
            } 

            // Запуск Nmap

            var pathAssembly = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var scriptNmap = Path.Combine(pathAssembly, "http-apache404-H3.nse");
            string requestNmap = "";

            if (string.IsNullOrWhiteSpace(portRangeString) || port2 != null )
                requestNmap = $" --script {scriptNmap} -p{port1}-{port2} {IPhostString} --oX Apache.xml";

            if(port2 == null)
                requestNmap = $" --script {scriptNmap} -p{port1} {IPhostString} --oX Apache.xml";


            using (Process nmapProcess = new Process())
            {
                try
                {
                    nmapProcess.StartInfo.FileName = "nmap.exe";
                    nmapProcess.StartInfo.Arguments = requestNmap;

                    nmapProcess.Start();
                    nmapProcess.WaitForExit();

                    if (nmapProcess.ExitCode != 0)
                    {
                        ShowWarning("Некорректный запрос в nmap");
                        return;
                    }                                                                          
                        
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
            doc.Load("Apache.xml");
            XmlElement? xRoot = doc.DocumentElement;
            XmlNodeList? portNodeList = xRoot?.SelectNodes("//nmaprun/host/ports/port");

            if (portNodeList == null)
            {
                DeleteFileXml();
                return;
            }

            var apacheCount = new Dictionary<string, string>();

            foreach (XmlNode node in portNodeList)
            {              
                var item = node.SelectSingleNode("script");

                if (item == null)
                    continue;

                var nodeAttrOutput = item.SelectSingleNode("@output");
                var apacheVersionString = nodeAttrOutput.Value.ToUpper();

                if (string.IsNullOrWhiteSpace(apacheVersionString) || !apacheVersionString.Contains("APACHE"))
                    continue;

                var attrPortId = node.SelectSingleNode("@portid");
                var portId = attrPortId.Value;
                apacheCount.Add(portId, apacheVersionString);
                                   
            }

            if(apacheCount.Count == 0)
            {
                ShowWarning($"На данном диапазоне портов - {port1} - {port2} либо на данном хосте - {IPhostString} не запущен APACHE");
                DeleteFileXml();
                return;
            }

            // Запись в БД
            
            try
            {
                using (ApacheContext db = new ApacheContext())
                {
                    foreach(var apaheItem in apacheCount)
                    {
                        var apache = new Apache { ScanDate = DateTime.Now, Port = apaheItem.Key, Version = apaheItem.Value };
                        db.Apaches.Add(apache);
                        db.SaveChanges();                       
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("ОбъектЫ успешно сохранены");
                    Console.ResetColor();
                }
            }
            catch
            {
                ShowWarning("Не удалось записать в БД");
            }
            
            DeleteFileXml();
        }

        //Удаление файла

        static private void DeleteFileXml()
        {
            var pathAssembly = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var pathFileXml = Path.Combine(pathAssembly, "Apache.xml");
            File.Delete(pathFileXml);
        }

        // Отображение ошибки

        static private void ShowWarning(string warn)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine();
            Console.WriteLine(warn);
            Console.ResetColor();
        }

        //Парсинг портов

        static private bool TryParsePort(string input, out int port1, out int? port2)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                Console.WriteLine("Выбран диапазон по умолчанию(8080-8090)");
                port1 = 8080;
                port2 = 8090;
                return true;

            }

           var splits = input.Split("-");

            if (!int.TryParse(splits[0], out int portBegin) || portBegin < 0 || portBegin > 65535)
            {
                port1 = -1;
                port2 = -1;
                return false;
            }

            if(splits.Length == 1)
            {
                Console.WriteLine($"Используется один порт {portBegin}") ;
                port1 = portBegin;
                port2 = null;
                return true;
            }
            
            if(!int.TryParse(splits[1], out int portEnd) || portEnd < 0 || portEnd > 65535 || portBegin > portEnd)
            {
                port1 = -1;
                port2 = -1;
                return false;
            }

            port1 = portBegin;
            port2 = portEnd;
            return true;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace ApacheVersionScan
{
 public class Apache
    {
        public int Id { get; set; }
        public string Product { get; set; }
        public string Version { get; set; }
        public DateTime ScanDate { get; set; }
    }
}

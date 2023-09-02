using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace Polling_Service
{
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// https://learn.microsoft.com/en-us/dotnet/framework/windows-services/walkthrough-creating-a-windows-service-application-in-the-component-designer
        /// 
        /// </summary>
        static void Main(string[] args)
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new FailedRDPLoginService(args)
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}

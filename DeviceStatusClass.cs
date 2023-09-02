using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
        
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Polling_Service
{
    internal class DeviceStatusClass
    {
        public static bool PingHost(string nameOrAddress)
        {
            bool pong = false;
            Ping ping = null;

            try
            {
                ping = new Ping();
                PingReply reply = ping.Send(nameOrAddress);
                pong = reply.Status == IPStatus.Success;
            }
            catch (PingException)
            {
                // Discard PingExceptions and return false;
            }
            finally
            {
                if (ping != null)
                {
                    ping.Dispose();
                }
            }

            return pong;
        }
   
        public static bool PingPort(string hostUri, int portNumber)
        {
            try
            {
                using (var client = new TcpClient(hostUri, portNumber))
                    return true; 
            }
            catch (SocketException ex)
            {
                return false; 
           
            }        
        }
    }
}

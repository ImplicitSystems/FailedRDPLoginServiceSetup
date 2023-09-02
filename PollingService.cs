using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

using System.Timers;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Polling_Service;

using System.Configuration;
using System.Collections.Specialized;
using System.Net.NetworkInformation;
using NetFwTypeLib;
using System.Text.RegularExpressions;
using System.Net;
using System.Globalization;


namespace Polling_Service
{
    public partial class FailedRDPLoginService : ServiceBase
    {
        // Used to declare the ServiceState values
        // and to add a structure for the service status,
        // used in a platform invoke call

        public enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatus
        {
            public int dwServiceType;
            public ServiceState dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        };

        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);

      
        private int TrollCount = 1;
        private int IntSeconds = 60;
        private bool ClearLogs = true;

        public FailedRDPLoginService(string[] args)
        {
            InitializeComponent();

            string eventSourceName = "FailedRDPLoginService";
            string logName = "FailedRDPLoginServiceLog";

            if (args.Length > 0)
            {
                eventSourceName = args[0];
            }

            if (args.Length > 1)
            {
                logName = args[1];
            }


            eventLog1 = new System.Diagnostics.EventLog();

            if (!EventLog.SourceExists(eventSourceName))
            {
                EventLog.CreateEventSource(eventSourceName, logName);
            }

            eventLog1.Source = eventSourceName;
            eventLog1.Log = logName;
        }
       
        protected override void OnStart(string[] args)
        {
            
            // Update the service state to Start Pending.
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
            serviceStatus.dwWaitHint = 100000;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            int.TryParse(ConfigurationManager.AppSettings["IntSeconds"], out IntSeconds);

            // Pull from database settings                                        
            int SecurityLogPollinterval = 1000 * IntSeconds;// = 60 seconds            
            int UpdatesPollinterval = 1000 * IntSeconds * 60; // = 60 seconds            

            try
            {
                // Set up a timer that triggers every XX minutes.
                Timer timer = new Timer();

                timer.Interval = SecurityLogPollinterval;

                timer.Elapsed += new ElapsedEventHandler(this.SecurityLogFailureAuditWatch);
                timer.Start();
                eventLog1.WriteEntry("Polling Service at " + SecurityLogPollinterval + " second monitoring intervals");


                //// Set up a timer that triggers every XX minutes.
                //Timer timer2 = new Timer();

                //timer2.Interval = UpdatesPollinterval;

                //timer2.Elapsed += new ElapsedEventHandler(this.MicrosoftUpdatesWatch);
                //timer2.Start();
                //eventLog1.WriteEntry("Microsoft Updates Watch Service at " + UpdatesPollinterval + " second monitoring intervals");

            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("Polling Service error: " + ex.ToString());
            }

    

            // Update the service state to Running.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);
            eventLog1.WriteEntry("Polling Service Started");

            // TODO: Send a Notification Alert
        }

        protected override void OnStop()
        {
            // Update the service state to Stop Pending.
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 100000;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Update the service state to Stopped.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // TODO: Send a Notification Alert 
            eventLog1.WriteEntry("Polling Service Stoped.");

        }
        protected override void OnContinue()
        {
            eventLog1.WriteEntry("In OnContinue.");
            // TODO: Send a Notification Alert 

        }
        /// <summary>
        /// Microsoft Updates Watch
        /// The method will monitor forced Windows updates and remove any unwanted Bing search services and software
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public void MicrosoftUpdatesWatch(object sender, ElapsedEventArgs args)
        {
            // Lookup for new updates and Kill all Stalker Services 

            // C:\Windows\SystemApps\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy
            // C:\Windows\SystemApps\Microsoft.Windows.FU.Search_cw5n1h2txyewy
            // C:\Windows\SystemApps\MicrosoftWindows.Client.FU.CBS_cw5n1h2txyewy
        }

        /// <summary>
        /// Checks the Security EventLog for the EntryType FailureAudit 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public void SecurityLogFailureAuditWatch(object sender, ElapsedEventArgs args)
        {

            List<string> IPAddresses = new List<string>();

            // Event Log Watch: Powershell: Get-EventLog -LogName Security  -EntryType FailureAudit
            eventLog1.WriteEntry("Security Log Checked at " + DateTime.Now.ToShortTimeString(), EventLogEntryType.Information, 1);

            EventLog eventLog = new EventLog();

            eventLog.Log = "Security";

            foreach (EventLogEntry entry in eventLog.Entries)
            {
                if (entry.EntryType == EventLogEntryType.FailureAudit)
                {
                    var match = Regex.Match(entry.Message, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
                    if (match.Success)
                    {
                        eventLog1.WriteEntry("IP: " + match.Value, EventLogEntryType.Warning, 666);

                        IPAddresses.Add(match.Value);
                    }
                }
            }

            // Add the IP addresses to the "BLOCK RDP FAILED LOGIN TROLLS" Firewall Rule
            if (IPAddresses.Count > 0)
            {
                TrollCount += IPAddresses.Count;
                eventLog1.WriteEntry("Added " + IPAddresses.Count + " To Firewall Rule", EventLogEntryType.Information, TrollCount);

                UpdateFWRule("BLOCK RDP FAILED LOGIN TROLLS", "3389", IPAddresses);

                // ToDo: Log to database
                // AddTrollToDatabase(IPAddresses)
            }
            else
            {
                eventLog1.WriteEntry("Troll Check Complete - NO FAILED LOGINS", EventLogEntryType.Information);
            }
            if (ClearLogs) /* bool.Parse(ConfigurationManager.AppSettings["ClearLogs"]) */
            {
                eventLog.Clear();
                eventLog1.WriteEntry("Security Event Log Cleared, next check in " + IntSeconds + " seconds", EventLogEntryType.Information);
            }

        }

        #region Evennt log Scanner Helpers

        public enum FirewallProfiles
        {
            // NetFwTypeLib.NET_FW_PROFILE_TYPE_
            Domain = 1,
            Private = 2,
            Public = 4
        }
        public bool IsInternal(string testIp)
        {
            if (testIp == "::1") return true;

            byte[] ip = IPAddress.Parse(testIp).GetAddressBytes();
            switch (ip[0])
            {
                case 10:
                case 127:
                    return true;
                case 172:
                    return ip[1] >= 16 && ip[1] < 32;
                case 192:
                    return ip[1] == 168;
                default:
                    return false;
            }
        }
        private bool IsPrivate(string ipAddress)
        {
            int[] ipParts = ipAddress.Split(new String[] { "." }, StringSplitOptions.RemoveEmptyEntries)
                                     .Select(s => int.Parse(s)).ToArray();
            // in private ip range
            if (ipParts[0] == 10 ||
                (ipParts[0] == 192 && ipParts[1] == 168) ||
                (ipParts[0] == 172 && (ipParts[1] >= 16 && ipParts[1] <= 31)))
            {
                return true;
            }

            // IP Address is probably public.
            // This doesn't catch some VPN ranges like OpenVPN and Hamachi.
            return false;
        }
        private void UpdateFWRule(string ruleName, string ports, List<string> IpAddresses)
        {

            IpAddresses = RemovePrivateIPAddresses(IpAddresses);

            string fwBlockedIPList = "";
            string ruleDescription = "Automated Rule - Failed RDP Login Service: Blocks a Trolls IP Addresses from connecting to the Remote Desktop Protocol (Port 3389).";
            // NetFwTypeLib.NET_FW_IP_VERSION_.NET_FW_IP_VERSION_V4

            foreach (var ip in IpAddresses)
            {
                if (fwBlockedIPList.Contains("*"))
                    return;

                // Remove all private IP's from the list               
                ChangeIPtoFullSubnet(ip);
                fwBlockedIPList += ip + ",";

            }
            if (IpAddresses.Count <= 0)
                return;

            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

            bool exists = true;
            // does the rule exist?
            try
            {
                INetFwRule testforRule = fwPolicy2.Rules.Item(ruleName);
            }
            catch
            {
                exists = false;
            }

            if (exists)
            {
                List<string> PortList;
                List<string> ExistingIPAddresses;

                INetFwRule ExistingRule = fwPolicy2.Rules.Item(ruleName);

                ExistingIPAddresses = new List<string>(ExistingRule.RemoteAddresses.Split(',').ToList());

                PortList = new List<string>(ExistingRule.LocalPorts.Split(',').ToList());

                //  ExistingIPAddresses = RemovePrivateIPAddresses(ExistingIPAddresses);
                // Clean the exisiting list and add it to the fwBlockedIPList
                foreach (var ip in ExistingIPAddresses)
                {
                    fwBlockedIPList += ip + ",";

                    if (fwBlockedIPList.Equals(null))
                        return;
                }
                ExistingRule.RemoteAddresses = fwBlockedIPList;
                ExistingRule.Description = ruleDescription;

            }
            else
            {

                INetFwRule2 NewRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

                var currentProfiles = fwPolicy2.CurrentProfileTypes;
                // Create a new rule

                NewRule.Enabled = true;
                // Allow through firewall
                NewRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                // Using protocol TCP
                NewRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP; // TCP = 6
                NewRule.InterfaceTypes = "All";


                // Name The rule
                NewRule.Name = ruleName;
                NewRule.Description = ruleDescription;
                NewRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN; // inbound
                NewRule.Profiles = currentProfiles;

                // firewallRule.Profiles = (int)(FirewallProfiles.Private | FirewallProfiles.Public);

                // Add the Trolls IP Address to the list
                NewRule.RemoteAddresses = fwBlockedIPList; // IpAddresses.FirstOrDefault().ToString();

                // add the RDP Port
                NewRule.LocalPorts = ports;

                // Add the rule
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(NewRule);

            }
        }

        private List<string> RemovePrivateIPAddresses(List<string> ipAddresses)
        {
            List<string> newList = new List<string>();

            foreach (string ipAddress in ipAddresses)
            {
                if (ipAddress.Equals('*'))
                    return ipAddresses;

                if (!IsPrivate(ipAddress))
                    newList.Add(ipAddress);
            }
            return newList;
        }

        private string ChangeIPtoFullSubnet(string ip)
        {

            if (ip == null)
                ip = string.Empty;
            else
                ip = ip.Trim() + "/24";


            return ip;
        }

        public bool IsIPAddressBlocked(INetFwPolicy2 policy, string ipAddress, out string ruleName, int port = -1)
        {
            string BlockRulePrefix = "";

            int MaxIpAddressesPerRule = 1000;
            ruleName = null;

            try
            {
                lock (policy)
                {
                    for (int i = 0; ; i += MaxIpAddressesPerRule)
                    {
                        string firewallRuleName = BlockRulePrefix + i.ToString(CultureInfo.InvariantCulture);
                        try
                        {
                            INetFwRule rule = policy.Rules.Item(firewallRuleName);
                            if (rule == null)
                            {
                                // No more rules to check
                                break;
                            }
                            else
                            {

                                HashSet<string> set = new HashSet<string>(rule.RemoteAddresses.Split(',').ToList());


                                if (set.Contains(ipAddress))
                                {
                                    ruleName = firewallRuleName;
                                    return (true);
                                }
                            }
                        }
                        catch
                        {
                            // no more rules to check
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                //  IPBanLog.Error(ex);
            }
            return (false);
        }

        #endregion

        //public void AddTrollToDatabase(List<string> ipAddresses)
        //{
        //    // Troll Status
        //    eventLog1.WriteEntry("Starting Troll Poll: " + DateTime.Now.ToShortTimeString(), EventLogEntryType.Information, eventId++);
        //    string message = "Troll Status\n\n";
        //    message += "Troll\t\tPing\tPort\tUrl\n";

        //    TrollTrackerEntities TrollDB = new TrollTrackerEntities();

        //    var Trolls = (from d in TrollDB.Troll
        //                   where d.Active == true
        //                   select d).ToArray();

        //    foreach (var troll in Trolls)
        //    {
        //        try
        //        {
        //            // Ping Trolls
        //            bool pongAlive = DeviceStatusClass.PingHost(troll.TrollIP);

        //            // Check Troll Ports
        //            bool portAlive = DeviceStatusClass.PingPort(troll.TrollIP, (int)troll.HTTPPort);

        //            // Check Troll URL
        //            bool URLAlive = DeviceStatusClass.PingHost(troll.LinkMgmtURL);

        //            message += troll.Name + "\t\t" + Responses(pongAlive) + "\t" + portAlive + "\t" + URLAlive + "\n";
        //        }
        //        catch (Exception ex)
        //        {
        //            message += troll.Name + "\t\tError: " + ex.Message + "\n";
        //            eventLog1.WriteEntry(troll.Name + " :(> \n\n" + ex);
        //        }
        //    }

        //    eventLog1.WriteEntry(message);
        //    eventLog1.WriteEntry(message, EventLogEntryType.Information, eventId++);


        // }

        public string Responses(bool pong)
        {
            string x = "Alive";

            return x;

        }


        private void eventLog1_EntryWritten(object sender, EntryWrittenEventArgs e)
        {

        }
    }
}

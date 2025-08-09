import os
import sys
import tempfile
import subprocess
import shutil
import requests
import socket
import urllib.parse
import re
import multiprocessing

# Constants

DIR = os.path.dirname(os.path.realpath(__file__))
TMP_DIR = tempfile.gettempdir()
CURL_RETRY_NUM = 5
CURL_TIMEOUT = 300
CACHE_DIR = os.path.join(DIR, 'cache')
FILE_IGNORED = os.path.join(DIR, 'ignored.txt')  # File to log ignored entries

SOURCES_HOST_FORMAT = [
    # ... (other URLs as in the original script)
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://www.github.developerdan.com/hosts/lists/dating-services-extended.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    "https://raw.githubusercontent.com/smed79/blacklist/master/hosts.txt",
    "https://raw.githubusercontent.com/Sinfonietta/hostfiles/refs/heads/master/gambling-hosts",
    "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/refs/heads/master/NoFormatting/AdditionalSupplementaryHosts.txt",
    "https://raw.githubusercontent.com/paulgb/BarbBlock/refs/heads/main/blocklists/hosts-file.txt",
    "https://oooo.b-cdn.net/blahdns/blahdns_hosts.txt",
    "https://threatfox.abuse.ch/downloads/hostfile/",
    "https://hosts.tweedge.net/malicious.txt"

]

SOURCES_DOMAINS_ONLY = [
    # ... (other URLs as in the original script)
    "https://raw.githubusercontent.com/dead-hosts/rlwpx.free.fr.htrc_git_FadeMind/master/clean.list",
    "https://raw.githubusercontent.com/dead-hosts/domain_blocklist_web_dbl-oisd-nl/master/clean.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/main/accomplist/hagezi-dyndns/optimized.black.domain.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/main/accomplist/hagezi-hoster/optimized.black.domain.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/accomplist/hagezi-tif-medium/optimized.black.domain.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/accomplist/hagezi-popupads/optimized.black.domain.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/main/accomplist/hagezi-fake/optimized.black.domain.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/accomplist/hagezi-doh/optimized.black.domain.list",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Ads",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Dynamic",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Tracking",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Dating",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Dynamic",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Gambling",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Malware",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Risk",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Scam",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Shock",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/Typo",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Dynamic",
    "https://badmojr.gitlab.io/1hosts/Lite/domains.txt",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/adware/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/malicious/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/phishing/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/redirector/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/scamming/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/spyware/domains.csv",
    "https://raw.githubusercontent.com/mypdns/matrix/refs/heads/master/source/tracking/domains.csv",
    "https://raw.githubusercontent.com/Th3M3/blocklists/refs/heads/master/tracking%26ads.list",
    "https://raw.githubusercontent.com/cbuijs/hagezi/main/accomplist/hagezi-pro/optimized.black.domain.list",
    "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/refs/heads/main/lists/wildcard_domains/scams.txt",
    "https://mkb2091.github.io/blockconvert/output/domains.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt",
    "https://raw.githubusercontent.com/soteria-nou/domain-list/refs/heads/master/all.txt",
    "https://raw.githubusercontent.com/TheAntiSocialEngineer/AntiSocial-BlockList-UK-Community/main/UK-Community.txt",
    "https://raw.githubusercontent.com/migueldemoura/ublock-umatrix-rulesets/master/Hosts/ads-tracking",
    "https://raw.githubusercontent.com/infinitytec/blocklists/master/ads-and-trackers.txt",
    "https://raw.githubusercontent.com/infinitytec/blocklists/master/scams-and-phishing.txt",
    "https://raw.githubusercontent.com/infinitytec/blocklists/master/medicalpseudoscience.txt",
    "https://raw.githubusercontent.com/infinitytec/blocklists/master/mlm.txt",
    "https://raw.githubusercontent.com/infinitytec/blocklists/master/clickbait.txt",
    "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/BlacklistedDomains.txt",
    "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/Misc/MD-Immortal_Domains-Backup.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers.txt",
    "https://raw.githubusercontent.com/x0uid/SpotifyAdBlock/refs/heads/master/SpotifyBlocklist.txt",
    "https://azorult-tracker.net/api/list/domain?format=plain",
    "https://raw.githubusercontent.com/xRuffKez/NRD/refs/heads/main/lists/30-day_phishing/domains-only/nrd-phishing-30day.txt",
    "https://raw.githubusercontent.com/xRuffKez/NRD/refs/heads/main/lists/14-day/domains-only/nrd-14day.txt",
    "https://badblock.celenity.dev/wildcards-no-star/badblock.txt",
    "https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/refs/heads/master/SNAFU.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/google_amp.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/spam.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/redirect.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/privacy.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/phishing.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/coinmining.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/malware.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/abuse.txt",
    "https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/main/Lists/adlist.txt",  
    "https://hosts.ubuntu101.co.za/domains.list",
    "https://gist.github.com/jordan-wright/95af062378e9a7436b94f893d195bcd2/raw/2f51a9b8f8bf06cfe1f24f98263da706d7e85035/cryptocurrency_mining_list.txt",
    "https://raw.githubusercontent.com/fmhy/FMHYFilterlist/refs/heads/main/filterlist-domains.txt",
    "https://raw.githubusercontent.com/stamparm/blackbook/refs/heads/master/blackbook.txt",
    "https://raw.githubusercontent.com/matomo-org/referrer-spam-list/refs/heads/master/spammers.txt",  
    "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/redirector/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/phishing/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/malware/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/gambling/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/fakenews/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/dating/domains",
    "https://raw.githubusercontent.com/cbuijs/ut1/refs/heads/master/cryptojacking/domains",
    "https://ente.dev/api/blocklist/youtube-advertising",
    "https://ente.dev/api/blocklist/tracking",
    "https://ente.dev/api/blocklist/suspicious",
    "https://ente.dev/api/blocklist/google-amp",
    "https://ente.dev/api/blocklist/advertising"

]

FILE_TEMP = tempfile.NamedTemporaryFile(delete=False).name

# Function to download a file to cache
def download_file_to_cache(url):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    
    filename = os.path.join(CACHE_DIR, urllib.parse.quote_plus(url))

    response = requests.get(url, timeout=CURL_TIMEOUT)
    response.raise_for_status()

    with open(filename, 'wb') as f:
        f.write(response.content)

    return filename

# Function to check if a domain resolves via DNS
def domain_resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

# Function to clean up temporary files
def cleanup():
    print("Cleaning up temp files")
    if os.path.exists(FILE_TEMP):
        os.remove(FILE_TEMP)

# Function to log messages
def log(message):
    print(f"{message}")

# Function to log an error and exit
def log_exit(message):
    log(message)
    cleanup()
    sys.exit(1)

# Function to download all sources in hosts format
def download_sources_hosts_format():
    for source in SOURCES_HOST_FORMAT:
        log(f"Downloading hosts source '{source}' to '{FILE_TEMP}'")
        try:
            filename = download_file_to_cache(source)
            with open(filename, 'r', encoding='utf-8') as src_file:
                with open(FILE_TEMP, 'a', encoding='utf-8') as dest_file:
                    dest_file.write(src_file.read())
        except Exception as e:
            log_exit(f"Failed to download {source}: {e}")

# Function to download all domain only sources
def download_sources_domains_only():
    for source in SOURCES_DOMAINS_ONLY:
        log(f"Downloading domain only source '{source}' to '{FILE_TEMP}'")
        try:
            filename = download_file_to_cache(source)
            with open(filename, 'r', encoding='utf-8') as src_file:
                lines = src_file.readlines()
                with open(FILE_TEMP, 'a', encoding='utf-8') as dest_file:
                    for line in lines:
                        if not line.startswith('#'):
                            line = re.sub(r'^', '0.0.0.0 ', line)
                            dest_file.write(line)
        except Exception as e:
            log_exit(f"Failed to download {source}: {e}")

# Function to clean up the merged hosts file
def clean_hosts_file():
    log("Cleaning up hosts file")

    with open(FILE_TEMP, 'r+', encoding='utf-8') as f:
        content = f.read()

        # Remove MS-DOS carriage returns and clean up lines
        content = content.replace('\r', '')
        content = content.replace('127.0.0.1', '0.0.0.0')
        content = re.sub(r'#.*', '', content)
        content = re.sub(r'[ \t]*$', '', content, flags=re.MULTILINE)
        content = content.replace('\t', ' ')
        content = re.sub(r'[^\w\d\.\s_-]', '', content)
        content = re.sub(r' {2,}', ' ', content)

        # Filter valid lines starting with "0.0.0.0"
        content = '\n'.join(line for line in content.splitlines() if line.startswith('0.0.0.0'))

        # Remove localhost lines and invalid domains
        content = re.sub(r'^0\.0\.0\.0 (local(host)?(.localdomain)?)$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^0\.0\.0\.0 \s*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^0\.0\.0\.0 [^\w\d]', '', content, flags=re.MULTILINE)

        # Write cleaned content back to the file
        f.seek(0)
        f.write(content)
        f.truncate()

# Function to check and clean whitelist and blacklist (to be implemented if needed)
def check_and_clean_lists():
    pass

# Function to number files and create Names.txt with full URLs as filenames
def number_files_and_create_names_txt():
    if not os.path.exists(CACHE_DIR):
        log_exit(f"Cache directory '{CACHE_DIR}' does not exist.")

    filenames = os.listdir(CACHE_DIR)

    # Prepare lists for hosts and domains
    hosts_files = []
    domain_files = []

    for filename in filenames:
        if filename.startswith('https%3A%2F%2F'):
            hosts_files.append(filename)
        elif filename.startswith('https://'):
            domain_files.append(filename)

    # Sort files for consistent ordering
    hosts_files.sort()
    domain_files.sort()

    names_txt_path = os.path.join(CACHE_DIR, 'Names.txt')
    
    with open(names_txt_path, 'w', encoding='utf-8') as names_file:
        index = 1

        # Number host sources first and rename files accordingly using full URLs
        for host_file in hosts_files:
            original_url = urllib.parse.unquote_plus(host_file)
            names_file.write(f"{index}. {original_url}\n")
            new_filename = f"{index}_{original_url.replace('https://', '').replace('/', '_')}.txt"
            os.rename(os.path.join(CACHE_DIR, host_file), os.path.join(CACHE_DIR, new_filename))
            index += 1

        # Then number domain sources and rename files accordingly using full URLs
        for domain_file in domain_files:
            original_url = urllib.parse.unquote(domain_file)
            names_file.write(f"{index}. {original_url}\n")
            new_filename = f"{index}_{original_url.replace('https://', '').replace('/', '_')}.txt"
            os.rename(os.path.join(CACHE_DIR, domain_file), os.path.join(CACHE_DIR, new_filename))
            index += 1

    log(f"Created '{names_txt_path}' with numbered file list.")

# Update the main function to call the new functionality for Adblock sources processing.
def main():
    try:
        # Download sources
        download_sources_hosts_format()
        download_sources_domains_only()

        # Clean up the hosts file.
        clean_hosts_file()

        # Additional processing (check and clean lists).
        check_and_clean_lists()

        # Move temp file to output.
        shutil.move(FILE_TEMP, os.path.join(DIR, 'hosts.txt'))

        log("Process completed successfully")

        # Call the function to number files and create Names.txt with full links as filenames.
        number_files_and_create_names_txt()
        
    except Exception as e:
        log_exit(f"An error occurred: {e}")
    finally:
        cleanup()

# Entry point.
if __name__ == "__main__":
    main()
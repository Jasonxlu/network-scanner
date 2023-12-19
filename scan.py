import sys
import subprocess

import time
import json
import re

import requests
import socket

import maxminddb


def findIPv4(url):
    try:
        with open("public_dns_resolvers.txt", "r") as file:
            resolvers = file.read().splitlines()

        ipv4_addresses = set()

        for resolver in resolvers:
            try:
                outputBody = subprocess.run(
                    ["nslookup", url, resolver], capture_output=True, text=True, timeout=10).stdout
                ipv4_pattern = r'Address: (\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'
                matches = re.findall(ipv4_pattern, outputBody)
                ipv4_addresses.update(matches)
            except Exception as e:
                print(f"Error during findIPv4 for resolver {resolver}: {e}")

        return list(ipv4_addresses)

    except Exception as ex:
        print(f"Error during findIPv4: {ex}")
        return []


def findIPv6(url):
    try:
        outputBody = subprocess.run(
            ["nslookup", "-type=AAAA", url], capture_output=True, text=True, timeout=10).stdout
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
        matches = re.findall(ipv6_pattern, outputBody)
        return matches
    except subprocess.CalledProcessError as e:
        print(f"Error during findIPv6: {e}")
        return []


def getHTTPServer(url):
    try:
        r = requests.get(("https://" + url), timeout=10)
        return r.headers["Server"] if "Server" in r.headers else None
    except:
        return -1


def getInsecureHTTPServer(url):
    try:
        r = requests.get(("https://" + url + ":80"), timeout=10)
        return True
    except:
        return False


def get_redirect_https(url, max_redirects=10):
    try:
        url = "http://" + url + ":80"
        for _ in range(max_redirects):
            r = requests.get(url, timeout=10,
                             allow_redirects=False)

            if r.status_code >= 300 and r.status_code < 310:
                if "Location" in r.headers:
                    location_header = r.headers["Location"]
                    if location_header.startswith("https://"):
                        return True
                    else:
                        url = location_header  # Follow the redirect
                else:
                    return False
            else:
                return False

        # If reached maximum redirects return False
        return False

    except Exception:
        return False


def get_hsts(url, max_redirects=10):
    try:
        url = "http://" + url + ":80"
        for _ in range(max_redirects):
            response = requests.get(
                url, timeout=10, allow_redirects=False)

            # Follow the redirect to the final location with 10 redirects
            if response.status_code >= 300 and response.status_code < 310:
                if "Location" in response.headers:
                    location_header = response.headers["Location"]
                    print(location_header)  # Print redirect location
                    url = location_header
                else:
                    break

        # Check if HSTS header is present
        hsts = 'Strict-Transport-Security' in response.headers

        return hsts

    except Exception:
        return False


def get_tls_versions(url):
    try:
        # Use nmap to scan for TLS versions up to TLSv1.2
        nmap_output = subprocess.run(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", url],
                                     capture_output=True, text=True)
        nmap_results = nmap_output.stdout

        # Use openssl to check for TLSv1.3
        openssl_output = subprocess.run(["openssl", "s_client", "-connect", f"{url}:443", "-tls1_3"],
                                        capture_output=True, text=True, input="")
        openssl_results = openssl_output.stderr

        tls_versions = re.findall(r'TLS\w*\.\w*', nmap_results)

        # Check for TLSv1.3
        if "CONNECTED" in openssl_results:
            tls_versions.append("TLSv1.3")

        return tls_versions

    except Exception as e:
        print(f"Error: {e}")
        return []


def get_root_ca(url):
    try:
        # Use openssl to get root CA
        openssl_output = subprocess.run(["openssl", "s_client", "-connect", f"{url}:443"],
                                        capture_output=True, text=True, input="")
        openssl_results = openssl_output.stdout

        pattern = r's:.*?O\s*=\s*(?:"([^"]+)"|([^,]+))'

        # Use re.findall to find all matches in the OpenSSL output
        matches = re.findall(pattern, openssl_results)

        # Check if any matches are found
        if matches:
            # Return the value of the first "O=" field in the subject
            return matches[0][0] if matches[0][0] else matches[0][1]
        else:
            print("Error: Unable to find the 'O' field in the certificate.")
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def get_rdns_names(ipv4_list):
    try:
        results = []
        # Perform reverse DNS lookup
        for ipv4_address in ipv4_list:
            hostnames, _, _ = socket.gethostbyaddr(ipv4_address)
            results.append(hostnames)

        return results
    except Exception:
        return []


def get_rtt(ipv4_address, port):
    try:
        command = f'sh -c "time echo -e \'\\x1dclose\\x0d\' | telnet {ipv4_address} {port}"'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=5)

        # Check if the command was successful
        if result.returncode == 0:
            # Extract the real time from the output
            real_time_str = result.stderr.splitlines()[1].split()[1]
            # Convert to milliseconds
            match = re.match(r'(\d+)m([\d.]+)s', real_time_str)
            if match:
                minutes = int(match.group(1))
                seconds = float(match.group(2))
                total_milliseconds = int(minutes * 60 * 1000 + seconds * 1000)
                print(f"Total milliseconds: {total_milliseconds:.3f} ms")
                return total_milliseconds
            else:
                print("Invalid time string format.")
                return None

        else:
            return None
    except Exception:
        return None


def get_rtt_range(ipv4_list):
    ports = [80, 443, 22]
    rtt_values = []

    for ipv4_address in ipv4_list:
        for port in ports:
            rtt = get_rtt(ipv4_address, port)
            if rtt is not None:
                rtt_values.append(rtt)
                break

    if not rtt_values:
        return None  # None if no reachable addresses

    min_rtt = min(rtt_values)
    max_rtt = max(rtt_values)

    return [min_rtt, max_rtt]


def get_geo_location(ipv4_list):
    # Initialize empty set to store unique locations
    unique_locations = set()

    # Load mmdb file
    try:
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            for ipv4_address in ipv4_list:
                try:
                    # Query the database for the location information of the current IP address
                    location_data = reader.get(ipv4_address)

                    # Extract city, province, and country
                    city = location_data['city']['names']['en'] if 'city' in location_data else None
                    province = location_data['subdivisions'][0]['names']['en'] if 'subdivisions' in location_data else None
                    country = location_data['country']['names']['en'] if 'country' in location_data else None

                    # Create a tuple representing the location and add to unique set
                    location_tuple = (city, province, country)
                    unique_locations.add(location_tuple)
                except Exception as e:
                    print(f"Error processing IP address {ipv4_address}: {e}")

    except FileNotFoundError:
        print("GeoLite2-City.mmdb file not found.")

    # Return the set of unique locations
    return unique_locations


def main():
    [_, inputfile, outputfile] = sys.argv

    results = {}

    with open(inputfile, "r") as f:
        for line in f:
            url = line.split("\n")[0]
            print(url)
            curr_scan = {}

            # Call time
            curr_scan["scan_time"] = time.time()

            # Get IPv4 and IPv6 addresses
            ipv4 = findIPv4(url)
            if len(ipv4) > 0:
                curr_scan["ipv4_addresses"] = ipv4

            ipv6 = findIPv6(url)
            if len(ipv6) > 0:
                curr_scan["ipv6_addresses"] = ipv6

            # Get HTTP server
            http_server = getHTTPServer(url)
            if http_server != -1:
                curr_scan["http_server"] = http_server

            # Get insecure HTTP server
            curr_scan["insecure_http"] = getInsecureHTTPServer(url)

            # Get redirect to HTTPS
            curr_scan["redirect_to_https"] = get_redirect_https(url, 10)

            # Get HSTS
            curr_scan["hsts"] = get_hsts(url, 10)

            # Get TLS versions
            tls_versions = get_tls_versions(url)
            if len(tls_versions) > 0:
                curr_scan["tls_versions"] = tls_versions

            # Get Root CA
            supports_tls = len(tls_versions) > 0
            if supports_tls:
                root_ca = get_root_ca(url)
                curr_scan["root_ca"] = root_ca
            else:
                curr_scan["root_ca"] = None

            # Get RDNS names
            rdns_names = get_rdns_names(ipv4)
            curr_scan["rdns_names"] = rdns_names

            # Get RTT range
            rtt_range = get_rtt_range(ipv4)
            curr_scan["rtt_range"] = rtt_range

            # Get Geo Location
            geo_location = list(get_geo_location(ipv4))
            # convert tuples to lists
            geo_location = [list(loc) for loc in geo_location]
            # remove None values
            geo_location = [[i for i in loc if i is not None]
                            for loc in geo_location]
            geo_list = []
            for loc in geo_location:
                geo_list.append(", ".join(loc))
            curr_scan["geo_location"] = geo_list

            results[url] = curr_scan

    with open(outputfile, "w") as f:
        json.dump(results, f, sort_keys=True, indent=4)


if __name__ == "__main__":
    main()

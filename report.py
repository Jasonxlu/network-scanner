import sys
import json
import texttable

def main():
    try:
        # Get json file name and results file name
        [_, data_filename, results_filename] = sys.argv

        with open(data_filename, 'r') as f:
            data = json.load(f)
            #print(json.dumps(data, indent=4))
            urls = data.keys()

            ### PART 1 ###
            table_1 = texttable.Texttable(0)

            rows = [["domain name", "scan_time", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]]

            rtts = [] # [url, min, max]
            root_ca_count = {}
            http_server_count = {}
            
            tls_supported = {"SSLv2": 0, "SSLv3": 0, "TLSv1.0": 0, "TLSv1.1": 0, "TLSv1.2": 0, "TLSv1.3": 0}
            insecure_https_supported = 0
            redirect_to_https_supported = 0
            hsts_supported = 0
            ipv6_supported = 0

            for url in urls:
                curr = [url]

                if "scan_time" in data[url]:
                    curr.append(data[url]["scan_time"])
                else:
                    curr.append("")
                
                if "ipv4_addresses" in data[url]:
                    curr.append(data[url]["ipv4_addresses"])
                else:
                    curr.append("")

                if "ipv6_addresses" in data[url]:
                    if data[url]["ipv6_addresses"]:
                        ipv6_supported += 1
                    curr.append(data[url]["ipv6_addresses"])
                else:
                    curr.append("")

                if "http_server" in data[url]:
                    http_server = data[url]["http_server"]
                    if http_server:
                        if not http_server in http_server_count:
                            http_server_count[http_server] = 0
                        http_server_count[http_server] +=1
                    curr.append(http_server)
                else:
                    curr.append("")

                if "insecure_http" in data[url]:
                    if data[url]["insecure_http"]:
                        insecure_https_supported += 1
                    curr.append(data[url]["insecure_http"])
                else:
                    curr.append("")

                if "redirect_to_https" in data[url]:
                    if data[url]["redirect_to_https"]:
                        redirect_to_https_supported += 1
                    curr.append(data[url]["redirect_to_https"])
                else:
                    curr.append("")

                if "hsts" in data[url]:
                    if data[url]["hsts"]:
                        hsts_supported += 1
                    curr.append(data[url]["hsts"])
                else:
                    curr.append("")

                if "tls_versions" in data[url]:
                    tls_versions = data[url]["tls_versions"]
                    if tls_versions:
                        for tls_version in tls_versions:
                            if not tls_version in tls_supported:
                                tls_supported[tls_version] = 0

                            tls_supported[tls_version] += 1

                    curr.append(tls_versions)
                else:
                    curr.append("")

                if "root_ca" in data[url]:
                    rca = data[url]["root_ca"]
                    if rca:
                        if not rca in root_ca_count:
                            root_ca_count[rca] = 0
                        root_ca_count[rca] +=1
                    curr.append(data[url]["root_ca"])
                else:
                    curr.append("")

                if "rdns_names" in data[url]:
                    curr.append(data[url]["rdns_names"])
                else:
                    curr.append("")

                if "rtt_range" in data[url]:
                    if data[url]["rtt_range"]:
                        rtts.append([url, data[url]["rtt_range"][0], data[url]["rtt_range"][1]])
                    curr.append(data[url]["rtt_range"])
                else:
                    curr.append("")

                if "geo_locations" in data[url]:
                    curr.append(data[url]["geo_locations"])
                else:
                    curr.append("")

                rows.append(curr)
                    
            #print(json.dumps(data, indent=4))
            table_1.add_rows(rows)
            table_1_str = table_1.draw()

            ### PART 2 ###
            def get_min_rtt(arr):
                return arr[1]
            

            rtts.sort(key=get_min_rtt)
            rtts.insert(0, ["domain name", "MIN RTT", "MAX RTT"])
            table_2 = texttable.Texttable(0)
            table_2.add_rows(rtts)
            table_2_str = table_2.draw()

            ### PART 3 ###
            def get_root_ca_count(d):
                return -root_ca_count[d]
            
            root_ca = list(root_ca_count.keys())
            root_ca.sort(key=get_root_ca_count)
            root_ca_data = [['root_ca', 'count']]

            for r in root_ca:
                root_ca_data.append([r, root_ca_count[r]])

            table_3 = texttable.Texttable(0)
            table_3.add_rows(root_ca_data)
            table_3_str = table_3.draw()

             ### PART 4 ###
            def get_http_server_count(d):
                return -http_server_count[d]
            
            http_servers = list(http_server_count.keys())
            http_servers.sort(key=get_http_server_count)
            http_servers_data = [['http_server', 'count']]

            for http_server in http_servers:
                http_servers_data.append([http_server, http_server_count[http_server]])

            table_4 = texttable.Texttable(0)
            table_4.add_rows(http_servers_data)
            table_4_str = table_4.draw()

            ### PART 5 ###
            scanned_domain_count = {}
            for tls in tls_supported:
                scanned_domain_count[tls] = tls_supported[tls]

            scanned_domain_count["plain http"] = insecure_https_supported
            scanned_domain_count["https redirect"] = redirect_to_https_supported
            scanned_domain_count["hsts"] = hsts_supported
            scanned_domain_count["ipv6"] = ipv6_supported

            def get_supported_count(e):
                return -scanned_domain_count[e]
            
            scanned_domain_supported = list(scanned_domain_count.keys())
            scanned_domain_supported.sort(key=get_supported_count)

            supported_rows = [["protocol", "percent supported"]]

            for domain in scanned_domain_supported:
                supported_rows.append([domain, scanned_domain_count[domain] / len(urls) * 100])

            table_5 = texttable.Texttable(0)
            table_5.add_rows(supported_rows)
            table_5_str = table_5.draw()
            
            with open(results_filename, 'w') as f:
                f.write("=========== PART 1 ===========\n")
                f.write(table_1_str)
                f.write("\n\n")
                f.write("=========== PART 2 ===========\n")
                f.write(table_2_str)
                f.write("\n\n")
                f.write("=========== PART 3 ===========\n")
                f.write(table_3_str)
                f.write("\n\n")
                f.write("=========== PART 4 ===========\n")
                f.write(table_4_str)
                f.write("\n\n")
                f.write("=========== PART 5 ===========\n")
                f.write(table_5_str)
                f.write("\n\n")

    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
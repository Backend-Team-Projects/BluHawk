import shodan
import BluHawk.load_env as myenv
from BluHawk.utils import *

import socket


def port_scanner(ip_or_domain, **kwargs):
    try:
        try:
            ip_list = socket.gethostbyname_ex(ip_or_domain)[2]
            if not ip_list:
                return {
                    "status": "success",
                    "data": []
                }
            ip = ip_list[0]
        except socket.gaierror:
            return {
                "status": "success",
                "data": []
            }

        api = shodan.Shodan(myenv.SHODAN_API_KEY)
        host = api.host(ip)

        response = {
            "status": "success",
            "data": list(host.get('ports', []))
        }

    except Exception as e:
        response = {
            "status": "error",
            "data": str(e)
        }
        log_exception(e)

    return response



# def port_scanner(domain, ports=None, max_workers=100, timeout=30):
    # def check_port(domain, port, timeout=timeout):
    #     try:
    #         with socket.create_connection((domain, port), timeout=timeout) as s:
    #             if port == 443:
    #                 try:
    #                     ssl_context = ssl.create_default_context()
    #                     ssl_socket = ssl_context.wrap_socket(s, server_hostname=domain)
    #                     ssl_socket.do_handshake()
    #                     return True
    #                 except ssl.SSLError as e:
    #                     logging.debug(f"SSL handshake error on {domain}:{port}: {e}")
    #                     return False
    #             return True
    #     except (OSError, TimeoutError) as e:
    #         logging.debug(f"Port {port} closed or unreachable on {domain}: {e}")
    #         return False
    #     except Exception as e:
    #         logging.error(f"An unexpected error occurred while checking {domain}:{port}: {e}")
    #         return None

    # def scan_ports(domain, ports, max_workers=max_workers, timeout=timeout): #use the max_workers and timeout from the outer function.
    #     """Scans a list of ports on a given domain using multithreading."""
    #     open_ports = {}
    #     status = 'error'
    #     with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    #         futures = {executor.submit(check_port, domain, port): port for port in ports}
    #         for future in concurrent.futures.as_completed(futures):
    #             port = futures[future]
    #             try:
    #                 result = future.result()
    #                 if result:
    #                     open_ports[port] = True
    #                     status = 'success'
    #             except Exception as exc:
    #                 logging.error(f"Port {port} generated an exception: {exc}")
    #     return {'data': list(open_ports.keys()), 'status': status}


    # def get_common_ports():
    #     return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # if ports is None:
    #     ports = get_common_ports()

    # logging.info(f"Scanning ports on {domain}...")
    # try:
    #     open_ports = scan_ports(domain, ports)
    #     logging.info(f"Scan completed. Open ports: {list(open_ports.keys())}")
    #     return open_ports
    # except Exception as e:
    #     logging.error(f"An error occurred during scanning: {e}")
    #     return None
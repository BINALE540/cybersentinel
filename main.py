import argparse
from modules.port_scanner import scan_target_ports
from modules.header_checker import audit_http_headers
from modules.sys_auditor import check_local_system
from utils.reporter import export_json_report

def main():
    parser = argparse.ArgumentParser(description="CyberSentinel — Vulnerability Scanner & System Auditor")
    parser.add_argument("-t", "--target", help="Target hostname or IP address to scan")
    parser.add_argument("--headers", action="store_true", help="Perform HTTP Security Header Audit")
    parser.add_argument("--local", action="store_true", help="Perform Local Linux Security Audit")
    parser.add_argument("-o", "--output", help="Save scan results to a JSON file (e.g., report.json)")

    args = parser.parse_args()
    results = {}

    print("=" * 60)
    print("      CyberSentinel — Vulnerability Scanner v1.0")
    print("=" * 60)

    if args.target:
        results["target"] = args.target
        print(f"\n[+] TARGET: {args.target}")
        
        # Run Port Scan
        ports = scan_target_ports(args.target)
        results["open_ports"] = ports
        print("\n--- Port Audit Results ---")
        if ports:
            for p in ports:
                print(f"  [OPEN] Port {p['port']}/TCP -> Service: {p['service']}")
        else:
            print("  No common open ports detected.")

        # Run Header Audit
        if args.headers:
            print("\n--- HTTP Security Header Audit ---")
            header_res = audit_http_headers(args.target)
            results["headers_audit"] = header_res
            if "error" in header_res:
                print(f"  [!] Header audit failed: {header_res['error']}")
            else:
                print(f"  [+] Present Headers: {len(header_res['present'])}")
                for h, v in header_res['present'].items():
                    print(f"      - {h}: {v}")
                
                print(f"  [!] Missing Security Headers: {len(header_res['missing'])}")
                for m in header_res['missing']:
                    print(f"      - {m}")

    if args.local:
        print("\n--- Local System Security Audit ---")
        sys_res = check_local_system()
        results["local_system"] = sys_res
        print(f"  [+] Operating System: {sys_res['os_release']}")
        print(f"  [+] UFW Firewall Active: {sys_res['firewall_active']}")

    if args.output and results:
        export_json_report(results, filename=args.output)

    if not args.target and not args.local:
        parser.print_help()

if __name__ == "__main__":
    main()
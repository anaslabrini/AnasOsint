# main.py

import argparse
import os
from tools import email_lookup, phone_lookup, ip_lookup, domain_lookup
from utils import output_manager

def banner():
    os.system("clear")
    print("""\033[94m

     █████╗ ███╗   ██╗ █████╗ ███████╗     
    ██╔══██╗████╗  ██║██╔══██╗██╔════╝     
    ███████║██╔██╗ ██║███████║███████╗     
    ██╔══██║██║╚██╗██║██╔══██║╚════██║     
    ██║  ██║██║ ╚████║██║  ██║███████║     
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝     
                                       
     ██████╗ ███████╗██╗███╗   ██╗████████╗
    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
    ██║   ██║███████╗██║██╔██╗ ██║   ██║   
    ██║   ██║╚════██║██║██║╚██╗██║   ██║   
    ╚██████╔╝███████║██║██║ ╚████║   ██║   
     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
                 \033[0m
\033[94m      Smart Advanced OSINT Tool by Anas Labrini - v1.0 
\033[0m
    """)

def menu():
    while True:
        banner()
        print("\033[94m  [1]\033[0m Email Lookup")
        print("\033[94m  [2]\033[0m Phone Lookup")
        print("\033[94m  [3]\033[0m IP Lookup")
        print("\033[94m  [4]\033[0m Domain Lookup")
        print("\033[91m  [0]\033[0m Exit\n")

        choice = input("\033[96m  [?]\033[0m Enter your choice: ").strip()
        if choice == '0':
            output_manager.success("Thanks for using the tool! Goodbye ")
            break

        # For choices 1-4: ask for target and save-report
        mapping = {
            '1': ('Email address', email_lookup.lookup),
            '2': ('Phone number', phone_lookup.lookup),
            '3': ('IP address', ip_lookup.lookup),
            '4': ('Domain', domain_lookup.lookup),
        }
        if choice in mapping:
            prompt, func = mapping[choice]
            target = input(f"\nEnter the {prompt}: ").strip()
            save = input("[?] Save report? (y/n): ").strip().lower() == 'y'
            func(target, save=save)
        else:
            output_manager.error("Invalid choice! Please select a valid option.")
        
        input("\n\033[95mPress Enter to return to the main menu...\033[0m")
        print("\n" + "-"*60 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Smart Advanced OSINT Tool by Anas ",
        epilog="""
Examples:
  python3 main.py --email target@example.com
  python3 main.py --phone +1234567890 --save-report
  python3 main.py --ip 8.8.8.8 --advanced
  python3 main.py --domain example.com

Interactive:
  python3 main.py            # opens menu-driven interface
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-e', '--email',   help='Email address to lookup')
    parser.add_argument('-p', '--phone',   help='Phone number to lookup')
    parser.add_argument('-i', '--ip',      help='IP address to lookup')
    parser.add_argument('-d', '--domain',  help='Domain to lookup')
    parser.add_argument('-s', '--save-report', action='store_true',
                        help='Save results to report file')
    parser.add_argument('-a', '--advanced', action='store_true',
                        help='Trigger advanced lookup prompts')

    args = parser.parse_args()

    # If no flags: run interactive menu
    if not any([args.email, args.phone, args.ip, args.domain]):
        menu()
        return

    # Configure report saving
    if args.save_report:
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        target = args.email or args.phone or args.ip or args.domain
        safe = target.replace("@","_at_").replace(".","_").replace("+","")
        path = os.path.join(report_dir, f"{safe}_report.txt")
        output_manager.set_report(save=True, path=path)
    else:
        output_manager.set_report(save=False)

    # Invoke appropriate lookup
    if args.email:
        output_manager.info("Requesting advanced scan prompts..." if args.advanced else "Advanced scan disabled.")
        email_lookup.lookup(args.email, save=args.save_report)
    elif args.phone:
        output_manager.info("Requesting advanced scan prompts..." if args.advanced else "Advanced scan disabled.")
        phone_lookup.lookup(args.phone, save=args.save_report)
    elif args.ip:
        output_manager.info("Requesting advanced scan prompts..." if args.advanced else "Advanced scan disabled.")
        ip_lookup.lookup(args.ip, save=args.save_report)
    elif args.domain:
        output_manager.info("Requesting advanced scan prompts..." if args.advanced else "Advanced scan disabled.")
        domain_lookup.lookup(args.domain, save=args.save_report)

if __name__ == "__main__":
    main()

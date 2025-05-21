import winreg
import argparse
from colorama import init, Fore, Style

# Initialize colorama
init()

BANNER = f"""
{Fore.CYAN}
      _ _ _    __ _           _           
  __| | | |  / _(_)_ __   __| | ___ _ __ 
 / _` | | | | |_| | '_ \ / _` |/ _ \ '__|
| (_| | | | |  _| | | | | (_| |  __/ |   
 \__,_|_|_| |_| |_|_| |_|\__,_|\___|_|   
                                       
{Style.BRIGHT}DLL Hijacking Scanner{Style.NORMAL} 
{Fore.YELLOW}by Tech and Fonfon{Style.RESET_ALL}
"""

def scan_dll_registry(verbose=False):
    results = []
    reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\dll"
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
            index = 0
            while True:
                try:
                    name, value, type_id = winreg.EnumValue(key, index)
                    
                    if name != "MRUListEx" and type_id == winreg.REG_BINARY:
                        text_data = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in value)
                        if ".dll" in text_data.lower():
                            for part in text_data.split():
                                if ".dll" in part.lower():
                                    results.append(part)
                                    if verbose:
                                        print(f"{Fore.GREEN}[+] Found DLL reference: {part}{Style.RESET_ALL}")
                    
                    index += 1
                except (OSError, WindowsError):
                    break
                except Exception as e:
                    if verbose:
                        print(f"{Fore.YELLOW}[!] Error reading registry value: {e}{Style.RESET_ALL}")
                    index += 1
    except FileNotFoundError:
        if verbose:
            print(f"{Fore.YELLOW}[!] Registry path not found: {reg_path}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[!] Error accessing registry: {e}{Style.RESET_ALL}")
    
    return results

def main():
    parser = argparse.ArgumentParser(description="DLL Hijacking Tool by Tech and Fonfon")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("-o", "--output", help="Save results to a file")
    args = parser.parse_args()

    print(BANNER)
    
    dll_entries = scan_dll_registry(args.verbose)
    
    if dll_entries:
        print(f"\n{Fore.RED}Possible DLL Hijacking Targets:{Style.RESET_ALL}")
        for i, path in enumerate(dll_entries, 1):
            print(f"  {i}. {Fore.CYAN}{path}{Style.RESET_ALL}")
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write("\n".join(dll_entries))
                print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}No suspicious DLL references found in registry.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
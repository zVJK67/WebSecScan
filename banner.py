from colorama import Fore, Style
import datetime

def print_banner():
    banner = r"""
     .->    (`-')  _<-.(`-')  (`-').->(`-')  _           (`-').->           (`-')  _ <-. (`-')_ 
 (`(`-')/`) ( OO).-/ __( OO)  ( OO)_  ( OO).-/ _         ( OO)_   _         (OO ).-/    \( OO) )
,-`( OO).',(,------.'-'---.\ (_)--\_)(,------. \-,-----.(_)--\_)  \-,-----. / ,---.  ,--./ ,--/ 
|  |\  |  | |  .---'| .-. (/ /    _ / |  .---'  |  .--.//    _ /   |  .--./ | \ /`.\ |   \ |  | 
|  | '.|  |(|  '--. | '-' `.)\_..`--.(|  '--.  /_) (`-')\_..`--.  /_) (`-') '-'|_.' ||  . '|  |)
|  |.'.|  | |  .--' | /`'.  |.-._)   \|  .--'  ||  |OO ).-._)   \ ||  |OO )(|  .-.  ||  |\    | 
|   ,'.   | |  `---.| '--'  /\       /|  `---.(_'  '--'\\       /(_'  '--'\ |  | |  ||  | \   | 
`--'   '--' `------'`------'  `-----' `------'   `-----' `-----'    `-----' `--' `--'`--'  `--' 
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "WebSecScan — Web Security Misconfiguration Analyzer" + Style.RESET_ALL)
    print(Fore.MAGENTA + "Developed by Lee Zhi Hui" + Style.RESET_ALL)
    print(Fore.WHITE + f"Scan started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + Style.RESET_ALL)
    print(Fore.WHITE + "======================================================================" + Style.RESET_ALL)


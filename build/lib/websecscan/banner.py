from colorama import Fore, Style, init
import datetime

# Initialize colorama so styles auto-reset after each print
init(autoreset=True)

def print_banner(title="WebSecScan — Web Security Misconfiguration Scanner",
                 author="Developed by Lee Zhi Hui"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    print(Fore.CYAN + banner)
    print(Fore.BLUE + title)
    print(Fore.BLACK + author)
    print(Fore.WHITE + f"\nScan started at: {now}")
    print(Fore.MAGENTA + "======================================================================")


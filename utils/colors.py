from colorama import Fore, Style, init
init(autoreset=True)
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

def red(text):
    return f"{RED}{text}{RESET}"
def green(text):
    return f"{GREEN}{text}{RESET}"
def yellow(text):
    return f"{YELLOW}{text}{RESET}"
def cyan(text):
    return f"{CYAN}{text}{RESET}"
def magenta(text):
    return f"{MAGENTA}{text}{RESET}"
def bold(text):
    return f"{BOLD}{text}{RESET}"
def critical(text):
    return f"{BOLD}{RED}[CRITICAL]{RESET} {text}"
def high(text):
    return f"{RED}[HIGH]{RESET} {text}"
def medium(text):
    return f"{YELLOW}[MEDIUM]{RESET} {text}"
def low(text):
    return f"{CYAN}[LOW]{RESET} {text}"
def info(text):
    return f"{GREEN}[INFO]{RESET} {text}"

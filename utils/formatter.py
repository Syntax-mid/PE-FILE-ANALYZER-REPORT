from colorama import Fore, Style

def color_flag(text, is_bad=False):
    if is_bad:
        return Fore.RED + text + Style.RESET_ALL
    return Fore.GREEN + text + Style.RESET_ALL

def human_size(size):
    if size > 1024 * 1024:
        return f"{size/1024/1024:.2f} MB"
    elif size > 1024:
        return f"{size/1024:.2f} KB"
    return f"{size} B"

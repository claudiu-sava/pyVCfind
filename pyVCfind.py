#!/usr/bin/env python3
from shutil import get_terminal_size
from colorama import Fore, deinit
from colorama import init
import threading
import argparse
import magic
import time
import math
import sys
import os


# filter ANSI escape sequences out of any text sent to stdout or stderr
# and replace them with equivalent Win32 calls.
init() 

## globals
PYVCFIND_VERSION = "1.3" # According to myself after 2 pulls on js-on official repo
FS_DIVIDER = 512
FS_MIN_SIZE = 299008
SIGNATURE = "application/octet-stream"
WIDTH = get_terminal_size().columns - 20
RED = Fore.RED
GREEN = Fore.GREEN
RESET = Fore.RESET
CYAN = Fore.CYAN
findings = []
paths = []


## vc container structure
class VCContainer:
    def __init__(self, path: str, size: int = 0, entropy: float = .0, signature: str = "", verify_size: bool = False, verify_entropy: bool = False, verify_signature: bool = False):
        self.path: str = path
        # metadata
        self.size = size
        self.entropy = entropy
        self.signature = signature
        # checkmarks
        self.verify_size = verify_size
        self.verify_entropy = verify_entropy
        self.verify_signature = verify_signature


## prompt
def banner():
    print(f"{GREEN}               {RED} _    ________{GREEN}_____           __{RESET}")
    print(f"{GREEN}    ____  __  _{RED}| |  / / ____/{GREEN} __(_)___  ____/ /{RESET}")
    print(f"{GREEN}   / __ \/ / / /{RED} | / / /   {GREEN}/ /_/ / __ \/ __  / {RESET}")
    print(f"{GREEN}  / /_/ / /_/ /{RED}| |/ / /___{GREEN}/ __/ / / / / /_/ /  {RESET}")
    print(f"{GREEN} / .___/\__, / {RED}|___/\____/{GREEN}_/ /_/_/ /_/\__,_/   {RESET}")
    print(f"{GREEN}/_/    /____/  {RED}                  " + "Version: %s" % PYVCFIND_VERSION + f"{RESET}")
    print(f"{CYAN}               (c) 2021 - Jakob Schaffarczyk{RESET}\n")
    print(f"{CYAN}               (c) 2022 - Claudiu Sava (WinFx){RESET}\n")


## print progress bar
def progress(size: int):
    prog = round(50/size*(size-len(paths)))
    msg = f"Progress: [{prog*'#'}{(50-prog)*' '}] {size-len(paths)}/{size}"
    msg += (WIDTH-len(msg)) * ' '
    print(msg, end='\r')


## print error message
def error(msg: str):
    msg = msg.replace("\n", "\n    ")
    if os.name != "nt":
        print(f"{RED}[!]{RESET} {msg}")
    else:
        print(f"[!] {msg}")
    deinit()
    sys.exit(1)


## print info message
def info(msg: str):
    msg = msg.replace("\n", "\n    ")
    if os.name != "nt":
        print(f"{GREEN}[i]{RESET} {msg}")
    else:
        print(f"[i] {msg}")


## calculate entropy for file content
def entropy(path: str) -> float:
    counting = 256*[0]
    length = 0
    with open(path, "rb") as f:
        for line in f:
            for c in line:
                counting[c] += 1
            length += len(line)
    counting = [i for i in counting if i != 0]
    return -sum(count/length * math.log(count/length, 2) for count in counting)


## get filesize in bytes
def file_size(path: str) -> int:
    return os.stat(path).st_size


## get signature of file
def signature(path) -> str:
    m = magic.from_file(path, mime=True)
    return m
    

## function to be threaded
def analyze(size: int, entropy: float):
    while len(paths) != 0:
        path = paths.pop()
        progress(size)
        try:
            check_file(path, entropy)
        except Exception as e:
            error(str(e) + "\nPlease file an issue at https://github.com/js-on/pyVCfind/issues")


## list all files and spawn analyze threads
def check_directory(path: str, jobs: int, entropy: float):
    for root, _, files in os.walk(path):
        for name in files:
            fname = os.path.join(root, name)
            paths.append(fname)
    
    procs = []
    size = len(paths)
    jobs = jobs if jobs < size else size
    for i in range(jobs):
        procs.append(threading.Thread(target=analyze, args=(size, entropy)))
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()

            
## analyze file
def check_file(path: str, entropy_threshold: float):
    if not os.path.exists(path):
        error("File does not exist!")

    vc = VCContainer(path=path)
    vc.size = file_size(vc.path)
    vc.signature = signature(vc.path)

    if vc.size >= FS_MIN_SIZE and vc.size % FS_DIVIDER == 0 and vc.signature == SIGNATURE:
        vc.entropy = entropy(vc.path)
        vc.verify_size = True
        vc.verify_entropy = vc.entropy >= entropy_threshold
        vc.verify_signature = True
        findings.append(vc)


## print findings
def print_findings():
    cross = RED + " X " + RESET
    check = GREEN + " ✔️ " + RESET
    symbol = [cross, check]
    print("\n")
    if len(findings) == 0:
        print(symbol[0] +  " This file does't look like an encrypted container\n")
    else:
        for finding in findings:
            print("Printing results for: %s" % finding.path)
            print(symbol[int(finding.verify_size)] + " filesize:  " + str(finding.size) + " B")
            print(symbol[int(finding.verify_entropy)] +  " entropy:   " + str(finding.entropy))
            print(symbol[int(finding.verify_signature)] +  " signature: " + str(finding.signature))
            print()
            

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--directory", help="Directory to scan for VeraCrypt containers", type=str)
    ap.add_argument("-f", "--file", help="Check if file could be a container or not", type=str)
    ap.add_argument("-t", "--threads", help="Number of threads to spawn. Default is 4", type=int, default=4)
    ap.add_argument("-e", "--entropy", help="Entropy threshold which must be exceeded. Default is 7.999", type=float, default=7.999)
    args = ap.parse_args(sys.argv[1:])

    JOBS = args.threads
    ENTROPY = args.entropy
    if args.directory:
        banner()
        t1 = time.time()
        info(f"Spawning {JOBS} threads\nStarted at {time.ctime(t1)}\n")
        check_directory(os.path.join(os.getcwd(), args.directory), JOBS, ENTROPY)
    elif args.file:
        banner()
        t1 = time.time()
        info(f"Started at {time.ctime(t1)}")
        check_file(os.path.join(os.getcwd(), args.file), ENTROPY)
    else:
        question = input("Do you want so search a Directory or a file? (D/F) ")
        if question == "d" or question == "D":
            directoryPath = input("Enter the directory path: ")
            banner()
            t1 = time.time()
            info(f"Spawning {JOBS} threads\nStarted at {time.ctime(t1)}\n")
            check_directory(os.path.join(os.getcwd(), directoryPath), JOBS, ENTROPY)
        
        elif question == "f" or question == "F":
            filePath = input("Enter the file path: ")
            banner()
            t1 = time.time()
            info(f"Started at {time.ctime(t1)}")
            check_file(os.path.join(os.getcwd(), filePath), ENTROPY)
        else:
            error("One of (-d) or (-f) is required!")
    
    t2 = time.time()
    print_findings()
    info(f"Took {round(t2-t1, 2)}s to execute")
    deinit()


if __name__ == "__main__":
    main()
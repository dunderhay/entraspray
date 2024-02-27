# entraspray

Entraspray is a rewrite of [MSOLSpray](https://github.com/dafthack/MSOLSpray) in python. The main purpose of this tool remains the same: to identify valid passwords for Microsoft Azure accounts while also providing detailed information about account status and errors; such as if MFA is enabled, if a tenant or user doesn't exist, if the account is locked or disabled and more.

### Enhancement:

- The script will remove "compromised" users from the input list. This feature prevents password spraying against accounts where the correct password has already been identified in previous execution of the script. A backup of the original user input list is created in the output directory. While seemingly minor, this change can reduce repeated password spraying and account lockouts, a feature I have not seen in most of the other password spraying tools. The operator can safely keep using the same user input list without risking unnecessary account lockout and alerting. 
- Random selection of user-agents supplied 
Additionally
Some additional error codes have also been added based on conditional access policy.

The tool supports using FireProx to rotate source IP addresses on authentication requests, avoiding being blocked by Microsoft Entra Smart Lockout.

# Usage

### Create/activate virtual env and install requirements:

```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

### Password Spraying

provide a userlist file with the target email addresses one per line for example 'user@example.com'. Use caution to avoid locking out accounts, as this tool can trigger Microsoft Entra Smart Lockout if used incorrectly.

```
python3 entraspray.py --userlist userlist.txt --password Password123
```

### Script Options

```
  --userlist   : Path to a file containing usernames one-per-line in the format 'user@example.com'.
  --password   : Password to be used for the password spraying.
  --url        : URL to spray against. Useful if using FireProx to randomize the IP address you are authenticating from.
  --delay      : Number of seconds to delay between requests.
  --verbose    : Show invalid password attempts.
  --force      : Force the spray to continue even if multiple account lockouts are detected.
  --debug      : Show web request and response.
```

# Acknowledgements

Massive shout out to [Beau Bullock / dafthack](https://github.com/dafthack) for his work on MSOLSpray.

Thanks to my employer <a href='https://www.aurainfosec.com/'>Aura Information Security</a> for providing time for me to work on this project. 

![aura-logo](https://user-images.githubusercontent.com/27876907/188373880-8157648c-eb94-4054-81c8-7c61692b0367.png)
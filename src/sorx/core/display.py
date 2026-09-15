import os
import yaml
from colorama import Fore, Style, init

from sorx import __version__
from sorx.data.loader.rule import get_rule
from sorx.checks.cors_analyze import analyze, prioritize_findings

init(autoreset=True)


SEVERITY_COLORS = {
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.GREEN,
    "info": "\033[38;5;250m",
}

GREY = "\033[38;5;250m"


def logo():
    TOP = "\033[38;2;148;0;211m"
    MID = "\033[38;2;138;0;200m"
    BOT = "\033[38;5;129m"
    ANO = "\033[38;2;192;192;192m"
    RES = Style.RESET_ALL
    return fr"""                      
{TOP}         . .       . .       . .       . .    {RES}
{TOP}      .+'|=|`+. .+'|=|`+. .+'|=|`+. .+'| |`+. {RES}
{TOP}      |  | `+.| |  | |  | |  | |  | |  | |  | {RES}
{MID}      |  | .    |  | |  | |  |'. '. .' .`. `. {RES}
{MID}      `+.|=|`+. |  | |  | |  | |  | |  | |  | {RES}
{BOT}      .    |  | |  | |  | |  | |  | |  | |  | {RES}
{BOT}      |`+. |  | |  | |  | |  | |  | |  | |  | {RES}
{BOT}      `+.|=|.+' `+.|=|.+' `+.| |.+' `+.| |.+' {RES} {ANO}v{__version__}{RES}
    
        {ANO}https://github.com/Just4Hunter/sorx{RES}
    """


def load_rules(config):
    current_dir = os.path.dirname(__file__)
    rules_path = os.path.abspath(
        os.path.join(
            current_dir,
            "..",
            "checks",
            "cors_rules.yaml",
        )
    )

    try:
        with open(rules_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        return data.get("rules", [])

    except (FileNotFoundError, yaml.YAMLError):
        return []


def show_all_rules():
    rules = load_rules({})

    for rule in rules:
        print(f"{rule['id']:<12} {rule['title']}")
        

def get_severity(finding_id):
    rule = get_rule(finding_id)

    if rule:
        return rule.get("severity", "info").lower()

    return "info"


def header(stat):
    mode = stat.mode

    if mode in {"quick", "normal", "deep"}:
        mode_display = f"{mode} (Active)"
    else:
        mode_display = "passive"

    delay = f"{stat.delay}s" if stat.delay else "Unset"
    rate = f"{stat.rate}/s" if stat.rate else "Unset"

    print(
        f"Targets: {stat.targets} | "
        f"Mode: {mode_display} | "
        f"Threads: {stat.threads} | "
        f"Delay: {delay} | "
        f"Rate limit: {rate}"
    )


def findings(url, target_findings, errors):
    print()
    print(f"{Fore.YELLOW}{url}{Style.RESET_ALL}")

    if errors:
        if "timeout" in errors:
            print(f"  {GREY}[Timeout]{Style.RESET_ALL}")
        elif "connection" in errors:
            print(f"  {GREY}[Connection error]{Style.RESET_ALL}")
        else:
            print(f"  {GREY}[Request error]{Style.RESET_ALL}")
        return

    if not target_findings:
        print(f"  {GREY}[No findings]{Style.RESET_ALL}")
        return

    for finding in target_findings:
        finding_id = finding[0]
        name = finding[1]
        related = finding[2]

        severity = get_severity(finding_id)
        color = SEVERITY_COLORS.get(severity, GREY)

        output = f"  {color}[{finding_id}]{Style.RESET_ALL} {name}"

        if related:
            output += f"   {format_related(related)}"

        print(output)


def summary(stat):
    print()
    print("─" * 44)

    print("Scan completed")
    print()

    print(f"Targets scanned : {stat.scanned}")
    print(f"Errors          : {stat.error}")
    print(f"Requests        : {stat.request}")
    print(f"Time            : {stat.elapsed}")
    print(f"Output          : {stat.output}")

    print("─" * 44)


# Utils
def show_id_details(rule_id):
    rule = get_rule(rule_id)

    if not rule:
        print(f"{Fore.RED}sorx: CORS ID '{rule_id}' not found{Style.RESET_ALL}")
        return

    severity = rule.get("severity", "info").lower()
    severity_color = SEVERITY_COLORS.get(severity, GREY)

    print(f"\n{Fore.YELLOW}* {rule['id']}{Style.RESET_ALL}  - {Fore.WHITE}{rule['title']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Severity: {Style.RESET_ALL}{severity_color}{rule['severity']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Description:{Style.RESET_ALL}")
    print(f"   - {rule['description'].strip()}")

    print(f"{Fore.YELLOW}* Evidence:{Style.RESET_ALL}")
    print(f"   - {rule['evidence'].strip()}")

    print(f"{Fore.YELLOW}* Suggestion:{Style.RESET_ALL}")
    print(f"   - {rule['suggestion'].strip()}")

    note = rule.get("note")

    if note:
        print(f"{Fore.YELLOW}* Note:{Style.RESET_ALL}")

        for line in note.strip().splitlines():
            print(f"   - {line}")

    example = rule.get("example")

    if example:
        print(f"{Fore.YELLOW}* Example:{Style.RESET_ALL}")

        if example.get("request"):
            print(f"   {Fore.CYAN}Request:{Style.RESET_ALL}")

            for line in example["request"].strip().splitlines():
                print(f"      {line}")

        if example.get("response"):
            print(f"   {Fore.CYAN}Response:{Style.RESET_ALL}")

            for line in example["response"].strip().splitlines():
                print(f"      {line}")


def format_related(related):
    if not related:
        return ""

    related_ids = []

    for related_id in related:
        severity = get_severity(related_id)
        color = SEVERITY_COLORS.get(severity, GREY)

        related_ids.append(f"{color}{related_id}{Style.RESET_ALL}")

    return (f"{GREY}-#- [Relate]:{Style.RESET_ALL} {{{', '.join(related_ids)}}}")

def show_verbose(results):
    REQUEST_HEADER_BLACKLIST = {
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "priority",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
    }

    RESPONSE_HEADER_BLACKLIST = {
        "x-xss-protection",
        "x-frame-options",
        "date",
        "content-security-policy",
        "via",
        "content-type",
        "cf-cache-status",
        "etag",
        "cache-control",
        "expires",
        "age",
        "server",
        "transfer-encoding",
        "fly-request-id",
        "last-modified",
        "cf-ray",
        "connection",
        "content-encoding",
    }

    for url, outputs in results.items():

        for result in outputs:
            task = result.get("task", {})
            response = result.get("response")
            error = result.get("error")

            method = task.get("method", "GET")
            target = task.get("url", url)
            headers = task.get("headers", {})
            data = task.get("data")

            # Analyze
            findings = []

            if response is not None and error is None:
                findings = analyze(response=response, task=task)
                findings = prioritize_findings(findings)

            # Request
            print(f"\n{Fore.YELLOW}Request:{Style.RESET_ALL}")
            print(f"  {method} {target}")

            for name, value in headers.items():
                if name.lower() not in REQUEST_HEADER_BLACKLIST:
                    print(f"  {name}: {value}")

            if data:
                print(f"\n  {data}")

            # Error
            if error:
                print(f"\n{Fore.RED}Error:{Style.RESET_ALL} {error}")
                print("\n" + "─" * 44)
                continue

            # Response
            print(f"\n{Fore.YELLOW}Response:{Style.RESET_ALL}")

            if response is None:
                print("  No response")
                print("\n" + "─" * 44)
                continue

            print(f"  HTTP {response.status_code}")

            for name, value in response.headers.items():
                if name.lower() not in RESPONSE_HEADER_BLACKLIST:
                    print(f"  {name}: {value}")

            # CORS IDs
            if findings:
                print(f"\n{Fore.YELLOW}CORS:{Style.RESET_ALL}")

                for finding_id, title, related in findings:
                    severity = get_severity(finding_id)
                    color = SEVERITY_COLORS.get(severity, GREY)

                    print(f"  [{color}{finding_id}{Style.RESET_ALL}] {title}")

                    if related:
                        print(f"      {format_related(related)}")

            print("\n" + "─" * 44)
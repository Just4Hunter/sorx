import json
import os

from sorx.data.loader.rule import get_rule


def get_severity(rule_id):
    rule = get_rule(rule_id)

    if rule:
        return rule.get("severity", "info").lower()

    return "info"


def format_related(related):
    if not related:
        return ""

    return f"-#- [Relate]: {{{', '.join(related)}}}"


def format_txt(findings, errors=None):
    blocks = []

    errors = errors or {}

    for target, target_findings in findings.items():
        lines = [target]

        target_error = errors.get(target)

        if target_error:
            if "timeout" in target_error:
                lines.append("  [Timeout]")
            elif "connection" in target_error:
                lines.append("  [Connection error]")
            else:
                lines.append("  [Request error]")

        elif not target_findings:
            lines.append("  [No findings]")

        else:
            for finding in target_findings:
                finding_id = finding[0]
                name = finding[1]
                related = finding[2] if len(finding) > 2 else []

                output = f"  [{finding_id}] {name}"

                if related:
                    output += f"   {format_related(related)}"

                lines.append(output)

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks) + "\n"


def format_json(findings, errors=None):
    data = {}

    errors = errors or {}

    for target, target_findings in findings.items():
        data[target] = []

        target_error = errors.get(target)

        if target_error:
            if "timeout" in target_error:
                data[target].append({"error": "timeout",})
            elif "connection" in target_error:
                data[target].append({"error": "connection",})
            else:
                data[target].append({"error": "request",})

            continue

        for finding in target_findings:
            finding_id = finding[0]
            name = finding[1]
            related = finding[2] if len(finding) > 2 else []

            data[target].append({
                "id": finding_id,
                "name": name,
                "severity": get_severity(finding_id),
                "related": related,
            })

    return json.dumps(data, indent=2)


def write(findings, path, json_output=False, errors=None):
    if json_output:
        content = format_json(findings, errors)
    else:
        content = format_txt(findings, errors)

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
import re

def parser(file_path):
    with open(file_path, 'r') as file:
        data_lines = file.readlines()

        for line in data_lines:
            pattern = r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+)\s+(.+?)(?:\s+User: (\w+))?(?:\s+IP: ([\d.]+))?$"

            match = re.match(pattern, line)

            if match:
                timestamp  = f"{match.group(1)} {match.group(2)}"
                log_level  = match.group(3)
                message    = match.group(4)
                user       = match.group(5) if match.group(5) else "N/A"
                ip_address = match.group(6) if match.group(6) else "N/A"

                if log_level in ("WARNING", "ERROR"):
                    print(
                        f"Timestamp: {timestamp}, "
                        f"Log Level: {log_level}, "
                        f"Message: {message}, "
                        f"User: {user}, "
                        f"IP Address: {ip_address}"
                    )

parser("sample.log")
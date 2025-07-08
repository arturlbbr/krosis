import re

def parse_log_line(line):
    """
    Parses a single line of log and extracts the timestamp, log level, and message.
    
    Args:
        line (str): A single line from the log file.
        
    Returns:
        dict: A dictionary containing 'timestamp', 'level', and 'message'.
    """
    # Regular expression to match the log format
    pattern = r''
    match = re.match(pattern, line)
    
    if match:
        return {
            'timestamp': match.group('timestamp'),
            'level': match.group('level'),
            'message': match.group('message')
        }
    else:
        return None
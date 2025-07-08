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
    #Try condensing later (like \d+\.{3} or something) and add parsing for GET calls tomorrow
    pattern = r'(\d+\.\d+\.\d+\.\d+)((\d{1,2}\/){2}\d{2})((\d{2}\:){2}\d{2})(\+\d{4})()'
    match = re.match(pattern, line)
    
    if match:
        return {
            'src_ip': match.group(1),
            'timestamp': match.group(2),
            'GET_call': match.group(3),
            'response_code': match.group(4),
            'port': match.group(5)
        }
    else:
        return None
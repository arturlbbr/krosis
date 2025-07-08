Krosis

Goal: Create a Log Analyzer to detect network anomalies, my way

Day 1:
- Created repository/project structure
- Started regex parsing

Day 2:
- Continuing regex parsing, learning that I can be very fluid with ingestion:
    - Can parse from the beginning to the first whitespace to grab the IP then trim the whitespace after ingestion for example
    - Or I can grab exactly what I need but creates more clutter in the regex pattern (does that matter?)
    - Have to decide which is more important to me, what's the best practice?
- For now will grab exactly what I need to not add clutter in main logic for string trimming
- Finished parsing, moving onto how to store data
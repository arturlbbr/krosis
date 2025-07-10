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
- Finished setting up local varibles that store the parsed data
    - Created a simple count system for now until I need to add like relationships between IPs & ports or some analyzation logic
- Starting to work on suspicious IP detection logic (first analysis feature)

Day 3:
- Thinking of eventually adding customization for thresholds so a user can set how many times an ip needs to be seen before triggering anything.
- Adding 3 functionalities to the IP detection logic; count check, subnet(botnet) check, OSINT score check (if I can find a good free api)
    - Decided not to put subnet and count check into one function yet so save on performance since this is going to be such a small script and keep it modular
    - Added ip count check and realized I will prob need a file with all the function calls to add if statements, if I'm returning statements of the same ip being suspicious over multiple functions, need to find a way to return all the things each ip is triggering effeciently (prob common practice)

Day 4:
- Forgot to push last commit from last time whoops lol
- Working on second analysis feature (subnet catch)
    - As I get closer to the data I need, finding that some iterations to pull certain data could be done within the first iteration but could also clutter the initial function, learning to find the balance still.
    - Finding that shorthand notations are a lot more useful than I thought, need to study up on them
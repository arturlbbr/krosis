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
- Starting API integration using AbuseIPDB to check ip scores
    - Going to skip over all internal ranges and only check external hosts, dear god don't let me accidentally push my API key
    - Added ipaddress & requests library for the API call and quickly checking if an ip is private or not
    - Added os and python-dotenv libraries to make sure you noobs dont get my API key
    - Learned about walrus operator(:=), pure bliss having the issue of not wanting to rerun the ip_score again or before removing the private ips resolved
- venv and ds store bloat was annoying me, added a .gitignore file
- Print statement looking kinda ugly, will make it prettier after all logic is logicing well

Day 5:
- Working on attack analysis now, first feature will be checking for SQL injections
    - This might be common info but now know that SQL injections should never appear in the logs that I am using since these aren't DB logs so can filter out any sort of SQL command seen as malicious without worry
    - Trying to find a better way to check if any of the request paths are seen with sql commands, nested for loop doesn't seem efficient
- Realizing big issue, doing the count on during parsing and deleting all the extra ips makes me lose the correlations, need to still be able to check what ip did what activity at any point.
    - Having to refactor everything, changed the parsing logic to just adding a dictionary of each parsed log into an array since I'm not going to have a massive amount of data anyways
    - FINALLY finished refactoring, brain absolutely fried, found some cool new ways to condense/shorthand some code along the way though like dictionary comprehensions
- Big day, completely refactored all my code, used much more shorthand notations for things, and finished another analysis feature

Day 6:
- Started working on next analysis feature, checking for brute force
    - Most likely will be very simple, so trying to find a way to do dictionary entry checks and the status code check in only one for loop
    - indeed did not find a way because i still need to make the GUI
- Made the off-hours analysis function as well, very simple using the datetime library to modify the dates/times into anything i need
- Starting to work on the GUI, most likely will use customtkinter since I've used it before
    - found some stackoverflows with lots of good references which streamlined creating everthing.
    - ended up making the krosis app a class so calls make more sense, tell me why remembering to type self. before everything is so hard
    - created a config file where users can save settings or reset to default
    - copied a lot of code/logic from a previous project sorry not sorry
- FINISHED MAIN GUI LOGIC LETS GOOOOOOOOOOOOOOOOO
    - making it prettier tomorrow im so fried i can't write any more code

Day 7:
- Fixed up some main logic issues where things weren't printing the way I wanted in the GUI
- Made outputs prettier by iterating over a print array in the return statement
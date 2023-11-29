# Memory-Mosaic
A Volatility 3 plugin that automatically analyzes an image for several different indicators of compromise

## Overview
Performing a memory dump analysis in a forensic investigation into a machine infected with malware is time consuming and has a high learning curve. New investigators may have trouble identifying “lookalike” programs and processes and may not know which processes are legitimate and which are suspicious. Most investigations also require manual analysis into file and process names, mutexes of processes, and IP addresses to name a few. These obstacles reduce the effectiveness of investigations as valuable time is spent becoming familiar with the tools and performing repetitive tasks.

In order to reduce time taken and experience necessary on the previously mentioned tasks, Memory Mosaic, a plugin for Volatility 3, includes several functions for automating analysis. 

## Features

- [ ] Looks up process mutexes against known malware
- [ ] Identifies third-party processes 
- [ ] Searches for common attack vectors
  - [ ] Hidden .exe file extension (ex. .doc.exe)
  - [ ] Right-to-left control character use to hide the true extension (ex. `payload.[U+202e]txt.exe` becomes `payload.‮(txt.exe‭`
- [ ] Looks up public IP addresses' reputation
- [ ] Flags suspicious files in system directories

## How to run
Simply download mosaic.py and place it in your `volatility3/volatility3/plugins/windows/` directory, then you can use `windows.mosaic` just like a normal plugin
Example:
```bash
./vol.py -f infected_machine.img windows.mosaic
```

## Credits

* Volatility3: [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
* Volatility Documentation: ["Writing Plugins"](https://volatility3.readthedocs.io/en/latest/development.html)


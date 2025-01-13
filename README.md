# klp-bugzilla
Automated analysis of bugzilla bugs for kernel livepatching. The tool fetches all the livepatching-related bugs from the indicated bugzilla instance and makes a small report about each one of them.
## Setup
```
$ zypper in python311-bugzilla python311-tabulate
$ export BUGZILLA_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxx"
```
Note: The script uses [klp-build](https://github.com/SUSE/klp-build) to scan each of the bugs found in the bugzilla instance.
Make sure it is correctly installed and configured.
## Run
klp-bugzilla is pretty straightforward and does not require any kind of configuration. 
The current version does not support commandline options, but that might change in the future.
Beware that klp-bugzilla is a multi-threaded program, and it will use all available cores to
speed up the analysis. For a batch of 111 bugs and 16 threads, it takes roughly 35 minutes to
process everything.
```
$ ./klp-bugzilla-cli.py
[+] Connecting to 'https://bugzilla.suse.com'
[+] Downloading bugs...
[+] Processing 111 bugs
[+] Scanning bugs with klp-build. Go for a coffee :)

     ID  CVE         SUBSYSTEM       CVSS    PRIORITY      CLASSIFICATION    STATUS         AFFECTED
-------  ----------  ------------  ------   ----------   ----------------  -------------  --------------------
122xxxx  2021-xxxxx  scsi             7.8    Medium         complex          Incomplete(0)  No
122xxxx  2024-xxxxx  drm/amdgpu       7.8    Medium         trivial          Fixed(3)       15.6rtu0 15.6u0
122xxxx  2024-xxxxx  iommu/vt-d       7.8    High           None             Fixed(1)       15.6rtu0 15.6u0-1
122xxxx  2024-xxxxx  scsi             7.0    Medim          trivial          Fixed(11)      12.5u50-54 15.4u20-26 15.5rtu7-15 15.5u7-14
...
...
```
## Output
Once all the bugs have been analyzed, klp-bugzilla spits to stdout a table
with the full report. Most of the fields are self-explanatory except for perhaps
the `status` and `affected` ones. 
* status:
  * `Fixed(n)`: Bug has been fixed in all the vulnerable SLEs.
  * `Incomplete(n)`: Most likely someone is working on the bug.
  * `Not-Fixed`: No one has started working on the bug yet. Or the bug has been discarded,
                 but it cannot be confirmed with klp-bugzilla alone.
  * `Dropped`: Bug has been discarded with 100% certainty, so no livepatch needed.

`n` is the total number of commits fixing the bug. 

NOTE: The `status` is derived from the available information in bugzilla, and as such
it might be incorrect and should be manually verified. That being said, in most cases
the reported information is realiable enough to be used as a hint.

* affected:
    * `No`: No codestreams were found that required to be livepatched.
    * `xx.x xx.x...`: List of codestreams still affected by the bug that need to be livepatched.

## What does it do?

Sherlock is basically designed to allow you to capture large amounts of vulnerability and penetration test evidence in an automated fashion.  

It does this by sucking in a directory of Nessus files, asks you which touse, then runs user-specified OS commands for a given pluginID. It will de-dupe any issues found across these Nessus files.

### Use Cases

If you look in /vulns/vulns.yaml you can see and edit the mappings file for yourself. Simply put, you provide a Nessus pluginID and a check (command) to run in order to gather extra evidence. For example, for every host and port that has "SSL / TLS Versions Supported", run sslscan, testssl.sh, nmap with ssl scripts and then write the output to files.  
There are several mappings included within the yaml file, but you can build this out to do whatever you need really.


### Installation 


Ensure that you are running Ruby 2.5+ and then:
bundle install

### Execution  

./sherlock.rb /path/to/nessus/folder/

Once Sherlock runs, it will prompt you to select which Nessus files you would like to use, which can be chosen using cursor keys and space/enter. It will then go off and perform its checks.

### Known Issues  
Currently it does not write evidence as it goes, so if it fails half way through a job, you won't get the evidence text files written to disk. At the moment, the debug.log will still contain all commands that Sherlock has run and all output as a safety net. Bear in mind that this covers commands run since you first installed it, so it could have data from multiple targets. The intention is to expand it to write evidence as it goes and allow session resumption.





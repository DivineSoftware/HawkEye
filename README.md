# HawkEye

### Antivirus program made using Python to provide open source security to wide public

<img src='screens/filescanner.png'>
<img src='screens/systemprotection.png'>
<img src='screens/runtimescanner.png'>
<img src='screens/quarantine.png'>
<img src='screens/settings.png'>

1. File Scanner
   - Yara rules match if offline
   - VirusTotal scanner (API key has to be provided)
   
2. System Scanner
   - Filesystem scanner that uses <a href='https://github.com/Neo23x0/Loki'>Loki</a>
   - Option to scan all computer drives

3. Runtime Scanner
   - Uses <a href='https://github.com/hasherezade/hollows_hunter'>Hollows Hunter</a> under the hood
   - Kills malicious processes and quarantines the infected files
   
4. Quarantine
   - File name, file path and scan origin is shown
   - Right click menu with "Show file in explorer", "Allow file" and "Delete from computer"
   
5. Settings
   - Auto kill malicious processes, auto quarantine findings
   - Start on boot (Run key in registry)
   - Auto check for updates (from github)
   - Submit samples to VirusTotal (only applies to File Scanner tab)
   
### Some of the upcoming updates are listed here
- [ ] Auto updater for the AV
- [ ] Logging or an API
- [ ] Linux version
- [ ] AI powered no distributional scanner
<b>(Please take these as long term goals that might have lower priority than the new projects)<b>

<u>Credits</u>
<a href='https://github.com/orgs/DivineSoftware/people/CroatianApoxyomenos'>GUI Author</a>
<a href='https://github.com/TomSchimansky/CustomTkinter'>CustomTkinter</a>
<a href='https://github.com/Neo23x0/Loki'>Loki</a>
<a href='https://github.com/hasherezade/hollows_hunter'>Hollows Hunter</a>

Follow our GitHub account to receive latest updates on our open source software releases and check out our <a href='https://thedivine.one/products/cybarrier/index.html'>0-Day scanner and Realtime Antivirus</a>
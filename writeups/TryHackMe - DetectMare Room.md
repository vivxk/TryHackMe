
PR# 1:
```
title: Spearphishing Attachment Spawns Suspicious Child Process
id: 3f9a2b10-1e44-4a2b-9b0a-1a2b3c4d5e06
status: experimental
description: Detects an Office application launching a script interpreter or living-off-the-land binary, consistent with APT21 lure documents.
author: jordan-blake
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\WINWORD.EXE'
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\onenote.exe'
      - '\onenotem.exe'
      - '\msaccess.exe'
      - '\mspub.exe'
      - '\visio.exe'
      - '\eqnedt32.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\mshta.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\certutil.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\bitsadmin.exe'
      - '\wmic.exe'
      - '\schtasks.exe'
      - '\hh.exe'
      - '\curl.exe'
  filter_finance:
    ParentImage|endswith: '\excel.exe'
    ParentCommandLine|contains:
      - 'monthend'
      - 'MonthEnd'
      - 'finance'
      - 'Finance'
      - 'template'
      - 'Template'
      - 'Templates'
      - '.xlt'
      - 'Automation'
      - 'ResearchIT'
    Image|endswith: '\cmd.exe'
    CommandLine|contains:
      - 'monthend_report.bat'
  filter_telemetry:
    Image|endswith: '\officetelemetryagent.exe'
  condition: selection
  condition: selection and not 1 of filter_*
falsepositives:
  - Legitimate internal automation workflows
level: high
```

PR#2:
```
title: Signed Binary Proxy Execution of NetTraveler Dropper
id: 3f9a2b10-1e44-4a2b-9b0a-1a2b3c4d5e07
status: experimental
description: Detects APT21 using signed Windows binaries to proxy execute the NetTraveler loader from a non-standard path.
author: jordan-blake
logsource:
  product: windows
  category: process_creation

detection:
  selection_binary:
    Image|endswith:
      - '\rundll32.exe'
      - '\regsvr32.exe'

  selection_dir:
    CommandLine|contains:
      - '\ProgramData\'
      - '\AppData\'
      - '\Windows\Temp\'
      - '\Users\Public\'

  filter_deploy_tool:
    ParentImage: 'C:\Program Files\ResearchIT\Deploy\researchdeploy.exe'
    CommandLine|contains: '\ProgramData\ResearchIT\pkg\'

  filter_cad_license:
    ParentImage: 'C:\Program Files\SOLIDWORKS\sldworks.exe'
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|all:
      - '\AppData\Local\Temp\'
      - 'LicenseCheck'

  filter_windows_WerSvcGroup:
    ParentImage: 'C:\Windows\System32\svchost.exe'
    ParentCommandLine|contains: 'WerSvcGroup'
    CommandLine|contains: '\ProgramData\Microsoft\Windows\WER\'

  condition: selection_binary and selection_dir and not 1 of filter_*
```

PR#3:
```
title: LSASS Memory Access for Credential Theft
id: 3f9a2b10-1e44-4a2b-9b0a-1a2b3c4d5e09
status: experimental
description: Detects suspicious handle access to LSASS consistent with APT21 credential dumping.
author: jordan-blake

logsource:
  product: windows
  category: process_access

detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'

  selection_access:
    GrantedAccess|contains:
      - '0x1038'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'

  selection_calltrace:
    CallTrace|contains:
      - 'comsvcs.dll'
      - 'UNKNOWN'

  filter_WerFault:
    SourceImage|startswith: 'C:\Windows\System32\WerFault.exe'
    GrantedAccess: '0x1410'

  filter_edr:
    SourceImage|startswith: 'C:\Program Files\ResearchEDR\'

  filter_pam:
    SourceImage|startswith: 'C:\Program Files\ResearchPAM\'

  condition: selection_target and (selection_access or selection_calltrace) and not 1 of filter_*
```

PR#4:
```
title: Pass the Hash Lateral Movement
id: 3f9a2b10-1e44-4a2b-9b0a-1a2b3c4d5e0a
status: experimental
description: Detects NTLM pass-the-hash authentication or suspicious remote service installation associated with lateral movement.
author: jordan-blake

logsource:
  product: windows

detection:

  selection_pth:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    KeyLength: 0

  selection_service_ioc:
    EventID: 7045
    ServiceName: 'WinHelpSvc'
    ServiceFileName|startswith: 'C:\ProgramData\Intel\nt.dat'

  selection_service_encoded:
    EventID: 7045
    ServiceFileName|contains|all:
      - 'cmd.exe'
      - 'powershell'
      - '-enc'

  filter_legacy_mes:
    EventID: 4624
    WorkstationName|startswith: 'MES-LEGACY01'

  filter_fail_cluster:
    EventID: 4624
    TargetUserName: 'svc_cluster'
    ComputerName|startswith:
      - 'FS-CLASSIFIED01'
      - 'FS-CLASSIFIED02'

  filter_service_backup:
    EventID: 7045
    ServiceName: 'ResearchBackupAgent'
    ServiceFileName|startswith: 'C:\Program Files\ResearchBackup\'

  filter_patch:
    EventID: 7045
    ServiceFileName|startswith: 'C:\Program Files\ResearchIT\Patch\'

  condition: (selection_pth or selection_service_ioc or selection_service_encoded) and not 1 of filter_*
```

PR#5:
```
title: Weapons Program Data Staged and Archived for Exfiltration
id: 3f9a2b10-1e44-4a2b-9b0a-1a2b3c4d5e0b
status: experimental
description: Detects classified design files being compressed into archives for staging prior to exfiltration.
author: jordan-blake

logsource:
  product: windows
  category: process_creation

detection:

  selection_archive_operation:
    CommandLine|contains:
      - ' a '

  selection_password_archive:
    CommandLine|contains:
      - ' -p'
      - ' -hp'

  selection_design_files:
    CommandLine|contains:
      - '.sldprt'
      - '.catpart'
      - '.dwg'

  selection_powershell_archive:
    CommandLine|contains:
      - 'Compress-Archive'

  filter_backup_agent:
    Image|endswith: '\researchbackup.exe'

  filter_cad_autobackup:
    CommandLine|contains: 'SW_AutoBackup'

  condition: |
    (
      (
        selection_archive_operation
        and selection_password_archive
        and selection_design_files
      )
      or
      (
        selection_powershell_archive
        and selection_design_files
      )
    )
    and not 1 of filter_*
```



*THM Security Services has been engaged for an Incident Response activity for Vantage Dynamics.**


Q1: What is the first timestamp at which a non-macOS device signed into Marcus Webb's account? (Format: YYYY-MM-DD HH:MM:SS)
```
index=* sourcetype="o365:graph:api" "marcus.webb@vantagedynamics.onmicrosoft.com"
| search "deviceDetail.operatingSystem"!="*Mac*" "deviceDetail.operatingSystem"!="*macOS*" "deviceDetail.operatingSystem"!="*OS X*"
| sort 0 _time asc
| rex field=createdDateTime "^(?<ct_date>[^T]+)T(?<ct_time>[^Z\.]+)"
| eval clean_timestamp=ct_date . " " . ct_time
| table clean_timestamp, createdDateTime, "deviceDetail.operatingSystem", "deviceDetail.browser", ipAddress, "status.errorCode"
| head 5
```

Q2: Just after logging in, the attacker accessed a large number of emails within the first few minutes of the session. How many emails were accessed during this window?
```
index=* sourcetype="o365:management:activity" "marcus.webb@vantagedynamics.onmicrosoft.com" Operation="MailItemsAccessed"
| rex field=CreationTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time=c_date . " " . c_time
| search clean_time >= "2026-08-27 12:28:31" AND clean_time <= "2026-08-27 12:35:00"
| stats sum(OperationCount) as total_emails_accessed by UserId
```

Q3: What subject line does the attacker's inbox rule match on?
```
index=* sourcetype="o365:management:activity" "marcus.webb@vantagedynamics.onmicrosoft.com" Operation="New-InboxRule"
```

Q4: How much time elapsed between the malicious inbox rule being created and a matching reply email arriving in the mailbox? (e.g. 2 minutes 51 seconds)
Inbox Rule Creation Time: *2026-08-27T12:30:10*
```
index=* "marcus.webb@vantagedynamics.onmicrosoft.com" "invoice"   sourcetype="o365:reporting:messagetrace" | sort _time
```

Q5: Marcus Webb's account logged a Teams message that had a link attached to it. What file did this link reference?
Time: 8/27/26 1:03:38.000 PM
```
index=* "marcus.webb@vantagedynamics.onmicrosoft.com" "invoice"   Workload=MicrosoftTeams | sort _time
```

Q6: What operating system was used in the suspicious sign-in to David Chen's account?
```
index=* sourcetype="o365:graph:api" "david.chen@vantagedynamics.onmicrosoft.com"
| rex field=createdDateTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time=c_date . " " . c_time
| table clean_time, "deviceDetail.operatingSystem", "deviceDetail.browser", ipAddress, "location.city", "location.countryOrRegion", "status.errorCode", riskDetail
| sort 0 clean_time asc
```

Q7: What IP address was used in this same sign-in?
```
index=* sourcetype="o365:graph:api" "david.chen@vantagedynamics.onmicrosoft.com" "Linux"
| rex field=createdDateTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time=c_date . " " . c_time
| table clean_time, ipAddress, "deviceDetail.operatingSystem", "deviceDetail.browser", "location.city", "location.countryOrRegion"
```

Q8: How much time passed between this message being created and the suspicious sign-in to David Chen's account? (e.g. 2 minutes 51 seconds)
Message Time: 8/27/26  1:03:38.000 PM , First Login Time: 8/27/26  1:27:04.000 PM
```
index=* "david.chen@vantagedynamics.onmicrosoft.com"  "91.219.237.88"  Operation=UserLoggedIn  RecordType=15 | sort _time
```

Q9: The file the attacker downloaded from David Chen's account was legitimately modified earlier that day. At what time? (Format: YYYY-MM-DD HH:MM:SS)
Identify File Downloaded:
```
index=* sourcetype="o365:management:activity" "david.chen@vantagedynamics.onmicrosoft.com" (Operation="FileDownloaded" OR Operation="FileSyncDownloadedFull")
| rex field=CreationTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time = c_date . " " . c_time
| where clean_time >= "2026-08-27 13:27:04"
| table clean_time, SourceFileName, SourceRelativeUrl, ObjectId, Operation, ClientIP
| sort clean_time asc
```
Identify Modification Time:
```
index=* sourcetype="o365:management:activity" "Q4_Board_Financial_Summary.xlsx" (Operation="FileModified")
```

Q10: What file stored on the Leadership site had a sensitivity label applied to it by the organization's data governance, prior to the incident?
```
index=* sourcetype="o365:management:activity" ("*Leadership*" OR "*leadership*") ("SensitivityLabelApplied" OR "FileSensitivityLabelApplied" OR "*Label*")
| rex field=CreationTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time = c_date . " " . c_time
| table clean_time, Operation, SourceFileName, SourceRelativeUrl, ObjectId, UserId
| sort clean_time asc
```

Q11: What file did the attacker create an external sharing link for?
```
index=* sourcetype="o365:management:activity" (Operation="AnonymousLinkCreated" OR Operation="SecureLinkCreated" OR Operation="*LinkCreated*" OR Operation="SharingSet")
| rex field=CreationTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time = c_date . " " . c_time
| table clean_time, UserId, Operation, SourceFileName, SourceRelativeUrl, ObjectId, ClientIP, TargetUserOrGroupName
| sort clean_time asc
```

Q12: What external email address was granted access to this file?
```
index=* sourcetype="o365:management:activity" "Vendor_Onboarding_Notes.docx" (Operation="*Share*" OR Operation="*Link*" OR Operation="SharingSet")
| rex field=CreationTime "^(?<c_date>[^T]+)T(?<c_time>[^Z\.]+)"
| eval clean_time = c_date . " " . c_time
| table clean_time, Operation, UserId, TargetUserOrGroupName, "Parameters{}.Value", ClientIP
```

Q13: According to the emails, what is the subject line of the notification sent to this external address by the sharing application?
```
index=* sourcetype="o365:reporting:messagetrace" "d.reynolds88@protonmail.com"
| eval raw_time=coalesce(Date, Received, strftime(_time, "%Y-%m-%d %H:%M:%S"))
| table raw_time, Subject, SenderAddress, RecipientAddress, Status, Size
```


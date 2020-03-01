# Qbot
Qakbot, also known as Qbot, is a well-documented banking trojan that has been around since 2008. Recent Qakbot campaigns, however, are utilizing an updated persistence mechanism that can make it harder for users to detect and remove the trojan. Qakbot is known to target businesses with the hope of stealing their login credentials and eventually draining their bank accounts. Qakbot has long utilized scheduled tasks to maintain persistence. In this blog post, we will detail an update to these schedule tasks that allows Qakbot to maintain persistence and potentially evade detection.

## Reference
https://blog.talosintelligence.com/2019/05/qakbot-levels-up-with-new-obfuscation.html

## KQL
ECS Data Source: [Filebeat w/Zeek or Suricata Module](https://www.elastic.co/beats/filebeat) or ECS Logstash pipelines ([example](https://github.com/rocknsm/rock-dashboards/tree/master/ecs-configuration/logstash/conf.d))

Query:
```
(event.module: suricata AND (destination.as.ip: 68.1.115.106 OR destination.ip: 68.1.115.106 OR gaevietovp.mobi OR url.original: /wp-content/uploads/2020/01/ahead/* OR destination.as.ip: 103.91.92.1 OR destination.ip: 103.91.92.1 OR source.ip: 103.91.92.1 OR source.as.ip: 103.91.92.1 OR dns.grouped.A: 103.91.92.1 OR suricata.dns.answers.rdata: 103.91.92.1 OR destination.domain: bhatner.com OR domain.1n2_name: bhatner.com OR domain.name: bhatner.com OR related.domain: bhatner.com OR source.domain: bhatner.com OR url.domain: bhatner.com OR dns.question.etld_plus_one: bhatner.com OR dns.question.domain: bhatner.com OR source.as.ip: 153.92.65.114 OR source.ip: 153.92.65.114 OR destination.as.ip: 153.92.65.114 OR destination.ip: 153.92.65.114 OR dns.grouped.A: 153.92.65.114 OR destination.ip: 54.36.108.120 OR source.ip: 54.36.108.120 OR destination.domain: pop3.arcor.de OR dns.question.name: pop3.arcor.de OR domain.1n2n3_name: pop3.arcor.de OR dns.question.name: pop3.arcor.de OR domain.name: pop3.arcor.de OR dns.question.etld_plus_one: arcor.de OR source.domain: pop3.arcor.de)) OR (event.module: zeek AND (destination.as.ip: 68.1.115.106 OR destination.address: 68.1.115.106 OR destination.ip: 68.1.115.106 OR server.address: 68.1.115.106 OR server.as.ip: 68.1.115.106 OR server.ip: 68.1.115.106 OR tls.server.subject: CN=gaevietovp.mobi* OR x509.certificate_issuer: CN=gaevietovp.mobi* OR x509.certificate_subject: CN=gaevietovp.mobi* OR notice.sub: CN=gaevietovp.mobi* OR tls.client.ja3: 7dd50e112cd23734a310b90f6f44a7cd OR tls.server.ja3s: 7c02dbae662670040c7af9bd15fb7e2f OR destination.as.ip: 5.61.27.159 OR destination.address: 5.61.27.159 OR destination.ip: 5.61.27.159 OR server.address: 5.61.27.159 OR server.as.ip: 5.61.27.159 OR server.ip: 5.61.27.159 OR dns.answers.name: 5.61.27.159 OR dns.question.resolved_ip: 5.61.27.159 OR dns.question.etld_plus_one: alphaenergyeng.com OR dns.question.name: alphaenergyeng.com OR domain.1n2_name: alphaenergyeng.com OR domain.level_2.name: alphaenergyeng OR domain.name: alphaenergyeng.com OR related.domain: alphaenergyeng.com OR url.original: /wp-content/uploads/2020/01/ahead/* OR file.hash.md5: c43367ebab80194fe69258ca9be4ac68 OR file.hash.sha1: d5168670355c872ec98cdf0fe60f8ca563d39305 OR server.as.ip: 103.91.92.1 OR server.address: 103.91.92.1 OR destination.as.ip: 103.91.92.1 OR destination.address: 103.91.92.1 OR destination.ip: 103.91.92.1 OR server.address: 103.91.92.1 OR server.as.ip: 103.91.92.1 OR server.ip: 103.91.92.1 OR dns.answers.name: 103.91.92.1 OR dns.question.resolved_ip: 103.91.92.1 OR dns.question.etld_plus_one: bhatner.com OR dns.question.domain: bhatner.com OR domain.1n2_name: bhatner.com OR domain.name: bhatner.com OR related.domain: bhatner.com OR file.hash.md5: 275ebb5c0264dac2d492efd99f96c8ad OR destination.address: 153.92.65.114 OR destination.as.ip: 153.92.65.114 OR destination.ip: 153.92.65.114 OR server.ip: 153.92.65.114 OR dns.question.resolved.ip: 153.92.65.114 OR destination.address: 54.36.108.120 OR destination.ip: 54.36.108.120 OR server.address: 54.36.108.120 OR server.ip: 54.36.108.120 OR dns.question.name: pop3.arcor.de OR dns.question.etld_plus_one: arcor.de OR domain.1n2n3_name: pop3.arcor.de OR domain.name: pop3.arcor.de OR related.domain: pop3.arcor.de))
```

## Yara
```
/*
   YARA Rule Set
   Author: Andrew D. Pease - HuntOps.blue
   Date: 2020-02-27
   Identifier: Qbot
   Reference: https://huntops.blue
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Qbot {
   meta:
      description = "Qbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/qbot.md"
      date = "2020-02-27"
      hash1 = "56ee803fa903ab477f939b3894af6771aebf0138abe38ae8e3c41cf96bbb0f2a"
   strings:
      $s1 = "http://www.hdtune.com" fullword wide
      $s2 = "Font color - normal temperature" fullword wide
      $s3 = "Font color - critical temperature" fullword wide
      $s4 = "Native Command Queuing (NCQ)" fullword wide
      $s5 = "Read Look-Ahead" fullword wide
      $s6 = "HD Tune 2.55 - Hard Disk Utility" fullword wide
      $s7 = "Show temperature in taskbar" fullword wide
      $s8 = "Temperature:" fullword wide
      $s9 = "<description>HD Tune</description>" fullword ascii
      $s10 = "Host Protected Area" fullword wide
      $s11 = "Folder Usage" fullword wide
      $s12 = "Scanning Speed" fullword wide
      $s13 = "Device Configuration Overlay" fullword wide
      $s14 = "constructor or from DllMain." fullword ascii
      $s15 = "codeDTheqfAreawould" fullword ascii
      $s16 = "bleeding-edgeT-Rexxavierset" fullword ascii
      $s17 = "Error Scan" fullword wide
      $s18 = "Recommended Value:" fullword wide
      $s19 = "HD Tune Version 2.55" fullword wide
      $s20 = "48-bit Address" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "758c1f5ddd18627bd4023e4f487706e4" or 8 of them )
}
```

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question".

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name: Software Packing
ID: T1045
Tactic: Defense Evasion
Platform: Windows, macOS
Data Sources: Binary file metadata
Defense Bypassed: Signature-based detection, Anti-virus, Heuristic detection
```
https://attack.mitre.org/techniques/T1045

```
Name: Scheduled Task
Tactic: Execution, Persistence, Privilege Escalation
Platform: Windows
Permissions Required: Administrator, SYSTEM, User
Effective Permissions: SYSTEM, Administrator, User
Data Sources: File monitoring, Process monitoring, Process command-line parameters, Windows event logs
Supports Remote:  Yes
```
https://attack.mitre.org/techniques/T1053

```
Name: Process Injection
ID: T1055
Tactic: Defense Evasion, Privilege Escalation
Platform: Linux, macOS, Windows
Permissions Required: User, Administrator, SYSTEM, root
Effective Permissions: User, Administrator, SYSTEM, root
Data Sources: API monitoring, Windows Registry, File monitoring, DLL monitoring, Process monitoring, Named Pipes
Defense Bypassed: Process whitelisting, Anti-virus
```
https://attack.mitre.org/techniques/T1055

```
Name: Process Discovery
ID: T1057
Tactic: Discovery
Platform: Linux, macOS, Windows
System Requirements: Administrator, SYSTEM may provide better process ownership details
Permissions Required: User, Administrator, SYSTEM
Data Sources: Process monitoring, Process command-line parameters
```
https://attack.mitre.org/techniques/T1057

```
Name: Registry Run Keys / Startup Folder
ID: T1060
Tactic: Persistence
Platform: Windows
System Requirements: HKEY_LOCAL_MACHINE keys require administrator access to create and modify
Permissions Required: User, Administrator
Data Sources: Windows Registry, File monitoring
```
https://attack.mitre.org/techniques/T1060

```
Name: Scripting
ID: T1064
Tactic: Defense Evasion, Execution
Platform: Linux, macOS, Windows
Permissions Required: User
Data Sources: Process monitoring, File monitoring, Process command-line parameters
Defense Bypassed: Process whitelisting, Data Execution Prevention, Exploit Prevention
```
https://attack.mitre.org/techniques/T1064

```
Name: Disabling Security Tools
ID: T1089
Tactic: Defense Evasion
Platform: Linux, macOS, Windows
Data Sources: API monitoring, File monitoring, Services, Windows Registry, Process command-line parameters, Anti-virus
Defense Bypassed: File monitoring, Host intrusion prevention systems, Signature-based detection, Log analysis, Anti-virus
```
https://attack.mitre.org/techniques/T1089

```
Name: Brute Force
ID: T1110
Tactic: Credential Access
Platform: Linux, macOS, Windows, Office 365, Azure AD, SaaS
Permissions Required: User
Data Sources: Office 365 account logs, Authentication logs
```
https://attack.mitre.org/techniques/T1110

```
Name: Modify Registry
ID: T1112
Tactic: Defense Evasion
Platform: Windows
Permissions Required: User, Administrator, SYSTEM
Data Sources: Windows Registry, File monitoring, Process monitoring, Process command-line parameters, Windows event logs
Defense Bypassed: Host forensic analysis
```
https://attack.mitre.org/techniques/T1112

```
Name: System Time Discovery
ID: T1124
Tactic: Discovery
Platform: Windows
Permissions Required: User
Data Sources: Process monitoring, Process command-line parameters, API monitoring
```
https://attack.mitre.org/techniques/T1124

```
Name: Network Share Discovery
ID: T1135
Tactic: Discovery
Platform: macOS, Windows, AWS, GCP, Azure
Permissions Required: User
Data Sources: Process monitoring, Process command-line parameters, Network protocol analysis, Process use of network
```
https://attack.mitre.org/techniques/T1135

```
Name: Forced Authentication
ID: T1187
Tactic: Credential Access
Platform: Windows
Permissions Required: User
Data Sources: File monitoring, Network protocol analysis, Network device logs, Process use of network
```
https://attack.mitre.org/techniques/T1187

```
Name: Virtualization / Sandbox Evasion
ID: T1497
Tactic: Defense Evasion, Discovery
Platform: Windows, macOS
Data Sources: Process monitoring, Process command-line parameters
Defense Bypassed: Anti-virus, Host forensic analysis, Signature-based detection, Static File Analysis
```
https://attack.mitre.org/techniques/T1497

### Diamond Model
This is a model that lays out 4 (or in the extended model, 6) elements of an intrusion phase. Adversary, Infrastructure, Victim, and Capability. As you collect information from each "point", you can begin to make assumptions as to what the other points _could_ be. The more you have on each point, the more accurate your assumptions can be.

This model should be used in conjunction with other intrusion models, like the Lockheed Martin Cyber Kill Chain.

Do not use this model as an equation. Just because infrastructure is used in 2 intrusions, doesn't mean the victim or adversary are the same.

#### Reference
https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

```
                    ┌───────────┐
                    │ Adversary │
                    └───────────┘
                          Λ
                         ╱│╲
┌──────────────┐        ╱ │ ╲
│Capabilities  │       ╱  │  ╲
│T1045         │      ╱   │   ╲
│T1053         │     ╱    │    ╲     ┌───────────────────────────────────────────────────────────────────────┐
│T1055         │    ╱     │     ╲    │Infrastructure                                                         │
│T1057         │   ╱      │      ╲   │68[.]1[.]115[.]106 (post infection SSL/TLS traffic)                    │
│T1060         │  ╱       │       ╲  │gaevietovp[.]mobi (post infection SSL/TLS traffic)                     │
│T1064         │ ╱        │        ╲ │7dd50e112cd23734a310b90f6f44a7cd (post infection ja3 fingerprint)      │
│T1089         │▕─────────┼─────────▏│5[.]61[.]27[.]159 (HTTP request for Qbot PE)                           │
│T1110         │ ╲        │        ╱ │alphaenergyeng[.]com (HTTP request for Qbot PE)                        │
│T1112         │  ╲       │       ╱  │/wp-content/uploads/2020/01/ahead/444444.png (HTTP request for Qbot PE)│
│T1124         │   ╲      │      ╱   │c43367ebab80194fe69258ca9be4ac68 (444444.png - Qbot PE)                │
│T1135         │    ╲     │     ╱    │103[.]91[.]92[.]1 (HTTP request for Qbot archive)                      │
│T1187         │     ╲    │    ╱     └───────────────────────────────────────────────────────────────────────┘
│T1497         │      ╲   │   ╱
└──────────────┘       ╲  │  ╱
                        ╲ │ ╱
                         ╲│╱
                          V
                    ┌───────────┐
                    │  Victim   │
                    └───────────┘               
```

### Lockheed Martin Cyber Kill Chain
Developed by Lockheed Martin, the Cyber Kill Chain® framework is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.

The seven steps of the Cyber Kill Chain® enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures.

1. Reconnaissance **<- Qbot**
1. Weaponization
1. Delivery
1. Exploitation
1. Installation **<- Qbot**
1. Command & Control **<- Qbot**
1. Actions on the Objective **<- Qbot**

#### Reference
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

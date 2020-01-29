# Detection Name
Description

## Reference
External URl

## KQL
Data Source: [Winlogbeat](https://www.elastic.co/beats/winlogbeat)  
Query: `query`

Data Source: [Zeek Plugin or Framework](https://github.com/0xxon/cve-2020-0601-plugin)  
Query: `zeek.notice.note:example`

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question". 

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name: 
ID: 
Tactic: 
Platform: 
Data Sources: 
Defense Bypassed: 
```
https://attack.mitre.org/techniques/{T####}

### Diamond Model
This is a model that lays out 4 (or in the extended model, 6) elements of an intrusion phase. Adversary, Infrastructure, Victim, and Capability. As you collect information from each "point", you can begin to make assumptions as to what the other points _could_ be. The more you have on each point, the more accurate your assumptions can be. 

This model should be used in conjunction with other intrusion models, like the Lockheed Martin Cyber Kill Chain.

Do not use this model as an equation. Just because infrastructure is used in 2 intrusions, doesn't mean the victim or adversary are the same.

#### Reference
https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

```
                              Event
                          ┌───────────┐                 
                          │ Adversary │                 
                          └───────────┘                 
                                Λ                       
┌──────────────────────────┐   ╱│╲                      
│      Capability          │  ╱ │ ╲                     
│    ex: CVE ####-####     │ ╱  │  ╲  ┌────────────────┐
│ ex: Code Signing (T####) │▕───┼───▏ │ Infrastructure │
│   ex: Defense Evasion    │ ╲  │  ╱  └────────────────┘
└──────────────────────────┘  ╲ │ ╱                     
                               ╲│╱                      
                                V                       
                          ┌──────────┐                 
                          │  Victim  │                 
                          └──────────┘                 
```

### Lockheed Martin Cyber Kill Chain
Developed by Lockheed Martin, the Cyber Kill Chain® framework is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.

The seven steps of the Cyber Kill Chain® enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures.

1. Reconnaissance
1. Weaponization
1. Delivery
1. Exploitation
1. Installation
1. Command & Control
1. Actions on the Objective

```
Ex: Exploitation - CVE-####-####
```

#### Reference
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

## Analysis Notes
Notes for analysts on some steps to take if observed.

### Collection 
Examples on how to collect data for analysis.

You can collect a Windows binary signature using Powershell.
```
Get-AuthenticodeSignature -FilePath "suspicious_file.extension"
```

You can collect a website SSL signature using openssl.
```
echo -n | openssl s_client -connect {HOSTNAME}:{PORT} -showcerts
```
*Note: `echo -n` gives a response to the server so that the connection is released and `-showcerts` downloads all the certificates in the chain.*

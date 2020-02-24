# Ursnif
Ursnif is a banking trojan and variant of the Gozi malware observed being spread through various automated exploit kits, Spearphishing Attachments, and malicious links. Ursnif is associated primarily with data theft, but variants also include components (backdoors, spyware, file injectors, etc.) capable of a wide variety of behaviors.

## Reference
https://attack.mitre.org/software/S0386/

## KQL
ECS Data Source: [Filebeat w/Zeek or Suricata Module](https://www.elastic.co/beats/filebeat)  
Query:
```
(event.module: suricata AND (destination.ip: 194.61.2.16 OR source.ip: 194.61.2.16 OR dns.grouped.A: 194.61.2.16 OR suricata.dns.answers.rdata: 194.61.2.16 OR destination.as.ip: 95.169.181.35 OR source.as.ip: 95.169.181.35 OR dns.grouped.A: 95.169.181.35 OR suricata.dns.answers.rdata: 95.169.181.35 OR destination.ip: 45.141.103.204 OR dns.grouped.A: 45.141.103.204 OR suricata.dns.answers.rdata: 45.141.103.204 OR destination.domain: qr12s8ygy1.com OR dns.question.name: qr12s8ygy1.com OR domain.1n2_name: qr12s8ygy1.com OR domain.level_2.name: qr12s8ygy1 OR domain.name: qr12s8ygy1.com OR source.domain: qr12s8ygy1.com OR url.domain: qr12s8ygy1.com OR related.domain: qr12s8ygy1.com OR destination.domain: lcdixieeoe.com OR dns.question.name: lcdixieeoe.com OR domain.1n2_name: lcdixieeoe.com OR domain.level_2.name: lcdixieeoe OR domain.name: lcdixieeoe.com OR source.domain: lcdixieeoe.com OR url.domain: lcdixieeoe.com OR related.domain: lcdixieeoe.com OR destination.domain: q68jaydon3t.com OR dns.question.name: q68jaydon3t.com OR domain.1n2_name: q68jaydon3t.com OR domain.level_2.name: q68jaydon3t OR domain.name: q68jaydon3t.com OR source.domain: q68jaydon3t.com OR url.domain: q68jaydon3t.com OR dns.question.etld_plus_one: q68jaydon3t.com OR url.domain: q68jaydon3t.com OR url.original: /khogpfyc8n/215z9urlgz.php?l=xubiz8.cab OR url.query: l=xubiz8.cab)) OR (event.module: zeek AND (destination.address: 194.61.2.16 OR server.address: 194.61.2.16 OR destination.address: 95.169.181.35 OR destination.as.ip: 95.169.181.35 OR server.address: 95.169.181.35 OR server.as.ip: 95.169.181.35 OR server.address: 45.141.103.204 OR destination.address: 45.141.103.204 OR destination.ip: 45.141.103.204 OR server.ip: 45.141.103.204))
```

## Yara
```
/*
   YARA Rule Set
   Author: Andrew D. Pease - HuntOps.blue
   Date: 2020-02-23
   Identifier: Ursnif
   Reference: https://huntops.blue
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Ursnif {
   meta:
      description = "Ursnif"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/ursnif.md"
      date = "2020-02-23"
      hash1 = "996fcd8c55f923e86477d3d8069f9e9b56c6301cf9b2678c5c5c40bf6a636a5f"
   strings:
      $s1 = "soldier.dll" fullword wide
      $s2 = "c:\\quart\\Settle\\Hold\\Note\\chief\\Real\\Waitto.pdb" fullword ascii
      $s3 = "6 6$6(6,60646~6" fullword ascii /* hex encoded string 'ff`df' */
      $s4 = "constructor or from DllMain." fullword ascii
      $s5 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s6 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s7 = "\\&* & " fullword ascii
      $s8 = "measure was" fullword wide
      $s9 = "morevalue fell" fullword wide
      $s10 = "*,#- " fullword ascii
      $s11 = "$$-+ " fullword ascii
      $s12 = "&+* \" " fullword ascii
      $s13 = "ofst- " fullword ascii
      $s14 = "&%!' -&  \"'" fullword ascii
      $s15 = "! \"*!- " fullword ascii
      $s16 = ".-  $+)#" fullword ascii
      $s17 = "ia\"ai-  " fullword ascii
      $s18 = "#_-*  " fullword ascii
      $s19 = "*$)* +" fullword ascii
      $s20 = "+ )-)!&" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "31e2046fc4455d3f68b72ad16fe9ee41" or 8 of them )
}
```

## Atomic Indicators
```
194[.]61[.]2[.]16
95[.]169[.]181[.]35
45[.]141[.]103[.]204 (found by Malware Traffic Analysis)
8962cd86b47148840b6067c971ada128
7e34d6e790707bcc862fd54c0129abfa
40186e831cd2e9679ca725064d2ab0fb
2b93fcafabab58a109fcbca4377cccda
qr12s8ygy1[.]com
lcdixieeoe[.]com
q68jaydon3t[.]com (found by Malware Traffic Analysis)
xubiz8[.]cab
/khogpfyc8n/215z9urlgz[.]php
```

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question".

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name: Ursnif
ID: S0386
Associated Software: Gozi-ISFB, PE_URSNIF, Dreambot
Type: Malware
Platforms: Windows
```
https://attack.mitre.org/software/S0386/

### Diamond Model
This is a model that lays out 4 (or in the extended model, 6) elements of an intrusion phase. Adversary, Infrastructure, Victim, and Capability. As you collect information from each "point", you can begin to make assumptions as to what the other points _could_ be. The more you have on each point, the more accurate your assumptions can be.

This model should be used in conjunction with other intrusion models, like the Lockheed Martin Cyber Kill Chain.

Do not use this model as an equation. Just because infrastructure is used in 2 intrusions, doesn't mean the victim or adversary are the same.

#### Reference
https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

```
                                     Ursnif
                                  ┌────────────┐                                      
                                  │ Adversary  │                                      
                                  └────────────┘                                      
                                         Λ                                             
                                        ╱│╲                                            
                                       ╱ │ ╲                                           
                                      ╱  │  ╲       ┌─────────────────────────────────┐
                                     ╱   │   ╲      │Infrastructure                   │
┌─────────────┐┌──────┐┌──────┐     ╱    │    ╲     │194[.]61[.]2[.]16                │
│Capabilities ││T1185 ││T1091 │    ╱     │     ╲    │95[.]169[.]181[.]35              │
│T1175        ││T1036 ││T1113 │   ╱      │      ╲   │45[.]141[.]103[.]204             │
│T1090        ││T1112 ││T1064 │  ╱       │       ╲  │8962cd86b47148840b6067c971ada128 │
│T1094        ││T1188 ││T1071 │ ╱        │        ╲ │7e34d6e790707bcc862fd54c0129abfa │
│T1132        ││T1050 ││T1082 │▕─────────┼─────────▏│40186e831cd2e9679ca725064d2ab0fb │
│T1005        ││T1027 ││T1007 │ ╲        │        ╱ │2b93fcafabab58a109fcbca4377cccda │
│T1074        ││T1086 ││T1080 │  ╲       │       ╱  │qr12s8ygy1[.]com                 │
│T1140        ││T1057 ││T1497 │   ╲      │      ╱   │lcdixieeoe[.]com                 │
│T1483        ││T1093 ││T1047 │    ╲     │     ╱    │q68jaydon3t[.]com                │
│T1106        ││T1055 │└──────┘     ╲    │    ╱     │xubiz8[.]cab                     │
│T1107        ││T1012 │              ╲   │   ╱      │/khogpfyc8n/215z9urlgz[.]php     │
│T1143        ││T1060 │               ╲  │  ╱       └─────────────────────────────────┘
│T1179        ││T1105 │                ╲ │ ╱                                           
└─────────────┘└──────┘                 ╲│╱                                            
                                         V                                             
                                   ┌────────────┐                                      
                                   │   Victim   │                                      
                                   └────────────┘                   
```

### Lockheed Martin Cyber Kill Chain
Developed by Lockheed Martin, the Cyber Kill Chain® framework is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.

The seven steps of the Cyber Kill Chain® enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures.

1. Reconnaissance
1. Weaponization
1. Delivery
1. Exploitation
1. Installation <- Ursnif
1. Command & Control <- Ursnif
1. Actions on the Objective <- Ursnif

#### Reference
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### Collection
Data can be collected leveraging host or network based sensors. The Zeek protocol analyzer as well as the NIDS, Suricata, were used for this analysis.

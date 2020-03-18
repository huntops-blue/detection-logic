# Hancitor
The Hancitor trojan, also known as Chanitor, is a downloader first observed in 2014. It distributes its payload via a Word document email attachment with embedded malicious macros. The most recent version of Hancitor contains the encoded shellcode within the macro and uses native API calls within Visual Basic (VB) code to pass execution, and carves out and decrypts the embedded malware in the attachment. Once executed, Hancitor drops an additional payload to download the Pony DLL and Vawtrak malware executables, which steals data and connects to a C2 server. In January 2017, SANS Internet Storm Center researchers identified a recent increase in Hancitor activity. The campaign sends phishing emails claiming to be a parking ticket notification. The message requests the recipient to click the link to pay their ticket and directs the victim to a Microsoft Word document containing a malicious VB macro to install Hancitor [1](https://www.cyber.nj.gov/threat-profiles/trojan-variants/hancitor).

## Reference
https://www.cyber.nj.gov/threat-profiles/trojan-variants/hancitor

## KQL
ECS Data Source: [Filebeat w/Zeek or Suricata Module](https://www.elastic.co/beats/filebeat) or ECS Logstash pipelines ([example](https://github.com/rocknsm/rock-dashboards/tree/master/ecs-configuration/logstash/conf.d))

Query:
```
(event.module: suricata OR event.module: zeek) AND (45.153.73.33 OR thumbeks.com
  OR freetospeak.me OR 68.208.77.171 OR shop.artaffinittee.com OR
  68.183.232.255 OR 5c9c955449d010d25a03f8cef9d96b41 OR
  8eb933c84e7777c7b623f19489a59a2a OR 19fe0b844a00c57f60a0d9d29e6974e7
  OR 204f36fb236065964964a61d4d7b1b9c OR /4/forum.php OR /d2/about.php OR
  /mlu/forum.php)
```

## Yara
```
/*
   YARA Rule Set
   Author: Andrew D. Pease - HuntOps.blue
   Date: 2020-03-18
   Identifier: Hancitor
   Reference: https://huntops.blue/2020/03/20/hancitor.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hancitor {
   meta:
      description = "Hancitor - file 0843_43.php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "4f6d4d8f279c03f1ddfa20f95af152109b7578a2bec0a16a56ff87745585169a"
   strings:
      $s1 = "SE670131329809.vbs" fullword ascii
      $s2 = "SE670131329809.vbsPK" fullword ascii
      $s3 = "SpY';q" fullword ascii
      $s4 = "nhA* ;P7m" fullword ascii
      $s5 = "TVAYOo7" fullword ascii
      $s6 = "#b* Se+" fullword ascii
      $s7 = "].UQr " fullword ascii
      $s8 = "KyIo?$ z" fullword ascii
      $s9 = "ANsrtnL" fullword ascii
      $s10 = "sdTEC4'." fullword ascii
      $s11 = "iQgMVDj" fullword ascii
      $s12 = "EOJI!|" fullword ascii
      $s13 = "Isjr!!P0" fullword ascii
      $s14 = "e.awB+" fullword ascii
      $s15 = "}QQQKSd9?" fullword ascii
      $s16 = "ZnwOC5Z" fullword ascii
      $s17 = "ZugG{Am" fullword ascii
      $s18 = "&9TFubD1M" fullword ascii
      $s19 = "gZTU?8" fullword ascii
      $s20 = "NxWgQhY" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and
      8 of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file forum(12).php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "7178eac489be92a096631a3857bdf124e43c6d72ba10006b9861564a0d9752a7"
   strings:
      $s1 = "FYBUARRABw==" fullword ascii
   condition:
      uint16(0) == 0x5946 and filesize < 1KB and
      all of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file forum(2).php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "4f2f18e31a46f21b20dd0c1bd71f48038582da19603cbb550df0fb2a1ce323d5"
   strings:
      $s1 = "NMNMARZAEg4OCkBVVQkSFQpUGwgOGxwcExQTDg4fH1QZFRdVDQpXExQZFg8eHwlVCRUeEw8XJRkVFwobDlVLBhIODgpAVVUYHw4bVBsIDhscHBMUEw4OHx9UGRUXVQ0K" ascii
      $s2 = "VBkVF1UNClcTFBkWDx4fCVUcFRQOCVVIBhIODgoJQFVVCRMJCVQZFVQTFFVIBhIODgpAVVUXExkIFRgWGx4TFB0RDxYPGA9UGRUXVUgGEg4OCkBVVQkOFRkRFxsIER8O" ascii
      $s3 = "VxMUGRYPHh8JVRwVFA4JVUsGEg4OCglAVVUJEwkJVBkVVBMUVUsGEg4OCkBVVRcTGQgVGBYbHhMUHREPFg8YD1QZFRdVSwYSDg4KQFVVCQ4VGREXGwgRHw4IHwwVFg8O" ascii
      $s4 = "NMNMARZAEg4OCkBVVQkSFQpUGwgOGxwcExQTDg4fH1QZFRdVDQpXExQZFg8eHwlVCRUeEw8XJRkVFwobDlVLBhIODgpAVVUYHw4bVBsIDhscHBMUEw4OHx9UGRUXVQ0K" ascii
      $s5 = "ExUUVBkVF1VLBwEYQBIODgpAVVUJEhUKVBsIDhscHBMUEw4OHx9UGRUXVQ0KVxMUGRYPHh8JVQkVHhMPFyUZFRcKGw5VSAYSDg4KQFVVGB8OG1QbCA4bHBwTFBMODh8f" ascii
      $s6 = "CB8MFRYPDhMVFFQZFRdVSAc=" fullword ascii
   condition:
      uint16(0) == 0x4d4e and filesize < 1KB and
      all of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file forum(8).php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "b4f1519e9814668f7f01188b02ba7965a5e8d39fa9ab671bcfbbd3ddd259c541"
   strings:
      $s1 = "CMNXARRABw==" fullword ascii
   condition:
      uint16(0) == 0x4d43 and filesize < 1KB and
      all of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file 2"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "4c8c3005642b01eb3db098b34ce3c7a089f12566bd67a7720c48e2fe751bfcb1"
   strings:
      $s1 = "wVfHWoS" fullword ascii
      $s2 = "tuTo>2TL" fullword ascii
      $s3 = "\\hDxTO" fullword ascii
      $s4 = "tfxPR1" fullword ascii
      $s5 = "vbT*<%TI" fullword ascii
      $s6 = "NbT*4%TQ" fullword ascii
      $s7 = "(f9EYS" fullword ascii
      $s8 = "g@CV<i" fullword ascii
      $s9 = "h!FT9a" fullword ascii
      $s10 = "!|%@@H" fullword ascii
      $s11 = "bTxm%[" fullword ascii
      $s12 = "ZTV+1Z" fullword ascii
      $s13 = "Z-%2Qb" fullword ascii
      $s14 = "^U0l!XTm" fullword ascii
      $s15 = "bT*|%T" fullword ascii
      $s16 = "`:_aUH" fullword ascii
      $s17 = "-t9|kZ[" fullword ascii
      $s18 = "&bT*l%Ty" fullword ascii
      $s19 = "hB5N5U" fullword ascii
      $s20 = "L7ElRe" fullword ascii
   condition:
      uint16(0) == 0xa880 and filesize < 100KB and
      8 of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file 1"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "d1e56e455e3a50d8e461665e46deb1979a642b32710433f59e7a16fb5e4abada"
   strings:
      $s1 = "PUhR/TV" fullword ascii
      $s2 = "phWQT.b" fullword ascii
      $s3 = "r saYF" fullword ascii
      $s4 = "AXW`X." fullword ascii
      $s5 = "U0-cQQMQ" fullword ascii
      $s6 = "2S`5uT" fullword ascii
      $s7 = "cx)X!)" fullword ascii
      $s8 = "[8hwTq" fullword ascii
      $s9 = "u4nmDa" fullword ascii
      $s10 = "1ZlXrD" fullword ascii
      $s11 = "QP;vJV" fullword ascii
      $s12 = "SDC0w/>z4`" fullword ascii
      $s13 = ";@(|9J" fullword ascii
      $s14 = "C5-MLE" fullword ascii
      $s15 = "2:vX^B" fullword ascii
      $s16 = "Q4:\"*U" fullword ascii
      $s17 = "0Q(LT0" fullword ascii
      $s18 = "jE#UnzW" fullword ascii
      $s19 = "aJFnrs" fullword ascii
      $s20 = "TuAVAB" fullword ascii
   condition:
      uint16(0) == 0xa880 and filesize < 100KB and
      8 of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file forum(20).php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "d1545c0c22c9496115d98a2a804cd457fa76a98ce1393e470b036c37225ae2fc"
   strings:
      $s1 = "AZAZARRABw==" fullword ascii
   condition:
      uint16(0) == 0x5a41 and filesize < 1KB and
      all of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file forum.php"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "d83cf47ab578d539b97d79006c136864357f22f9fe62f19abb226a8d5b2944d7"
   strings:
      $s1 = "GUID=10108318379165689344&BUILD=0903_7832478324&INFO=UMBRELLA-WIN10 @ UMBRELLA-WIN10\\rhianna&IP=173.6.46.112&TYPE=1&WIN=10.0(x6" ascii
      $s2 = "GUID=10108318379165689344&BUILD=0903_7832478324&INFO=UMBRELLA-WIN10 @ UMBRELLA-WIN10\\rhianna&IP=173.6.46.112&TYPE=1&WIN=10.0(x6" ascii
      $s3 = "10108318379165689344" ascii
   condition:
      uint16(0) == 0x5547 and filesize < 1KB and
      all of them
}

rule Hancitor {
   meta:
      description = "Hancitor - file SE670131329809.vbs"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://huntops.blue/2020/03/20/hancitor.html"
      date = "2020-03-18"
      hash1 = "6897a3b85046ba97fb3868dfb82338e5ed098136720a6cf73625e784fc1e1e51"
   strings:
      $x1 = ".Create \"regsvr32.exe -s \"+CStr(WScript.CreateObject(\"Scripting.FileSystemObject\").GetSpecialFolder(Cint(\"2\"))+\"\\\")+\"a" ascii
      $x2 = ".Create \"regsvr32.exe -s \"+CStr(WScript.CreateObject(\"Scripting.FileSystemObject\").GetSpecialFolder(Cint(\"2\"))+\"\\\")+\"a" ascii
      $s3 = ".SaveToFile CStr(WScript.CreateObject(\"Scripting.FileSystemObject\").GetSpecialFolder(2)+\"\\\")+\"adobe.txt\", 2" fullword ascii
      $s4 = "Set HeJddyu=GetObject(\"winmgmts:Win32_Process\")" fullword ascii
      $s5 = ",,processid" fullword ascii
      $s6 = "Dim GtYbDTHjR: Set GtYbDTHjR=CreateObject(\"Scripting.FileSystemObject\"): Dim etEWDmZOL: Set etEWDmZOL=CreateObject(\"ADODB.Str" ascii
      $s7 = "Dim GtYbDTHjR: Set GtYbDTHjR=CreateObject(\"Scripting.FileSystemObject\"): Dim etEWDmZOL: Set etEWDmZOL=CreateObject(\"ADODB.Str" ascii
      $s8 = "244,34,47,239,244,34,47,243,244,34,47,247,244,34,47,251,244,34,47,255,244,34,47,259,244,34,47,263,244,34,47,267,244,34,47,271,24" ascii /* hex encoded string '$CDr9$CDrC$CDrG$CDrQ$CDrU$CDrY$CDrc$CDrg$CDrq$' */
      $s9 = "39,242,34,47,243,242,34,47,247,242,34,47,251,242,34,47,255,242,34,47,247,243,34,47,123,244,34,47,127,244,34,47,251,243,34,47,255" ascii /* hex encoded string '9$#DrC$#DrG$#DrQ$#DrU$#DrG$3Dq#$CDq'$CDrQ$3DrU' */
      $s10 = "31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31" ascii /* hex encoded string '1111111111111111111111111111111111111111111' */
      $s11 = "79l136l69l316l278l136l69l316l278l136l69l76l279l136l69l76l279l136l69l316l278l136l69l316l278l136l69l268l278l136l69l268l278l136l69l" ascii
      $s12 = "188l278l136l185l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l" ascii
      $s13 = "184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l76l275l136l69l319l274l135l69l316" ascii
      $s14 = "5l252l154l83l81l203l148l283l317l103l110l257l151l100l186l260l324l101l146l204l85l184l184l184l184l184l184l184l184l184l184l184l184l1" ascii
      $s15 = "3l146l288l162l83l81l193l198l152l112l79l102l271l154l268l160l75l89l129l283l133l146l208l160l91l89l147l289l237l71l241l281l237l242l12" ascii
      $s16 = "69l316l275l99l264l248l103l212l273l127l167l244l200l167l298l256l185l306l168l75l81l254l275l136l120l204l136l116l254l267l275l136l69l1" ascii
      $s17 = "8l136l85l75l101l155l73l108l274l152l304l266l287l200l162l185l85l212l273l184l85l212l273l319l232l244l200l295l276l284l69l268l276l124l" ascii
      $s18 = "269l138l80l221l84l85l204l199l109l154l296l257l269l138l288l220l83l77l184l184l184l184l184l184l184l184l184l184l184l184l184l184l184l1" ascii
      $s19 = "l136l69l316l96l257l324l316l96l257l324l232l307l136l69l90l307l136l69l188l275l135l69l248l242l123l179l169l235l107l183l256l199l84l115" ascii
      $s20 = "69l140l274l136l69l316l306l136l69l74l307l136l69l118l249l136l69l98l249l136l69l320l251l136l69l76l252l136l69l106l252l136l69l80l252l1" ascii
   condition:
      uint16(0) == 0x3327 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */
```

## Atomic Indicators
```
45[.]153[.]73[.]33 - Pony Downloader C2
thumbeks[.]com - Pony Downloader C2
/4/forum[.]php - Hancitor C2
/d2/about[.]php - Pony Downloader C2
/mlu/forum[.]php - Pony Downloader C2
freetospeak[.]me - Initial Infection
68[.]208[.]77[.]171 - Initial Infection
shop[.]artaffinittee[.]com - Part of Hancitor infrastructure
68[.]183[.]232[.]255 - Part of Hancitor infrastructure
5c9c955449d010d25a03f8cef9d96b41 - VBScript archive (0843_43.php)
8eb933c84e7777c7b623f19489a59a2a - VBScript dropper (SE670131329809.vbs)
19fe0b844a00c57f60a0d9d29e6974e7 - Part of Hancitor infrastructure (1)
204f36fb236065964964a61d4d7b1b9c - Part of Hancitor infrastructure (2)
```

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question".

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name: Execution Through API
ID: T1106
Tactic: Execution
Platform: Windows
Permissions Required: User, Administrator, SYSTEM
Data Sources: API monitoring, Process monitoring
```
https://attack.mitre.org/techniques/T1106/

```
Name: PowerShell
ID: T1086
Tactic: Execution
Platform: Windows
Permissions Required: User, Administrator
Data Sources: PowerShell logs, Loaded DLLs, DLL monitoring, Windows Registry, File monitoring, Process monitoring, Process command-line parameters
Supports Remote:  Yes
```
https://attack.mitre.org/techniques/T1086/

### Diamond Model
This is a model that lays out 4 (or in the extended model, 6) elements of an intrusion phase. Adversary, Infrastructure, Victim, and Capability. As you collect information from each "point", you can begin to make assumptions as to what the other points _could_ be. The more you have on each point, the more accurate your assumptions can be.

This model should be used in conjunction with other intrusion models, like the Lockheed Martin Cyber Kill Chain.

Do not use this model as an equation. Just because infrastructure is used in 2 intrusions, doesn't mean the victim or adversary are the same.

#### Reference
https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

```
                       Hancitor
                     ┌───────────┐                                                                             
                     │ Adversary │                                                                             
                     └───────────┘                                                                             
                           Λ                                                                                   
                          ╱│╲                                                                                  
                         ╱ │ ╲        ┌───────────────────────────────────────────────────────────────────────┐
                        ╱  │  ╲       │Infrastructure                                                         │
                       ╱   │   ╲      │45[.]153[.]73[.]33 - Pony Downloader C2                                │
                      ╱    │    ╲     │thumbeks[.]com - Pony Downloader C2                                    │
                     ╱     │     ╲    │/4/forum[.]php - Hancitor C2                                           │
                    ╱      │      ╲   │/d2/about[.]php - Pony Downloader C2                                   │
 ┌──────────────┐  ╱       │       ╲  │/mlu/forum[.]php - Pony Downloader C2                                  │
 │Capabilities  │ ╱        │        ╲ │freetospeak[.]me - Initial Infection                                   │
 │T1106         │▕─────────┼─────────▏│68[.]208[.]77[.]171 - Initial Infection                                │
 │T1086         │ ╲        │        ╱ │shop[.]artaffinittee[.]com - Part of Hancitor infrastructure           │
 └──────────────┘  ╲       │       ╱  │68[.]183[.]232[.]255 - Part of Hancitor infrastructure                 │
                    ╲      │      ╱   │5c9c955449d010d25a03f8cef9d96b41 - VBScript archive (0843_43.php)      │
                     ╲     │     ╱    │8eb933c84e7777c7b623f19489a59a2a - VBScript dropper                    │
                      ╲    │    ╱     │(SE670131329809.vbs)                                                   │
                       ╲   │   ╱      │19fe0b844a00c57f60a0d9d29e6974e7 - Part of Hancitor infrastructure (1) │
                        ╲  │  ╱       │204f36fb236065964964a61d4d7b1b9c - Part of Hancitor infrastructure (2) │
                         ╲ │ ╱        └───────────────────────────────────────────────────────────────────────┘
                          ╲│╱                                                                                  
                           V                                                                                   
                     ┌───────────┐                                                                             
                     │  Victim   │                                                                             
                     └───────────┘                                                                                             
```

### Lockheed Martin Cyber Kill Chain
Developed by Lockheed Martin, the Cyber Kill Chain® framework is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.

The seven steps of the Cyber Kill Chain® enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures.

1. Reconnaissance
1. Weaponization **<- Hancitor**
1. Delivery **<- Hancitor**
1. Exploitation **<- Hancitor**
1. Installation **<- Hancitor**
1. Command & Control
1. Actions on the Objective

#### Reference
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### Collection
Data can be collected leveraging host or network based sensors. The Zeek protocol analyzer as well as the NIDS, Suricata, were used for this analysis.

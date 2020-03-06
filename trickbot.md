# Trickbot
TrickBot is a Trojan spyware program that has mainly been used for targeting banking sites in United States, Canada, UK, Germany, Australia, Austria, Ireland, London, Switzerland, and Scotland. TrickBot first emerged in the wild in September 2016 and appears to be a successor to Dyre. TrickBot is developed in the C++ programming language.

## Reference
https://attack.mitre.org/software/S0266/

## KQL
ECS Data Source: [Filebeat w/Zeek or Suricata Module](https://www.elastic.co/beats/filebeat) or ECS Logstash pipelines ([example](https://github.com/rocknsm/rock-dashboards/tree/master/ecs-configuration/logstash/conf.d))

Query:
```
(event.module: suricata OR event.module: zeek) AND ((5.2.77.18 AND destination.port: 447) OR (85.143.216.206 AND destination.port: 447) OR (186.71.150.23 AND destination.port: 449) OR (190.214.13.2 AND destination.port: 449) OR (195.133.145.31 AND destination.port: 443) OR (66.85.173.20 AND destination.port: 447) OR (93.189.41.185 AND destination.port: 447) OR (203.176.135.102 AND destination.port: 8082) OR file.hash.md5: 9149a43c1fd3c74269648223255d2a83 OR file.hash.md5: fed45d3744a23e40f0b0452334826fc2 OR file.hash.md5: acf866d6a75d9100e03d71c80e1a85d6 OR (tls.client.ja3: 72a589da586844d7f0818ce684948eea AND tls.server.ja3s: 0eec924176fb005dfa419c80ab72d27c) OR (tls.client.ja3: 72a589da586844d7f0818ce684948eea AND tls.server.ja3s: e35df3e00ca4ef31d42b34bebaa2f86e) OR (tls.client.ja3: 72a589da586844d7f0818ce684948eea AND tls.server.ja3s: 46df52e211001fa8da188599db66e0db))
```

## Yara
```
/*
YARA Rule Set
Author: Andrew D. Pease - HuntOps.blue
Date: 2020-03-05
Identifier: Trickbot
Reference: https://huntops.blue
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Trickbot {
   meta:
      description = "Trickbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md"
      date = "2020-03-05"
      hash1 = "7946ad031ab8b4c35eafb7805226726cfd8998b3f4079a2da81ac3290a999fdd"
   strings:
      $s1 = "'  original source code downloaded from VBCity @ www.vbcity.com" fullword ascii
      $s2 = "oleaut32.DLL" fullword ascii
      $s3 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii
      $s4 = "ECKBOX, 3, (R.Bottom - R.Top) - nHeight - 15, (TempForm.TextWidth(MsgBoxCheckBoxText) / Screen.TwipsPerPixelX) + 22, nHeight, Ms" ascii
      $s5 = "MsgBoxCheckBoxHWND = CreateWindowEx(0, \"Button\", MsgBoxCheckBoxText, WS_CHILD Or WS_VISIBLE Or WS_TABSTOP Or BS_AUTOCHECKBOX, " ascii
      $s6 = "GetProcessHeap" fullword wide
      $s7 = "F*\\AC:\\L\\CODE_UPLOAD36202262000\\m1.vbp" fullword wide
      $s8 = "'  WebSite: www.iridiumsoftware.com" fullword ascii
      $s9 = "'  WebSite: www.mkccomputers.com" fullword ascii
      $s10 = "pShellCode" fullword ascii
      $s11 = "http://members.xoom.com/devsfort/index.html" fullword wide
      $s12 = "m1.exe" fullword wide
      $s13 = "MoveWindow MsgBoxHWND, R.Left, R.Top, R.Right - R.Left, R.Bottom - R.Top + nHeight, 1&" fullword ascii
      $s14 = "Private Declare Function GetFocus Lib \"user32\" () As Long" fullword ascii
      $s15 = "Private Declare Function GetWindowRect Lib \"user32\" (ByVal hwnd As Long, lpRect As RECT) As Long" fullword ascii
      $s16 = "If MsgBoxY > (H - (.Bottom - .Top) - 1) Then MsgBoxY = (H - (.Bottom - .Top) - 1)" fullword ascii
      $s17 = "Private Const WM_GETFONT = &H31" fullword ascii
      $s18 = "Private Const BM_GETSTATE = &HF2" fullword ascii
      $s19 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "67948c0cd7b82f32e58d445465986541" or 8 of them )
}

rule Trickbot {
   meta:
      description = "Trickbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md"
      date = "2020-03-05"
      hash1 = "9be4fed11762b4cd592a60c96b19481d42cb74bc15f62f78581d43627faf87fd"
   strings:
      $s1 = "'  original source code downloaded from VBCity @ www.vbcity.com" fullword ascii
      $s2 = "oleaut32.DLL" fullword ascii
      $s3 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii
      $s4 = "ECKBOX, 3, (R.Bottom - R.Top) - nHeight - 15, (TempForm.TextWidth(MsgBoxCheckBoxText) / Screen.TwipsPerPixelX) + 22, nHeight, Ms" ascii
      $s5 = "MsgBoxCheckBoxHWND = CreateWindowEx(0, \"Button\", MsgBoxCheckBoxText, WS_CHILD Or WS_VISIBLE Or WS_TABSTOP Or BS_AUTOCHECKBOX, " ascii
      $s6 = "GetProcessHeap" fullword wide
      $s7 = "F*\\AC:\\L\\CODE_UPLOAD36202262000\\m1.vbp" fullword wide
      $s8 = "'  WebSite: www.iridiumsoftware.com" fullword ascii
      $s9 = "'  WebSite: www.mkccomputers.com" fullword ascii
      $s10 = "pShellCode" fullword ascii
      $s11 = "http://members.xoom.com/devsfort/index.html" fullword wide
      $s12 = "m1.exe" fullword wide
      $s13 = "MoveWindow MsgBoxHWND, R.Left, R.Top, R.Right - R.Left, R.Bottom - R.Top + nHeight, 1&" fullword ascii
      $s14 = "Private Declare Function GetFocus Lib \"user32\" () As Long" fullword ascii
      $s15 = "Private Declare Function GetWindowRect Lib \"user32\" (ByVal hwnd As Long, lpRect As RECT) As Long" fullword ascii
      $s16 = "If MsgBoxY > (H - (.Bottom - .Top) - 1) Then MsgBoxY = (H - (.Bottom - .Top) - 1)" fullword ascii
      $s17 = "Private Const WM_GETFONT = &H31" fullword ascii
      $s18 = "Private Const BM_GETSTATE = &HF2" fullword ascii
      $s19 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "67948c0cd7b82f32e58d445465986541" or 8 of them )
}

rule Trickbot {
   meta:
      description = "Trickbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md"
      date = "2020-03-05"
      hash1 = "2b576a956b8757d866b0711b75ee965249bc09cc4a90e6fe36f5a1b178457549"
   strings:
      $s1 = "'  original source code downloaded from VBCity @ www.vbcity.com" fullword ascii
      $s2 = "oleaut32.DLL" fullword ascii
      $s3 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii
      $s4 = "ECKBOX, 3, (R.Bottom - R.Top) - nHeight - 15, (TempForm.TextWidth(MsgBoxCheckBoxText) / Screen.TwipsPerPixelX) + 22, nHeight, Ms" ascii
      $s5 = "MsgBoxCheckBoxHWND = CreateWindowEx(0, \"Button\", MsgBoxCheckBoxText, WS_CHILD Or WS_VISIBLE Or WS_TABSTOP Or BS_AUTOCHECKBOX, " ascii
      $s6 = "GetProcessHeap" fullword wide
      $s7 = "F*\\AC:\\L\\CODE_UPLOAD36202262000\\m1.vbp" fullword wide
      $s8 = "'  WebSite: www.iridiumsoftware.com" fullword ascii
      $s9 = "'  WebSite: www.mkccomputers.com" fullword ascii
      $s10 = "pShellCode" fullword ascii
      $s11 = "http://members.xoom.com/devsfort/index.html" fullword wide
      $s12 = "m1.exe" fullword wide
      $s13 = "MoveWindow MsgBoxHWND, R.Left, R.Top, R.Right - R.Left, R.Bottom - R.Top + nHeight, 1&" fullword ascii
      $s14 = "Private Declare Function GetFocus Lib \"user32\" () As Long" fullword ascii
      $s15 = "Private Declare Function GetWindowRect Lib \"user32\" (ByVal hwnd As Long, lpRect As RECT) As Long" fullword ascii
      $s16 = "If MsgBoxY > (H - (.Bottom - .Top) - 1) Then MsgBoxY = (H - (.Bottom - .Top) - 1)" fullword ascii
      $s17 = "Private Const WM_GETFONT = &H31" fullword ascii
      $s18 = "Private Const BM_GETSTATE = &HF2" fullword ascii
      $s19 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "67948c0cd7b82f32e58d445465986541" or 8 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule Trickbot {
   meta:
      description = "Trickbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md"
      date = "2020-03-05"
      hash1 = "7946ad031ab8b4c35eafb7805226726cfd8998b3f4079a2da81ac3290a999fdd"
      hash2 = "9be4fed11762b4cd592a60c96b19481d42cb74bc15f62f78581d43627faf87fd"
      hash3 = "2b576a956b8757d866b0711b75ee965249bc09cc4a90e6fe36f5a1b178457549"
   strings:
      $s1 = "'  original source code downloaded from VBCity @ www.vbcity.com" fullword ascii
      $s2 = "oleaut32.DLL" fullword ascii
      $s3 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii
      $s4 = "ECKBOX, 3, (R.Bottom - R.Top) - nHeight - 15, (TempForm.TextWidth(MsgBoxCheckBoxText) / Screen.TwipsPerPixelX) + 22, nHeight, Ms" ascii
      $s5 = "MsgBoxCheckBoxHWND = CreateWindowEx(0, \"Button\", MsgBoxCheckBoxText, WS_CHILD Or WS_VISIBLE Or WS_TABSTOP Or BS_AUTOCHECKBOX, " ascii
      $s6 = "GetProcessHeap" fullword wide
      $s7 = "F*\\AC:\\L\\CODE_UPLOAD36202262000\\m1.vbp" fullword wide
      $s8 = "'  WebSite: www.iridiumsoftware.com" fullword ascii
      $s9 = "'  WebSite: www.mkccomputers.com" fullword ascii
      $s10 = "pShellCode" fullword ascii
      $s11 = "http://members.xoom.com/devsfort/index.html" fullword wide
      $s12 = "m1.exe" fullword wide
      $s13 = "MoveWindow MsgBoxHWND, R.Left, R.Top, R.Right - R.Left, R.Bottom - R.Top + nHeight, 1&" fullword ascii
      $s14 = "Private Declare Function GetFocus Lib \"user32\" () As Long" fullword ascii
      $s15 = "Private Declare Function GetWindowRect Lib \"user32\" (ByVal hwnd As Long, lpRect As RECT) As Long" fullword ascii
      $s16 = "If MsgBoxY > (H - (.Bottom - .Top) - 1) Then MsgBoxY = (H - (.Bottom - .Top) - 1)" fullword ascii
      $s17 = "Private Const WM_GETFONT = &H31" fullword ascii
      $s18 = "Private Const BM_GETSTATE = &HF2" fullword ascii
      $s19 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "67948c0cd7b82f32e58d445465986541" and ( 8 of them )
      ) or ( all of them )
}

rule Trickbot {
   meta:
      description = "Trickbot"
      author = "Andrew D. Pease - HuntOps.blue"
      reference = "https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md"
      date = "2020-03-05"
      hash1 = "7946ad031ab8b4c35eafb7805226726cfd8998b3f4079a2da81ac3290a999fdd"
      hash2 = "9be4fed11762b4cd592a60c96b19481d42cb74bc15f62f78581d43627faf87fd"
   strings:
      $s1 = "!H2%f%" fullword ascii
      $s2 = "sDOBMb4" fullword ascii
      $s3 = "wWrMWZ<" fullword ascii
      $s4 = "sQgbg_`" fullword ascii
      $s5 = "HWqNAyh" fullword ascii
      $s6 = "HDtddsK" fullword ascii
      $s7 = "d9cIyW!" fullword ascii
      $s8 = "^HKizd\"%z" fullword ascii
      $s9 = ".wVp,1s" fullword ascii
      $s10 = "tHyrC?" fullword ascii
      $s11 = "OKkPoAB" fullword ascii
      $s12 = "pz$uoEf?" fullword ascii
      $s13 = "N$.ovs?_" fullword ascii
      $s14 = "jcte\\>" fullword ascii
      $s15 = "jjpci}(o" fullword ascii
      $s16 = "\\x3! t" fullword ascii
      $s17 = "EWBwO9" fullword ascii
      $s18 = "\\}NHBc" fullword ascii
      $s19 = "NnAQV5" fullword ascii
      $s20 = "\\]ki46" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "67948c0cd7b82f32e58d445465986541" and ( 8 of them )
      ) or ( all of them )
}
```

## Atomic Indicators
```
5[.]2[.]77[.]18 port 447 (Trickbot, GTAG, Red4 TLS traffic)
85[.]143[.]216[.]206 port 447 (Trickbot, GTAG, Red4 TLS traffic)
186[.]71[.]150[.]23 port 449 (Trickbot, GTAG, Red4 TLS traffic)
190[.]214[.]13[.]2 port 449 (Trickbot, GTAG, Red4 TLS traffic)
195[.]133[.]145[.]31 port 443 (Trickbot, GTAG, Red4 TLS traffic)
66[.]85[.]173[.]20 port 447 (Trickbot, GTAG, Red4 TLS traffic)
93[.]189[.]41[.]185 port 447 (Trickbot, GTAG, Red4 TLS traffic)
203[.]176[.]135[.]102 port 8082 (enumeration data exfil)
192[.]3[.]124[.]40 (Trickbot binary)
9149a43c1fd3c74269648223255d2a83 - lastimage[.]png (Trickbot binary)
fed45d3744a23e40f0b0452334826fc2 - lastimage[.]png (Trickbot binary)
acf866d6a75d9100e03d71c80e1a85d6 - mini[.]png (Trickbot binary)
```

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question".

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name: Trickbot
ID: S0266
Associated Software: Totbrick, TSPY_TRICKLOAD
Type: MALWARE
Platforms: Windows
```
https://attack.mitre.org/software/S0266/

### Diamond Model
This is a model that lays out 4 (or in the extended model, 6) elements of an intrusion phase. Adversary, Infrastructure, Victim, and Capability. As you collect information from each "point", you can begin to make assumptions as to what the other points _could_ be. The more you have on each point, the more accurate your assumptions can be.

This model should be used in conjunction with other intrusion models, like the Lockheed Martin Cyber Kill Chain.

Do not use this model as an equation. Just because infrastructure is used in 2 intrusions, doesn't mean the victim or adversary are the same.

#### Reference
https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

```
                                     Trickbot
                                   ┌───────────┐                                                                             
                                   │ Adversary │                                                                             
                                   └───────────┘                                                                             
                                         Λ                                                                                   
                                        ╱│╲                                                                                  
                                       ╱ │ ╲                                                                                 
 ┌──────────────┐┌─────┐┌─────┐       ╱  │  ╲       ┌───────────────────────────────────────────────────────────────────────┐
 │Capabilities  ││T1083││T1082│      ╱   │   ╲      │Infrastructure                                                         │
 │T1087         ││T1179││T1016│     ╱    │    ╲     │5[.]2[.]77[.]18 port 447                                               │
 │T1043         ││T1185││T1007│    ╱     │     ╲    │85[.]143[.]216[.]206 port 447                                          │
 │T1503         ││T1112││T1065│   ╱      │      ╲   │186[.]71[.]150[.]23 port 449                                           │
 │T1081         ││T1027││T1204│  ╱       │       ╲  │190[.]214[.]13[.]2 port 449                                            │
 │T1214         ││T1055│└─────┘ ╱        │        ╲ │195[.]133[.]145[.]31 port 443                                          │
 │T1024         ││T1060│       ▕─────────┼─────────▏│66[.]85[.]173[.]20 port 447                                            │
 │T1005         ││T1105│        ╲        │        ╱ │93[.]189[.]41[.]185 port 447                                           │
 │T1140         ││T1053│         ╲       │       ╱  │203[.]176[.]135[.]102 port 8082                                        │
 │T1089         ││T1064│          ╲      │      ╱   │192[.]3[.]124[.]40                                                     │
 │T1482         ││T1045│           ╲     │     ╱    │9149a43c1fd3c74269648223255d2a83                                       │
 │T1114         ││T1193│            ╲    │    ╱     │fed45d3744a23e40f0b0452334826fc2                                       │
 │T1106         ││T1071│             ╲   │   ╱      │acf866d6a75d9100e03d71c80e1a85d6                                       │
 └──────────────┘└─────┘              ╲  │  ╱       └───────────────────────────────────────────────────────────────────────┘
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

1. Reconnaissance **<- Trickbot**
1. Weaponization **<- Trickbot**
1. Delivery
1. Exploitation
1. Installation **<- Trickbot**
1. Command & Control **<- Trickbot**
1. Actions on the Objective **<- Trickbot**

#### Reference
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### Collection
Data can be collected leveraging host or network based sensors. The Zeek protocol analyzer as well as the NIDS, Suricata, were used for this analysis.

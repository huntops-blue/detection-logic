# Detection Name
Description

## Reference
External URl

## KQL
ECS Data Source: [Filebeat w/Zeek or Suricata Module](https://www.elastic.co/beats/filebeat) or ECS Logstash pipelines ([example](https://github.com/rocknsm/rock-dashboards/tree/master/ecs-configuration/logstash/conf.d))

Query:
```
(event.module: suricata AND (destination.as.ip: 68.1.115.106 OR destination.ip: 68.1.115.106 OR gaevietovp.mobi OR url.original: /wp-content/uploads/2020/01/ahead/* OR destination.as.ip: 103.91.92.1 OR destination.ip: 103.91.92.1 OR source.ip: 103.91.92.1 OR source.as.ip: 103.91.92.1 OR dns.grouped.A: 103.91.92.1 OR suricata.dns.answers.rdata: 103.91.92.1 OR destination.domain: bhatner.com OR domain.1n2_name: bhatner.com OR domain.name: bhatner.com OR related.domain: bhatner.com OR source.domain: bhatner.com OR url.domain: bhatner.com OR dns.question.etld_plus_one: bhatner.com OR dns.question.domain: bhatner.com OR source.as.ip: 153.92.65.114 OR source.ip: 153.92.65.114 OR destination.as.ip: 153.92.65.114 OR destination.ip: 153.92.65.114 OR dns.grouped.A: 153.92.65.114 OR destination.ip: 54.36.108.120 OR source.ip: 54.36.108.120 OR destination.domain: pop3.arcor.de OR dns.question.name: pop3.arcor.de OR domain.1n2n3_name: pop3.arcor.de OR dns.question.name: pop3.arcor.de OR domain.name: pop3.arcor.de OR dns.question.etld_plus_one: arcor.de OR source.domain: pop3.arcor.de)) OR (event.module: zeek AND (destination.as.ip: 68.1.115.106 OR destination.address: 68.1.115.106 OR destination.ip: 68.1.115.106 OR server.address: 68.1.115.106 OR server.as.ip: 68.1.115.106 OR server.ip: 68.1.115.106 OR tls.server.subject: CN=gaevietovp.mobi* OR x509.certificate_issuer: CN=gaevietovp.mobi* OR x509.certificate_subject: CN=gaevietovp.mobi* OR notice.sub: CN=gaevietovp.mobi* OR tls.client.ja3: 7dd50e112cd23734a310b90f6f44a7cd OR tls.server.ja3s: 7c02dbae662670040c7af9bd15fb7e2f OR destination.as.ip: 5.61.27.159 OR destination.address: 5.61.27.159 OR destination.ip: 5.61.27.159 OR server.address: 5.61.27.159 OR server.as.ip: 5.61.27.159 OR server.ip: 5.61.27.159 OR dns.answers.name: 5.61.27.159 OR dns.question.resolved_ip: 5.61.27.159 OR dns.question.etld_plus_one: alphaenergyeng.com OR dns.question.name: alphaenergyeng.com OR domain.1n2_name: alphaenergyeng.com OR domain.level_2.name: alphaenergyeng OR domain.name: alphaenergyeng.com OR related.domain: alphaenergyeng.com OR url.original: /wp-content/uploads/2020/01/ahead/* OR file.hash.md5: c43367ebab80194fe69258ca9be4ac68 OR file.hash.sha1: d5168670355c872ec98cdf0fe60f8ca563d39305 OR server.as.ip: 103.91.92.1 OR server.address: 103.91.92.1 OR destination.as.ip: 103.91.92.1 OR destination.address: 103.91.92.1 OR destination.ip: 103.91.92.1 OR server.address: 103.91.92.1 OR server.as.ip: 103.91.92.1 OR server.ip: 103.91.92.1 OR dns.answers.name: 103.91.92.1 OR dns.question.resolved_ip: 103.91.92.1 OR dns.question.etld_plus_one: bhatner.com OR dns.question.domain: bhatner.com OR domain.1n2_name: bhatner.com OR domain.name: bhatner.com OR related.domain: bhatner.com OR file.hash.md5: 275ebb5c0264dac2d492efd99f96c8ad OR destination.address: 153.92.65.114 OR destination.as.ip: 153.92.65.114 OR destination.ip: 153.92.65.114 OR server.ip: 153.92.65.114 OR dns.question.resolved.ip: 153.92.65.114 OR destination.address: 54.36.108.120 OR destination.ip: 54.36.108.120 OR server.address: 54.36.108.120 OR server.ip: 54.36.108.120 OR dns.question.name: pop3.arcor.de OR dns.question.etld_plus_one: arcor.de OR domain.1n2n3_name: pop3.arcor.de OR domain.name: pop3.arcor.de OR related.domain: pop3.arcor.de))
```

## Yara

## Modeling
Modeling is an important part of analysis, however it is not 1:1 "answer" to your analytical "question".

### MITRE ATT&CK
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

#### Reference
https://attack.mitre.org/

```
Name:
ID:
Technique:
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

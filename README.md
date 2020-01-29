# KQL Queries
The [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html) is a standardized query structure that makes it _generally_ easier to ask Kibana questions. It does provide for standardized queries and, in conjunction with the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)(ECS), allows you to easily share Kibana queries with the community.

# Exploit Queries

## CVE 2020-0601 AKA "Curveball"
A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.

### Reference
https://nvd.nist.gov/vuln/detail/CVE-2020-0601

### KQL
Data Source: `Winlogbeat-*` https://www.elastic.co/beats/winlogbeat  
Query: `winlog.provider_name:"Microsoft-Windows-Audit-CVE"`

### ECS
```
{
  "classification": "CVSS",
  "enumeration": "CVE",
  "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
  "score.base": "8.1",
  "score.version": "3.x",
  "category": ["Windows"],
  "description": "A vulnerability exists in the way Windows validates certificates.",
  "id": "CVE-2020-0601",
  "severity": "High",
}
```

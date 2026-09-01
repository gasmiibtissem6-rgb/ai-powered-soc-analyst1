from pathlib import Path


RUNBOOKS = [
    {
        "id": "credential-stuffing",
        "title": "Credential Stuffing",
        "mitre": "T1110.004 - Credential Stuffing",
        "detection": [
            "High volume of authentication attempts against many user accounts.",
            "Repeated login failures followed by successful authentication.",
            "Authentication attempts originating from suspicious or unusual IP addresses.",
            "Use of previously leaked credentials across multiple accounts.",
        ],
        "triage": [
            "Identify targeted accounts and source IP addresses.",
            "Check whether successful logins occurred after repeated failures.",
            "Review geolocation, ASN, device, and user-agent anomalies.",
            "Enrich suspicious IP addresses using threat intelligence providers.",
        ],
        "investigation": [
            "Correlate authentication logs across Wazuh, applications, VPN, and identity systems.",
            "Check for concurrent sessions or impossible travel.",
            "Review account activity after successful authentication.",
            "Search for lateral movement or privilege escalation after login.",
        ],
        "containment": [
            "Temporarily block malicious source IP addresses when safe.",
            "Force password reset for confirmed compromised accounts.",
            "Revoke suspicious sessions and refresh tokens.",
            "Enable or enforce MFA where available.",
        ],
        "eradication": [
            "Remove unauthorized sessions and persistence mechanisms.",
            "Rotate exposed credentials.",
            "Review password reuse and compromised credential exposure.",
        ],
        "recovery": [
            "Restore normal account access after verification.",
            "Monitor affected users for additional suspicious activity.",
            "Confirm that MFA and authentication controls operate correctly.",
        ],
    },
    {
        "id": "password-spraying",
        "title": "Password Spraying",
        "mitre": "T1110.003 - Password Spraying",
        "detection": [
            "A small number of passwords are attempted against many accounts.",
            "Distributed authentication failures occurring below lockout thresholds.",
            "Repeated failed logins from one or several related source IP addresses.",
        ],
        "triage": [
            "Determine the number of targeted accounts.",
            "Identify source IPs and the authentication services involved.",
            "Check whether any account successfully authenticated.",
        ],
        "investigation": [
            "Correlate failures across time windows and authentication services.",
            "Review successful logins from the same source after failed attempts.",
            "Check whether privileged accounts were targeted.",
        ],
        "containment": [
            "Block or rate-limit malicious sources when appropriate.",
            "Reset credentials for confirmed compromised accounts.",
            "Require MFA for affected or privileged users.",
        ],
        "eradication": [
            "Remove unauthorized sessions.",
            "Review weak password policies and exposed credentials.",
        ],
        "recovery": [
            "Restore accounts after identity verification.",
            "Increase monitoring of affected authentication services.",
        ],
    },
    {
        "id": "sql-injection",
        "title": "SQL Injection",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "detection": [
            "HTTP requests containing SQL control characters or injection patterns.",
            "WAF, application, or Suricata alerts indicating SQL injection attempts.",
            "Unexpected database errors caused by crafted user input.",
        ],
        "triage": [
            "Identify the affected application endpoint.",
            "Record source IP, URI, method, parameters, and timestamp.",
            "Determine whether the request reached the database successfully.",
        ],
        "investigation": [
            "Review web server, application, WAF, Suricata, and database logs.",
            "Check for unauthorized database queries or data access.",
            "Search for subsequent command execution or account compromise.",
        ],
        "containment": [
            "Block confirmed malicious sources when appropriate.",
            "Disable or restrict vulnerable endpoints if necessary.",
            "Apply WAF protections while the vulnerability is remediated.",
        ],
        "eradication": [
            "Replace unsafe dynamic SQL with parameterized queries.",
            "Patch vulnerable frameworks or libraries.",
            "Remove any attacker-created database objects or accounts.",
        ],
        "recovery": [
            "Restore services after validation.",
            "Verify database integrity.",
            "Increase monitoring for repeated exploitation attempts.",
        ],
    },
    {
        "id": "xss",
        "title": "Cross-Site Scripting",
        "mitre": "T1189 - Drive-by Compromise",
        "detection": [
            "HTTP input containing suspicious script tags, event handlers, or JavaScript payloads.",
            "WAF or application alerts associated with reflected or stored XSS.",
            "Unexpected script execution in user-facing pages.",
        ],
        "triage": [
            "Identify the vulnerable parameter and affected page.",
            "Determine whether the payload is reflected, stored, or DOM-based.",
            "Check which users may have been exposed.",
        ],
        "investigation": [
            "Review application, reverse proxy, WAF, and browser-related telemetry.",
            "Check whether session tokens or sensitive information were accessed.",
            "Look for malicious stored payloads in application data.",
        ],
        "containment": [
            "Disable or sanitize the vulnerable input path.",
            "Remove stored malicious payloads.",
            "Invalidate compromised sessions if necessary.",
        ],
        "eradication": [
            "Implement contextual output encoding and input validation.",
            "Apply Content Security Policy where appropriate.",
            "Patch vulnerable application components.",
        ],
        "recovery": [
            "Restore the affected functionality after security validation.",
            "Monitor for repeated exploit attempts.",
        ],
    },
    {
        "id": "rce",
        "title": "Remote Code Execution",
        "mitre": "T1203 - Exploitation for Client Execution / T1190 - Exploit Public-Facing Application",
        "detection": [
            "Unexpected commands or child processes spawned by network-facing services.",
            "Exploit signatures indicating command injection or remote code execution.",
            "Suspicious outbound connections immediately after exploitation activity.",
        ],
        "triage": [
            "Identify the affected host, service, process, and source IP.",
            "Determine whether command execution was successful.",
            "Assess privileges of the compromised process.",
        ],
        "investigation": [
            "Review process trees, network connections, shell history, and security alerts.",
            "Identify downloaded payloads or persistence mechanisms.",
            "Search for lateral movement and privilege escalation.",
        ],
        "containment": [
            "Isolate the affected endpoint when compromise is confirmed.",
            "Block known malicious IOCs.",
            "Disable the vulnerable service if operationally possible.",
        ],
        "eradication": [
            "Patch the exploited vulnerability.",
            "Remove attacker tools, payloads, accounts, and persistence.",
            "Rotate credentials exposed on the compromised system.",
        ],
        "recovery": [
            "Restore the host from a trusted state if necessary.",
            "Validate services before reconnecting the endpoint.",
            "Monitor closely for recurrence.",
        ],
    },
    {
        "id": "ransomware",
        "title": "Ransomware",
        "mitre": "T1486 - Data Encrypted for Impact",
        "detection": [
            "Rapid modification or encryption of many files.",
            "Ransom notes or suspicious file extensions appearing on endpoints.",
            "Security alerts indicating known ransomware tools or behaviors.",
            "Backup deletion or shadow copy manipulation.",
        ],
        "triage": [
            "Identify affected endpoints and user accounts.",
            "Determine whether encryption is still active.",
            "Check for lateral movement and shared-drive impact.",
        ],
        "investigation": [
            "Determine the initial access vector.",
            "Review process execution, authentication, SMB, and network telemetry.",
            "Identify malicious binaries, hashes, domains, and IP addresses.",
            "Assess data exfiltration before encryption.",
        ],
        "containment": [
            "Immediately isolate infected endpoints.",
            "Disable compromised accounts.",
            "Block malicious hashes, domains, and IP addresses.",
            "Protect backups from further access.",
        ],
        "eradication": [
            "Remove malware and persistence mechanisms.",
            "Patch exploited vulnerabilities.",
            "Reset compromised credentials.",
        ],
        "recovery": [
            "Restore systems from verified clean backups.",
            "Validate integrity before reconnecting systems.",
            "Monitor for reinfection or remaining persistence.",
        ],
    },
    {
        "id": "port-scan",
        "title": "Port Scan",
        "mitre": "T1046 - Network Service Discovery",
        "detection": [
            "A source host connects to many destination ports in a short period.",
            "Suricata signatures detect SYN or TCP port scanning.",
            "Repeated connection attempts to closed or uncommon services.",
        ],
        "triage": [
            "Identify scanner source and destination hosts.",
            "Determine scanned ports, protocol, and time window.",
            "Decide whether the source is an approved vulnerability scanner.",
        ],
        "investigation": [
            "Correlate Suricata, firewall, Wazuh, and flow telemetry.",
            "Check whether scanning was followed by exploitation attempts.",
            "Enrich external source IP addresses with threat intelligence.",
        ],
        "containment": [
            "Block confirmed unauthorized scanners when appropriate.",
            "Restrict unnecessary exposed services.",
        ],
        "eradication": [
            "Close unauthorized services.",
            "Correct firewall or segmentation weaknesses discovered during investigation.",
        ],
        "recovery": [
            "Restore intended network access.",
            "Monitor the source for additional reconnaissance or exploitation.",
        ],
    },
    {
        "id": "ddos",
        "title": "Distributed Denial of Service",
        "mitre": "T1498 - Network Denial of Service",
        "detection": [
            "Sudden abnormal growth in network traffic or connection rate.",
            "Large numbers of requests from distributed source addresses.",
            "Service latency, resource exhaustion, or availability degradation.",
        ],
        "triage": [
            "Identify targeted services and protocols.",
            "Measure traffic volume and request rate.",
            "Determine whether traffic originates from one source or a distributed set.",
        ],
        "investigation": [
            "Review Suricata, firewall, load balancer, and application telemetry.",
            "Identify common traffic characteristics.",
            "Check whether the event hides another intrusion attempt.",
        ],
        "containment": [
            "Apply rate limiting or upstream filtering.",
            "Block malicious sources only when operationally safe.",
            "Use provider or network-level DDoS protections when available.",
        ],
        "eradication": [
            "Correct exposed services or configurations that amplify the attack.",
            "Remove compromised internal systems if they participated in the attack.",
        ],
        "recovery": [
            "Restore normal traffic policies gradually.",
            "Verify service availability and monitor for repeated waves.",
        ],
    },
    {
        "id": "privilege-escalation",
        "title": "Privilege Escalation",
        "mitre": "TA0004 - Privilege Escalation",
        "detection": [
            "Unexpected use of sudo, su, administrative tools, or privileged tokens.",
            "New privileged accounts or group membership changes.",
            "Exploitation activity targeting local privilege escalation vulnerabilities.",
        ],
        "triage": [
            "Identify the account, host, process, and privilege change.",
            "Determine whether the activity was authorized.",
            "Assess whether attacker access existed before the escalation.",
        ],
        "investigation": [
            "Review authentication, process, audit, and endpoint telemetry.",
            "Identify exploited vulnerabilities or stolen credentials.",
            "Check for persistence and lateral movement.",
        ],
        "containment": [
            "Disable compromised accounts.",
            "Isolate affected endpoints when necessary.",
            "Remove unauthorized administrative privileges.",
        ],
        "eradication": [
            "Patch exploited vulnerabilities.",
            "Remove malicious tools and persistence.",
            "Rotate affected privileged credentials.",
        ],
        "recovery": [
            "Restore legitimate privileges after validation.",
            "Monitor administrative activity closely.",
        ],
    },
    {
        "id": "lateral-movement",
        "title": "Lateral Movement",
        "mitre": "TA0008 - Lateral Movement",
        "detection": [
            "Unusual SMB, RDP, SSH, WinRM, or remote-service connections between internal systems.",
            "Authentication from one endpoint to many internal hosts.",
            "Remote execution or service creation activity.",
        ],
        "triage": [
            "Identify source host, destination hosts, and accounts involved.",
            "Determine whether the communication is expected.",
            "Identify the earliest suspicious lateral connection.",
        ],
        "investigation": [
            "Build a timeline of authentication and network events.",
            "Review endpoint process execution and remote administration activity.",
            "Identify compromised credentials and additional affected systems.",
        ],
        "containment": [
            "Isolate compromised endpoints.",
            "Disable compromised accounts.",
            "Restrict lateral communication using segmentation controls.",
        ],
        "eradication": [
            "Remove persistence and attacker tooling.",
            "Rotate compromised credentials.",
            "Patch vulnerabilities used for propagation.",
        ],
        "recovery": [
            "Reconnect systems after validation.",
            "Monitor internal authentication and east-west traffic.",
        ],
    },
    {
        "id": "data-exfiltration",
        "title": "Data Exfiltration",
        "mitre": "TA0010 - Exfiltration",
        "detection": [
            "Unusual outbound transfer volume.",
            "Large archive creation followed by outbound network communication.",
            "Transfers to unfamiliar domains, cloud services, or external IP addresses.",
        ],
        "triage": [
            "Identify source host, account, destination, and transferred volume.",
            "Determine what data may have been accessed.",
            "Check whether the destination is approved.",
        ],
        "investigation": [
            "Review endpoint, proxy, DNS, firewall, cloud, and DLP telemetry.",
            "Identify files collected or staged before transfer.",
            "Determine whether credentials or systems were compromised.",
        ],
        "containment": [
            "Block malicious destinations.",
            "Disable compromised accounts.",
            "Isolate affected endpoints if active exfiltration continues.",
        ],
        "eradication": [
            "Remove attacker access and persistence.",
            "Rotate affected credentials and tokens.",
        ],
        "recovery": [
            "Restore required connectivity.",
            "Assess data exposure and notify appropriate stakeholders according to policy.",
            "Monitor for further outbound transfers.",
        ],
    },
    {
        "id": "insider-threat",
        "title": "Insider Threat",
        "mitre": "Multiple techniques depending on observed behavior",
        "detection": [
            "Unusual access to sensitive resources inconsistent with normal duties.",
            "Large downloads, file copying, or transfers outside normal working patterns.",
            "Unauthorized privilege use or attempts to bypass security controls.",
        ],
        "triage": [
            "Validate user identity and business context.",
            "Determine whether the activity is authorized.",
            "Preserve evidence before contacting the subject.",
        ],
        "investigation": [
            "Review authentication, file access, endpoint, cloud, and network activity.",
            "Build a timeline and compare with the user's expected role.",
            "Coordinate with authorized HR, legal, or management personnel where required.",
        ],
        "containment": [
            "Restrict access only according to approved organizational procedures.",
            "Revoke sessions or credentials if immediate risk is confirmed.",
        ],
        "eradication": [
            "Remove unauthorized access paths or copied sensitive data where possible.",
            "Correct excessive permissions.",
        ],
        "recovery": [
            "Restore legitimate access according to management authorization.",
            "Continue enhanced monitoring where policy permits.",
        ],
    },
    {
        "id": "command-and-control",
        "title": "Command and Control",
        "mitre": "TA0011 - Command and Control",
        "detection": [
            "Repeated beacon-like outbound connections.",
            "Connections to known malicious domains or IP addresses.",
            "Suspicious DNS, TLS, HTTP, or uncommon protocol patterns.",
        ],
        "triage": [
            "Identify affected endpoint, process, destination, and communication interval.",
            "Enrich domains and IP addresses with threat intelligence.",
            "Determine whether communication is expected.",
        ],
        "investigation": [
            "Review Suricata, DNS, proxy, firewall, and endpoint telemetry.",
            "Identify the process responsible for network communication.",
            "Search for payload downloads, persistence, and additional compromised hosts.",
        ],
        "containment": [
            "Block confirmed malicious destinations.",
            "Isolate compromised endpoints.",
            "Disable compromised accounts where relevant.",
        ],
        "eradication": [
            "Remove malware and persistence.",
            "Patch the initial access vector.",
            "Rotate compromised credentials.",
        ],
        "recovery": [
            "Reconnect cleaned endpoints after validation.",
            "Monitor for recurring beaconing or alternate C2 channels.",
        ],
    },
]


def render_list(items):
    return "\n".join(
        "- " + item
        for item in items
    )


def build_runbook(runbook):
    return "\n".join(
        [
            (
                "# SOC Runbook - "
                + runbook["title"]
            ),
            "",
            "**Document Type:** Internal SOC Runbook",
            (
                "**Runbook ID:** SOC-RUNBOOK-"
                + runbook["id"]
            ),
            (
                "**Incident Type:** "
                + runbook["title"]
            ),
            (
                "**MITRE ATT&CK:** "
                + runbook["mitre"]
            ),
            "",
            "## Detection",
            "",
            render_list(
                runbook["detection"]
            ),
            "",
            "## Triage",
            "",
            render_list(
                runbook["triage"]
            ),
            "",
            "## Investigation",
            "",
            render_list(
                runbook["investigation"]
            ),
            "",
            "## Containment",
            "",
            render_list(
                runbook["containment"]
            ),
            "",
            "## Eradication",
            "",
            render_list(
                runbook["eradication"]
            ),
            "",
            "## Recovery",
            "",
            render_list(
                runbook["recovery"]
            ),
            "",
            "## Evidence to Preserve",
            "",
            "- Alert and incident identifiers.",
            "- Relevant timestamps.",
            "- Source and destination IP addresses.",
            "- User and host identifiers.",
            "- Relevant process, network, and authentication telemetry.",
            "- Threat-intelligence enrichment results.",
            "- Analyst actions and response decisions.",
            "",
            "## Escalation",
            "",
            (
                "Escalate when the incident is confirmed, "
                "affects critical assets, involves privileged "
                "accounts, causes significant business impact, "
                "or requires containment actions that need "
                "human approval."
            ),
            "",
            "## Human-in-the-Loop",
            "",
            (
                "High-risk or disruptive response actions "
                "must be reviewed and approved by an authorized "
                "SOC analyst before execution."
            ),
            "",
        ]
    )


def main():
    project_root = (
        Path(__file__)
        .resolve()
        .parents[3]
    )

    output_directory = (
        project_root
        / "data"
        / "knowledge_base"
        / "runbooks"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    generated = 0

    for runbook in RUNBOOKS:
        output_path = (
            output_directory
            / (
                runbook["id"]
                .replace("-", "_")
                + "_runbook.md"
            )
        )

        output_path.write_text(
            build_runbook(runbook),
            encoding="utf-8",
        )

        generated += 1

        print(
            "Generated:",
            output_path.name,
        )

    print()
    print(
        "SOC runbooks generated: OK"
    )
    print(
        "Output directory:",
        output_directory,
    )
    print(
        "Runbooks generated:",
        generated,
    )


if __name__ == "__main__":
    main()

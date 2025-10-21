# Incident-Response-Network-Simulation

**Objective**

The goal of this incident response simulation was to run a controlled, documented detection-and-response exercise inside an isolated virtual lab. The workflow demonstrates starting pfSense and Suricata, running a safe Scapy-based network simulation from a Kali VM against an Ubuntu target VM, capturing packets with Wireshark, observing alerts in Suricata, documenting the incident, and performing containment, analysis, and eradication.

**Skills Learned**

- Intrusion Detection Tool (Suricata) 
- Network Traffic Analysis 
- Incident Detection 
- JIRA & Google Docs (Documentation) 
- Wireshark 

**Tools Used**

- VirtualBox  (VM host)
- pfSense (firewall) with Suricata (IDS)
- Kali Linux (attacker/tester) 
- Ubuntu (target) with UFW and pfSense active
- Scapy for launching network attack simulation
- Wireshark (GUI capture)
- CLI tools: `ps aux`, `kill`, `grep`
- Documentation: Google Docs, JIRA (for incident tracking)

**Lab Overview (topology / roles)**

- *Kali VM* — attacker / traffic generator (Scapy). Example IP: `192.168.56.108`.
- *pfSense VM* — firewall/gateway and Suricata sensor. LAN IP example: `192.168.56.1`.
- *Ubuntu VM* — target/endpoint with UFW and Wireshark for packet capture. Example IP: `192.168.56.104`.

**Steps**

1. *Boot & Verify*  
   - Power on pfSense first, then the Ubuntu target, then Kali.  
   - Confirm virtual NICs and IP addresses (`ip addr`). Ensure the host-only/internal network is correctly assigned.

2. *Enable Detection*  
   - Open pfSense GUI → `Services → Suricata`. Start Suricata on the interface monitoring the lab traffic.  
   - Temporarily disable the two rules you want to observe behavior for (log & block) so the test traffic will be seen and not immediately dropped.

     <img width="1151" height="533" alt="Screenshot 2025-10-18 164058" src="https://github.com/user-attachments/assets/271da452-c6fb-4b51-8b27-c0290d06b90a" />


3. *Prepare Capture & Logging* 
   - Start Wireshark on the Ubuntu VM and begin a live capture on the Ubuntu network interface (or start tcpdump if preferred).  
   - Ensure UFW logging (if used) is enabled to capture host-level events.

   <img width="821" height="389" alt="Screenshot 2025-10-18 174038" src="https://github.com/user-attachments/assets/1ecfd9d4-1257-4b59-ad8b-bcc03f3b7cbc" />

4. *Execute Simulation*  
   - On Kali, prepare a safe Scapy script (`single_icmp_test.py`) that sends low-volume, non-destructive packets to the Ubuntu VM.  
   - Run the Scapy script while captures are running on Ubuntu and Suricata is active on pfSense.
  ``` bash
      from scapy.all import sr1, IP, ICMP, wrpcap
      TARGET = "192.168.56.104"   
      IFACE  = "eth0"             

      resp = sr1(IP(dst=TARGET)/ICMP(), timeout=2, iface=IFACE, verbose=False)
      if resp:
           print("Reply received:")
           resp.show()
           wrpcap("../captures/single_icmp_reply.pcap", [resp])
       else:
           print("No reply (timeout or filtered)")
```

5. *Monitor & Collect (Detection & evidence)*  
   - Observe Suricata’s Alerts view for triggered signatures and note timestamps and alert IDs.  
   - Save Wireshark in form of pcaps and any relevant Suricata logs in form of screenshots.
  
<img width="944" height="286" alt="Screenshot 2025-10-18 163813" src="https://github.com/user-attachments/assets/975d1500-18e7-43bb-a349-7494c6ea8128" />

<img width="1128" height="343" alt="Screenshot 2025-10-18 163747" src="https://github.com/user-attachments/assets/c2df040c-ea1b-4b49-bf2c-4f8f90013e94" />


6. *Containment & Analysis*  
   - Re-enable the previously disabled Suricata rules (log & block) to return the environment to its defended state.  
   - Analyze PCAPs and Suricata alerts: correlate timestamps, identify the most suspicious packets, and produce short per-artifact notes.

<img width="1150" height="495" alt="Screenshot 2025-10-18 164116" src="https://github.com/user-attachments/assets/b8214bdf-7194-4616-868b-4de6706c973b" />


7. *Eradication, Recovery & Documentation*  
   - Terminate the Scapy process on Kali (`ps aux | grep scapy` → `kill -9 <PID>`) and stop any running captures.  
   - Verify Suricata and Ubuntu networking are normal. Archive pcaps, logs, and screenshots.  
   - Complete incident documentation in Google Docs / JIRA and store artifacts in the `docs/` folders.

**Network Diagram**
This project successfully demonstrated an incident response simulation in an isolated virtual environment  
<img width="1042" height="721" alt="Screenshot 2025-10-21 225533" src="https://github.com/user-attachments/assets/6228e0c5-f405-43e1-acd5-8ed453c98f2a" />


**Conclusion**

This incident-response simulation successfully demonstrated the end-to-end workflow of a contained cyber incident within an isolated lab. It validated the ability to generate and detect controlled network activity, observe alerts from Suricata, capture forensic packet evidence with Wireshark, and perform containment/eradication steps while maintaining an evidence trail. The exercise reinforced the IR lifecycle  preparation, detection, containment, analysis, eradication, and recovery in a reproducible, safe environment.

**Key Takeaways**

- *Isolation is critical:* Running the simulation entirely in a host-only network ensures safe experimentation without external impact.  
- *Structured response improves efficiency:* Following the IR lifecycle (Preparation → Detection → Containment → Eradication → Recovery) gives clarity and repeatability.  
- *Suricata visibility:* The IDS effectively detected Scapy-generated packets, proving its capability to catch anomalies and malformed ICMP traffic.  
- *Wireshark correlation:* Packet captures complemented Suricata alerts, confirming detection accuracy and providing forensic visibility.  

**Safety & Ethics**

- All testing MUST be done in a fully isolated virtual lab (host-only/internal network) and on VMs you own or have explicit authorization to test.
- Tests are intentionally low-impact (single packets or very small sequences) avoid loops, floods, or exploit payloads.
- Keep logs, pcaps, and screenshots secure and timestamped for reproducibility and reporting.

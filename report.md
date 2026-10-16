# Suricata-Based Network Intrusion Detection and Evaluation

## 1. Introduction
Network Intrusion Detection Systems (NIDS) are designed to analyze and identify malicious traffic in order to identify potentially malicious activity by inspecting patterns associated with known attacks or unusual behaviour. This project aims to investigate the effectiveness and the limitations of a signature-based approach. We wrote a custom ruleset for Suricata, an open-source network analysis and threat detection software, and measure it on labelled packet captures.

We assess them by comparing Suricata's alerts with the ground truth of each capture, which gives true positives, false negatives, false positives and true negatives. From these we compute recall, precision, false positive rate, true negative rate, accuracy and F1. The goal is to see how well custom signatures separate malicious from legitimate traffic, and what trade-offs appear when rules are refined to reduce false alarms.

### 1.1 Network Intrusion Detection
The Network Intrusion Detection System (NIDS) is a security mechanism designed to monitor network traffic and devices for known or potential malicious activity, suspicious behaviours or any violations [1]. The main purpose of an NIDS is to automate threat detection within a network, alerting administrators of suspicious activities.

### 1.2 Detection models
Depending on the chosen detection model, IDSs can generally be classified in three categories:
- Signature-based detection, which identifies malicious activity by comparing network traffic against signatures and rules associated with common and known attack patterns. However, its ability to detect previously unseen attacks is limited by the signatures currently available to the system.
- Anomaly-based detection, which identifies potentially malicious activity by detecting deviations from an established model of normal network behaviour. This approach can potentially detect either known and unknown attacks, but at the same time it can easily generate false positive from abnormal legitimate activities.
- Hybrid-based detection [2] combines signature-based and anomaly-based detection mechanisms. This approach can provide a broader detection capabilities, but generally introduces greater complexity with using a single detection methodology.

## 2. Background
For this project, we use Suricata [3], an open-source Network Intrusion Detection and Prevention System (NIDS/NIPS), widely used for real-time network traffic analysis. Suricata supports rule-based inspection of network traffic and provides mechanisms for detecting predefined patterns associated with malicious activity.

Suricata was selected primarily because it supports custom detection rules, allowing us to investigate the effectiveness and limitations of a relatively simple signature-based approach.

### 2.1 Attack Categories
The ruleset covers multiple protocols and attack categories rather than focusing exclusively on a single type of traffic. The selected rules target web application threats, such as SQL injection and cross-site scripting (XSS), as well as authentication attacks, vulnerability scanning, port scanning, reconnaissance, and denial-of-service (DoS) and distributed denial-of-service (DDoS) activity.

Although some rules inspect application-layer content, others identify suspicious patterns at the transport or network layer, including TCP flag combinations, packet characteristics, and traffic rates. This diversity allows us to evaluate the applicability of the rules to  different network activities.

## 3. Threat Model and Scope
### 3.1 Defensive Scenario
The considered scenario consists of a monitored network in which Suricata is deployed to observe and report potentially suspicious traffic. Suricata observes the traffic exchanged between several hosts (including the attacker) and a monitored server and generates alerts when the configured detection rules match the observed traffic. The primary objective is detection rather than prevention. The project evaluates whether specific malicious activities can be identified from the observed network traffic.

The experimental environment is based on pre-recorded network traffic obtained from public datasets [4]. These datasets provide labelled traffic that can be used as ground truth for evaluating the detection results.

### 3.2 Attacker Capabilities
We assume an attacker capable of generating and controlling network traffic directed towards the monitored server. The attacker is able to perform different type of network intrusion, for instance: port scanning, malicious web requests and repeated authentication attempts, DoS and other enumeration techniques. The attacker can modify the characteristics of the generated traffic in order to deceive the detection mechanisms.

The attacker is not assumed to have control over or be able to compromise the monitoring infrastructure or the monitored server.

### 3.3 Assumptions
The analysis assumes that Suricata is able to observe the relevant network traffic offline.

Since the experiments are conducted in a controlled environment, the ground truth of each traffic sample is known in advance and can be used to evaluate the effectiveness of the selected rule set, only after the detection analysis is performed. Suricata can only differentiate the traffic from its signatures and patterns, it has no access to the labeled evaluation.

### 3.4 Out-of-Scope Scenarios
The scope of the project is limited to a network-based, signature-based intrusion detection using Suricata. Therefore, the following detections are not addressed or performed in any way: host-based intrusion detection, malware analysis, and prevention (blocking) of traffic.

## 4. Experimental Environment
### 4.1 Environment
All experiments were run offline on a Linux machine with Suricata. Suricata read the recorded traffic from the pcap files instead of a live network. The same setup was used for both datasets. We ran Suricata with:

```
suricata -r <file.pcap> -S custom.rules -l <output folder> -k none
```

We use `-r` to read a pcap file, `-S` to load only our rules, `-l` to choose the output folder and `-k none` to turn off checksum checks, since recorded traffic often has wrong checksums.

Suricata writes its alerts to `eve.json`. Two Python scripts compare these alerts with the ground truth: `evaluate_training.py` for Edge-IIoTset and `evaluate_test.py` for CIC-IDS-2017. The training script uses the `dpkt` library to read packet timestamps from the pcap. `setup.sh` puts the datasets in place and `run.sh` runs Suricata and then the right evaluation script.

### 4.2 Dataset
The rules were developed on one dataset and then evaluated on another second dataset in a different network. This was done in order to test whether the rules also generalises to other environments rather to where they were created.

#### 4.2.1 Edge-IIoTset
Edge-IIoTset [5] is a cybersecurity dataset for IoT and Industrial IoT applications, published by Ferrag et al. in 2022. It was generated in a purpose-build testbed using more than ten types of IoT devices, such as heart rate sensor, water level sensor, pH meter sensor, soil moisture sensor and more. These are labelled as normal traffic in the set. Moreover, the dataset contains 14 attacks, which are grouped into five categories, these are Dos/DDoS, information gathering, Man in the middle, injection and malware. The dataset includes both the normal traffic and the attack traffic in raw pcap format and labelled CSV files.

We used Edge-IIoTset to develop our rules. It covers most of the attack types in our scope and the dataset was relatively small in size which made it practical to work with. Each record in the CSV files is labelled as normal or attack with its corresponding attack type. This marks the ground truth for the evaluation. During the work we found that the CSV file for the UDP flood attack contained errors with the labelling, so we regenerated it from the corresponding pcap file.

#### 4.2.2 CIC-IDS-2017
CIC-IDS-2017 [6] is a dataset created by the Canadian Institute for Cybersecurity. It includes both benign traffic and traffic from the most common attacks. The dataset contains traffic from five days, captured from Monday to Friday in July 2017. Monday is a normal day with only benign traffic, while the remaining days also contain attacks, such as brute force, DoS and DDoS, web attacks, port scanning, and more. As in Edge-IIoTset, the dataset includes both raw pcap files and labelled CSV files.

We used CIC-IDS-2017 as an external test set, since its attack types overlap with Edge-IIoTset and because the dataset is in another network. The original labels of CIC-IDS-2017 contain a number of error. We therefore used a corrected version of the labels [7], together with the original pcap files.

### 4.3 Attack Scenarios
#### 4.3.1 SQL Injections
A SQL injection attack is an attack which targets a web application’s database by injecting SQL code into its queries. If the application has a field for user input that it does not validate, then an attacker can enter valid SQL code instead of a normal input. This can lead to the attacker being able to read, change or delete data in the database [8]. The traffic in our scope is HTTP, and because of that the requests are sent in cleartext. Therefore, the injected code is visible in the request, containing SQL keywords that uncommonly appear in normal requests.

#### 4.3.2 Brute Force
A brute force attack is an attack that systematically tries a large number of passwords against an account, with the aim of gaining access to it. The attack typically goes through a list of common passwords until one of them works. Each login attempt looks like normal traffic, since normal users also log in and sometimes enter the wrong password. The difference lies in the number of attempts. During a brute force attack many login attempts are sent from the same source to the same login page, where most of the login attempts fail. This makes it possible to distinguish an attack from a normal user logging in [9].

#### 4.3.3 Vulnerability Scanner
A vulnerability scanner is a tool used in the reconnaissance stage to find a way into a system, but it can also be used by system administrators to find weaknesses in their own systems. It probes the system for any known weaknesses, such as misconfigurations, outdated versions, coding flaws and more. [10] Because the scanner looks for many types of weakness at the same time, a large number of requests are being sent in quick succession. Some requests might give a meaningful response, while others may end up giving error responses since the scanner might scan for weaknesses that do not exist on the system [11].

#### 4.3.4 Web Shell
A web shell is a malicious script that an attacker uploads to a web server through a vulnerable file upload function. The script allows the attacker to execute commands on the server through HTTP requests [12]. The goal is to gain control over the server, or use it as a foothold for persistent access or lateral movements [13].

#### 4.3.5 Path Traversal
A path traversal attack is when the attacker tries to read files on a web server that should not be reachable from the web. The attacker does this by adding `../` to the file path in a request, which means "go up one folder". By repeating it several times, the attacker can access system files such as `/etc/passwd`. The `../` can also be encoded, for example as `%2e%2e%2f` [17]. Since the request is sent over HTTP, these patterns are visible in the URL. Our rules therefore look for repeated `../`, its encoded forms and the names of common system files in the URL.

#### 4.3.6 XSS
A cross-site scripting (XSS) attack is when the attacker injects JavaScript code into a web page. This works when a website takes user input, such as a search field or a comment, and shows it on the page without checking it. The code then runs in the browser of anyone who opens the page and can steal data such as their cookies [18]. The attack is sent in HTTP requests, so the code is visible in the URL or the request body. It often contains HTML tags like `<script>` or `<img>`, or JavaScript like `onerror=` or `alert(`. Our rules look for these patterns in the URL. A few rules also check the request body, for example for `%3Cscript`, which is `<script` in encoded form.

#### 4.3.7 Port Scanning
A port scan is when the attacker checks which ports on a target are open, to find out which services are running on it. Attackers use this to find services that might have weaknesses they can exploit [19]. The most common way is a SYN scan. The attacker sends a SYN packet to many ports and looks at the replies. A SYN/ACK means the port is open and a RST means the port is closed. The attacker never finishes the three-way handshake. For UDP, a closed port answers with an ICMP port unreachable message instead [20]. In the traffic, a port scan shows up as one host sending packets to many different ports in a short time and getting many RST or ICMP replies back. Our rules count these replies and alert when there are too many in a short time. They also look for packets with odd TCP flags, such as only FIN set, and SYN packets with an unusual window size.

#### 4.3.8 DoS

##### 4.3.8.1 HTML DoS
A HTML DDoS (HyperText Markup Language Distributed Denial of Service)
attack is an attack which aims to overwhelm a system by subjecting it to
a large number of HTML requests, thus occupying too much computational
load for the system to respond to legitimate traffic. These attacks are
very obvious from an intrusion detection perspective, as they consist of
more traffic than the system would ever legitimately handle. The rules
written for these attacks cover the two most common types of HTML
requests, the GET and POST requests, as well as two different variations
of DDoS attacks, one where the system is subjected to an extreme burst
of requests over a short amount of time, and one where the system is
subjected to a larger flood of requests over a longer amount of time. Of
note is also the difference between a DoS (Denial of Service) attack and
a DDoS attack. A DDoS attack specifically launches attacks from multiple
different sources in an effort to disguise the attack as merely an
abnormal amount of possibly legitimate traffic, which means that the
rules have to track the request frequency by the destination of the
requests instead of the source.

##### 4.3.8.2 ICMP Flood
An ICMP flood is a DoS attack where the attacker sends a large number of ICMP echo requests, normally known as pings, to a target. Under normal circumstances, when a ping is sent, the host answers the echo request with an ICMP echo reply to notify that it is reachable. However, during a flood, the target must process every request and send a reply, which might overwhelm the target in handling the requests [14]. Therefore, the distinguishing factor is the rate of the ICMP echo requests. Our rules therefore count the number of ICMP echo requests sent to the same host, both in short bursts and over an extended time, and sends an alert when the count exceeds a threshold. Another rule only counts echo requests sent without a payload, and then sends an alert when a certain threshold is reached. This is because ICMP echo requests typically contain a payload.

##### 4.3.8.3 UDP Flood
An UDP flood is a DoS attack where the attacker sends a large number of UDP packets to a target. UDP is stateless, meaning that it does not need to establish a connection before communicating. The attacker can utilize this to send packets directly to the target, without any previous connection being made. The target then receives a UDP packet, and if no program is listening to the port where it was sent to, it replies with an ICMP destination unreachable message. When a large number of UDP packets are being sent in quick succession, the target then has to check and reply back with an error message to most of the packets. This process uses up the target resources [15], leading to the target not being able to handle normal traffic. The rules for the UDP are similar to those for ICMP, with regards to the burst and extended rule. There are also rules for empty packets being sent and when the target host sends a large number of ICMP destination unreachable messages.

##### 4.3.8.4 TCP SYN Flood
A TCP SYN flood is a DoS attack where the three-way handshake is misused. In a normal TCP connection, the client sends a SYN packet, the server answers with a SYN, ACK, and the client establishes the connection with an ACK. In a SYN flood, the attacker sends a large number of SYN packets. These packets initiate a connection to the server, but the three-way handshake is never completed. The server keeps the state from the half-open connection in a backlog queue. The backlog queue is limited, therefore when several SYN’s are sent in quick succession, the limit is reached quickly. When the backlog is full, the server can no longer establish any new connections [16]. In the traffic, the attack can be seen as a large number of packets with only the SYN flag set going to the same host within a short time. The rules for the TCP SYN floods are the same as for the other floods, with regards to the burst and extended rule. But also rules for when SYN packets without TCP option are sent and when the target answers with many RST,ACK (answer for SYN packets that are sent to a port that is not listening).

#### 4.3.9 Reconnaissance
#### 4.3.10 OS Fingerprinting
An OS Fingerprinting attack is an attack which aims to discover the OS
(Operating System) of the target. This information can then be used in
order to exploit known vulnerabilities in those operating systems. OS
Fingerprinting can be difficult to defend against as it can take many
different forms. In the training dataset OS Fingerprinting mainly takes
the form of ICMP analysis and TCP SYN requests to an invalid port. ICMP
analysis is difficult to detect, as it simply observes the response to
legitimate ICMP traffic, so the rules instead track TCP requests to a
port which is not used by legitimate traffic. Other forms of OS
Fingerprinting can use other forms of scanning, like TCP Null, FIN or
XMAS scans, in order to gather data.

#### 4.3.11 MITM
A MITM (Man In The Middle) attack is an attack which aims to hijack a
connection in order to allow the attacker to pretend to be another part
of the network. In the training dataset this consists of two different
types of spoofing, DNS (Domain Name Service) and ARP (Address Resolution
Protocol) spoofing. As ARP is a layer 2 protocol, Suricata does not
support rules that interact with it, so ARP spoofing will not be covered
by this project. DNS spoofing is an attack where the attacker attempts
to insert a fraudulent domain-to-IP address translation into a DNS
cache, which will redirect all traffic that was supposed to go to that
domain to the attacker. In the dataset this involves repeated
retransmissions of DNS requests with transmission ID 0 from the
attacker, so that the fake translation is more likely to be accepted.
Unfortunately, Suricata supports neither checking for retransmissions
nor the DNS transmission ID, so the rules simply check for repeated DNS
requests during a short time, which is likely to cause false positives.

### 4.4 Benign Traffic
### 4.5 Ground Truth
The ground truth tells us which traffic is really an attack and which is benign. Suricata does not see it. We only use it after Suricata has run, to check if the alerts were right. Both datasets come with CSV files that hold the labels, but they label the traffic in different ways.

In Edge-IIoTset, each row in the CSV is one packet, with a label that is 1 for attack and 0 for normal traffic. In the attack files all rows are labelled as attack, and in the normal files all rows are labelled as normal.

In CIC-IDS-2017, each row in the CSV is one flow, which means all the packets of one connection between two hosts. A flow is identified by its source IP, source port, destination IP, destination port and protocol. Its label is either `BENIGN` or the name of an attack, and we count every label other than `BENIGN` as an attack.

We used the corrected labels for CIC-IDS-2017 and a regenerated CSV for the UDP flood in Edge-IIoTset.

## 5. Suricata Rules
### 5.1 Rule Design Principles
The rules were written to detect the attacks that are described in Section 4.3. This was done by looking at what makes each attack different from normal traffic. For some of the attacks, the difference is in the content of the packets, for example HTTP requests containing SQL code. For the other attacks, where the content of the packets do not differ, the packets on their own look like normal traffic, but they differ in how many of them are sent. For these, the rules instead count how many matching packets are sent within a certain time, and sends an alert when the count goes above a threshold.

Each rule has its own purpose and detects something that the other rules don’t. Having two rules that match the same traffic does not improve the detection. It only doubles the alert. Therefore, we’ve tried creating rules that are specific enough to not alert on normal traffic, but at the same time general enough to be able to detect variants of certain attacks.

### 5.2 Initial Rules
The first version consisted of a small set of rules with roughly one rule for each attack. The rules were tested on Edge-IIoTset by running Suricata on the attack traffic and the normal traffic, seeing if an alert was raised or not. When an alert was raised on the attack traffic, it meant that the rule detected the attack. In contrast, when an alert was raised on the normal traffic it meant that the rule gave a false alarm. The first version of the rules already worked, but having only one rule per attack meant that it only covered one way the attack could be executed. Therefore, more rules were added to ensure that variants of the attacks could be detected as well.

### 5.3 Rule Thresholds
The rules that count packets have a threshold. When a certain number of matching packets are detected within a certain time, the threshold is reached and an alert is raised. A low threshold can help in detecting slower attacks, but there is a risk it alerts on normal traffic. A high threshold avoids false alarms, but instead it misses the slower attacks. The thresholds were chosen empirically. Several different values were tested against both the attack traffic and the normal traffic in the Edge-IIoTset dataset. It is worth noting that the amount of traffic differs between networks, meaning that a threshold that works for one network might not work in another. The threshold value has to be adjusted for networks with a higher or lower load of normal traffic.

## 6. Evaluation Methodology
### 6.1 Experimental Procedure
We ran Suricata on each pcap file on its own: the 24 captures of Edge-IIoTset and the 5 days of CIC-IDS-2017. After each run, an evaluation script compared the alerts with the ground truth of the same capture.

For Edge-IIoTset, the script links each alert to a packet using the packet number, and links each CSV row to a packet using its time. A packet counts as detected if Suricata alerted on it or on another packet in the same connection.

For CIC-IDS-2017, the script links each alert to a flow using its IP addresses, ports and protocol. A flow counts as detected if at least one alert is linked to it.

### 6.2 Confusion Matrix
The confusion matrix compares what Suricata said with the ground truth. Every packet or flow ends up in one of four groups:

|        | Alert               | No alert            |
|--------|---------------------|---------------------|
| Attack | True Positive (TP)  | False Negative (FN) |
| Benign | False Positive (FP) | True Negative (TN)  |

True positives are attacks that got an alert, and false negatives are attacks that were missed. False positives are benign traffic that got an alert by mistake, and true negatives are benign traffic with no alert. In Edge-IIoTset we count packets, and in CIC-IDS-2017 we count flows. Since each Edge-IIoTset capture has only attack or only normal traffic, an attack capture can only have TP and FN, and a normal capture can only have FP and TN.

### 6.3 Evaluation Metrics
From the four numbers in the confusion matrix we calculate these metrics:

| Metric    | Formula                          | What it tells us |
|-----------|----------------------------------|------------------|
| Recall    | TP / (TP + FN)                   | How many of the attacks were detected |
| Precision | TP / (TP + FP)                   | How many of the alerts were real attacks |
| FPR       | FP / (FP + TN)                   | How much of the benign traffic got a false alarm |
| TNR       | TN / (TN + FP)                   | How much of the benign traffic got no alert |
| Accuracy  | (TP + TN) / (TP + FN + FP + TN)  | How much of all traffic was handled correctly |
| F1        | 2TP / (2TP + FP + FN)            | Recall and precision combined in one number |

FPR stands for false positive rate and TNR for true negative rate. If a formula would divide by 0, the metric is shown as N/A in the results.

## 7. Results

### 7.1 Training (Attacks)

#### 7.1.1 Backdoor Attack

Metrics:


 |    Type    |  Number|
 | -----------| ---------|
 |     TP     |     0|
 |     FN     |  24,862|
 |     FP     |     0|
 |     TN     |     0|
 |    Total   |  24,862|
 |            | |
 |   Recall   |  0.0000%|
 |  Precision |    N/A|
 |     FPR    |    N/A|
 |     TNR    |    N/A|
 |  Accuracy  |  0.0000%|
 |     F1     |  0.0000%|



#### 7.1.2 HTTP DDoS

Evaluated signatures:

  | Number  |                      Type|
  |-------- |-------------------------------------------------|
  | 16,645  |         TCP SYN flood (extended flood)|
  | 2,870   |           TCP SYN flood (burst flood)|
  |  895    | Potential HTTP DDoS attack detected (GET burst)|
  |  441    | Potential HTTP DDoS attack detected (GET flood)|
  |   45    |                 DoS: SYN flood|
  |   23    |                 Recon: SYN scan|


Metrics:

  |   Type    |   Number|
  |-----------| -----------|
  |    TP     |   143,471|
  |    FN     |   85,551|
  |    FP     |      0|
  |    TN     |      0|
  |   Total   |   229,022|
  |           | |
  |  Recall   |  62.6451%|
  | Precision |  100.0000%|
  |    FPR    |     N/A|
  |    TNR    |     N/A|
  | Accuracy  |  62.6451%|
  |    F1     |  77.0329%|

#### 7.1.3 ICMP DDoS:

Evaluated signatures:

  |  Number   |                    Type|
  |-----------| -------------------------------------------|
  | 2,403,102 |  ICMP flood echo requests (empty payload)|
  | 2,201,181 |  ICMP flood echo requests (extended flood)|
  | 2,185,117 |   ICMP flood echo requests (burst flood)|
  |    81     |            DoS: ICMP echo flood|

Metrics:

  |   Type    |   Number|
  |-----------| -----------|
  |    TP     |  2,913,922|
  |    FN     |     432|
  |    FP     |      0|
  |    TN     |      0|
  |   Total   |  2,914,354|
  |           | |
  |  Recall   |  99.9852%|
  | Precision |  100.0000%|
  |    FPR    |     N/A|
  |    TNR    |     N/A|
  | Accuracy  |  99.9852%|
  |    F1     |  99.9926%|

#### 7.1.4 TCP SYN DDoS:

Evaluated signatures:

 |   Number   |                      Type|
 | -----------| -----------------------------------------------|
 |  1,163,807 |           TCP SYN flood (no options)|
 |   908,098  |           TCP SYN flood (burst flood)|
 |   881,320  |         TCP SYN flood (extended flood)|
 |   792,514  |  TCP SYN flood victim answering with many RSTs|
 |     118    |                 DoS: SYN flood|

Metrics:

|     Type     |  Number|
|  ----------- |-----------|
|      TP      | 2,019,071|
|      FN      |   1,049|
|      FP      |     0|
|      TN      |     0|
|     Total    | 2,020,120|
|             | |
|    Recall   |  99.9481%|
|   Precision |  100.0000%|
|     FPR     |    N/A|
|      TNR    |     N/A|
|   Accuracy  |  99.9481%|
|      F1     |  99.9740%|


#### 7.1.5 UDP DDoS:

Evaluated signatures:

 |   Number    |                      Type|
 | ----------- |-------------------------------------------------|
 |  2,890,950  |            UDP flood (empty payload)|
 |  2,818,556  |           UDP flood (extended flood)|
 |  2,701,600  |             UDP flood (burst flood)|
 |   284,147   | UDP flood victim sending many ICMP unreachables|
 |     82      |                 DoS: UDP flood|

Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |  3,214,994|
|      FN     |     738|
|      FP     |      0|
|      TN     |      0|
|     Total   |  3,215,732|
|             | |
|    Recall   |  99.9771%|
|   Precision |  100.0000%|
|      FPR    |     N/A|
|      TNR    |     N/A|
|   Accuracy  |  99.9771%|
|      F1     |  99.9885%|

#### 7.1.6 MITM:

Evaluated signatures:


 |  Number |           Type|
 | --------| ------------------------|
 |    26   |  Possible MDNS Spoofing|


Metrics:

 |    Type    |  Number|
 | -----------| --------|
 |     TP     |    0|
 |     FN     |    0|
 |     FP     |    0|
 |     TN     |    0|
 |    Total   |    0|
 |            | |
 |   Recall   |   N/A|
 |  Precision |   N/A|
 |     FPR    |   N/A|
 |     TNR    |   N/A|
 |  Accuracy  |   N/A|
 |     F1     |   N/A|


#### 7.1.7 OS Fingerprinting:

Evaluated signatures:

|   Number  |   Type|
|  ---------| --------------------------------------------|
|   135     |  Possible OS Fingerprinting attack|
|   54      | Port scan: many closed port replies|
|   35      |      TCP SYN flood (no options)|
|    3 |   Recon: many RST/ACK replies (closed ports)|


Metrics:

 |    Type    |   Number|
 | -----------| -----------|
 |     TP     |     270|
 |     FN     |     731|
 |     FP     |      0|
 |     TN     |      0|
 |    Total   |    1,001|
 |            | |
 |   Recall   |  26.9730%|
 |  Precision |  100.0000%|
 |     FPR    |     N/A|
 |     TNR    |     N/A|
 |  Accuracy  |  26.9730%|
 |     F1     |  42.4862%|


#### 7.1.8 Password attacks:

Evaluated signatures:

|   Number   |     Type|
|  -------- |-----------------|
|     11    | Recon: SYN scan|


Metrics:

 |    Type    |   Number|
 | -----------| -----------|
 |     TP     |     877|
 |     FN     |  1,052,508|
 |     FP     |      0|
 |     TN     |      0|
 |    Total   |  1,053,385|
 |            | |
 |   Recall   |   0.0833%|
 |  Precision |  100.0000%|
 |     FPR    |     N/A|
 |     TNR    |     N/A|
 |  Accuracy  |   0.0833%|
 |     F1     |   0.1664%|

#### 7.1.9 Port Scan:

Evaluated signatures:

  | Number |                      Type|
  |-------- |-----------------------------------------------|
  | 9,987   |           Port scan: SYN window 512|
  | 7,612   |      Port scan: many closed port replies|
  | 3,681   |          TCP SYN flood (no options)|
  | 1,645   | TCP SYN flood victim answering with many RSTs|
  |  461    |          TCP SYN flood (burst flood)|
  |   84    |            Possible MDNS Spoofing|
  |   30    |  Recon: many RST/ACK replies (closed ports)|
  |   15    |        Port scan: UDP port unreachable|
  |   3     |                Recon: SYN scan|
  |   1     |                DoS: SYN flood|
  |   1     |      Recon: ICMP port unreachable burst|


Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |   19,974|
|      FN     |    2,590|
|      FP     |      0|
|      TN     |      0|
|     Total   |   22,564|
|             | |
|    Recall   |  88.5215%|
|   Precision |  100.0000%|
|      FPR    |     N/A|
|      TNR    |     N/A|
|   Accuracy  |  88.5215%|
|      F1     |  93.9113%|

#### 7.1.10 Ransomware attacks:

Metrics:

|     Type    |  Number|
|  -----------| ---------|
|      TP     |     0|
|      FN     |  10,925|
|      FP     |     0|
|      TN     |     0|
|     Total   |  10,925|
|             | |
|    Recall   |  0.0000%|
|   Precision |    N/A|
|      FPR    |    N/A|
|      TNR    |    N/A|
|   Accuracy  |  0.0000%|
|      F1     |  0.0000%|


#### 7.1.11 SQL Injection:

Evaluated signatures:

|   Number  |             Type|
|  -------- |-------------------------------|
|    842    |    SQLi: time-based in URI|
|    480    |  SQLi: stacked query in URI|
|    300    | SQLi: OR/AND tautology in URI|
|     60    |   SQLi: UNION SELECT in URI|
|     14    v        Recon: SYN scan|

Metrics:

 |    Type    |   Number|
 | -----------| -----------|
 |     TP     |   16,994|
 |     FN     |   34,209|
 |     FP     |      0|
 |     TN     |      0|
 |    Total   |   51,203|
 |            | |
 |   Recall   |  33.1895%|
 |  Precision |  100.0000%|
 |     FPR    |     N/A|
 |     TNR    |     N/A|
 |  Accuracy  |  33.1895%|
 |     F1     |  49.8380%|


#### 7.1.12 Uploading attack:

Evaluated signatures:

 |  Number  |                       Type|
 | -------- |---------------------------------------------------|
 |  5,514   |        Port scan: many closed port replies|
 |  1,904   | Web shell: PHP file requested from uploads folder|
 |  1,904   |     Web shell: curl requesting PHP in uploads|
 |   771    |   TCP SYN flood victim answering with many RSTs|
 |    18    |                  Recon: SYN scan|
 |    7     |    Recon: many RST/ACK replies (closed ports)|
 |    4     |                  DoS: SYN flood|

Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |   34,383|
|      FN     |    3,251|
|      FP     |      0|
|      TN     |      0|
|     Total   |   37,634|
|             | |
|    Recall   |  91.3615%|
|   Precision |  100.0000%|
|      FPR    |     N/A|
|      TNR    |     N/A|
|   Accuracy  |  91.3615%|
|      F1     |  95.4858%|


#### 7.1.13 Vulnerability Scanner:

Evaluated signatures:

|   Number   |                         Type|
|  --------- |-------------------------------------------------------|
|   111,106  |             Vulnerability scanner: Nikto|
|   104,994  |    Vulnerability scanner: excessive 404 responses|
|   72,599   |    Potential HTTP DDoS attack detected (GET burst)|
|   62,263   |    Potential HTTP DDoS attack detected (GET flood)|
|    5,671   |   Vulnerability scanner: random prefix enumeration|
|    4,326   |                   XSS: alert() call|
|    4,309   |   Vulnerability scanner: system file access attempt|
|    3,793   |   Vulnerability scanner: file extension enumeration|
|    3,738   |                XSS: script tag in URI|
|    3,724   |                    XSS: script tag|
|    2,063   |     Vulnerability scanner: Path traversal attempt|
|     930    |           Vulnerability scanner: Shellshock|
|     238    |                 XSS: javascript: URI|
|     210    |          Web shell: command parameter in URI|
|     57     | Vulnerability scanner: Path traversal attempt encoded|
|     56     |            SQLi: comment + keyword in URI|
|     56     |                     XSS: img tag|
|     28     |               SQLi: UNION SELECT in URI|
|     14     |              SQLi: stacked query in URI|
|     14     |            SQLi: information_schema in URI|
|     14     |                 XSS: JS event onload|
|      2     |                    Recon: SYN scan|
|      1     |                    DoS: SYN flood|

Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |   145,462|
|      FN     |     407|
|      FP     |      0|
|      TN     |      0|
|     Total   |   145,869|
|             | |
|    Recall   |  99.7210%|
|   Precision |  100.0000%|
|      FPR    |     N/A|
|      TNR    |     N/A|
|   Accuracy  |  99.7210%|
|      F1     |  99.8603%|


#### 7.1.14 XSS attack:

Metrics:

|     Type    |  Number|
|  -----------| ---------|
|      TP     |     0|
|      FN     |  15,915|
|      FP     |     0|
|      TN     |     0|
|     Total   |  15,915|
|             | |
|    Recall   |  0.0000%|
|   Precision |    N/A|
|      FPR    |    N/A|
|      TNR    |    N/A|
|   Accuracy  |  0.0000%|
|      F1     |  0.0000%|


### 7.2 Training (Benign)

#### 7.2.1 Distance:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|    159    | Recon: SYN scan|
|     1     | DoS: SYN flood|

Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |      0|
|      FN     |      0|
|      FP     |   11,457|
|      TN     |  1,132,083|
|     Total   |  1,143,540|
|             | |
|    Recall   |     N/A|
|   Precision |   0.0000%|
|      FPR    |   1.0019%|
|      TNR    |  98.9981%|
|   Accuracy  |  98.9981%|
|      F1     |   0.0000%|

#### 7.2.2 Flame Sensor:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|    142    | Recon: SYN scan|
|     5     | DoS: SYN flood|


Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |      0|
|      FN     |      0|
|      FP     |    9,601|
|      TN     |  1,060,595|
|     Total   |  1,070,196|
|              ||
|    Recall    |    N/A|
|   Precision  |  0.0000%|
|      FPR     |  0.8971%|
|      TNR     | 99.1029%|
|   Accuracy   | 99.1029%|
|      F1       | 0.0000%|


#### 7.2.3 Heart Rate:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|     1     | Recon: SYN scan|

Metrics:

|     Type    |   Number|
|  -----------| ----------|
|      TP     |     0|
|      FN     |     0|
|      FP     |     16|
|      TN     |  165,303|
|     Total   |  165,319|
|             | |
|    Recall   |    N/A|
|   Precision |  0.0000%|
|      FPR    |  0.0097%|
|      TNR    |  99.9903%|
|   Accuracy  |  99.9903%v
|      F1     |  0.0000%|


#### 7.2.4 IR Reciever:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|    180    | Recon: SYN scan|
|     2     | DoS: SYN flood|


Metrics:

|     Type     |  Number|
|  ----------- |-----------|
|      TP      |     0|
|      FN      |     0|
|      FP      |  14,615|
|      TN      | 1,293,163|
|     Total    | 1,307,778|
|             | |
|    Recall   |     N/A|
|   Precision |   0.0000%|
|      FPR    |   1.1175%|
|      TNR    |  98.8825%|
|   Accuracy  |  98.8825%|
|      F1     |   0.0000%|


#### 7.2.5 Modbus:

Evaluated signatures:


|   Number  |          Type|
|  -------- |------------------------|
|     2     | Possible MDNS Spoofing|

Metrics:

|     Type     |  Number|
|  ----------- |-----------|
|      TP      |     0|
|      FN      |     0|
|      FP      |     0|
|      TN      |  155,543|
|     Total    |  155,543|
|             | |
|    Recall   |     N/A|
|   Precision |     N/A|
|      FPR    |   0.0000%|
|      TNR    |  100.0000%|
|   Accuracy  |  100.0000%|
|      F1     |     N/A|

#### 7.2.6 ph Value:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|    173    | Recon: SYN scan|


Metrics:

|     Type     |  Number|
|  ----------- |----------|
|      TP      |    0|
|      FN      |    0|
|      FP      |  8,262|
|      TN      | 738,646|
|     Total    | 746,908|
|              ||
|    Recall    |   N/A|
|   Precision  | 0.0000%|
|      FPR     | 1.1062%|
|      TNR     | 98.8938%|
|   Accuracy   | 98.8938%|
|      F1      | 0.0000%|


#### 7.2.7 Soil Moisture:

Evaluated signatures:

|   Number  |      Type|
|  -------- |-----------------|
|    269    | Recon: SYN scan|


Metrics:


|     Type    |   Number|
|  -----------| -----------|
|      TP     |      0|
|      FN     |      0|
|      FP     |   19,942|
|      TN     |  1,172,835|
|     Total   |  1,192,777|
|             | |
|    Recall   |     N/A|
|   Precision |   0.0000%|
|      FPR    |   1.6719%|
|      TNR    |  98.3281%|
|   Accuracy  |  98.3281%|
|      F1     |   0.0000%|

#### 7.2.8 Sound Sensor:

Evaluated signatures:


|   Number |       Type|
|  --------| -----------------|
|    191   |  Recon: SYN scan|
|     20   |  DoS: SYN flood|


Metrics:


  |   Type     |  Number|
  |----------- |-----------|
  |    TP      |     0|
  |    FN      |     0|
  |    FP      |  19,567|
  |    TN      | 1,493,316|
  |   Total    | 1,512,883|
  |            ||
  |  Recall    |    N/A|
  | Precision  |  0.0000%|
  |    FPR     |  1.2934%|
  |    TNR     | 98.7066%|
  | Accuracy   | 98.7066%|
  |    F1      |  0.0000%|

#### 7.2.9 Temperature and Humidity:

Evaluated signatures:


|   Number  |                Type|
|  -------- |------------------------------------|
|    152    |       Possible MDNS Spoofing|
|     3     |  Port scan: UDP port unreachable|
|     1     | Recon: ICMP port unreachable burst|
|     1     |          Recon: SYN scan|

Metrics:


|     Type     |  Number|
|  ----------- |-----------|
|      TP      |     0|
|      FN      |     0|
|      FP      |   7,812|
|      TN      | 1,607,910|
|     Total    | 1,615,722|
|             | |
|    Recall   |     N/A|
|   Precision  |  0.0000%|
|      FPR     |  0.4835%|
|      TNR     | 99.5165%|
|   Accuracy   | 99.5165%|
|      F1      |  0.0000%|

#### 7.2.10 Water Levels:

Evaluated signatures:

|   Number |       Type|
|  --------| -----------------|
|    309   |  Recon: SYN scan|
|     16   |  DoS: SYN flood|


Metrics:

|     Type    |   Number|
|  -----------| -----------|
|      TP     |      0|
|      FN     |      0|
|      FP     |   46,203|
|      TN     |  2,249,085|
|     Total   |  2,249,085|
|             | |
|    Recall   |     N/A|
|   Precision |   0.0000%|
|      FPR    |   2.0130%|
|      TNR    |  97.9870%|
|   Accuracy  |  97.9870%|
|      F1     |   0.0000%|

### 7.3 Test

#### 7.3.1 Monday:

Evaluated signatures:

|   Number |                       Type|
|  --------| ------------------------------------------------|
|   8,775  |              Possible MDNS Spoofing|
|    557   |       Port scan: many closed port replies|
|    309   |                 Recon: SYN scan|
|    193   |  TCP SYN flood victim answering with many RSTs|
|     94   |         Port scan: UDP port unreachable|
|     47   |    Recon: many RST/ACK replies (closed ports)|
|     28   |  Vulnerability scanner: excessive 404 responses|
|     11   |        Recon: ICMP port unreachable burst|
|     4    |               XSS: JS event onload|
|     3    |            XSS: script tag (encoded)|
|     3    |                  DoS: UDP flood|
|     2    |            UDP flood (empty payload)|
|     1    |                Recon: ICMP sweep|
|     1    |          SQLi: OR/AND tautology in body|


Metrics:

|     Type    |   Number|
|  -----------| ----------|
|      TP     |     0|
|      FN     |     0|
|      FP     |    894|
|      TN     |  248,244|
|     Total   |  249,138|
|             | |
|    Recall   |    N/A|
|   Precision |  0.0000%|
|      FPR    |  0.3588%|
|      TNR    |  99.6412%|
|   Accuracy  |  99.6412%|
|      F1     |  0.0000%|


#### 7.3.2 Tuesday:

Evaluated signatures:

|   Number  |                       Type|
|  -------- |--------------------------------------------------|
|   7,046   |              Possible MDNS Spoofing|
|   2,208   |       Port scan: many closed port replies|
|    269    |                 Recon: SYN scan|
|     82    | Vulnerability scanner: random prefix enumeration|
|     79    |  TCP SYN flood victim answering with many RSTs|
|     78    |    Recon: many RST/ACK replies (closed ports)|
|     52    |         Port scan: UDP port unreachable|
|     14    |       Brute force: repeated 403 responses|
|     8     |               XSS: javascript: URI|
|     5     |        Recon: ICMP port unreachable burst|
|     1     |                  DoS: UDP flood|
|     1     |                  DoS: SYN flood|
|     1     |          SQLi: comment + keyword in URI|
|     1     |          SQLi: OR/AND tautology in body|


Metrics:

|     Type    |   Number|
|  -----------| ----------|
|      TP     |     0|
|      FN     |   6,934|
|      FP     |   1,840|
|      TN     |  202,923|
|     Total   |  211,697|
|             | |
|    Recall   |  0.0000%|
|   Precision |  0.0000%|
|      FPR    |  0.8986%|
|      TNR    |  99.1014%|
|   Accuracy  |  95.8554%|
|      F1     |  0.0000%|


#### 7.3.3 Wednesday:

Evaluated signatures:

|   Number  |                        Type|
|  ---------| --------------------------------------------------|
|   107,907 |        Port scan: many closed port replies|
|   80,575  |  Potential HTTP DDoS attack detected (GET flood)|
|   77,619  |            TCP SYN flood (burst flood)|
|   76,757  |   TCP SYN flood victim answering with many RSTs|
|   50,629  |           TCP SYN flood (extended flood)|
|   45,924  |  Potential HTTP DDoS attack detected (GET burst)|
|    5,356  |               Possible MDNS Spoofing|
|     416   |                  Recon: SYN scan|
|     89    |                   DoS: SYN flood|
|     86    |     Recon: many RST/ACK replies (closed ports)|
|     36    |          Port scan: UDP port unreachable|
|     30    |  Vulnerability scanner: random prefix enumeration|
|     19    |                XSS: JS event onload|
|      4    |         Recon: ICMP port unreachable burst|
|      3    |           SQLi: comment + keyword in URI|
|      2    |                XSS: javascript: URI|
|      2    |           SQLi: OR/AND tautology in body|
|      2    |             XSS: script tag (encoded)|
|      1    |                   DoS: UDP flood|
|      1    |          SQLi: comment + keyword in body|


Metrics:

|     Type    |   Number|
|  -----------| ----------|
|      TP     |   2,951|
|      FN     |     2|
|      FP     |   6,446|
|      TN     |  206,222|
|     Total   |  215,621|
|             | |
|    Recall   |  99.9323%|
|   Precision |  31.4036%|
|      FPR    |  3.0310%|
|      TNR    |  96.9690%|
|   Accuracy  |  97.0096%|
|      F1     |  47.7895%|


#### 7.3.4 Thursday:

Evaluated signatures:

|   Number  |                        Type|
|  ---------| --------------------------------------------------|
|   128,879 |          Port scan: Nmap SYN window 1024|
|   68,302  |        Port scan: many closed port replies|
|   58,338  |            TCP SYN flood (burst flood)|
|   55,655  |   TCP SYN flood victim answering with many RSTs|
|   16,694  |           TCP SYN flood (extended flood)|
|    4,188  |               Possible MDNS Spoofing|
|     891   |               XSS: script tag in URI|
|     888   |                  XSS: script tag|
|     346   |                  Recon: NULL scan|
|     308   |                  Recon: SYN scan|
|     284   |                  Recon: Xmas scan|
|     96    |            Vulnerability scanner: Nmap|
 |    94    |             Port scan: SYN window 512|
 |    80    |     Recon: many RST/ACK replies (closed ports)|
 |    73    |              UDP flood (burst flood)|
 |    70    |                   DoS: SYN flood|
 |    61    |  Vulnerability scanner: random prefix enumeration|
 |    32    |          Port scan: UDP port unreachable|
 |    10    |                XSS: javascript: URI|
 |     8    |                 Recon: ICMP sweep|
 |     3    |         Recon: ICMP port unreachable burst|
 |     3    |          SQLi: information_schema in URI|
 |     3    |         SQLi: information_schema in header|
 |     2    |                   DoS: UDP flood|
 |     1    |             XSS: script tag (encoded)|
 |     1    |           SQLi: comment + keyword in URI|

Metrics:

|     Type    |   Number|
|  -----------| ----------|
|      TP     |   63,742|
|      FN     |   2,975|
|      FP     |   3,297|
|      TN     |  188,597|
|     Total   |  258,611|
|             | |
|    Recall   |  95.5409%|
|   Precision |  95.0820%|
|      FPR    |  1.7181%|
|      TNR    |  98.2819%|
|   Accuracy  |  97.5747%|
|      F1     |  95.3109%|


#### 7.3.5 Friday:

Evaluated signatures:

|   Number  |                        Type|
|  ---------| --------------------------------------------------|
|   255,532 |        Port scan: many closed port replies|
|   212,101 |   TCP SYN flood victim answering with many RSTs|
|   98,558  |           TCP SYN flood (extended flood)|
|   78,932  |          Port scan: Nmap SYN window 1024|
|   75,074  |            TCP SYN flood (burst flood)|
|    5,871  |               Possible MDNS Spoofing|
|     391   |                  Recon: SYN scan|
|     225   |                   DoS: SYN flood|
|     120   |             UDP flood (empty payload)|
|     115   |         Port scan: UDP port unreachable|
|     114   |     Recon: many RST/ACK replies (closed ports)|
|     69    |  Potential HTTP DDoS attack detected (GET flood)|
|     61    |  Vulnerability scanner: random prefix enumeration|
|      7    |          SQLi: comment + keyword in body|
|      6    |         Recon: ICMP port unreachable burst|
|      4    |                XSS: javascript: URI|
|     3     |                  DoS: UDP flood|
 |     3    |           SQLi: OR/AND tautology in body|

Metrics:

|     Type     |  Number|
|  ----------- |----------|
|      TP      | 202,905|
|      FN      |  2,520|
|      FP      |  2,683|
|      TN      | 188,097|
|     Total    | 396,205|
|             | |
|    Recall   |  98.7733%|
|   Precision |  98.6950%|
|      FPR    |  1.4063%|
|      TNR    |  98.5937%|
|   Accuracy  |  98.6868%|
|      F1     |  98.7341%|

### 7.4 Analysis

The results from the testing data show greatly varied effectiveness from
day to day. This is likely to be because the attacks represented in that
data varied from day to day, and so the signatures used were effective
against the attacks that they were designed to detect, but less so when
faced with attacks that they were not.

The results from the malicious training data show that none of the rules
were perfectly accurate when detecting the attacks they were designed to
find, which is to be expected. Not every part of a malicious attack can
be detected, as some parts of them will be identical to legitimate
traffic. The purpose of an IDS is to alert the network to the fact that
it is under attack, so that more active security measures may be
deployed.

The results from the benign training data show that some rules cause
false positives, even on data they are trained on. This might be because
some rules need to be calibrated, or because some attacks are
indistinguishable from legitimate traffic. In all cases, these false
positives are comparatively few in number, with the accuracy of the
detection rules reaching over 95% in all cases.


## 8. Discussion
### 8.1 Effectiveness of Simple Signatures
From the data we can see that the effectiveness of the rules vary from
attack to attack. As an example, the rules detected a TCP DDoS attack
over 99% of the time, while SQL injection attacks were detected only
about a third of the time. We also see that the simplicity of the rules
allows for some overlap in detection of suspicious activity, as seen in
the example of the vulnerability scanner, which also set off rules for
XSS attacks and SQL injections. On the other hand, the simpler rules
also risk false positives, as they have a higher risk of mistaking
normal traffic for an attack scenario.
### 8.2 Detection vs. False Positives
An important part of the discussion of security is the tradeoff between
detection and false positives. A set of rules which is broad enough to
catch all types of attack is inevitably going to generate false
positives, as some attacks are practically indistinguishable from
legitimate traffic. The decision to be made is, in essence, "What
degree of false positives is acceptable in order to detect attacks?",
or alternatively, "What degree of undetected attacks is acceptable in
order to eliminate false positives?"

The role of the security engineer in this question is to tighten the
margins to the most extreme degree. It is the engineer who analyses the
data in order to determine where the cutoff lies for what amount of
traffic is legitimate business as usual and what amount is a DDoS attack
attempting to disable critical systems. It is the engineer who decides
which SQL queries are legitimate requests for information and which are
attempts to inject malicious code into the database. It is the engineer
who decides which requests to connect to a port are legitimate
connections and which are attempts to discover the OS the system runs
on. It is therefore vital for a security engineer to know what the
system they are working on is expected to do, and to know what to do
when it is doing something it should not.
### 8.3 Limitations
Suricata is not a perfect program. It has a number of constraints which
limit its usefulness in several places. One of these constraints is that
it only operates on protocols and services which act in layer 3 or
above. As such, it cannot act upon attacks which target processes in
layers 1 or 2, leaving a vulnerability which must be covered by other
systems.

Another limitation of the program is the simplicity of its memory.
Suricata does not remember any of the packets it has analyzed in the
past, and rules which rely on flow rate or capacity simply count how
many times that rule has been triggered during the relevant time period
to determine if an alert should be made. This means that Suricata cannot
detect suspicious rebroadcasts of requests, which might be indicative of
an attack.

Finally, Suricata is also heavily dependent on knowledge of the
legitimate goings-on of the system in order to identify legitimate
traffic. This means that it is impractical to import rules wholesale
from one network to another, instead requiring thresholds for matters
like number of request per minute, or what ports indicate legitimate or
illicit activity, to be recalibrated from system to system.

## 9. Conclusion
The aim of this project was to see how well custom signature-based rules in Suricata can distinguish malicious traffic from normal traffic. The results show that the effectiveness varies from attack to attack. The TCP SYN flood was detected in over 99% of the cases, while SQL injection was only detected in about a third of the cases. The false alarms on the normal traffic were few, but shows that some rules may need further calibration. The results from CIC-IDS-2017 varied from day to day. The rules worked well on the days with the attacks they were written for, but missed the attacks that were not part of the scope. Finally, the rules and their thresholds depend on the normal traffic and load in the network in which they were created. The rules cannot be moved to another network without first being adjusted.

## 10. Individual contributions

### Fabrizio Sclosa
I worked mainly on the project datasets, the implementation and experimentation of the evaluation scripts, and parts of the Suricata detection rules, which together make up the experimental side of the project. In addition, I worked on setting up the environment and documenting the repository structure and usage.

At first, I searched for and selected possible datasets to work with (both for developing the rules and for testing them). I opted for Edge-IIoTset as the training set because of its broad range of attack patterns and benign traffic, and CIC-IDS-2017 as the test set (using the improved CSV flows along with the original PCAPs). During the selection process, I extensively tested [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) as well, but at the end excluded it, since it was out of scope.

Secondly, I built the evaluation scripts, `evaluate_training.py` and `evaluate_test.py`. They serve the same purpose but compare `eve.json` against the ground truth CSVs in different ways: the former matches by the pair timestamp + pcap_cnt, the latter by packet flow using the 5-tuple (IPs, ports and protocol). This difference is due to the fact that the two ground-truth CSVs have different structures and labelling criteria. Both scripts report the confusion matrix of the Suricata analysis, which includes true positives, false negatives, false positives, true negatives, recall, precision, false positive rate, true negative rate, accuracy and F1. These scripts made it possible to find a proper matching mechanism between the Suricata alerts and the ground truth, and also allowed a quick performance overview of the tested rules.

Along with this experimental part of the project, I adapted and fixed the `run.sh` script to allow centralized control of the Python scripts, Suricata and the datasets, which made the repository easier to use. Finally, I prepared and configured the setup, the usage documentation and the repository layout described in the `README.md`.

Contribution in the report: 1, 2, 3.

### Carl Sahlin
I worked on determining what software we should use for the intrusion detection, parts of the Suricata detection rules, and analysis and reflection of the results of the project.

Initially, I looked through the documentation for Suricata and Zeek, determining that Suricata was more suitable for the project as we had envisioned it. My primary motivation for this was that Suricata had better and more available documentation, which indicated that it would be easier to create and customize our own rules for network detection.

Additionally, I created rules for detecting HTTP DDoS attacks, OS Fingerprinting, and MITM attacks. In this process I found that Suricata was not particularly well suited for detecting the DNS and ARP spoofing found in the MITM attacks, but decided that this was an interesting display of an area where Suricata is lacking, which would be a good point of discussion.

Finally, I analyzed the results of the testing scripts, and drew conclusions from those results. I also formatted the results into tables for ease of understanding. I then discussed parts of the project which I thought would be interesting in the project report. This included the aforementioned limitations of Suricata, but also the tensions between detecting malicious traffic and allowing for false positives, and how effective the rules had actually been for detecting attacks.

Contribution in the report 4.3.8.1, 4.3.10, 4.3.11, 7, 8.

### Fabian Älvebratt
I worked on finding datasets for the project, the Suricata rules for the flooding attacks and their thresholds, and a large part of the written report.

At the start of the project, I went through the candidate datasets and suggested CIC-IDS-2017, since it had raw pcap files, several of the attacks in our scope, and labelled traffic that we could compare our alerts against to count false alarms and missed attacks. I then wrote the rules for the ICMP, UDP and TCP SYN floods. The first version had one rule per attack, which I later extended into several rules to account for different variations of the attacks. To choose the thresholds, I empirically tested different values against both the attack traffic and the normal traffic in Edge-IIoTset, to find a balance for traffic load since it differs a lot from network to network. While doing this, I found that the ground truth CSV file for the UDP flood contained errors, so I regenerated it from the original pcap file and structured it accordingly for the project.

Later, when we needed an external dataset to test our rules on, I looked for further candidates with benign traffic that could be used to measure false alarms. We ended up going back to CIC-IDS-2017, as it was in line with our scope. Because of the problems I had found in Edge-IIoTset, I checked whether CIC-IDS-2017 had any similar labelling issues. It turned out that it had a number of errors, but I found that a corrected version of the labels existed, and this is the version we used to test our rules.

Contribution in the report: 4.2, 4.3.1, 4.3.2, 4.3.3, 4.3.4, 4.3.8.2, 4.3.8.3, 4.3.8.4, 5.1, 5.2, 5.3, 9.

### Youssef Abdelrahman
I worked on finding the training dataset and writing the Suricata rules for XSS, port scanning and the uploading attack. I also wrote parts of the report.

At the start of the project, I found Edge-IIoTset, which we used as the training set. I went through it to see which attacks it had and how its pcap and CSV files looked.

I wrote the rules for XSS, port scanning and the uploading attack. The XSS rules look for HTML tags and JavaScript code in the URL and the request body. The port scanning rules look for many replies from closed ports, packets with odd TCP flags and SYN packets with unusual window sizes. The uploading rules look for PHP files being uploaded to the server and then requested from the uploads folder, which is how a web shell is used.

Contribution in the report: 4.1, 4.3.5, 4.3.6, 4.3.7, 4.5, 6.

## References
[1] https://www.ibm.com/think/topics/intrusion-detection-system
[2] https://onlinelibrary.wiley.com/doi/10.1155/2022/9663052
[3] https://suricata.io/
[4] https://github.com/EANimesha/Network-Intrusion-Detection-Datasets
[5] https://ieeexplore.ieee.org/document/9751703
[6] https://www.unb.ca/cic/datasets/ids-2017.html
[7] https://intrusion-detection.distrinet-research.be/CNS2022/index.html
[8] https://community.owasp.org/attacks/SQL_Injection
[9] https://attack.mitre.org/techniques/T1110/001/
[10] https://www.ibm.com/think/topics/vulnerability-scanning
[11] https://owasp.github.io/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning
[12] https://community.owasp.org/vulnerabilities/Unrestricted_File_Upload
[13] https://attack.mitre.org/techniques/T1505/003/
[14] https://www.cloudflare.com/learning/ddos/ping-icmp-flood-ddos-attack/
[15] https://www.cloudflare.com/learning/ddos/udp-flood-ddos-attack/
[16] https://www.rfc-editor.org/info/rfc4987/
[17] https://community.owasp.org/attacks/Path_Traversal
[18] https://community.owasp.org/attacks/xss
[19] https://attack.mitre.org/techniques/T1046/
[20] https://nmap.org/book/man-port-scanning-techniques.html

# Detecting-Web-Attacks-Using-Machine-Learning
Our Web Attack Detection System addresses these gaps by leveraging an unsupervised machine learning model—an autoencoder neural network—to learn the statistical characteristics of normal HTTP/TCP traffic 
and flag deviations indicative of attacks. The model is trained solely on benign flows from the CICIDS2017 


# ABSTRACT 

The increasing reliance on web applications in every domain—from ecommerce to finance—has made them prime targets for cyber adversaries. Common attack vectors such as Distributed Denial of Service (DDoS), SQL Injection (SQLi), and CrossSite Scripting (XSS) exploit application-layer vulnerabilities to disrupt services, exfiltrate data, or compromise user trust. Traditional security appliances (firewalls, signaturebased Intrusion Detection Systems) and rulebased scanners struggle to keep pace with the constantly evolving threat landscape, often producing high false positive rates or failing to detect novel, “zeroday” exploits. 

Our Web Attack Detection System addresses these gaps by leveraging an unsupervised machine learning model—an autoencoder neural network—to learn the statistical characteristics of normal HTTP/TCP traffic and flag deviations indicative of attacks. The model is trained solely on benign flows from the CICIDS2017 “FridayWorkingHoursAfternoonDDoS” dataset. During inference, each incoming flow is passed through the network; the reconstruction error (mean squared error between input and output) serves as the anomaly score. A dynamic threshold (computed as μ + 3σ of validationset errors) automatically adapts to traffic variability, ensuring robust separation of benign versus malicious flows. 

Complementing the detection engine is a Streamlitbased dashboard offering: 

Live Monitoring & Alerts: Start/Stop controls to capture packets in real time, with immediate warning banners when an attack is flagged. 

Historical Log Visualization: Bar charts of attacktype frequencies and line plots of reconstructionerror distributions. 

URL Safety Checker: Regexbased scanner for SQLi, XSS, suspicious fileextension, and credentialembedded URLs. 

Connectivity Guard: Prevents operation when offline to avoid false alerts. 

All packets and anomaly flags are logged to CSV for auditability. Visual reports and URLscan results help security teams quickly triage threats. In tests, the autoencoder achieved a recall of 94%, precision of 91%, and F1score of 92% on heldout attack flows, outperforming baseline rulebased IDS in both detection rate and false positive reduction. 

This framework is modular and extensible: future modules could include encryptedtraffic inspection, dynamic mitigation (e.g., autoblock rules), and integration with SIEM platforms.

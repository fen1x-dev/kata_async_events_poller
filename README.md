# KATA_API_POLLER
## INSTALLATION
A Linux service that accesses KATA via the [API](https://support.kaspersky.com/help/KATA/7.0/ru-RU/248951.htm) and receives events, after which it sends the received events to 514/UDP port syslog-ng

1) Create a folder on the path **/opt/kata** and put all the files from the repository there:
```
mkdir /opt/kata
```

2) _Edit_ the **KATA_PARAMS.YAML** file by substituting the necessary KATA node IP addresses (DNS can be written instead of an IP address) and generate unique [UUIDs](https://www.uuidgenerator.net/version1)
for them, respectively. The service can collect events from multiple KATA nodes. Also add the IP address of the device (broker) that will receive events on syslog-ng.
The structure required for the operation of the service is presented below:
```
kata_installations:
  - kata_ip_address: 192.168.1.1
    UUID: b67a6284-057d-11f0-9cd2-0242ac120002
broker_ip: 192.168.1.4
```
_Optional_: if there is a need to use _trusted certificates_, then they must be located along the path /opt/kata/cert. The certificate and key must _**strictly**_ have the names **kata_cert.pem** and **kata_key.key**, respectively. You also need to add the ca_file_path parameter to the KATA_PARAMS.YAML configuration file. with the **absolute path** to the root CA file. The structure required for the operation of the service is presented below:
```
kata_installations:
  - kata_ip_address: 192.168.1.1
    UUID: b67a6284-057d-11f0-9cd2-0242ac120002
broker_ip: 192.168.1.4
ca_file_path: "/path/to/your/ca_file.ca"
```

4) It is necessary to _install_ dependencies **requirements.txt**
```
pip install -r requirements.txt
```

5) _Run_ the script from under **sudo** rights
```
sudo python3 /opt/kata/kata_api_poller.py  # The file name can be any
```

## DEBUG

You can view the service logs on the path **/opt/kata/log**

## Uninstall

_Run_ **kata_api_poller_uninstaller.py** using **sudo** and **not** from the /opt/kata working directory, as this requires access to **systemctl** and deletion of system files.
```
sudo python3 /path/to/dir/kata_api_poller_uninstaller.py
```


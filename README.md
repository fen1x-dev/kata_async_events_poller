# KATA_API_POLLER
## SYSTEM REQUIREMENTS
System requirements for a Host (VM) with an event collection service
| CPU (Cores) | RAM  | DISK SIZE |
| :-:         | :--: | :-------: |
|  4          | 4 Gb |   50 Gb   |
## INSTALLATION
A Linux service that accesses KATA via the [API](https://support.kaspersky.com/help/KATA/7.0/ru-RU/248951.htm) and receives events, after which it sends the received events to 514/UDP port syslog-ng

It is possible to select a version specifically for MP SIEM. To do this, select the MPSIEM branch

1) Create a folder on the path **/opt/kata** and put all the files from the repository there:
```shell
mkdir /opt/kata
```

2) _Edit_ the **KATA_PARAMS.YAML** file by substituting the necessary KATA node IP addresses (DNS can be written instead of an IP address) and generate unique [UUIDs](https://www.uuidgenerator.net/version1)
for them, respectively. The service can collect events from multiple KATA nodes. Also add the IP address of the device (broker) that will receive events on syslog-ng.
The structure required for the operation of the service is presented below:
```yaml
kata_installations:
  - kata_ip_address: 192.168.1.1
    UUID: b67a6284-057d-11f0-9cd2-0242ac120002
broker_ip: 192.168.1.4
```
_Optional_: if there is a need to use _trusted certificates_, then they must be located along the path /opt/kata/cert. The certificate and key must _**strictly**_ have the names **kata_cert.pem** and **kata_key.key**, respectively. You also need to add the ca_file_path parameter to the KATA_PARAMS.YAML configuration file. with the **absolute path** to the root CA file. The structure required for the operation of the service is presented below:
```yaml
kata_installations:
  - kata_ip_address: 192.168.1.1
    UUID: b67a6284-057d-11f0-9cd2-0242ac120002
broker_ip: 192.168.1.4
ca_file_path: "/path/to/your/ca_file.ca"
```

3) It is necessary to _install_ dependencies **requirements.txt**
```shell
pip install -r requirements.txt
```

4) _Run_ the script from under **sudo** rights
```shell
sudo python3 /opt/kata/kata_api_poller.py  # The file name can be any
```

## UPDATING
When updating the service version, you must perform the following steps:
1) Stop the service:
```shell
sudo systemctl stop kata_api.service
```

2) Migration of a new script:
```shell
sudo cp /path/to/new/kata_api_poller.py /opt/kata/kata_api_poller.py
sudo chmod +x /opt/kata/kata_api_poller.py
```

3) Reboot the systemd configuration:
```shell
sudo systemctl daemon-reload
```

4) Starting the service:
```shell
sudo systemctl start kata_api.service
```

5) Checking the service:
```shell
sudo systemctl status kata_api.service
```

## DEBUG
For the DEBUG log level required in KATA_PARAMS.YAML add parameter
```yaml
logging_level: DEBUG
```
You can view the service logs on the path **/opt/kata/log**

## Uninstall

_Run_ **kata_api_poller_uninstaller.py** using **sudo** and **not** from the /opt/kata working directory, as this requires access to **systemctl** and deletion of system files.
```shell
sudo python3 /path/to/dir/kata_api_poller_uninstaller.py
```


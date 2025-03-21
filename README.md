# KATA_API_POLLER
A Linux service that accesses KATA via the API and [receives events](https://support.kaspersky.com/help/KATA/5.1/ru-RU/248951.htm), after which it sends the received events to 514/UDP port syslog-ng

1) Create a folder on the path /opt/kata and put all the files from the repository there
```
mkdir /opt/kata
```

2) Edit the KATA_PARAMS.YAML file by substituting the necessary KATA node IP addresses and generate unique [UUIDs](https://www.uuidgenerator.net/version1)
for them, respectively. The service can collect events from multiple KATA nodes. Also add the IP address of the device (broker) that will receive events on syslog-ng.
The structure required for the operation of the service is presented below:
```
kata_installations:
  - kata_ip_address: 192.168.1.1
    UUID: b67a6284-057d-11f0-9cd2-0242ac120002
broker_ip: 192.168.1.4
```

4) It is necessary to install dependencies requirements.txt
```
pip install -r requirements.txt
```

5) Run the script from under sudo rights
```
sudo python3 /opt/kata/kata_api_poller_new.py
```

# DEBUG

You can view the service logs on the path /opt/kata/log

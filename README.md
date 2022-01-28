# DevOps, Configuration Management with Ansible, Infrastructure as code.

The goal of this assignment is to set up a complete local network (domain name `infra.lan`) with some typical services: a web application server (e.g. to host an intranet site), DHCP and DNS. A router will connect the LAN to the Internet. The table below lists the hosts in this network:

| Host name         | Alias | IP             | Function         |
| :---------------- | :---- | :------------- | :--------------- |
| (physical system) |       | 172.16.0.1     | Your physical pc |
| r001              | gw    | 172.16.255.254 | Router           |
| srv001            | ns    | 172.16.128.2   | DNS              |
| srv003            | dhcp  | 172.16.128.3   | DHCP server      |
| srv010            | www   | 172.16.128.10  | Webserver        |
| ws0001            |       | (DHCP)         | workstation      |

## Learning goals

- Automate the setup of network services with a configuration management system
- Install and configure reproducible virtual environments (Infrastructure as Code) with suitable tools for the automation of the entire lifecycle of a VM


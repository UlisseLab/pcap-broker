# pcap-broker

`pcap-broker` is a tool to capture network traffic and make this available to one or more clients via PCAP-over-IP.

PCAP-over-IP can be useful in situations where low latency is a priority, for example during Attack and Defend CTFs.
More information on PCAP-over-IP can be found here:

 * https://www.netresec.com/?page=Blog&month=2022-08&post=What-is-PCAP-over-IP

`pcap-broker` supports the following features:

* Distributing packet data to one or more PCAP-over-IP listeners
* Read from stdin pcap data (for example from a `tcpdump` command)
* `pcap-broker` will exit if the capture command exits

## Building

To build `pcap-broker`:

```shell
$ go build ./cmd/pcap-broker
$ ./pcap-broker --help
```

Or you can build the Docker container:

```shell
$ docker build -t pcap-broker .
$ docker run -it pcap-broker --help
```

## Running

```shell
$ ./pcap-broker --help
Usage of ./pcap-broker:
  -debug
        enable debug logging
  -json
        enable json logging
  -listen string
        listen address for pcap-over-ip (eg: localhost:4242)
  -n    disable reverse lookup of connecting PCAP-over-IP client IP address
```

Arguments can be passed via commandline:

```shell
$ sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w - | ./pcap-broker -listen :4242
```

Or alternatively via environment variables:

```bash
#!/bin/bash
export LISTEN_ADDRESS=:4242

sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w - | ./pcap-broker
```

Now you can connect to it via TCP and stream PCAP data using `nc` and `tcpdump`:

```shell
$ nc -v localhost 4242 | tcpdump -nr -
```

Or use a tool that natively supports PCAP-over-IP, for example `tshark`:

```shell
$ tshark -i TCP@localhost:4242
```

# Acquiring PCAP data over SSH

One use case is to acquire PCAP from a remote machine over SSH and make this available via PCAP-over-IP.

```shell
$ ssh user@remotehost "sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -" | ./pcap-broker -listen :4242
```

> [!TIP]
> To filter out SSH traffic, you can use `tcpdump`'s `not port 22` filter:
> ```shell
> $ ssh user@remotehost "sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w - not port 22" | ./pcap-broker -listen :4242
> ```


## Background

This tool was initially written for Attack & Defend CTF purposes but can be useful in other situations where low latency is preferred, or whenever a no-nonsense PCAP-over-IP server is needed. During the CTF that Fox-IT participated in, `pcap-broker` allowed the Blue Team to capture network data once and disseminate this to other tools that natively support PCAP-over-IP, such as:

* [Arkime](https://arkime.com/)
* [Tulip](https://github.com/OpenAttackDefenseTools/tulip) (after we did some custom patches)
* WireShark's dumpcap and tshark

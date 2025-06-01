# SROS IPsec Debug Output Matcher (SRIDM)
sridm is a utility to filter through [Nokia SROS](https://documentation.nokia.com/sr/) IPsec debug output with specified IDi regular expression pattern so that only debug msg of matched tunnel is displayed.

**Limitation: debug on SR router rely on logging infrastructure, which means there is no guarantee that all debug events will be delivered at all time, specicially when the debug log is throttled. so it is recommand to narrow down the tunnels to debug as much as possible (e.g. use a small prefix as `tunnel-subnet` in `debug ipsec` config)**

## Input
sridm supports two types of input:
1. A file contains the debug output
2. Netconf event steam from SROS router

## SROS Provision 
1. file input: for best result, configure the debug log destination as file, an example config is following:
    ```
    (gl)[/configure log log-id "10"]
    A:admin@vsim17# info
        netconf-stream "log10"
        source {
            debug true
        }
        destination {
            file "debugfile"
        }
    (gl)[/configure log file "debugfile"]
    A:admin@vsim17# info
        compact-flash-location {
            primary cf3
        }

    ```
    above config will save debug output to a file under `cf3:\log`
2. netconf input: 
    1. enable netconf, make sure the router could be access by sridm via netconf
    2. configure debug log destination as netconf, with `netconf-stream` name, following is an example

    ```
    (gl)[/configure log log-id "10"]
    A:admin@vsim17# info
        netconf-stream "log10"
        source {
            debug true
        }
        destination {
            netconf {
                max-entries 3000
            }
        }

    ```
3. debug configuration: set both `detail` to true (and also `suppress-dpd-debug` to true if dpd output is not important), like:
    ```
    [ex:/debug]
    A:admin@vsim17# info
        ipsec {
            gateway "rw300" {
                tunnel-subnet 2001:beef::0100/120 port any {
                    detail true
                    suppress-dpd-debug true
                }
            }
        }

    ```

## usage 
sridm has two types of output:
1. a mapping between matched IDi and remote tunnel endpoints, following is an example using file input (`log1001-20250530-033456-UTC` is the filename):
```
./sridm -d client-100 file log1001-20250530-033456-UTC
Found following matched tunnel EPs:
1 matched out of total 935
IDi 'client-100.nokia.com' ==>  [2001:beef::101]:500
```
2. the debug msgs of tunnels with matched IDi:
```
./sridm -d client-100 file log1001-20250530-033456-UTC -m
Found following matched tunnel EPs:
1 matched out of total 935
IDi 'client-100.nokia.com' ==>  [2001:beef::101]:500

132808 2025-05-30 03:35:05.187 +0000 UTC
"IPsec: 2001:dead::100[500]-2001:bee*
Responding to new IKE_SA_INIT exchange negotiation: tep={2001:dead::100[500],2001:beef::101[500],100}"

-------
132809 2025-05-30 03:35:05.187 +0000 UTC
"IPsec: 2001:dead::100[500]-2001:bee*
>>>> Received IKE message on tunnel "2001:dead::100[500]-2001:beef::101[500]-100" >>>>
Source: 2001:beef::101[500]
Destination: 2001:dead::100[500]
Initiator cookie: 0x6839277287F7E47F
Responder cookie: 0x0000000000000000
Next payload: IKEv2 Security Association (33)
Version: 2.0
Exchange type: IKE_SA_INIT (34)
Flags: 0x08
    .... 1... = Initiator
    ...0 .... =
    ..0. .... = Request
Message ID: 0x00000000 (0)
Length: 450
IKEv2 Security Association payload
    Next payload: IKEv2 Key Exchange (34)
    Payload length: 72
    Proposal #1
        Length: 36
        Protocol ID: ISAKMP (1)
        SPI Size: 0
        Number Transforms: 3
        Transform #1
            Length: 12
            Encryption Alg (1): AESGCM16 (20)
            Attrib #1 - Key Len: 128
        Transform #2
            Length: 8
            Pseudorandom Fn (2): SHA2_256 (5)
        Transform #3
            Length: 8
            DH Group (4): MODP2048 (14)
...
```
3. using netconf input
    1. start sridm `sridm -p <idipattern> netconf <Router> <Stream> [flags]`, where `<Router>` is target SR router's netconf address & port with format `addr:port`, and `stream` is the configured `netconf-stream` name   like:
        ```
        ./sridm -d client-100 netconf 192.168.1.100:830 log10
        Press Enter to stop...
        Rcvd: 94
        ```
    2. once enough debug output are received, press `enter` key
        ```
        ./sridm -d client-100 netconf 192.168.1.100:830 log10
        Press Enter to stop...
        Rcvd: 94
        Found following matched tunnel EPs:
        1 matched out of total 935
        IDi 'client-100.nokia.com' ==>  [2001:beef::101]:500

        ```

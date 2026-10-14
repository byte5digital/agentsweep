rule as_0502_bare_dev_tcp {
  meta:
    id          = 502
    title       = "A bash network device opened to a host that is not this machine"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Hook,Plugin,McpServer"
    status      = "stable"
    plain       = "This file opens a raw network connection to another machine using a shell trick that leaves no trace."
    phrase      = "opens a hidden network connection"
    description = "A /dev/tcp or /dev/udp path naming a host and a port. The shell opens the socket itself, so no network tool appears in the process list and nothing has to be installed. Waiting for a local port to come up is the honest use, so a loopback address never counts and a file that only ever names one stays silent. The full reverse-shell shape, with the interactive shell redirected into the socket, is rule 0002's."
    references  = "https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $device   = /\/dev\/(tcp|udp)\/[A-Za-z0-9._${}-]{1,80}\/[0-9${]/
    $loopback = /\/dev\/(tcp|udp)\/(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\//

  condition:
    #device > #loopback
}

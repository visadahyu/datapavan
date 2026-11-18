# Keeps, of Watch's flows (protocol app destination uid outcome named-by ech dns network dns-name name), only
# what belongs to the lab: flows to the lab's server and the emulator's own addresses (10.0.2.0/24), loopback,
# and the tunnel's addresses, with names only under .gaps.example or another name reserved for testing (RFC
# 2606). The DNS name beside a connection's own (since W5's first part) and the name are each kept only so,
# else "-". Any other flow becomes "<protocol> - other:<port> <uid> - - - - - - -", which keeps its count, its
# port and its UID and nothing that could tell where the run's computer is, such as the addresses and names of
# the servers that the image's own components reached through the computer's network (lab/run.sh).
#
#   awk -f lab/redact-flows.awk FLOWS > REDACTED

function host_of(address) {
    if (substr(address, 1, 1) == "[") return substr(address, 1, index(address, "]"))
    sub(/:[0-9]+$/, "", address)
    return address
}

function port_of(address) {
    if (match(address, /:[0-9]+$/)) return substr(address, RSTART + 1)
    return "-"
}

function ours(host) {
    return host ~ /^10\.0\.2\.[0-9]+$/ || host ~ /^10\.1\.10\.[0-9]+$/ || host ~ /^10\.215\.173\.[0-9]+$/ ||
        host ~ /^127\.[0-9]+\.[0-9]+\.[0-9]+$/ || host == "[::1]" || host ~ /^\[fd00:1:fd00:1:fd00:1:fd00:[0-9a-f]+\]$/
}

function reserved(name) {
    return name == "-" || (name !~ / / && (name ~ /(^|\.)(example|test|invalid|localhost)$/ || name ~ /(^|\.)example\.(com|net|org)$/))
}

NF >= 4 {
    if (!ours(host_of($3))) {
        print $1, "-", "other:" port_of($3), $4, "-", "-", "-", "-", "-", "-", "-"
        next
    }
    app = ours(host_of($2)) ? $2 : "-"
    dns_name = (NF >= 10 && reserved($10)) ? $10 : "-"
    name = $11
    for (i = 12; i <= NF; i++) name = name " " $i
    if (NF < 11 || !reserved(name)) name = "-"
    print $1, app, $3, $4, $5, $6, $7, $8, $9, dns_name, name
}

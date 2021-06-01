#!/usr/bin/env bats

setup() {
    # Create test namespaces
    sudo ip netns add NorthNS
    sudo ip netns add SouthNS
    # Connect the namespaces using a veth pair
    sudo ip link add name vethSouth type veth peer name vethNorth
    sudo ip link set netns NorthNS dev vethNorth
    sudo ip link set netns SouthNS dev vethSouth

    # Configure the namespaces network so they can reach each other
    sudo ip netns exec NorthNS ip link set up dev lo
    sudo ip netns exec NorthNS ip link set up dev vethNorth
    sudo ip netns exec NorthNS ip addr add 1.1.1.1/24 dev vethNorth
    
    sudo ip netns exec SouthNS ip link set up dev lo
    sudo ip netns exec SouthNS ip link set up dev vethSouth
    sudo ip netns exec SouthNS ip addr add 1.1.1.2/24 dev vethSouth

    # Check connectivity works
    sudo ip netns exec SouthNS ping -c 2 1.1.1.1

    # Create file with random data
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1 > /tmp/test_short.log
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8128 | head -n 1 > /tmp/test_long.log
}

teardown() {
    # Delete namespaces
    sudo ip netns del NorthNS
    sudo ip netns del SouthNS
}

@test "TCP connect without iptables" {
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_short.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_short.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

@test "TCP connect without iptables long file" {
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_long.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_long.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

@test "TCP connect with iptables in output" {
    # add iptables rule to block traffic
    sudo ip netns exec NorthNS bash -c "iptables -A OUTPUT -d 1.1.1.2 -j DROP"
    # verify it actually drops traffic
    run sudo ip netns exec NorthNS ping -c 1 1.1.1.2
    [ "$status" -eq 1 ]
    # verify netkat can send traffic anyway
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_short.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_short.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

@test "TCP connect with iptables in output long file" {
    # add iptables rule to block traffic
    sudo ip netns exec NorthNS bash -c "iptables -A OUTPUT -d 1.1.1.2 -j DROP"
    # verify it actually drops traffic
    run sudo ip netns exec NorthNS ping -c 1 1.1.1.2
    [ "$status" -eq 1 ]
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_long.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_long.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

@test "TCP connect with iptables in input" {
    # add iptables rule to block traffic
    sudo ip netns exec NorthNS bash -c "iptables -A INPUT -s 1.1.1.2 -j DROP"
    # verify it actually drops traffic
    run sudo ip netns exec NorthNS ping -c 1 1.1.1.2
    [ "$status" -eq 1 ]
    # verify netkat can send traffic anyway
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_short.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_short.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

@test "TCP connect with iptables in input long file" {
    # add iptables rule to block traffic
    sudo ip netns exec NorthNS bash -c "iptables -A INPUT -s 1.1.1.2 -j DROP"
    # verify it actually drops traffic
    run sudo ip netns exec NorthNS ping -c 1 1.1.1.2
    [ "$status" -eq 1 ]
    sudo ip netns exec SouthNS bash -c "nc -l 9090 > /tmp/test_output.log 3>&- &"
    sudo ip netns exec NorthNS bash -c "cat /tmp/test_long.log | ../bin/netkat 1.1.1.2 9090"
    run diff /tmp/test_long.log /tmp/test_output.log
    [ "$status" -eq 0 ]
}

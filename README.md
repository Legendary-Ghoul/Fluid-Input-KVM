# Fluid Input KVM

A lightweight network-based KVM solution that streams keyboard and mouse input from a host machine to a remote client over the network.

## TL;DR

**Build:**
```bash
g++ -o host host.cpp
g++ -o client client.cpp
```

**Run:**
```bash
# On the remote machine (receives input)
./client

# On the host machine (sends input)
./host <client-ip> <keyboard-event> <mouse-event>
```

Example:
```bash
./host 192.168.1.100 /dev/input/event0 /dev/input/event1
```

## Overview

Fluid Input KVM allows you to share keyboard and mouse input from your host machine to a remote client over a network connection. The client listens for incoming connections and receives input events, while the host reads from your system's input devices and streams them to the client.

## Building

Compile both executables:

```bash
g++ -o host host.cpp
g++ -o client client.cpp
```

## Usage

### Client (Remote Machine)

Start the client listener on the machine that will receive keyboard and mouse input:

```bash
./client
```

The client will listen for incoming connections from a host. Note the client's IP address if you need to run the host from another machine.

### Host (Input Source Machine)

Run the host on the machine with the keyboard and mouse you want to share:

```bash
./host <client-ip> <keyboard-event> <mouse-event>
```

**Arguments:**
- `<client-ip>`: IP address of the machine running the client
- `<keyboard-event>`: Path to keyboard input device (e.g., `/dev/input/event0`)
- `<mouse-event>`: Path to mouse input device (e.g., `/dev/input/event1`)

**Example:**
```bash
./host 192.168.1.50 /dev/input/event0 /dev/input/event2
```

## Finding Your Input Devices

To find the correct `/dev/input/event*` files for your devices:

```bash
ls -l /dev/input/event*
cat /proc/bus/input/devices
```

Look for entries labeled "keyboard" and "mouse" or "touchpad" to identify the correct event files.

## Requirements

- Linux system with `/dev/input/` support
- Network connectivity between host and client machines
- Appropriate permissions to read input devices

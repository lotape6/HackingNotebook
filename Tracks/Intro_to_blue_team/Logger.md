We open wireshark and start taking a look to the packets:
After searching for some USB protocol information we find out something interesting:  https://wiki.wireshark.org/USB
```
The 'transfer_type' specifies if this transfer is isochronous (0), interrupt (1), control (2) or bulk (3).
```

So we can filter out the interruptions to try to check which keystrokes where present:
```
usb.transfer_type == 1
```

Then we find there are 2 types of communications from the host to some ID and back. Also it's noteworthy to check that there are 2 different IDs 1.16.1 and 1.13.1.

It looks like the ID 1.13.1 starts communicating and somewhen the 1.16.1 comes into play and breaks the communication with the 1.13.1 device.
Checking the communication, it looks like all the packages being sent from 1.16.1 to host have a fixed lenght of 35, and the vicebersa comm has a 27 lenght. There is another kind of frames that looks like they contain some further info with length 33
```
usb.transfer_type == 1 &&  frame.len == 35 && !(usb.capdata == 00:00:00:00:00:00:00:00)
```

We can now export all the packages and try to decode them out of wireshark.

```
cat keystrokes.csv | cut -d, -f10 | cut -d"\"" -f2  | grep -vE "Leftover Capture Data"

```

```
HTB[i-C4n...
HTB{i_C4n...
[CAPSLOCK]htb[[CAPSLOCK]i-[CAPSLOCK]c4n-533-[CAPSLOCK]y[CAPSLOCK]ou[CAPSLOCK]r-[CAPSLOCK]k3y2[CAPSLOCK]]

HTB{I_C4n...

[CAPSLOCK]htb{[CAPSLOCK]i_[CAPSLOCK]c4n_533_[CAPSLOCK]y[CAPSLOCK]ou[CAPSLOCK]r_[CAPSLOCK]k3y2[CAPSLOCK]}%

HTB{i_C4N...
```
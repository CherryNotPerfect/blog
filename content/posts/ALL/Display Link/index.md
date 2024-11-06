---
title: 'How to Use a ThinkPad Dock with External Monitors on Linux'
date: 2024-02-03T18:36:13-05:00
tags: [monitors]
---

This guide is for someone who has a a Thunderbolt dock that supports DisplayLink and wants to use two external monitors on Arch Linux running X11. This is how I've gotten this to work as of writing. Consult the [Arch Wiki DisplayLink](https://wiki.archlinux.org/title/DisplayLink) page for proper documentation, this is the main source for this guide.  

By default, the only things that will work on the ThinkPad 40AF dock will be the USB ports, additional ethernet interface, and the charging. These will appear in `dmesg` output. In order for any monitors to work at all, the aforementioned Arch Wiki DisplayLink guide needs to be followed, however only one monitor output will be supported unless additional steps found in this guide are followed.


## Things to note:
- This was tested with a [Thinkpad Type 40AF](https://pcsupport.lenovo.com/us/en/products/accessory/docks/thinkpad-hybrid-usb-c-with-usb-a-dock/40af/documentation/doc_userguide) dock, Thinkpad X13 Gen 1 (Intel), on Arch Linux running kernel `6.6.8-arch1-1`.
- I have only tested this with HDMI and DisplayPort monitors. A DVI-D monitor (Dell S23340Mc) using a DVI-D to DisplayPort cable was not properly functioning when attempting this method. Both working monitors are using HDMI.
- Consult your dock's manual for a compatibility table and physical connection guide.
- You will be downgrading to a less efficient graphics driver.
- This was tested using KDE as the desktop environment, and I would by lying if I said it worked perfectly smoothly. Still worth it.


### Debugging commands
- Debugging with `dmesg -w` is highly recommended to see events.
- `xrandr --listproviders` will show you a list of display outputs.

## How-To
1. Install the following (earliest versions tested to work are listed):
    - evdi-git (`evdi-git 1.14.1.r5.g0313eca-1`)
    - displaylink (`displaylink 5.8-1`)
2. Enable the `displaylink.service`.
3. Create the file `/etc/X11/xorg.conf.d/20-evdi.conf` with the following content:
    - (this is to set the compatible driver options)
```
Section "OutputClass"
	Identifier "DisplayLink"
	MatchDriver "evdi"
	Driver "modesetting"
	Option "AccelMethod" "none"
EndSection
```
4. Ensure you are using the fallback Intel kernel driver. For me, I had to uninstall `xf86-video-intel`.
    - See the [Driver Installation](https://wiki.archlinux.org/title/xorg#Driver_installation) page.
5. Enable the `udl` kernel module at boot by creating the file `/etc/modules-load.d/udl.conf` with the following content:
```
# Load udl kernel module at boot
udl
```
6. Enable the `evdi` kernel module at boot by creating the file `/etc/modules-load.d/evdi.conf` with the following content:
    - (to ensure that evdi looks for more than one monitor at boot)
```
# Load evdi kernel module at boot
evdi
```
<!--FIXME cursed way to get proper indentation.-->
&nbsp;&nbsp;&nbsp;&nbsp;And create the file `/etc/modprobe.d/dkms.conf` with the content:
```
"options evdi initial_device_count=2"
```
&nbsp;&nbsp;&nbsp;&nbsp;Replacing "2" with your expected number of additional monitors (total count 0-indexed).

7. Finally, reboot and hope that everything actually worked correctly. Consult the Arch Wiki's [Troubleshooting](https://wiki.archlinux.org/title/DisplayLink#Troubleshooting) page for any issues.

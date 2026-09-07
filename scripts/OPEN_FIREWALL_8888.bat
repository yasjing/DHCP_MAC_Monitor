@echo off
netsh advfirewall firewall add rule name="DHCP MAC Monitor TCP 8888" dir=in action=allow protocol=TCP localport=8888
pause

# CVE-2019-9730: Synaptics Audio Driver LPE

The vulnerability in this driver package was with the CxUtilSvc system service. It hosted a COM object that low-privileged code can use to perform arbitrary reads and writes to the registry as SYSTEM. The .NET code adds the `IRegistryHelper` COM interface as a reference to invoke its methods.

In terms of exploitation, a less subtle approach is used that replaces the binary path of a given service with a command that creates a local Administrator account. Although standard user accounts cannot start/stop every service, there is usually a small subset where they can (e.g. `ose`). They can also reboot the system if they cannot immediately start a service.

Write-up and technical advisory here: [http://jackson-t.ca/synaptics-cxutilsvc-lpe.html](http://jackson-t.ca/synaptics-cxutilsvc-lpe.html).

## Affected Vendors

- Lenovo
  - https://support.lenovo.com/us/en/downloads/DS120091
  - https://download.lenovo.com/pccbbs/mobiles/n1ma113w.exe
- HP
  - https://support.hp.com/us-en/drivers/selfservice/hp-envy-m6-aq100-x360-convertible-pc/12499188/model/13475171
  - https://ftp.hp.com/pub/softpaq/sp82501-83000/sp82767.exe
- Asus
  - https://www.asus.com/Laptops/ASUS-ZenBook-Flip-UX360CA/HelpDesk_Download/
  - https://dlcdnets.asus.com/pub/ASUS/nb/DriversForWin10/Audio/Audio_Conexant_Win10_64_VER8663452.zip
- LG
  - https://www.lg.com/us/support-product/lg-13Z970-U.AAW5U1
  - http://gscs-b2c.lge.com/downloadFile?fileId=vJimjDlGp1oPCTuNuDDsMw

This list is not comprehensive.

#!\bin\sh
# 
# Bluetooth Low Energy Fuzzer Version 2.1
# code by @delciouskek (Jordan H.)
#
# Greetings to @DA_667, Lesley Carhart (@hacksforpancakes), #allcatpack, Jayson E. Street, @lojikil
# @anarchistdalek, @cryptoishard, @metalgearreynrd, @lnxdork, @7th_protocol, @m3atshi3ld, @savagememes,
# @tribl_a2k, @grubthor, @skoomapipe, @t3h_arch3r, @livebeef, @zawarudad, @fuckcrunchroll, @sonichu1,
# @rustlay, @myhaxorninja, @mywhiteninja, @tsundereranger, Dan Aleksander (@havetilfive), @yokalli,
# @epikmani, @apexcybertwat, @genxmedia, @ra6bit, @detinspector, @teridax, @mcrealname, @mo0ty, 
# @yungjeune, @alizardx, @doubyadee, @rhowlingcayote, @ameera_1978, @lojikalscope, @enwroughtdreams,
# @sneakdotberlin, @rabite, @haribogangsta, @hula121, @hackerfantastic, @violetblue, @soulmech, @no0psl
# @radia_a_a, @mrvasnormandy, rip blacktric, AKilluminati, @eskiggalu, @babybarracudess, @siren_six,
# @effluviah, @cykocurt_, @papacone_, @y6k_virus, @oaklandelle, @0embarc0, @joruto_, @slowingtail, 
# Hentie (which @ are you on?), @arachnera, @bluemoonninja, @cybertaters, @mzbat, @Schuyler Towne,
# @shadow__creeper, @erzfiend, @datingsims, @polarisu, @_1gbps, @pr1ntf, @strthry, @oscaron, 
# @thatbrickster, @bacon_incident, @dzwoo0, @chkconfig, @rick636, @undeadlrrlicht, Benjikins, 
# Gilgamesh, @aoighost, @ephy_t, @doertedev, @tfwnoplayoffs, @wanitalilly, @thedukexx99, 
# @amazinmojostarz, @kjatar, @stauken, @videogameczar, @oshamurip, @ben_neato, @wevachannel4, 
# @_blo0p_, @sp0ngey_b0b, @issabailout, Lops, @operationcastle, @t0kerfr0g, West Florissant Ave,
# Elizabeth Bathory, @johnnypanics, Anyone I may have forgotten on Twitterz :3
#
# Modification granted with credit given to this author, including partially usages, of this file.
# Permission to electronically redistribute this script in its unmodified form is granted. All other
# rights, including the use of other media, are reserved by the author. 
#
# The information provided in this script is provided as it is without any warranty. The author
# disclaims #all warranties, either expressed or implied, including the warranties of merchantability
# and capability for a particular purpose. The author is not liable in any case of damage, including
# direct, indirect, incidental, consequential loss of business profits or special damages, even if the
# author has been advised of the possibility of such damages. Some states do not allow the exclusion or
# limitation of liability for consequential or incidental damages so the foregoing limitation may not
# apply. 
#
# The author does not approve or encourage anybody to break any vendor licenses, policies, deface
# websites, hack into databases, unlawfully obtain PII, interfere/deny service to any bluetooth device
# not in the individual's ownership or trade with fraud/stolen material. The author does not approve or
# encourage any illegal activity carried out with the use of this script 
# 
# Technical Details & Description:
#
# This is a bash script to be run on a linux os that makes use of a variety of gatttool commands 
# in order to determine primary services, characteristics, key uuid's and uuid-related character
# descriptors. It runs through all common uuid's in the bluetooth spec first, before attempting
# to read all character descriptors on the device. It is intended to test Bluetooth Low Energy
# devices and determine characteristics as well as provide a foundation for following up with
# other testing criteria, such as attempting writes or setting notifications/indications. 
#
# requires bluez (ie apt-get install bluez)
# may require pairing
# Exhaustive Characteristics read commented for time. Trim to specific application in seperate file, 
# uncomment, and repaste in.
read -p "Enter Bluetooth Address (eg. 00:00:00:00:00:00) : " BLE1
read -p "Is the Address is Random? Enter '-t random' : " BLE2
hciconfig hci0 down; hciconfig hci0 up
echo "Characteristics Read"; gatttool $BLE2 -b $BLE1 --characteristics
echo "Profile Read"; gatttool $BLE2 --primary -b $BLE1
echo "sleep 5"; sleep 5
echo "Start Basic Device Configuration Read";
echo "Client Configuration Characteristic"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2902
echo "Server Configuration Characteristic"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2903
echo "Basic Device Configuration Read Completed";
echo "Device Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a00
echo "Appearance"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a01
echo "Peripheral Privacy Flag"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a02
echo "Reconnection Address"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a03
echo "Peripheral Preferred Connection Parameters"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a04
echo "Service Changed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a05
echo "Heart Rate Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a37
echo "Heart Rate Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a39
echo "System ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a23
echo "Model Number String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a24
echo "Serial Number String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a25
echo "Firmware Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a26
echo "Hardware Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a27
echo "Software Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a28
echo "Manufacturer Name String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a29
echo "Reg Compliance List for IEEE 11073-20601 Personal Health Data Devices"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a2a
echo "PnP ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a50
echo "Undefined"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a30
echo "Scan Refresh"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a32
echo "Aerobic Heartrate Lower Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a7e
echo "Aerobic Heartrate Upper Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a84
echo "Aerobic Threshold"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a7f
echo "Age"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2a80
echo "Aggregate"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5A
echo "Alert Category ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A43
echo "Alert Category ID Bit Mask"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A42
echo "Alert Level"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A06
echo "Alert Notification Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A44
echo "Alert Status"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A3F
echo "Altitude"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB3
echo "Anaerobic Heart Rate Lower Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A81
echo "Anaerobic Heart Rate Upper Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A82
echo "Anaerobic Threshold"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A83
echo "Analog"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A58
echo "Apparent Wind Direction "; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A73
echo "Apparent Wind Speed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A72
echo "Appearance"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A01
echo "Barometric Pressure Trend"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA3
echo "Battery Level"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A19
echo "Blood Pressure Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A49
echo "sleep 5"; sleep 5
echo "Blood Pressure Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A35
echo "Body Composition Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9B
echo "Body Composition Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9C
echo "Body Sensor Location"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A38
echo "Bond Management Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA4
echo "Bond Management Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA5
echo "Boot Keyboard Input Report"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A22
echo "Boot Keyboard Output Report"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A32
echo "Boot Mouse Input Report"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A33
echo "Central Address Resolution"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA6
echo "CGM Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA8
echo "CGM Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA7
echo "CGM Session Run Time"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAB
echo "CGM Session Start Time"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAA
echo "CGM Specific Ops Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAC
echo "CGM Status"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA9
echo "CSC Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5C
echo "CSC Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5B
echo "Current Time"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A2B
echo "Cycling Power Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A66
echo "Cycling Power Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A65
echo "Cycling Power Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A63
echo "Cycling Power Vector"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A64
echo "Database Change Increment"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A99
echo "Date of Birth"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A85
echo "Date of Threshold Assessment "; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A86
echo "Date Time"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A08
echo "Day Date Time"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A0A
echo "Day of Week"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A09
echo "Descriptor Value Changed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A7D
echo "Device Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A00
echo "Dew Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A7B
echo "Digital"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A56
echo "DST Offset"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A0D
echo "Elevation"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6C
echo "Email Address"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A87
echo "Exact Time 256"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A0C
echo "Fat Burn Heart Rate Lower Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A88
echo "Fat Burn Heart Rate Upper Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A89
echo "Firmware Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A26
echo "sleep 5"; sleep 5
echo "First Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8A
echo "Five Zone Heart Rate Limits"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8B
echo "Floor Number"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB2
echo "Gender"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8C
echo "Glucose Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A51
echo "Glucose Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A18
echo "Glucose Measurement Context"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A34
echo "Gust Factor"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A74
echo "Hardware Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A27
echo "Heart Rate Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A39
echo "Heart Rate Max"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8D
echo "Heart Rate Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A37
echo "Heat Index"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A7A
echo "Height"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8E
echo "HID Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4C
echo "HID Information"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4A
echo "Hip Circumference"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A8F
echo "HTTP Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABA
echo "HTTP Entity Body"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB9
echo "HTTP Headers"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB7
echo "HTTP Status Code"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB8
echo "HTTPS Security"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABB
echo "Humidity"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6F
echo "IEEE 11073-20601 Regulatory Certification Data List"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A2A
echo "Indoor Positioning Configuration"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAD
echo "Intermediate Cuff Pressure"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A36
echo "Intermediate Temperature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A1E
echo "Irradiance"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A77
echo "Language"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA2
echo "Last Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A90
echo "Latitude"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAE
echo "LN Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6B
echo "LN Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6A
echo "Local East Coordinate"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB1
echo "Local North Coordinate"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB0
echo "Local Time Information"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A0F
echo "Location and Speed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A67
echo "Location Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB5
echo "Longitude"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AAF
echo "Magnetic Declination"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A2C
echo "sleep 5"; sleep 5
echo "Magnetic Flux Density - 2D"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA0
echo "Magnetic Flux Density - 3D"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AA1
echo "Manufacturer Name String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A29
echo "Maximum Recommended Heart Rate"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A91
echo "Measurement Interval"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A21
echo "Model Number String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A24
echo "Navigation"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A68
echo "New Alert"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A46
echo "Object Action Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC5
echo "Object Changed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC8
echo "Object First-Created"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC1
echo "Object ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC3
echo "Object Last-Modified"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC2
echo "Object List Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC6
echo "Object List Filter"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC7
echo "Object Name"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABE
echo "Object Properties"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC4
echo "Object Size"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AC0
echo "Object Type"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABF
echo "OTS Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABD
echo "Peripheral Preferred Connection Parameters"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A04
echo "Peripheral Privacy Flag"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A02
echo "PLX Continuous Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5F
echo "PLX Features"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A60
echo "PLX Spot-Check Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5E
echo "PnP ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A50
echo "Pollen Concentration"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A75
echo "Position Quality"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A69
echo "Pressure"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6D
echo "Protocol Mode"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4E
echo "Rainfall"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A78
echo "Reconnection Address"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A03
echo "Record Access Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A52
echo "Reference Time Information"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A14
echo "Report"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4D
echo "Report Map"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4B
echo "Resting Heart Rate"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A92
echo "Ringer Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A40
echo "Ringer Setting"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A41
echo "RSC Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A54
echo "sleep 5"; sleep 5
echo "RSC Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A53
echo "SC Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A55
echo "Scan Interval Window"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A4F
echo "Scan Refresh"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A31
echo "Sensor Location"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A5D
echo "Serial Number String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A25
echo "Service Changed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A05
echo "Software Revision String"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A28
echo "Sport Type for Aerobic and Anaerobic Thresholds"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A93
echo "Supported New Alert Category"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A47
echo "Supported Unread Alert Category"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A48
echo "System ID"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A23
echo "TDS Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2ABC
echo "Temperature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A6E
echo "Temperature Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A1C
echo "Temperature Type"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A1D
echo "Three Zone Heart Rate Limits"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A94
echo "Time Accuracy"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A12
echo "Time Source"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A13
echo "Time Update Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A16
echo "Time Update State"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A17
echo "Time with DST"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A11
echo "Time Zone"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A0E
echo "True Wind Direction"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A71
echo "True Wind Speed"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A70
echo "Two Zone Heart Rate Limit"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A95
echo "Tx Power Level"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A07
echo "Uncertainty"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB4
echo "Unread Alert Status"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A45
echo "URI"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2AB6
echo "User Control Point"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9F
echo "User Index"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9A
echo "UV Index"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A76
echo "VO2 Max"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A96
echo "Waist Circumference "; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A97
echo "Weight"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A98
echo "Weight Measurement"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9D
echo "Weight Scale Feature"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A9E
echo "Wind Chill"; gatttool $BLE2 -b $BLE1 --char-read --uuid=0x2A79
echo "Start Full Characteristics Read";
echo "sleep 5"; sleep 5
#while true; do
echo "0x0001"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0001 
echo "0x0002"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0002 
echo "0x0003"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0003 
echo "0x0004"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0004 
echo "0x0005"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0005 
echo "0x0006"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0006
echo "0x0007"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0007 
echo "0x0008"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0008
echo "0x0009"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0009 
echo "0x000a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000a 
echo "0x000b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000b 
echo "0x000c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000c 
echo "0x000d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000d
echo "0x000e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000e 
echo "0x000f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x000f 
echo "0x0010"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0010 
echo "0x0011"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0011
echo "0x0012"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0012
echo "0x0013"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0013
echo "0x0014"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0014
echo "sleep 5"; sleep 5
echo "0x0015"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0015
echo "0x0016"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0016
echo "0x0017"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0017
echo "0x0018"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0018
echo "0x0019"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0019
echo "0x001a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001a
echo "0x001b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001b
echo "0x001c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001c
echo "0x001d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001d
echo "0x001e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001e
echo "0x001f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x001f
echo "0x0020"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0020
echo "0x0021"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0021
echo "0x0022"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0022
echo "0x0023"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0023
echo "0x0024"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0024
echo "0x0025"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0025
echo "0x0026"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0026
echo "0x0027"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0027
echo "0x0028"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0028
echo "sleep 5"; sleep 5
echo "0x0029"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0029
echo "0x002a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002a
echo "0x002b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002b
echo "0x002c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002c
echo "0x002d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002d
echo "0x002e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002e
echo "0x002f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x002f
echo "0x0030"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0030
echo "0x0031"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0031
echo "0x0032"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0032
echo "0x0033"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0033
echo "0x0034"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0034
echo "0x0035"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0035
echo "0x0036"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0036
echo "0x0037"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0037
echo "0x0038"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0038
echo "0x0039"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0039
echo "0x003a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003a
echo "0x003b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003b
echo "0x003c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003c
echo "sleep 5"; sleep 5
echo "0x003d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003d
echo "0x003e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003e
echo "0x003f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x003f
echo "0x0040"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0040
echo "0x0041"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0041
echo "0x0042"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0042
echo "0x0043"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0043
echo "0x0044"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0044
echo "0x0045"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0045
echo "0x0046"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0046
echo "0x0047"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0047
echo "0x0048"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0048
echo "0x0049"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0049
echo "0x004a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x004a
echo "0x004b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x004b
echo "0x004c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x004c
echo "0x004d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x004d
echo "0x004e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00fe
echo "0x004f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x004f
echo "0x0050"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0050
echo "sleep 5"; sleep 5
echo "0x0051"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0051
echo "0x0052"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0052
echo "0x0053"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0053
echo "0x0054"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0054
echo "0x0055"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0055
echo "0x0056"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0056
echo "0x0057"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0057
echo "0x0058"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0058
echo "0x0059"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0059
echo "0x005a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005a
echo "0x005b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005b
echo "0x005c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005c
echo "0x005d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005d
echo "0x005e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005e
echo "0x005f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x005f
echo "0x0060"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0060
echo "0x0061"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0061
echo "0x0062"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0062
echo "0x0063"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0063
echo "0x0064"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0064
echo "sleep 5"; sleep 5
echo "0x0065"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0065
echo "0x0066"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0066
echo "0x0067"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0067
echo "0x0068"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0068
echo "0x0069"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0069
echo "0x006a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006a
echo "0x006b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006b
echo "0x006c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006c
echo "0x006d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006d
echo "0x006e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006e
echo "0x006f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x006f
echo "0x0070"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0070
echo "0x0071"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0071
echo "0x0072"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0072
echo "0x0073"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0073
echo "0x0074"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0074
echo "0x0075"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0075
echo "0x0076"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0076
echo "0x0077"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0077
echo "0x0078"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0078
echo "sleep 5"; sleep 5
echo "0x0079"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0079
echo "0x007a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007a
echo "0x007b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007b
echo "0x007c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007c
echo "0x007d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007d
echo "0x007e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007e
echo "0x007f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x007f
echo "0x0080"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0080
echo "0x0081"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0081
echo "0x0082"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0082
echo "0x0083"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0083
echo "0x0084"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0084
echo "0x0085"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0085
echo "0x0086"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0086
echo "0x0087"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0087
echo "0x0088"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0088
echo "0x0089"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0089
echo "0x008a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008a
echo "0x008b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008b
echo "0x008c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008c
echo "sleep 5"; sleep 5
echo "0x008d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008d
echo "0x008e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008e
echo "0x008f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x008f
echo "0x0090"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0090
echo "0x0091"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0091
echo "0x0092"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0092
echo "0x0093"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0093
echo "0x0094"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0094
echo "0x0095"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0095
echo "0x0096"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0096
echo "0x0097"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0097
echo "0x0098"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0098
echo "0x0099"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0099
echo "0x009a"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009a
echo "0x009b"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009b
echo "0x009c"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009c
echo "0x009d"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009d
echo "0x009e"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009e
echo "0x009f"; gatttool $BLE2 -b $BLE1 --char-read -a 0x009f
echo "0x00a0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a0
echo "sleep 5"; sleep 5
echo "0x00a1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a1
echo "0x00a2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a2
echo "0x00a3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a3
echo "0x00a4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a4
echo "0x00a5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a5
echo "0x00a6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a6
echo "0x00a7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a7
echo "0x00a8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a8
echo "0x00a9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00a9
echo "0x00aa"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00aa
echo "0x00ab"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ab
echo "0x00ac"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ac
echo "0x00ad"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ad
echo "0x00ae"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ae
echo "0x00af"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00af
echo "0x00bb"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00bb
echo "0x00b0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b0
echo "0x00b1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b1
echo "0x00b2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b2
echo "0x00b3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b3
echo "sleep 5"; sleep 5
echo "0x00b4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b4
echo "0x00b5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b5
echo "0x00b6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b6
echo "0x00b7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b7
echo "0x00b8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b8
echo "0x00b9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00b9
echo "0x00ba"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ba
echo "0x00bc"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00bc
echo "0x00bd"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00bd
echo "0x00be"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00be
echo "0x00bf"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00bf
echo "0x00c0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c0
echo "0x00c1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c1
echo "0x00c2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c2
echo "0x00c3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c3
echo "0x00c4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c4
echo "0x00c5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c5
echo "0x00c6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c6
echo "0x00c7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c7
echo "0x00c8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c8
echo "sleep 5"; sleep 5
echo "0x00c9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00c9
echo "0x00cc"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00cc
echo "0x00ca"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ca
echo "0x00cb"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00cb
echo "0x00cd"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00cd
echo "0x00ce"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ce
echo "0x00cf"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00cf
echo "0x00d0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d0
echo "0x00d1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d1
echo "0x00d2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d2
echo "0x00d3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d3
echo "0x00d4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d4
echo "0x00d5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d5
echo "0x00d6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d6
echo "0x00d7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d7
echo "0x00d8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d8
echo "0x00d9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00d9
echo "0x00dd"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00dd
echo "0x00da"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00da
echo "0x00db"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00db
echo "sleep 5"; sleep 5
echo "0x00dc"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00dc
echo "0x00de"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00de
echo "0x00df"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00df
echo "0x00e0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e0
echo "0x00e1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e1
echo "0x00e2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e2
echo "0x00e3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e3
echo "0x00e4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e4
echo "0x00e5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e5
echo "0x00e6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e6
echo "0x00e7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e7
echo "0x00e8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e8
echo "0x00e9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00e9
echo "0x00ee"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ee
echo "0x00ea"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ea
echo "0x00eb"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00eb
echo "0x00ec"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ec
echo "0x00ed"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ed
echo "0x00ef"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ef
echo "0x00f0"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f0
echo "sleep 5"; sleep 5
echo "0x00f1"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f1
echo "0x00f2"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f2
echo "0x00f3"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f3
echo "0x00f4"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f4
echo "0x00f5"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f5
echo "0x00f6"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f6
echo "0x00f7"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f7
echo "0x00f8"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f8
echo "0x00f9"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00f9
echo "0x00ff"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00ff
echo "0x00fa"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00fa
echo "0x00fb"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00fb
echo "0x00fc"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00fc
echo "0x00fd"; gatttool $BLE2 -b $BLE1 --char-read -a 0x00fd
echo "0x0100"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0100
echo "0x0101"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0101
echo "0x0102"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0102
echo "0x0103"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0103
echo "0x0104"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0104
echo "0x0105"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0105
echo "sleep 5"; sleep 5
echo "0x0106"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0106
echo "0x0107"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0107
echo "0x0108"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0108
echo "0x0109"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0109
echo "0x010A"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010A
echo "0x010B"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010B
echo "0x010C"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010C
echo "0x010D"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010D
echo "0x010E"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010E
echo "0x010F"; gatttool $BLE2 -b $BLE1 --char-read -a 0x010F
echo "0x0110"; gatttool $BLE2 -b $BLE1 --char-read -a 0x0110
#done
echo "Characteristics Read Completed";
#echo "Start Exhaustive Characteristics Read"
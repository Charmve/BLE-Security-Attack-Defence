<div align="center">
	<img border=0 src="logo.jpg" width="300">
</div>
<h4 align="center">Bluetooth-LE Security: Method, Tools and Stack</h4>
<p align="center">
  <a href="https://github.com/Charmve/BLE-Security-Attack-Defence"><img src="https://img.shields.io/badge/👓-B1ueB0y-blue" alt="B1ueB0y"></a>
  <a href="https://github.com/Charmve"><img src="https://img.shields.io/badge/Github-Charmve-lightblue" alt="github"></a>
  <a href="./Code-of-Conduct.md"><img src="https://img.shields.io/badge/Licence-GPL-green" alt="Code-of-Conduct"></a>
</p>
<br>

## ✨ News! ✨

- <img width="30" height="30" src="image/BlackHat.jpg">&nbsp;&nbsp;<font size="4"><b>2020.10.13:</b> A heap-based type confusion affecting Linux kernel 4.8 and higher was discovered in ``net/bluetooth/l2cap_core.c.`` by <a href="https://github.com/google/security-research" target="_blank">Google Security Research</a> !<br>
- <img width="30" height="30" src="https://static.leiphone.com/uploads/new/images/20200326/5e7c5dc11daa1.png?imageView2/2/w/740">&nbsp;&nbsp;<font size="4"><b>2020.03.26:</b> A memory corruption issue was addressed with improved input validation by <a href="https://www.leiphone.com/news/202003/gENc7OITqoxKchYo.html" target="_blank">Qihoo 360 Alpha Lab</a> !
<br>

## BLE Vulnerability TOP5
- <a href="./01_BlueBorne" target="_blank">BlueBorne</a>
- <a href="./02_BleedingBit" target="_blank">BleedingBit</a>
- <a href="./03_SweynTooth" target="_blank">SweynTooth</a>
- <a href="./04_BtleJuice" target="_blank">BtleJuice</a>
- <a href="./05_BLE-CTF" target="_blank">BLE-CTF</a>

<br>
<p align="center"><img border=0 src="profile.jpg"><br></p>
<br>

## Table of Content
```
BLE-Security-Attack&Defence
 |-- BLE Vulnerability TOP5
 |  |-- BlueBorne
 |  |-- BleedingBit
 |  |-- SweynTooth
 |  |-- BtleJuice
 |  |-- BLE-CTF
 |-- ble-stack
 |  |-- Mynewt-Nimble
 |  |-- nRF5_SDK_15.0.0_a53641a
 |  |-- PyBluez
 |  |-- LightBlue
 |-- cap - capture package
 |  |-- CrackLE
 |  |-- TI-BLTE2Pcap
 |  |-- blefuzz_V21
 |  |-- Fuzzing Bluetooth
 |-- image
 |-- tools - hardware&sofrware
 |  |-- Ubertooth
 |  |-- GATTacker
 |  |-- BladeRF
 |  |-- HackRF
 |  |-- Adafruit-BluefruitLE
 ...
```
<br>

## Bluetooth LE Vulnerabilities

<table>
	<tr>
		<td><font size="4">1.</font></td>
		<td><center><a href="https://www.youtube.com/watch?v=WWQTlogqF1I" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601457791/video_to_markdown/images/youtube--WWQTlogqF1I-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="BlueBorne: A New Class of Airborne Attacks that can Remotely Compromise Any Linux/IoT Device" width="6816" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BlueBorne</b>: A New Class of Airborne Attacks that can Remotely Compromise Any Linux/IoT Device
			<br>
			<b>Ben Seri</b> & <b>Gregory Vishnepolsky </b></p>
			<p align="left"><font size =2>In this talk we will present the ramifications of airborne attacks, which bypass all current security measures and provide hackers with a contagious attack, capable of jumping over "air-gapped" networks...</font></p>
			<p align="center"><img width="30" height="30" src="image/BlackHat.jpg"> Black Hat 2017
			<br>
			[<b><a href="https://www.armis.com/blueborne/" target="_blank">PDF</a></b> | <a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/01_BlueBorne" target="_blank"><b>Project Page</b></a> |  <a href="https://www.youtube.com/watch?v=WWQTlogqF1I" target="_blank"><b>Video</b></a>  |  <a href="https://github.com/marsyy/littl_tools/tree/master/bluetooth" target="_blank"><b>PoC</b></a>]
			</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">2.</font></td>
		<td><center><a href="https://www.youtube.com/watch?v=G08fh5Sa7TU" target="_blank"><img src="https://img-blog.csdnimg.cn/img_convert/127a037eb210b12e714618610e1b9697.png" alt="BtleJuice: the Bluetooth Smart Man In The Middle Framework by Damiel Cauquil" width="6816" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BtleJuice</b>: the Bluetooth Smart Man In The Middle Framework 
			<br>
			<b>Damiel Cauquil</p></b>
			<p align="left" ><font size =2>A lot of Bluetooth Low Energy capable devices are spread since the last few years, offering a brand new way to compromise many “smart” objects: fitness wristbands, smart locks and padlocks and even healthcare devices. But this protocol poses some new challenges...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/DEFCON.jpg"> DefConference 2016 (<b>DEFCOON</b>) </i>
			<br>
			[<a href="https://www.youtube.com/watch?v=G08fh5Sa7TU" target="_blank"><b>Video</b></a> | <a href="https://speakerdeck.com/virtualabs/btlejuice-the-bluetooth-smart-mitm-framework?slide=40" target="_blank"><b>PDF</b></a> | <a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/04_BtleJuice" target="_blank"><b>Project Page</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">3.</font></td>
		<td><center><a href="https://www.youtube.com/watch?v=VHJfd9h6G2s" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601457995/video_to_markdown/images/youtube--VHJfd9h6G2s-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="Damien virtualabs Cauquil - You had better secure your BLE devices" width="6816" height="240" /></a></center></td>
		<td>
			<p align="center">You had better secure your BLE devices 
			<br>
			<b>Damiel Cauquil</b> </p>
			<p align="left"><font size =2>Sniffing and attacking Bluetooth Low Energy devices has always been a real pain. Proprietary tools do the job but cannot be tuned to fit our offensive needs, while opensource tools work sometimes, ... <br></p>
			<p align="center"><i><img width="30" height="30" src="image/DEFCON.jpg"> DefConference 2018 (<b>DEFCOON26</b>) </i>
			<br>
			[<b><a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/04_BtleJuice" target="_blank">PDF</a></b> | <a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/04_BtleJuice" target="_blank"><b>Project Page</b></a> | <a href="https://www.youtube.com/watch?v=VHJfd9h6G2s" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">4.</font></td>
		<td><center><a href="https://www.youtube.com/embed/D5FIIqLWtYw?list=PLKV_4pHyTj0GUtdyOZotJJFwsjHbBT83l" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458076/video_to_markdown/images/youtube--D5FIIqLWtYw-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="BLEEDINGBIT - Takeover of Aruba Access Point Access Point 325" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BLEEDINGBIT </b>- Takeover of Aruba Access Point Access Point 325 
			<br>
			<b>Armis</b></p>
			<p align="left" ><font size =2>In this demo, Armis will demonstrate the takeover of an Aruba Access Point Access Point 325 using a TI cc2540 BLE chip. For more information, please visit https://armis.com/bleedingbit.</font></p>
			<p align="center"><i><img width="30" height="30" src="image/armis.jpg"> BLEEDINGBIT RCE vulnerability (CVE-2018-16986) </i>
			<br>
			[<b><a href="https://www.armis.com/bleedingbit/" target="_blank">PDF</a></b> | <a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/02_BLEEDINGBIT" target="_blank"><b>Project Page</b></a> | <a href="https://www.youtube.com/watch?v=D5FIIqLWtYw&list=PLKV_4pHyTj0GUtdyOZotJJFwsjHbBT83l&index=2" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">5.</font></td>
		<td><center><a href="https://www.youtube.com/embed/oty1yTdsEXs" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458144/video_to_markdown/images/youtube--oty1yTdsEXs-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="SweynTooth: Unleashing Mayhem over Bluetooth Low Energy" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>SweynTooth</b>: Unleashing Mayhem over Bluetooth Low Energy 
			<br>
			<b>Matheus E. Garbelini</b></p>
			<p align="left" ><font size =2>The Bluetooth Low Energy (BLE) is a promising short-range communication technology for Internet-of-Things (IoT) with reduced energy consumption. Vendors implement BLE protocols in their manufactured devices compliant to Bluetooth Core Specification. Recently, several vulnerabilities were discovered in the BLE protocol ...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/USENIX.jpg"> <b>USENIX Security 20</b></i>
			<br>
			[<b><a href="https://www.usenix.org/conference/atc20/presentation/garbelini" target="_blank">PDF</a></b> | <a href="https://github.com/Charmve/BLE-Security-Attack-Defence/tree/master/03_SweynTooth" target="_blank"><b>Code</b></a> | <a href="https://asset-group.github.io/disclosures/sweyntooth/" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=oty1yTdsEXs" target="_blank"><b>Video</b></a> | <a href="https://www.usenix.org/system/files/atc20-paper43-slides-garbelini.pdf" target="_blank"><b>Slides</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">6.</font></td>
		<td><center><a href="https://www.youtube.com/embed/wIWZaSZsRc8" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458197/video_to_markdown/images/youtube--wIWZaSZsRc8-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="BLESA: Spoofing Attacks against Reconnections in Bluetooth Low Energy" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BLESA</b>:  Spoofing Attacks against Reconnections in Bluetooth Low Energy 			
		<br>
			<b>Jianliang Wu, Yuhong Nan ..., Purdue University</b></p>
			<p align="left" ><font size =2>In this paper, we analyze the security of the BLE link-layer, focusing on the scenario in which two previously-connected devices reconnect. Based on a formal analysis of the reconnection procedure defined by the BLE specification, we highlight two critical security weaknesses in the specification. As a result, even a device implementing the BLE protocol correctly may be vulnerable to spoofing attacks...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/USENIX.jpg"> <b>WOOT '20</b></i>
			<br>
			[<b><a href="https://www.usenix.org/conference/woot20/presentation/wu" target="_blank">PDF</a></b> | <a href="https://github.com/Charmve/mhaiyang.github.io/blob/master/ICME2020_MCERN/index.html" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=wIWZaSZsRc8" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">7.</font></td>
		<td><center><a href="https://www.youtube.com/embed/uKqdb4lF0XU" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458318/video_to_markdown/images/youtube--uKqdb4lF0XU-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="Gattacking Bluetooth Smart Devices - Introducing a New BLE Proxy Tool" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>Gattacking Bluetooth Smart Devices</b> - Introducing a New BLE Proxy Tool 
			<br>
			<b>Slawomir Jasek</b></p>
			<p align="left" ><font size =2>Using a few simple tricks, we can assure the victim will connect to our impersonator device instead of the original one, and then just proxy the traffic - without consent of the mobile app or device. And here it finally becomes interesting - just imagine how many attacks you might be able to perform with the possibility to actively intercept the BLE communication....</font></p>
			<p align="center"><i><img width="30" height="30" src="image/BlackHat.jpg"> Black Hat 2016 (<b>Black Hat</b>) </i>
			<br>
			[<a href="https://www.blackhat.com/docs/us-16/materials/us-16-Jasek-GATTacking-Bluetooth-Smart-Devices-Introducing-a-New-BLE-Proxy-Tool.pdf" target="_blank"><b>Slides</b></a>]</p>
			</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">8.</font></td>
		<td><center><a href="https://www.youtube.com/embed/fASGU7Og5_4" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1603432192/video_to_markdown/images/youtube--fASGU7Og5_4-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="BIAS: Bluetooth Impersonation AttackS" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BIAS</b>: Bluetooth Impersonation AttackS
			<br>
			<b> Daniele Antonioli</b>, <b>Nils Ole Tippenhauer</b> & <b>Kasper Rasmussen</b></p>
			<p align="left" ><font size =2>The Bluetooth standard provides authentication mechanisms based on a long term pairing key, which are designed to protect against impersonation attacks. The BIAS attacks from <a href="https://francozappa.github.io/publication/bias/paper.pdf" target="_blank">our new paper</a> demonstrate that those mechanisms are broken, and that an attacker can exploit them to impersonate any Bluetooth master or slave device. Our attacks are standard-compliant, and can be combined with other attacks, including the <a href="https://knobattack.com/" target="_blank">KNOB attack</a>. In the paper, we also describe a low cost implementation of the attacks and our evaluation results on 30 unique Bluetooth devices using 28 unique Bluetooth chips.</font>
			</p>
			<p align="center"><i>📑 IEEE Symposium on Security and Privacy</i>
			<br>
			[<b><a href="https://francozappa.github.io/publication/bias/paper.pdf" target="_blank">PDF</a></b> | <a href="https://francozappa.github.io/publication/bias/" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=fASGU7Og5_4&feature=emb_logo" target="_blank"><b>Video</b></a> | <a href="https://francozappa.github.io/publication/bias/slides.pdf" target="_blank"><b>Slides</b></a> | <a href="https://github.com/francozappa/bias" target="_blank"><b>PoC</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">9.</font></td>
		<td><center><a href="https://www.youtube.com/embed/iH7VPUNz-dU" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458374/video_to_markdown/images/youtube--iH7VPUNz-dU-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="BLEKey: Breaking Access Controls With BLEKey" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>BLEKey</b>: Breaking Access Controls With BLEKey 
			<br>
			<b> Eric Evenchick</b>  &  <b>Mark Baseggio</b></p>
			<p align="left" ><font size =2>RFID access controls are broken. In this talk, we will demonstrate how to break into buildings using open-source hardware we are releasing.Over the years, we have seen research pointing to deficiencies in every aspect of access control systems: the cards...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/BlackHat.jpg"> Black Hat 2016 (<b>Black Hat</b>) </i>
			<br>
			[<b><a href="" target="_blank">PDF</a></b> | <a href=" " target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/embed/iH7VPUNz-dU" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">10.</font></td>
		<td><center><a href="https://www.youtube.com/embed/s79CG2Os0Nc" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458432/video_to_markdown/images/youtube--s79CG2Os0Nc-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="MASHaBLE: Mobile Applications of Secret Handshakes Over Bluetooth LE" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>MASHaBLE</b>: Mobile Applications of Secret Handshakes Over Bluetooth LE 
			<br>
			<b>Yan Michalevsky</b></p>
			<p align="left" ><font size =2>In this talk, we present new applications for cryptographic secret handshakes between mobile devices on top of Bluetooth Low-Energy (LE). Secret handshakes enable mutual authentication between parties that did not meet before (and therefore don't trust each other) but are both associated with a virtual secret group or community...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/BlackHat.jpg"> Black Hat 2016 (<b>Black Hat</b>) </i>
			<br>
			[<b><a href="https://www.blackhat.com/docs/asia-17/materials/asia-17-Michalevsky-MASHABLE-Mobile-Applications-Of-Secret-Handshakes-Over-Bluetooth-LE-wp.pdf" target="_blank">PDF</a></b> | <a href="https://www.blackhat.com/asia-17/briefings.html#mashable-mobile-applications-of-secret-handshakes-over-bluetooth-le" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=s79CG2Os0Nc" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">11.</font></td>
		<td><center><a href="https://www.youtube.com/embed/X2ARyfjzxhY" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458478/video_to_markdown/images/youtube--X2ARyfjzxhY-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="Safe Mode Wireless Village - The Basics Of Breaking BLE v3" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>Safe Mode Wireless Village</b> - The Basics Of Breaking BLE v3 
			<br>
			<b> FreqyXin</b></p>
			<p align="left" ><font size =2>Evolving over the past twenty-two years, Bluetooth, especially Bluetooth Low Energy (BLE), has become the ubiquitous backbone ...</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/DEFCON.jpg"> DefConference 2020 (<b>DEFCOON</b>) </i>
			<br>
			[<b><a href=" " target="_blank">PDF</a></b> | <a href=" " target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=X2ARyfjzxhY" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">12.</font></td>
		<td><center><a href="https://www.youtube.com/watch?v=v9Xg9XcnNh0" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1605671088/video_to_markdown/images/youtube--v9Xg9XcnNh0-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="USENIX Security '19 - The KNOB is Broken: Exploiting Low Entropy in the Encryption Key" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center"><b>Key Negotiation Of Bluetooth (KNOB)</b>: Breaking Bluetooth Security
				<br>
				<b>Daniele Antonioli, SUTD</b>
			</p>
			<p align="left" ><font size =2>We present an attack on the encryption key negotiation protocol of Bluetooth BR/EDR. The attack allows a third party, without knowledge of any secret material (such as link and encryption keys), to make two (or more) victims agree on an encryption key with only 1 byte (8 bits) of entropy. Such low entropy enables the attacker to easily brute force the negotiated encryption keys, decrypt the eavesdropped ciphertext, and inject valid encrypted messages (in real-time)....</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/USENIX.jpg"> <b>USENIX Security 19</b></i>
			<br>
			[<b><a href="https://www.usenix.org/system/files/sec19-antonioli.pdf" target="_blank">PDF</a></b> | <a href="https://knobattack.com/" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=v9Xg9XcnNh0" target="_blank"><b>Video</b></a> | <a href="https://github.com/francozappa/knob/tree/master/poc-internalblue" target="_blank"><b>PoC</b></a>]</p>
		</td>
	</tr>
	<tr>
		<td><font size="4">13.</font></td>
		<td><center><a href="https://www.youtube.com/embed/gCQ3iSy6R-U" target="_blank"><img src="https://res.cloudinary.com/marcomontalbano/image/upload/v1601458589/video_to_markdown/images/youtube--gCQ3iSy6R-U-c05b58ac6eb4c4700831b2b3070cd403.jpg" alt="Bluetooth Reverse Engineering: Tools and Techniques" width="3408" height="240" /></a></center></td>
		<td>
			<p align="center">Bluetooth Reverse Engineering: Tools and Techniques
			<br>
			<b>Mike Ryan, Founder</b>, ICE9 Consulting
			<p align="left" ><font size =2>With the continuing growth of IoT, more and more devices are entering the market with Bluetooth. This talk will shed some light on how these devices use Bluetooth and will cover reverse engineering techniques that in many cases can be accomplished with hardware you already have! Whether you're a Bluetooth newbie or a seasoned pro, you’ll learn something from this talk....</font>
			</p>
			<p align="center"><i><img width="30" height="30" src="image/RSA_Conference.png"> RSA Conference</i>
			<br>
			[<b><a href="https://www.blackhat.com/docs/asia-17/materials/asia-17-Michalevsky-MASHABLE-Mobile-Applications-Of-Secret-Handshakes-Over-Bluetooth-LE-wp.pdf" target="_blank">PDF</a></b> | <a href="https://www.blackhat.com/asia-17/briefings.html#mashable-mobile-applications-of-secret-handshakes-over-bluetooth-le" target="_blank"><b>Project Page</b></a>  | <a href="https://www.youtube.com/watch?v=gCQ3iSy6R-U" target="_blank"><b>Video</b></a>]</p>
		</td>
	</tr>
</table>
<br>
<br>

# <a href="https://asset-group.github.io/disclosures/sweyntooth/" target="_blank">MORE</a>


<!--
<div align="center">
    <a href="https://github.com/Charmve/"><img src="image.jpg"></a>
</div>
<br>
--->

0. BlueBorne - A New Class of Airborne Attacks that can Remotely Compromise Any Linux/IoT Device
https://www.youtube.com/watch?v=WWQTlogqF1I

   Hack.lu 2016 BtleJuice: the Bluetooth Smart Man In The Middle Framework by Damiel Cauquil
https://www.youtube.com/watch?v=G08fh5Sa7TU

1. MASHaBLE: Mobile Applications of Secret Handshakes Over Bluetooth LE
https://www.youtube.com/watch?v=s79CG2Os0Nc
2. Automatic Discovery of Evasion Vulnerabilities Using Targeted Protocol Fuzzing 
https://www.youtube.com/watch?v=NDWGwrMk3AU
3. Hacking the Wireless World with Software Defined Radio - 2.0
https://www.youtube.com/watch?v=MKbU3HhG2vk
4. Effective File Format Fuzzing – Thoughts, Techniques and Results
https://www.youtube.com/watch?v=qTTwqFRD1H8
5. Hacking the Wireless World with Software Defined Radio - 2.0
https://www.youtube.com/watch?v=x3UUazj0tkg

 
6. DEF CON 26 - Damien virtualabs Cauquil - You had better secure your BLE devices
https://www.youtube.com/watch?v=VHJfd9h6G2s&t=646s

7. DEF CON 24 Wireless Village - Jose Gutierrez and Ben Ramsey - How Do I BLE Hacking
https://www.youtube.com/watch?v=oP6sx2cObrY

8. DEF CON Safe Mode Wireless Village - FreqyXin - The Basics Of Breaking 
https://www.youtube.com/watch?v=X2ARyfjzxhY

9. DEF CON 26 - Vincent Tan - Hacking BLE Bicycle Locks for Fun and a Small Profit
https://www.youtube.com/watch?v=O-caTVpHWoY

10. DEF CON 26 WIRELESS VILLAGE - ryan holeman - BLE CTF
https://www.youtube.com/watch?v=lx5MAOyu9N0

11. DEF CON 21 - Ryan Holeman - The Bluetooth Device Database
https://www.youtube.com/watch?v=BqiIERArnA8

12. DEF CON 22 - Grant Bugher - Detecting Bluetooth Surveillance Systems
https://www.youtube.com/watch?v=85uwy0ACJJw

13. KnighTV Episode 11: Hacking BLe Devices Part 1/6: Attacking August Smart Lock Pro
https://www.youtube.com/watch?v=3e4DBk5BKLg

14. Gattacking Bluetooth Smart Devices - Introducing a New BLE Proxy Tool
https://www.youtube.com/watch?v=uKqdb4lF0XU&list=LLxFkZjbpt0KyhEv1d342SQQ&index=6&t=91s

15. Bluetooth Reverse Engineering: Tools and Techniques
https://www.youtube.com/watch?v=gCQ3iSy6R-U

16. Hopping into Enterprise Networks from Thin Air with BLEEDINGBIT
https://www.youtube.com/watch?v=ASod9cRtZf4

   漏洞预警 | BleedingBit蓝牙芯片远程代码执行漏洞 
https://www.anquanke.com/post/id/163307  https://www.secpulse.com/archives/78841.html

17. BA03 Breaking the Teeth of Bluetooth Padlocks Adrian Crenshaw
https://www.youtube.com/watch?v=k8Tp5hj6ylY

18. The NSA Playset Bluetooth Smart Attack Tools
https://www.youtube.com/watch?v=_Z4gYyrKVFM

## Code of Conduct

[免责申明 Code of Conduct](Code-of-Conduct.md)

## To-Do
- 2020.10 <a href="https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq" target="_blank"><b>BleedingTooth</b></a>  CVE-2020-12351 CVE-2020-12352 CVE-2020-24490<br>
- 2020.04 <a href="https://francozappa.github.io/about-bias/" target="_blank"><b>BIAS</b></a> CVE-2020-10135<br>
- 2020.03 <a href="https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq" target="_blank"><b>Bluewave</b></a> CVE-2020-3848 CVE-2020-3849 CVE-2020-3850<br>
- 2020.03 <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-15802" target="_blank"><b>BLURtooth</b></a> CVE-2020-15802<br>
- 2020.03 <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-9770" target="_blank">BLESA</a> CVE-2020-9770<br>
- 2020.03 <a href="https://knobattack.com/" target="_blank">KNOB</a> CVE-2019-9506<br>

## Citation
Use this bibtex to cite this repository:
```
@misc{BLE Security,
  title={Bluetooth LE-Security: Method, Tools and Stack},
  author={Charmve},
  year={2020.09},
  publisher={Github},
  journal={GitHub repository},
  howpublished={\url{https://github.com/Charmve/BLE-Security-Attack-Defence}},
}
```
<strong>*updade on 2020/10/23</strong> @ <a href="https://github.com/Charmve" target="_blank"><b>Charmve</b></a>

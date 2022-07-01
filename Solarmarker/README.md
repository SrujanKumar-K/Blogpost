# &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**Solarmarker a.k.a Jupyter Infostealer**



## Table of Contents
[File Information](#file-information)  
[Behavioral Analysis](#behavioral-analysis)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**:--** [Static](#static)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**:--** [Dynamic](#dynamic)  
[Code Analysis](#code-analysis)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**:--** [Stage1](#stage1)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**:--** [Stage2](#stage2)  
[Final Payload](#final-payload)  
[Indicators of Compromise](#indicators-of-compromise)  
[References](#references)

### File Information

&nbsp;&nbsp;&nbsp;&nbsp;SolarMarker, a malware family known for its info stealing and backdoor capabilities include the exfiltration of auto-fill data, saved passwords and saved card information from victims’ web browsers. [^1]

This blog post is a technical analysis of the Jupyter info Stealer tagged as { _Polazert & solarmarker & YellowCockatoo_ }. Victims are targeted through malspam ZIP attachment containing an embedded EXE file that initiates the infection chain. The malware sample is available [here](https://bazaar.abuse.ch/sample/e864d8d2a93f38d2714ad1f0b5f79cef79d46022cd6b29c3ed8e52c8c79e7ff9/)

It is a _.Net compiled binary_; the file size is around **210MB** and it has _26/63_ detection count in VirusTotal as on writing this blogpost.  

![image](https://user-images.githubusercontent.com/71969773/175195516-9d108f7f-702d-4cce-a305-3b03b2197178.png)
|:--:|
| *Figure1. VirtusTotal Detection count* |    



Before we jump into the source code analysis, let's analyze the behavior of malware through static & dynamic approach using windows sysinternals inside FLARE VM.    

####  Behavioral Analysis

#### Static  
By running the sample through the "_Strings & FLoss_" tools, didn't find much useful readable strings as the code is heavily obfuscated. It is an indication that the strings will be resolved dynamically. However, the sample is compiled with original file name as  

     wABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZRZMn63PNTTJDlrIDa2qzvPQW0AQVccp4BN8YTSRlE4LJTJR_U4TkV

The digital certificate parsed through cyberchef shows below information:

![image](https://user-images.githubusercontent.com/71969773/176126128-4a2c24aa-52ad-41e6-b522-5ff895d0b976.png)
|:--:|
| *Figure2. Digital Certificate of malware* |

 
#### Dynamic  

After executing, it spawns multiple PowerShell windows in hidden mode and in parallel execute an MSI installer of a legitimate PDF program to avoid the user attention.

![d1](https://user-images.githubusercontent.com/71969773/176131509-97eaf71f-e2d9-469d-8759-d3108bcbb2e2.PNG)
|:--:|
| *Figure3. Process graph overview & Legitimate PDF installer wizard* |  

The ProcessHacker tool helps in identifying the different .Net modules loaded in memory, the one in highlighted below is a malicious and, we could see the extracted C2 server from its string's module.  

![d2](https://user-images.githubusercontent.com/71969773/176133414-2496357e-59c6-4b22-a595-8ea448375c7d.PNG)
|:--:|
| *Figure4. ProcessHacker window*|

The threat actors achieve persistence just by dropping a randomized LNK file in user's startup directory and this file is linked to random folder created under TEMP folder.  

![autorun](https://user-images.githubusercontent.com/71969773/176118865-d03e6378-9413-4cfb-a9ae-cc5cfe6fc85f.PNG)  
|:--:|
| *Figure5. Autorun*|

![PM1](https://user-images.githubusercontent.com/71969773/176118819-303819f9-4924-4655-8f82-97040727abac.PNG)  
|:--:|
| *Figure6. Procmon filter*|
 
### Code Analysis
#### **Stage1**
"Dnspy" tool is used to analyze the disassembled code. It is heavily obfuscated with randomized classes and function names. In main, it shows that AES-CBS encryption is being used and attributes such _IV&Key_ is comes on the fly to decode the obfuscated content.

![image](https://user-images.githubusercontent.com/71969773/175199348-729b64e9-deea-408a-96c5-619cfb591a25.png)
|:--:|
| *Figure7. Program's Main in DnSpy*|

Below Cyberchef recipe can used to extract stage2 payload which was invoked by PowerShell process.

AES-Key: "CNxL4vqimJxTpB/dkmebJ09Rml9kkAr+7ZzN5orLHW0=" (Base64 format)  
AES-IV: "03421d55fea7d98abb51d5ee7e510e56" (Hex) --> taken from first 16Bytes of encoded payload

![image](https://user-images.githubusercontent.com/71969773/175204939-b0ae7129-f608-4de2-a52b-188f9dd3040c.png)
|:--:|
| *Figure8. Symmetric (AES-CBC) Encryption*|

#### **Stage2**
The formatted PowerShell code do the following things,

1. Creates random folder in **%TEMP%** directory, consists of encrypted data
2. **LNK** file is added to _Startup folder_ for maintain the persistence
3. Symmetric _AES-CBC mode_ is initialized to decode the encrypted data blob
4. Reflectively load the decoded EXE into memory at defined class & function.

![Jupyt1](https://user-images.githubusercontent.com/71969773/175224989-682f8599-c056-43db-a445-a3a610e2245f.PNG)
|:--:|
| *Figure9. Formatted output of Figure8*|

Following cyberchef recipe is used to get the final payload.

![image](https://user-images.githubusercontent.com/71969773/175225924-0f5d4bbb-f200-414f-82fe-3b58c990ecad.png)
|:--:|
| *Figure10. Symmetric (AES-CBC) Encryption*|

#### **Final Payload**

The Final Solar Marker backdoor is a .NET DLL with sha256 as 56be46171da5aa65aa8ad5eec2252259fb8f9a3539c821377de357af7e459041 reflectively loaded into the memory. The internal name of this DLL application is classified as

    "BABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZVRRBgNb4WgReOQMVLyAaV0XHSX0iqLgUUUZSEVJh8BTY1BXH7mjXQp8q4jzMAp5U6APNVPSwQ"  
Inside sample, the stings are encrypted in two different formats, which are decoded dynamically while program execution.

(i) XOR-Encryption:

![image](https://user-images.githubusercontent.com/71969773/175229878-bf4aa8a6-d3bd-4ea6-8028-a01a3b8f4e65.png)
|:--:|
| *Figure11. Encrypted strings through XOR*|  

[This](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Simple%20string','string':'byte.MaxValue'%7D,'255',true,false,true,false)Remove_whitespace(true,true,true,true,true,false)Regular_expression('User%20defined','byte%5C%5C%5B%5C%5C%5Darray%5C%5C%3Dnewbyte%5C%5C%5B%5C%5C%5D.%2B?%5C%5C%7D;byte%5C%5C%5B%5C%5C%5Darray2%5C%5C%3Dnewbyte%5C%5C%5B%5C%5C%5D.%2B?%5C%5C%7D%5C%5C;',true,true,true,false,false,false,'List%20matches')Fork('%5C%5Cn','%5C%5Cn%5C%5Cn',false)Find_/_Replace(%7B'option':'Regex','string':'(byte%5C%5C%5B%5C%5C%5Darray%5C%5C%3Dnewbyte%5C%5C%5B%5C%5C%5D)%7Cbyte%5C%5C%5B%5C%5C%5Darray2%3Dnewbyte%5C%5C%5B%5C%5C%5D'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':','%7D,'%20',true,false,true,false)Register('(?%3C%3D%5C%5C%7B)(%5B%5E%5C%5C%7D%5D%2B).*',true,false,false)Regular_expression('User%20defined','(?%3C%3D;%5C%5C%7B)(%5B%5E%5C%5C%7D%5D%2B)',true,true,false,false,false,false,'List%20matches')From_Decimal('Space',false)To_Hex('None',0)Register('(%5B%5C%5Cs%5C%5CS%5D*)',true,false,false)Find_/_Replace(%7B'option':'Regex','string':'.*'%7D,'$R0',false,false,false,true)From_Decimal('Space',false)XOR(%7B'option':'Hex','string':'$R1'%7D,'Standard',false)) cyberchef recipe automatically performs XOR of two array and displays the strings.

![image](https://user-images.githubusercontent.com/71969773/175233778-cd9ebd42-cb03-44ed-b48a-71fcaea2ebac.png)  
|:--:|
| *Figure12(i). Decrypted strings in Cyberchef*|
![image](https://user-images.githubusercontent.com/71969773/175234091-46e8fbbe-3dc0-415a-8091-f64e74dfefb3.png)
|:--:|
| *Figure12(ii). Decrypted strings in Cyberchef*|  

Listing only readable ascii strings to your reference as by ignoring unreadable strings in above shown figures.
```
command
temp
","version":"
","pc_name":"
ps1
powershell
false
RedirectStandardInput
type
task_id
.exe
","arch":"
x64
","workgroup":"? | ?","dns":0,"protocol_version":2}
{"action":"get_file","hwid":"
status
+
;exit\r
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
<RSAKeyValue><Modulus>vjEvoW8nA/5q1oDr2MU0Q5KbYV14gco/yInNeaZrfR86DKWADAQ4JZzn+IJHCLdh+h3nikjbW7tkhCvHSCDHiXoH1bNKqriZ6St525Du3DkppbTr0KC7By+r389zkV2QFelUGFGG90r8RjjFh/VQg3sT4GLOAotxI4qMrHSqpWg3wVPUa2VlP/rbZk9aJN9llsygE8PHsonC5R7AevfG53ZLKok4jM2vuCgGLNhw+VWEp4i94W8SyCY5T5CUs7sp9EwBGAwd3l1jvg2w2FON1t1IMD0nFS/ObXCbbCV1XuqQZrRJMLbyaVWa8mFbRGY23OhIXBWrfTYP9zWecRGE6w==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
http://37.120.247.120
\APPDATA\ROAMING
Mode
BlockSize
Key
string
false
-.0123456789e+
-0123456789e+
{}[]:,
true
````

(ii) Char Encoding

![image](https://user-images.githubusercontent.com/71969773/175236138-36cc0b71-67b8-4afd-bccd-f1bdf8848ff6.png)  
|:--:|
| *Figure13. Encrypted strings through CHAR encoding*|

[This ](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%5Ct%5Ct%5Ct'%7D,'',true,false,true,false)Filter('Line%20feed','string%20arg%7Cint%20num(%5C%5Cd%2B)?%5C%5Cs%2B%5C%5C%3D%5C%5Cs%2B%5C%5Cd%7B2,%7D%7C%5C%5C(char%5C%5C)%5C%5C(%7Creturn%20arg%20%2B',false)Find_/_Replace(%7B'option':'Regex','string':'string%20%7C;%7Cint%20'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'(%5C%5Cd%2B%5C%5C))'%7D,'int($1)',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'(?%3C%3Dnum%5C%5Cd%2B%5C%5Cs%2B%5C%5C%3D%5C%5Cs%2B)(%5C%5Cd%2B)'%7D,'int($1)',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'char'%7D,'chr',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'return(.*)'%7D,'print(%22%5C%5C%5C%5Cn%22%2B$1)',true,false,true,false)Filter('Line%20feed','',false)) cyberchef recipe will convert the code into python format. And upon executing it with python complier, we could see both ascii and unreadable data.  


Listing below few is for reference.

```
,"protocol_version":2}
true
CreateNoWindow
UseShellExecute
","task_id":"
file
{"action":"change_status","hwid":"
task_id
","task_⟳d":"
","is_success":
x86
","rights":"
","os_name":"Win
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_
exe
","protocol_version":2}
{"action":"ping","hwid":"
command
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ
userprofile
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
ProductName
SOFTWARE\Microsoft\Windows NT\CurrentVersion
Method
uniq_hash
IV
Key
POST
```
Based on above strings as reference, we can presume that the adversaries collect basic system information such as Host, User, HWID, OS version and user profile data etc.  

These collected data is encrypted with RSA Key and exfiltrated over C2 server **37.120.247.120**

    <RSAKeyValue><Modulus>vjEvoW8nA/5q1oDr2MU0Q5KbYV14gco/yInNeaZrfR86DKWADAQ4JZzn+IJHCLdh+h3nikjbW7tkhCvHSCDHiXoH1bNKqriZ6St525Du3DkppbTr0KC7By+r389zkV2QFelUGFGG90r8RjjFh/VQg3sT4GLOAotxI4qMrHSqpWg3wVPUa2VlP/rbZk9aJN9llsygE8PHsonC5R7AevfG53ZLKok4jM2vuCgGLNhw+VWEp4i94W8SyCY5T5CUs7sp9EwBGAwd3l1jvg2w2FON1t1IMD0nFS/ObXCbbCV1XuqQZrRJMLbyaVWa8mFbRGY23OhIXBWrfTYP9zWecRGE6w==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>

![Postc2](https://user-images.githubusercontent.com/71969773/175892585-2745ef29-f003-4c99-aa96-ae752ad1e0f2.PNG)  
|:--:|
| *Figure15. Network communication*|

Following figure shows Wireshark intercepted traffic with C2 channel,  referenced from Twitter [^2]  

![image](https://user-images.githubusercontent.com/71969773/175892805-42dc1394-cf41-43f6-82c0-b38bd267c10f.png)  
|:--:|
| *Figure16. Data exfiltration over C2*|


#### Indicators of Compromise
_ZIP_  
e864d8d2a93f38d2714ad1f0b5f79cef79d46022cd6b29c3ed8e52c8c79e7ff9

_Unpacked EXE_    
56be46171da5aa65aa8ad5eec2252259fb8f9a3539c821377de357af7e459041  

_C2_  
37.120.247[.]120

#### References
[^1]: https://malpedia.caad.fkie.fraunhofer.de/details/win.solarmarker
[^2]:  [https://twitter.com/James_inthe_box/status/1524794392929705987]  


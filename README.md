Oracle PeopleSoft PS_TOKEN Extractor
====================================
Created by Sayed Hamzah, Centurion Information Security<br>
Twitter handle: @xxxbaemaxxx

Overview
--------
This is a Burp Plugin implementation of the TokenChpoken Tool developed by ERPScan.<br><br>

To use it, go to the dist/ folder and download the .py file onto your machine. Then simply add it as a Burp Plugin under the "Extender" tab. (Jython is required for this plugin to work!)

Functionalities
---------------
- Extracts and displays token information based on the decompressed data<br>
- Generates the Hashcat format <hash>:<salt> to perform brute-force/dictionary attacks in order to obtain the local node password<br>
- Generates a new PSTOKEN value that can be used in order to authenticate as another user (requires knowledge of the local node password, if need be)<br>

References
-----------
https://erpscan.com/author/alexey-tyurin/<br>
http://peoplesofttutorial.com/how-peoplesoft-single-signon-works/<br>
https://erpscan.com/press-center/blog/peoplesoft-security-part-4-peoplesoft-pentest-using-tokenchpoken-tool/


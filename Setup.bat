@echo off
set /p os=Enter your operating system (windows/linux): 

if /i "%os%"=="windows" (
    echo Installing required packages for Windows...
    pip install pystyle
    pip install colorama
    pip install requests
    pip install beautifulsoup4
    pip install tldextract
    pip install scapy
    pip install dnspython
    pip install python-whois
) else if /i "%os%"=="linux" (
    echo Installing required packages for Linux...
    pip3 install pystyle
    pip3 install colorama
    pip3 install requests
    pip3 install beautifulsoup4
    pip3 install tldextract
    pip3 install scapy
    pip3 install dnspython
    pip3 install python-whois
) else (
    echo Invalid operating system. Please enter "windows" or "linux".
    exit /b 1
)

echo Packages installed successfully.
exit /b 0
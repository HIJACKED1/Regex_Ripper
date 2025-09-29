#!/bin/bash

pip3 install -r requirements.txt
sudo mv Regex_Ripper.py /usr/local/bin/Regex_Ripper
sudo chmod +x /usr/local/bin/Regex_Ripper
sudo rm -rf ../Regex_Ripper

echo "Please Restart Your Terminal!!!"
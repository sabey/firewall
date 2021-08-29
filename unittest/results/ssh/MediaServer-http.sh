#!/bin/bash
### Server: "MediaServer"
### SSH Reverse Tunnel Shell: "http"
ssh -i secret_rsa -R 8080:127.0.0.1:3306 username@host

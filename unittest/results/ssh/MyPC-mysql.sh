#!/bin/bash
### Server: "MyPC"
### SSH Local Tunnel Shell: "mysql"
ssh -i secret_rsa -L localhost:3306:127.0.0.1:3306 username@host

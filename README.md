# SMTP-Client
Simple SMTP client written in Python.

# Usage

```
usage: client.py [-h] [-v] [-f FILE] server port sender

Simple SMTP client

positional arguments:
  server                smtp server address
  port                  smtp server listening port
  sender                sender e-mail address

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -f FILE, --file FILE  read composed e-mail message from a file. If not specified, read standard input
  ```
  
  # Gmail Issue 
  Sending an email using Gmail SMTP server *(smtp.gmail.com, 465)* requires an application-specific password for authentication, which can be configured using [this guide]( https://devanswers.co/outlook-and-gmail-problem-application-specific-password-required/).
  

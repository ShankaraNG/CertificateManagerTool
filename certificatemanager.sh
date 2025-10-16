#!/bin/bash

############################################################################################################
##                                 Certificate Manager                                                    ##
##                                                                                                        ##
## This Script is developed by Shankara N G                                                               ##
## It is to trigger certificate manager application to automate the certificate renewal process           ##
## It will check the certificate in the domain and then if the expiry date is 30 days it will             ##
## trigger the application to renew it                                                                    ##
## This Script is for Linux Terminal                                                                      ##
## Please edit the url and expiry days and the path where application is running                          ##
############################################################################################################

URL="yourdomain.com"
THRESHOLD_DAYS=30

# Get certificate expiry date
expiry_date=$(echo | openssl s_client -servername "$URL" -connect "$URL:443" 2>/dev/null | \
  openssl x509 -noout -enddate | cut -d= -f2)

if [ -z "$expiry_date" ]; then
  echo "Failed to fetch certificate expiry date"
  exit 1
fi

expiry_seconds=$(date -d "$expiry_date" +%s)
now_seconds=$(date +%s)
diff_days=$(( (expiry_seconds - now_seconds) / 86400 ))

echo "Certificate expires in $diff_days days."

if [ "$diff_days" -le "$THRESHOLD_DAYS" ]; then
  echo "Certificate is expiring. Proceeding to renew..."
  cd ~/PythonCertificates/CertificateManagerTool || exit
  source .venv/bin/activate
  python3 app.pyz
  deactivate
else
  echo "Certificate is valid"
fi

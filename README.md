############################################################################################################
##                                 Certificate Manager                                                    ##
##                                                                                                        ##
## This application is developed by Shankara N G                                                          ##
## This Application is to automate the process of certificate renewal and maintainance                    ##
## Generate both CSR and the key pair                                                                     ##
## Create a certificate based on the users requirement                                                    ##
## Automatically renew it and maintain it                                                                 ##
## Create keystore if necessary                                                                           ##
## Contact Shankara for further details on how to set up and run it                                       ##
############################################################################################################

I have installed Python 3.13.7 and build the environment and code accordingly please follow the steps below
Incase if you are using a different version of python remove the versions which is present in the end in the python code

To run the application on Windows server

cd E:\PythonCertificates\CertificateManagerTool
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Set-Content -Path app\__main__.py -Value "from main import main`nmain()"
# OR, if main.py runs directly without main()
# Set-Content -Path app\__main__.py -Value "import main"
python -m zipapp app -o app.pyz
python app.pyz


To Run the application on Linux Server

cd ~/PythonCertificates/CertificateManagerTool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
echo -e "from main import main\nmain()" > app/__main__.py
# OR, if main.py runs directly without main()
# echo "import main" > app/__main__.py
python -m zipapp app -o app.pyz
python app.pyz

To run it on your local machine through vs code

cd ~/PythonCertificates/CertificateManagerTool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt


I have also placed an automation scripts which is on Linux and Windows which will automatically trigger this
application on expiry. you can either schedule it over a cron or you can make it run on task manager

the scripts are

certificatemanager.sh
certificatemanager.bat

use these scripts to trigger the application. Please verify and read the scripts carefully . Understand and modify the threshold and paths accordingly

import os
import sys
import service.startup as startlog
import service.CSRAndKeyGeneration as CSRAndKeyGeneration
import service.certificateGenerator as certificateGenerator
import service.keystoreGenerator as keystoreGenerator
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import configloader as confloader
import log as logging


def certificatedriver():
    try:
        start = startlog.intro()
        logging.startinglogger(start)
        logging.logger('INFO', 'Certificate Manager', 200, "Starting the Certificate manager application")
        logging.logger('INFO', 'Certificate Manager', 200, "Proceeding to generate CSR and Key")
        result = CSRAndKeyGeneration.maincsrdriver()
        if not result:
            raise ValueError((400, f"Failed to generate CSR and Key"))
        logging.logger('INFO', 'Certificate Manager', 200, "CSR and Key generation successfull")
        logging.logger('INFO', 'Certificate Manager', 200, "Proceeding to generate the certificate")
        result = certificateGenerator.maincertdriver()
        if not result:
            raise ValueError((400, f"Failed to Generate the certificate"))
        logging.logger('INFO', 'Certificate Manager', 200, "Certificate Generated Successfully")
        logging.logger('INFO', 'Certificate Manager', 200, "Proceeding to either Generate the Keystore or converting the certificate to required format")
        result1,result2 = keystoreGenerator.mainkeystoredriver()
        if not result1 or not result2:
            raise ValueError((400, f"Failed to either Generate the Keystore or converting the certificate to required format"))
        logging.logger('INFO', 'Certificate Manager', 200, "Successfully completed the process to either Generate the Keystore or converting the certificate to required format")
        logging.logger('INFO', 'Certificate Manager', 200, "Certificate Manager has been ran successfully")
        config = confloader.read_config_cert()
        save_directory = config['save_directory']
        logging.logger('INFO', 'Certificate Manager', 200, f"Please find the required files in the following path {save_directory}")
        logging.logger('INFO', 'Certificate Manager', 200, "Shutting down the application")
        logging.logger('INFO', 'Certificate Manager', 200, "Application Shut down has been completed")
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)


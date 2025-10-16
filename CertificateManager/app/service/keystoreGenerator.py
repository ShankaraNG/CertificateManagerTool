import subprocess
import os
import sys
import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import configloader as confloader
import log as logging


def keystorewithfullchain(pathtofile,filename,keystorename,keystore_password, alias, alias_indicator):
    try:

        logging.logger('INFO', 'Certificate Manager', 200, "Creating a keystore from the given Root, Intermediate and server certificate")
        # Create a full chain of certificates
        fullchain= os.path.join(pathtofile, f"{filename}_fullchain.crt")
        certificate_crt= os.path.join(pathtofile, f"{filename}_certificate.pem")
        intermediate_crt= os.path.join(pathtofile, f"{filename}_intermediate_certificate.pem")
        root_crt= os.path.join(pathtofile, f"{filename}_root_certificate.pem")
        try:
            with open(fullchain, "wb") as f:
                with open(certificate_crt, "rb") as cert:
                    f.write(cert.read())
                with open(intermediate_crt, "rb") as intermediate:
                    f.write(intermediate.read())
                with open(root_crt, "rb") as root:
                    f.write(root.read())

            logging.logger('INFO', 'Certificate Manager', 200, f"Full certificate chain created successfully at {fullchain}.")
        except Exception as e:
            if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
                code, message = e.args[0]
            else:
                code, message = 400, str(e)
            logging.logger('ERROR', 'Certificate Manager', code, message)
            if code in [204, 400]:
                sys.exit(1)
            return None
        # Define the OpenSSL command with the password option
        private_key_filename=os.path.join(pathtofile, f"{filename}.key")
        keystorename=os.path.join(pathtofile, f"{keystorename}.p12")
        openssl_path = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
        if(alias_indicator):
            openssl_command = [
                openssl_path, "pkcs12", "-export",
                "-in", fullchain, "-inkey", private_key_filename,
                "-out", keystorename,
                "-name", alias,
                "-password", f"pass:{keystore_password}"
            ]
        else:
            openssl_command = [
                "openssl", "pkcs12", "-export",
                "-in", fullchain, "-inkey", private_key_filename,
                "-out", keystorename,
                "-password", f"pass:{keystore_password}"
            ]        
        subprocess.run(openssl_command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, "Keystore created successfully")
        return "success"
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None

def keystorewithonlycertificate(pathtofile,filename,keystorename,keystore_password, alias, alias_indicator):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, "Creating a keystore from the given Self signed certificate")
        # Define the OpenSSL command with the password option
        certificate_crt= os.path.join(pathtofile, f"{filename}_certificate.pem")
        private_key_filename=os.path.join(pathtofile, f"{filename}.key")
        keystorename=os.path.join(pathtofile, f"{keystorename}.p12")
        openssl_path = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
        if(alias_indicator):
            openssl_command = [
                openssl_path, "pkcs12", "-export",
                "-in", certificate_crt, "-inkey", private_key_filename,
                "-out", keystorename,
                "-name", alias,
                "-password", f"pass:{keystore_password}"
            ]
        else:
            openssl_command = [
                "openssl", "pkcs12", "-export",
                "-in", certificate_crt, "-inkey", private_key_filename,
                "-out", keystorename,
                "-password", f"pass:{keystore_password}"
            ]        
        subprocess.run(openssl_command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, "Keystore created successfully")
        return "success"
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None

def converttojks(keytoolpath, pathtofile, keystorename, src_password, dest_password):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, f"Converting the Keystore to JKS format")
        src_keystore=os.path.join(pathtofile, f"{keystorename}.p12")
        dest_keystore=os.path.join(pathtofile, f"{keystorename}.jks")
        command = [
            keytoolpath, #add your keytool path
            "-importkeystore", 
            "-srckeystore", src_keystore, 
            "-srcstoretype", "PKCS12", 
            "-srcstorepass", src_password,
            "-destkeystore", dest_keystore, 
            "-deststoretype", "JKS", 
            "-deststorepass", dest_password
        ]
        requiredValues = {
            'keytoolpath': keytoolpath,
            'pathtofile': pathtofile,
            'keystorename': keystorename,
            'src_password': src_password,
            'dest_password': dest_password
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))

        # Run the command using subprocess
        subprocess.run(command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, f"Keystore {src_keystore} converted to JKS successfully.")
        return "success"
    except subprocess.CalledProcessError as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None

def converttobks(keytoolpath, pathtofile, keystorename, src_password, dest_password, bc_provider_path):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, f"Converting the Keystore to BKS format")
        src_keystore=os.path.join(pathtofile, f"{keystorename}.p12")
        dest_keystore=os.path.join(pathtofile, f"{keystorename}.bks")    
        command = [
            keytoolpath, 
            "-importkeystore", 
            "-srckeystore", src_keystore, 
            "-srcstoretype", "PKCS12", 
            "-srcstorepass", src_password,   # Specify source keystore password
            "-destkeystore", dest_keystore, 
            "-deststoretype", "BKS", 
            "-deststorepass", dest_password, # Specify destination keystore password
            "-providerClass", "org.bouncycastle.jce.provider.BouncyCastleProvider", 
            "-providerPath", bc_provider_path  # Path to Bouncy Castle JAR file
        ]

        requiredValues = {
            'keytoolpath': keytoolpath,
            'pathtofile': pathtofile,
            'keystorename': keystorename,
            'src_password': src_password,
            'dest_password': dest_password,
            'bc_provider_path': bc_provider_path
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))


        # Run the command using subprocess
        subprocess.run(command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, f"Keystore {src_keystore} converted to BKS successfully.")
        return "success"
    except subprocess.CalledProcessError as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None

def converttojceks(keytoolpath, pathtofile, keystorename, src_password, dest_password):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, f"Converting the Keystore to JCEKS format")
        src_keystore=os.path.join(pathtofile, f"{keystorename}.p12")
        dest_keystore=os.path.join(pathtofile, f"{keystorename}.jceks")
        command = [
            keytoolpath, 
            "-importkeystore", 
            "-srckeystore", src_keystore, 
            "-srcstoretype", "PKCS12", 
            "-srcstorepass", src_password,   # Specify source keystore password
            "-destkeystore", dest_keystore, 
            "-deststoretype", "JCEKS", 
            "-deststorepass", dest_password  # Specify destination keystore password
        ]

        requiredValues = {
            'keytoolpath': keytoolpath,
            'pathtofile': pathtofile,
            'keystorename': keystorename,
            'src_password': src_password,
            'dest_password': dest_password
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))

        subprocess.run(command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, f"Keystore {src_keystore} converted to JCEKS successfully.")
        return "success"
    except subprocess.CalledProcessError as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None


def convert_pem_to_crt(pathtofile,filename):    
    try:
        pem_file=os.path.join(pathtofile, f"{filename}_certificate.pem")
        crt_file=os.path.join(pathtofile, f"{filename}_certificate.crt")
        openssl_path = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
        command = [
            openssl_path, "x509", 
            "-in", pem_file, 
            "-out", crt_file
        ]
        subprocess.run(command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, f"Successfully converted {pem_file} to {crt_file}")
        return "success"
    except subprocess.CalledProcessError as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None

def convert_pem_to_cer(pathtofile,filename):   
    try:
        pem_file=os.path.join(pathtofile, f"{filename}_certificate.pem")
        cer_file=os.path.join(pathtofile, f"{filename}_certificate.cer")
        openssl_path = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
        command = [
            openssl_path, "x509", 
            "-in", pem_file, 
            "-out", cer_file
        ]
        subprocess.run(command, check=True)
        logging.logger('INFO', 'Certificate Manager', 200, f"Successfully converted {pem_file} to {cer_file}")
        return "success"
    except subprocess.CalledProcessError as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None



def mainkeystoredriver():    
    try:
        config = confloader.read_key_config_keystoregenerator()
        save_directory = config['save_directory']
        filename = config['filename']
        keytoolpath = config['keytoolpath']
        bc_provider_path = config['bc_provider_path']
        alias_indicator = config['alias_indicator']
        alias = config['alias']
        keystore_password = config['keystore_password']
        keystorename = config['keystorename']
        keystoretypeRequired = config['keystoretypeRequired']
        keystoreformatRequired = config['keystoreformatRequired']
        keystoreindicator = config['keystoreindicator']
        required_keys = [
            'save_directory',
            'filename',
            'keytoolpath',
            'bc_provider_path',
            'alias_indicator',
            'alias',
            'keystore_password',
            'keystorename',
            'keystoretypeRequired',
            'keystoreformatRequired',
            'keystoreindicator'
        ]

        if any(not config.get(k) or str(config.get(k)).strip() == '' for k in required_keys):
            raise ValueError((400, "Required configuration values are missing or empty"))
        result1 = None
        result2 = None
        if(keystoreindicator):
            if(keystoretypeRequired=='fullchainkeystore'):
                result1 = keystorewithfullchain(save_directory,filename,keystorename,keystore_password, alias, alias_indicator)
                if(keystoreformatRequired == "jks"):
                    result2 = converttojks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password)
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the JKS format")
                elif(keystoreformatRequired == "p12"):
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the p12 format")
                    result2 = result1
                elif(keystoreformatRequired == "bks"):
                    result2 = converttobks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password, bc_provider_path)
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the bks format")
                elif(keystoreformatRequired == "jceks"):
                    result2 = converttojceks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password)
                else:
                    raise Exception((400,"Invalid Input for the keystoreformat"))
            elif(keystoretypeRequired=='selfsignedkeystore'):
                result1 = keystorewithonlycertificate(save_directory,filename,keystorename,keystore_password, alias, alias_indicator)
                if(keystoreformatRequired == "jks"):
                    result2 = converttojks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password)
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the JKS format")
                elif(keystoreformatRequired == "p12"):
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the p12 format")
                    result2 = result1
                elif(keystoreformatRequired == "bks"):
                    result2 = converttobks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password, bc_provider_path)
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the bks format")
                elif(keystoreformatRequired == "jceks"):
                    result2 = converttojceks(keytoolpath, save_directory, keystorename, keystore_password, keystore_password)
                    logging.logger('INFO', 'Certificate Manager', 200, "Keystore Created in the jceks format")
                else:
                    raise Exception((400,"Invalid Input for the keystoreformat"))
            else:
                raise Exception((400,"Invalid Input for the keystoretypeRequired"))
        elif(not keystoreindicator):
            if(keystoretypeRequired== "cer"):
                result1 = "success"
                result2 = convert_pem_to_cer(save_directory,filename)
                logging.logger('INFO', 'Certificate Manager', 200, "certificates converted into cer format")
            elif(keystoreformatRequired == "pem"):
                result1 = "success"
                logging.logger('INFO', 'Certificate Manager', 200, "certificates converted into pem format")
                result2 = result1
            elif(keystoreformatRequired == "crt"):
                result1 = "success"
                result2 = convert_pem_to_crt(save_directory,filename)
                logging.logger('INFO', 'Certificate Manager', 200, "certificates converted into crt format")
            else:
                raise Exception((400,"Invalid Input for the keystoretypeRequired"))
        else:
            raise Exception((400,"Invalid Input for the keystoretypeRequired"))
        
        return result1,result2
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None, None

# mainkeystoredriver()
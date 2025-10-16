from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509 import load_pem_x509_csr, load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
import datetime
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import configloader as confloader
import log as logging

def selfsignedcertificate(pathtofile,filename):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, "Creating a self signed certificate")
        keyfilepath= os.path.join(pathtofile, f"{filename}.key")
        with open(keyfilepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        csrfilepath= os.path.join(pathtofile, f"{filename}.csr")
        with open(csrfilepath, 'rb') as csr_file:
            csr = load_pem_x509_csr(csr_file.read())

        subject = csr.subject
        logging.logger('INFO', 'Certificate Manager', 200, f"CSR Subject: {subject}")
        
        certificate_builder = CertificateBuilder()
        # Use CSR's subject for self-signed certificate
        certificate_builder = certificate_builder.subject_name(subject)
        # Set issuer as the same subject for a self-signed certificate
        certificate_builder = certificate_builder.issuer_name(subject)
        # Use the public key from the CSR to generate the certificate
        certificate_builder = certificate_builder.public_key(csr.public_key())
        # Set certificate validity period 
        not_valid_before = datetime.datetime.now(datetime.UTC)
        not_valid_after = not_valid_before + datetime.timedelta(days=365)
        certificate_builder = certificate_builder.not_valid_before(not_valid_before)
        certificate_builder = certificate_builder.not_valid_after(not_valid_after)
        # Set the serial number (could be any large number, for example 1000)
        certificate_builder = certificate_builder.serial_number(1000)
        # Sign the certificate with the private key
        certificate = certificate_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        # Save the self-signed certificate to a file
        certfilepath= os.path.join(pathtofile, f"{filename}_certificate.pem")
        with open(certfilepath, 'wb') as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        logging.logger('INFO', 'Certificate Manager', 200, "Self-signed certificate generated successfully.")
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



def selfsignedcertificate_Withrootandintermediate_withoutCSRandKeyforrootandintermediate(pathtofile,filename):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, "Creating a Self Signed certificate by creating an Intermediate and Root")
        # Function to generate a certificate from a CSR
        def generate_certificate_withoutCSRandKeyforrootandintermediate(csr, private_key, issuer_name, serial_number, valid_days, issuer_private_key):
            certificate_builder = CertificateBuilder()
            certificate_builder = certificate_builder.subject_name(csr.subject)
            certificate_builder = certificate_builder.issuer_name(issuer_name)
            certificate_builder = certificate_builder.public_key(csr.public_key())
            
            not_valid_before = datetime.datetime.now(datetime.UTC)
            not_valid_after = not_valid_before + datetime.timedelta(days=valid_days)
            certificate_builder = certificate_builder.not_valid_before(not_valid_before)
            certificate_builder = certificate_builder.not_valid_after(not_valid_after)
            
            certificate_builder = certificate_builder.serial_number(serial_number)
            
            # Sign the certificate with the private key of the issuer (or self for root)
            if issuer_private_key:
                certificate = certificate_builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
            else:
                certificate = certificate_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
            
            return certificate


        keyfilepath= os.path.join(pathtofile, f"{filename}.key")
        # Load the private key for the root CA from a file
        with open(keyfilepath, 'rb') as key_file:
            root_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # Load the CSR for the end entity (leaf certificate)
        csrfilepath= os.path.join(pathtofile, f"{filename}.csr")
        with open(csrfilepath, 'rb') as csr_file:
            end_entity_csr = load_pem_x509_csr(csr_file.read())

        # Extract subject information from CSR (optional)
        subject = end_entity_csr.subject
        logging.logger('INFO', 'Certificate Manager', 200, f"End Entity CSR Subject: {subject}")

        # Generate Root Certificate (Self-signed)
        root_subject = subject
        root_certificate = generate_certificate_withoutCSRandKeyforrootandintermediate(end_entity_csr, root_private_key, root_subject, serial_number=1000, valid_days=3650, issuer_private_key=None)  # Root certificate valid for 10 years
        rootcertfilepath= os.path.join(pathtofile, f"{filename}_root_certificate.pem")
        with open(rootcertfilepath, 'wb') as root_cert_file:
            root_cert_file.write(root_certificate.public_bytes(serialization.Encoding.PEM))

        logging.logger('INFO', 'Certificate Manager', 200, "Root certificate generated successfully")

        #Generate Intermediate Certificate signed by Root Certificate
        intermediate_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate_csr = end_entity_csr
        intermediate_certificate = generate_certificate_withoutCSRandKeyforrootandintermediate(intermediate_csr, intermediate_private_key, root_subject, serial_number=2000, valid_days=1825, issuer_private_key=root_private_key)
        intermmediatecertfilepath= os.path.join(pathtofile, f"{filename}_intermediate_certificate.pem")
        with open(intermmediatecertfilepath, 'wb') as intermediate_cert_file:
            intermediate_cert_file.write(intermediate_certificate.public_bytes(serialization.Encoding.PEM))
        logging.logger('INFO', 'Certificate Manager', 200, "Intermediate certificate generated successfully")


        # Generate Server Certificate signed by Intermediate Certificate
        certfilepath= os.path.join(pathtofile, f"{filename}_certificate.pem")
        end_entity_certificate = generate_certificate_withoutCSRandKeyforrootandintermediate(end_entity_csr, root_private_key, root_subject, serial_number=3000, valid_days=365, issuer_private_key=intermediate_private_key)
        with open(certfilepath, 'wb') as end_entity_cert_file:
            end_entity_cert_file.write(end_entity_certificate.public_bytes(serialization.Encoding.PEM))

        logging.logger('INFO', 'Certificate Manager', 200, "server certificate generated successfully")
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

def selfsignedcertificate_Withrootandintermediate_withCERandKeyforrootandintermediate(pathtofile, filename):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, "Creating a Server Certificate with already existing intermediate certificate")
        def generate_certificate_withCERandKeyforrootandintermediate(csr, private_key, issuer_name, serial_number, valid_days, issuer_private_key=None):
            try:
                certificate_builder = CertificateBuilder()
                certificate_builder = certificate_builder.subject_name(csr.subject)
                certificate_builder = certificate_builder.issuer_name(issuer_name)
                certificate_builder = certificate_builder.public_key(csr.public_key())
                
                not_valid_before = datetime.datetime.now(datetime.UTC)
                not_valid_after = not_valid_before + datetime.timedelta(days=valid_days)
                certificate_builder = certificate_builder.not_valid_before(not_valid_before)
                certificate_builder = certificate_builder.not_valid_after(not_valid_after)
                
                certificate_builder = certificate_builder.serial_number(serial_number)
                
                # Sign the certificate with the private key of the issuer (either root or intermediate)
                if issuer_private_key:
                    certificate = certificate_builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
                else:
                    certificate = certificate_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
                
                return certificate
            except Exception as e:
                if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
                    code, message = e.args[0]
                else:
                    code, message = 500, str(e)
                logging.logger('ERROR', 'Certificate Manager', code, message)
                if code in [204, 400]:
                    sys.exit(1)
                return None 

        # Load the private key for the intermediate CA
        intermediatekeyfilepath= os.path.join(pathtofile, f"{filename}_intermediate_private_key.key")
        with open(intermediatekeyfilepath, 'rb') as key_file:
            intermediate_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        # Load the CSR for the server certificate (leaf certificate)
        csrfilepath= os.path.join(pathtofile, f"{filename}.csr")
        with open(csrfilepath, 'rb') as csr_file:
            end_entity_csr = load_pem_x509_csr(csr_file.read())
        # Load the intermediate certificate
        intermmediatecertfilepath= os.path.join(pathtofile, f"{filename}_intermediate_certificate.pem")
        with open(intermmediatecertfilepath, 'rb') as cert_file:
            intermediate_certificate = load_pem_x509_certificate(cert_file.read())
        subject = end_entity_csr.subject
        logging.logger('INFO', 'Certificate Manager', 200, f"End Entity CSR Subject: {subject}")

        # Generate Server Certificate signed by the Intermediate Certificate
        server_certificate = generate_certificate_withCERandKeyforrootandintermediate(end_entity_csr, intermediate_private_key, intermediate_certificate.subject, serial_number=3000, valid_days=365, issuer_private_key=intermediate_private_key)
        certfilepath= os.path.join(pathtofile, f"{filename}_certificate.pem")
        with open(certfilepath, 'wb') as server_cert_file:
            server_cert_file.write(server_certificate.public_bytes(serialization.Encoding.PEM))
        logging.logger('INFO', 'Certificate Manager', 200, "Server certificate signed by intermediate certificate generated successfully")
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


def maincertdriver():    
    try:
        config = confloader.read_config_cert()
        save_directory = config['save_directory']
        filename = config['filename']
        CertTypeRequired = config['CertTypeRequired']
        IntermediateCertFile = config['IntermediateCertFile']
        IntermediateKeyFile = config['IntermediateKeyFile']
        result = None
        if(not CertTypeRequired or CertTypeRequired.isspace()):
            raise ValueError("CertTypeRequired is missing or empty in the configuration file")
        else:
            if(CertTypeRequired == "SelfSignedCert"):
                logging.logger('INFO', 'Certificate Manager', 200, "Proceeding to create a self signed certificate")
                result = selfsignedcertificate(save_directory,filename)
            elif(CertTypeRequired == "CertOverIntermmediate"):
                if(IntermediateCertFile and IntermediateKeyFile):
                    logging.logger('INFO', 'Certificate Manager', 200, "Generating Server Certificate over Intermediate")
                    result = selfsignedcertificate_Withrootandintermediate_withCERandKeyforrootandintermediate(save_directory,filename)
                else:
                    logging.logger('INFO', 'Certificate Manager', 200, "Generating Certificate over Intermediate by creating own root and intermmediate certificate")
                    result = selfsignedcertificate_Withrootandintermediate_withoutCSRandKeyforrootandintermediate(save_directory, filename)
            else:
                raise Exception("The Input value for the the CertTypeRequired is invalid")
        return result            
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None 

# maincertdriver()
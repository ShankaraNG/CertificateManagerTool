from OpenSSL import crypto
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import configloader as confloader
import log as logging

# Generate a private key
def generate_private_key(save_dir, filename):
    try:
        logging.logger('INFO', 'Certificate Manager', 200, "Generating the Private Key")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        key_file_path = os.path.join(save_dir, f"{filename}.key")
        with open(key_file_path, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        logging.logger('INFO', 'Certificate Manager', 200, "Successfully generated the private Key")

        return key_file_path, key
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None    

def create_openssl_config_with_san(san_dns, save_dir, country, state, city, organization, commonname):
    try:
        requiredValues = {
            'san_dns': san_dns,
            'save_dir': save_dir,
            'country': country,
            'state': state,
            'city': city,
            'organization': organization,
            'commonname': commonname
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))
        config_file_path = os.path.join(save_dir, "openssl.cnf")
        with open(config_file_path, "w") as config:
            config.write(f"""
    [ req ]
    default_bits = 2048
    distinguished_name = req_distinguished_name
    req_extensions = req_ext
    prompt = no

    [ req_distinguished_name ]
    C = {country}
    ST = {state}
    L = {city}
    O = {organization}
    CN = {commonname}

    [ req_ext ]
    subjectAltName = @alt_names

    [ alt_names ]
    """)
            for i, dns in enumerate(san_dns, 1):
                config.write(f"DNS.{i} = {dns}\n")

        return config_file_path
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None    
       


def create_openssl_config(save_dir, country, state, city, organization, commonname):
    try:
        requiredValues = {
            'save_dir': save_dir,
            'country': country,
            'state': state,
            'city': city,
            'organization': organization,
            'commonname': commonname
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))


        config_file_path = os.path.join(save_dir, "openssl.cnf")
        with open(config_file_path, "w") as config:
            config.write(f"""
    [ req ]
    default_bits = 2048
    distinguished_name = req_distinguished_name
    prompt = no

    [ req_distinguished_name ]
    C = {country}
    ST = {state}
    L = {city}
    O = {organization}
    CN = {commonname}

    """)

        return config_file_path
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None   


# Step 3: Generate CSR with SAN using OpenSSL configuration file
def generate_csr_with_san(private_key_path, san_dns, save_dir, country, state, city, organization, commonname, filename, san_check):
    try:
        if(san_check):
            logging.logger('INFO', 'Certificate Manager', 200, "Creating the config file to generate CSR with SAN")
            config_file_path = create_openssl_config_with_san(san_dns, save_dir, country, state, city, organization, commonname)
            if config_file_path:
                logging.logger('INFO', 'Certificate Manager', 200, "Config file has been created successfully")
            else:
                raise ValueError((400, f"Config file has not been generated"))
        else:
            logging.logger('INFO', 'Certificate Manager', 200, "Creating the config file to generate CSR without SAN")
            config_file_path = create_openssl_config(save_dir, country, state, city, organization, commonname)
            if config_file_path:
                logging.logger('INFO', 'Certificate Manager', 200, "Config file has been created successfully")
            else:
                raise ValueError((400, f"Config file has not been generated"))
                
        csr_file_path = os.path.join(save_dir, f"{filename}.csr")
        openssl_path = r'"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"'
        command = f"{openssl_path} req -new -key {private_key_path} -out {csr_file_path} -config {config_file_path}"
        logging.logger('INFO', 'Certificate Manager', 200, f"Generating CSR")
        os.system(command)
        logging.logger('INFO', 'Certificate Manager', 200, f"CSR generated and saved to {csr_file_path}")
        os.remove(config_file_path)
        logging.logger('INFO', 'Certificate Manager', 200, f"Config file has been removed")
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



def maincsrdriver():    

    try:
        config = confloader.read_config_csrandkeygenerator()
        save_directory = config['save_directory']
        filename = config['filename']
        san_check = config['san_check']
        san_dns = config['san_dns']
        country = config['country']
        state = config['state']
        city = config['city']
        organization = config['organization']
        commonname = config['commonname']
        requiredValues = {
            'save_directory': save_directory,
            'filename': filename,
            'san_check': san_check,
            'san_dns': san_dns,
            'country': country,
            'state': state,
            'city': city,
            'organization': organization,
            'commonname': commonname
        }

        for key, value in requiredValues.items():
            if value is None or str(value).strip() == '':
                raise ValueError((400, f"Required value '{key}' is missing or empty"))
    # Code that may raise an exception
        private_key_path, private_key = generate_private_key(save_directory, filename)
        if(not private_key):
            raise ValueError((400, "Private key is missing or invalid!"))
    # Code that may raise an exception
        result = None
        result = generate_csr_with_san(private_key_path, san_dns, save_directory, country, state, city, organization, commonname, filename, san_check)
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
    
# maincsrdriver()
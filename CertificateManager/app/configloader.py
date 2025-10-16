import configparser
import logging as logging
import sys

def read_key_config_keystoregenerator():
    try:
        config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
        config = configparser.ConfigParser()
        config.read(config_file)
        
        settings = {
            'save_directory': config.get('DEFAULT', 'save_directory'),
            'filename': config.get('DEFAULT', 'filename'),
            'keytoolpath': config.get('DEFAULT', 'keytoolpath'),
            'bc_provider_path': config.get('DEFAULT', 'bc_provider_path'),
            'alias_indicator': config.get('DEFAULT', 'alias_indicator').strip().lower() == 'true',
            'alias': config.get('DEFAULT', 'alias'),
            'keystore_password': config.get('DEFAULT', 'keystore_password'),
            'keystorename': config.get('DEFAULT', 'keystorename'),
            'keystoretypeRequired': config.get('DEFAULT', 'keystoretypeRequired'),
            'keystoreformatRequired': config.get('DEFAULT', 'keystoreformatRequired'),
            'keystoreindicator': config.get('DEFAULT', 'keystoreindicator')
        }
        
        for key, value in settings.items():
            if value == '':
                raise ValueError(f"Configuration value for '{key}' is missing or empty.")
        
        return settings
    except Exception as e:
        if isinstance(e.args[0], tuple) and len(e.args[0]) == 2:
            code, message = e.args[0]
        else:
            code, message = 500, str(e)
        logging.logger('ERROR', 'Certificate Manager', code, message)
        if code in [204, 400]:
            sys.exit(1)
        return None


def read_config_csrandkeygenerator():
    config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
    config = configparser.ConfigParser()
    config.read(config_file)
    
    settings = {
        'save_directory': config.get('DEFAULT', 'save_directory'),
        'filename': config.get('DEFAULT', 'filename'),
        'san_check': config.get('DEFAULT', 'san_check').strip().lower() == 'true',
        'san_dns': config.get('DEFAULT', 'san_dns').split(','),
        'country': config.get('DEFAULT', 'country'),
        'state': config.get('DEFAULT', 'state'),
        'city': config.get('DEFAULT', 'city'),
        'organization': config.get('DEFAULT', 'organization'),
        'commonname': config.get('DEFAULT', 'commonname'),
        'opensslpath': config.get('DEFAULT', 'opensslpath')
    }
    for key, value in settings.items():
        if value == '':
            raise ValueError(f"Configuration value for '{key}' is missing or empty.")


    return settings

def read_config_cert():
    config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
    config = configparser.ConfigParser()
    config.read(config_file)
    settings = {
        'save_directory': config.get('DEFAULT', 'save_directory'),
        'filename': config.get('DEFAULT', 'filename'),
        'CertTypeRequired': config.get('DEFAULT', 'CertTypeRequired', fallback=None),
        'IntermediateCertFile': config.get('DEFAULT', 'IntermediateCertFile').strip().lower() == 'true',
        'IntermediateKeyFile': config.get('DEFAULT', 'IntermediateKeyFile').strip().lower() == 'true'
    }

    for key, value in settings.items():
        if value == '':
            raise ValueError(f"Configuration value for '{key}' is missing or empty.")

    return settings

def read_config_log():
    config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
    config = configparser.ConfigParser()
    config.read(config_file)
    settings = {
        'loggingFilePath': config.get('DEFAULT', 'loggingFilePath')
    }

    for key, value in settings.items():
        if value == '':
            raise ValueError(f"Configuration value for '{key}' is missing or empty.")

    return settings
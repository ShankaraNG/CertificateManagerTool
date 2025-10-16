# '{date} INFO [Certificate Manager] 200 certificate csr file has been generated'.format(date=datetime.now().strftime('%d %B %Y %H:%M:%S,%f')[:-3])
from datetime import datetime
import sys
import os
import configparser


def logger(information, type, exceptioncode, data):
    log = '{date} {information} [{type}] {exceptioncode} {data}'.format(date=datetime.now().strftime('%d %B %Y %H:%M:%S,%f')[:-3],information = information, type= type, exceptioncode = exceptioncode, data = data)
    print(log)
    config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
    config = configparser.ConfigParser()
    config.read(config_file)
    logfile = config.get('DEFAULT', 'loggingFilePath')
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(log + '\n')

def startinglogger(data):
    print(data)
    config_file = "E:\\PythonCertificates\\CertificateManagerTool\\CertificateManagerTool\\CertificateManager\\config\\configuration.properties"
    config = configparser.ConfigParser()
    config.read(config_file)
    logfile = config.get('DEFAULT', 'loggingFilePath')
    print(logfile)
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(data + '\n')

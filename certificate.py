#!/usr/bin/python
from OpenSSL import crypto
from flask_restful import Resource
from flask import request
import os
import datetime
import base64

#Variables
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
HOME = "./certificates" #os.getenv("HOME")
now = datetime.datetime.now()
d = now.date()

#Retrieve key path
def get_keypath(cn) -> str:
    return HOME + '/' + cn + '-' + str(d) + '.key'

#Retrieve csr path
def get_csrpath(cn) -> str:
    return HOME + '/' + cn + '-' + str(d) + '.csr'

#Retrieve crt path
def get_crtpath(cn) -> str:
    return HOME + '/' + cn + '-' + str(d) + '.crt'

def print_log(msg):
    print(datetime.datetime.now(), msg)

class CrearCertificados(Resource):
    def post(self):
        api = request.json["api"]
        print_log('Api requests certificate:' + api)
        response = create_certificate(api)
        return response

def create_certificate(name) -> object:
    print_log('Creating certificate for:' + name)
    
    generatekey(name)
    return generatecrt(name)

def initialize_certificates():
    print_log('Initializing certificates for root')
    create_certificate("root")


#Generate the key  
def generatekey(cn):
    
    key = crypto.PKey()
    keypath = get_keypath(cn)
    if os.path.exists(keypath):
        print_log("Certificate file exists, aborting.")
        print_log(keypath)
    #Else write the key to the keyfile
    else:
        print_log("Generating Key Please standby")
        key.generate_key(TYPE_RSA, 4096)
        f = open(keypath, "wb")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        f.close()

    #return key    
            
#Generate CRT
def generatecrt(cn) -> object:
    crtpath = get_crtpath(cn)
    
    c = 'CO'
    st = 'CUNDINAMARCA'
    l = ""
    if cn == "root": 
        l = 'BOGOTA D.C.'
    else:
        l = "MADRID"
    o = 'UNIANDES'
    ou = 'MISO'
    keypath = get_keypath(cn)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(keypath).read())
    #Generate the certificate
    cert = crypto.X509()

    cert.get_subject().CN = cn
    cert.get_subject().C = c
    cert.get_subject().ST = st
    cert.get_subject().L = l
    cert.get_subject().O = o
    cert.get_subject().OU = ou
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_pubkey(key)
        
    if cn == "root":
        cert.set_issuer(cert.get_subject())
        cert.sign(key, "sha256")
    else:
        cert_root = crypto.load_certificate(
            crypto.FILETYPE_PEM, 
            open(get_crtpath('root')).read())
        
        cert.set_issuer(cert_root.get_subject())
        
        root_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, 
            open(get_keypath('root')).read())
        
        cert.sign(root_key, "sha256")

    if os.path.exists(crtpath):
        print_log("Certificate File Exists, aborting.")
        print_log(crtpath)
    else:
        f = open(crtpath, "wb")
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.close()
        print_log('Success')


    return_key = base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return_cert = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    return {
        "api": cn,
        "private_key": return_key.decode("ascii"),
        "public_cert": return_cert.decode("ascii")
    }

"""This module describes Tornado handler,
   which receives a message from certified sender,'
   checks certificate and certficate_DN
   and if all is ok send message to message queue,
   configuration is described in handler_config.json"""

import datetime
import json
import sys
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import tornado.web
import tornado.httpserver
import tornado.ioloop
from tornado.options import options, define
from stompSender import StompSender


# pylint: disable=invalid-name,protected-access,arguments-differ,abstract-method,line-too-long,unused-argument,too-many-locals


def read_cert(cert_path):
    """
    Function which return x509 certificate from string path
    """
    cert_file = open(cert_path, 'r')
    cert_data = cert_file.read()
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    return cert


def are_params_valid(files, server_cert_path, CA_cert_path, network):
    """Checking if params are valid, params:
        files - list of file_paths to certificates and json
        server_cert - path to server certificate
        CA_cert - path to CA certificate
        network - dictionary of tuples
        {Tornado:('server_url',port), MQ:('MQ_url', port)}"""
        #Checking if files exists
    for filename in files:
        try:
            open(filename)
        except IOError:
            raise IOError('This %s cannot be accessed' %  filename)
    #Checking certificates
    today = datetime.datetime.now()
    print 'Today is %s ' % today.date()
    print 'Time of checking certificates - %d hour, %d minute,  %d second' % (today.hour, today.minute, today.second)
    #Checking certificates dates
    for cert_path in [server_cert_path, CA_cert_path]:
        cert = read_cert(cert_path)
        if cert.not_valid_after < today or cert.not_valid_before > today:
            raise RuntimeError('This certficate %s isn`t valid at this moment' % cert_path)
    print 'Date and time of certificates is ok'
    #Checking certificates signature
    server_cert = read_cert(server_cert_path)
    CA_cert = read_cert(CA_cert_path)
    CA_key = CA_cert.public_key()
    CA_key.verify(server_cert.signature, server_cert.tbs_certificate_bytes, padding.PKCS1v15(), server_cert.signature_hash_algorithm)
    print 'Signature of certificate is ok'
    #Checking certificates CN
    Tornado_CN = network['Tornado'][0]
    cert_subject = server_cert.subject
    cert_CN = cert_subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if Tornado_CN != cert_CN:
        raise RuntimeError('CN of this server certificate doesn`t equals to url of Tornado Handler')
    else:
        print 'CN of server certificate subject is equal to url of handler'
    #Test if address is already in use
    try:
        test = socket.socket()
        test.bind(network['Tornado'])
        test.close()
    except Exception, e:
        raise e
    return True

def transform_str_to_dict(strdn):
    """From  /DC=ch/DC=cern/OU=computers/CN=lhcbci-cernvm03.cern.ch
       to {'subject':['DC', 'ch', 'DC', 'cern', 'CN', 'lhcbi-cernvm03.cern.ch']}"""
    dn_list = strdn.split('/')
    json_dict = {'subject':[]}
    for element in dn_list:
        if '=' in element:
            element_list = element.split('=')
            json_dict['subject'].append(element_list[0])
            json_dict['subject'].append(element_list[1])
    return json_dict

def transform_dn_components_to_str(dn_list):
    """ [('DC', 'ch'), ('DC', 'cern'), ('OU', 'computers'), ('CN', 'lhcbci-cernvm03.cern.ch')]
        to /DC=ch/DC=cern/OU=computers/CN=lhcbci-cernvm03.cern.ch"""
    for element in dn_list:
        if len(element) != 2:
            raise ValueError('There must be only 2 elements in this tuple')
    transformed = ['/'+element[0]+'='+element[1] for element in dn_list]
    return ''.join(transformed)

def extract_DN(cert):
    """Extract DN from certificate (bytes ?)"""
    certificate = x509.load_der_x509_certificate(cert, default_backend())
    subject = certificate.subject
    dn = {}
    for attribute in subject:
        dn[attribute.oid._name] = attribute.value

    return dn
def valid_cert(client_cert, validDNs):
    '''Comparing client DN in dictionary form to DN which are in text file'''
    client_dn = extract_DN(client_cert)
    return client_dn in validDNs

def generateMQConfig(old_conf):
    """This function generates configuration from old one"""
    conf = {}
    conf['Host'] = old_conf['mq_host']
    conf['Port'] = old_conf['mq_port']
    conf['QueuePath'] = old_conf['mq_queue']
    conf['Username'] = old_conf['mq_user']
    conf['Password'] = old_conf['mq_password']
    return conf

def getValidDNs_from_file(filename='Test_DN.json'):
    """This function create list of valid dn from json file"""
    dn_list = []
    try:
        with open(filename) as fileDN:
            dn_list = json.load(fileDN)
            return dn_list
    except IOError:
        raise IOError('Cannot find file %s with Valid DNs' % filename)

class MainHandler(tornado.web.RequestHandler):
    """Request handler for json messages"""
    def __init__(self, *args, **kwargs):
        super(MainHandler, self).__init__(*args, **kwargs)
        configParams = options.as_dict()
        self.sender = StompSender(generateMQConfig(configParams))


    def initialize(self):
        """Auth by cert"""
        self.validDNs = getValidDNs_from_file(options.as_dict()["dn_filename"])

    def prepare(self):
        client_cert = self.request.get_ssl_certificate(True)
        print extract_DN(client_cert)
        if not valid_cert(client_cert, self.validDNs):
            print "This certificate is not authorized! Bad DN!"
            self.finish()

    def get(self):
        """get function of handler"""
        self.write("getting some info")

    def post(self):
        """post function of handler"""
        self.write(self.request.get_ssl_certificate())
        msg = self.request.body.decode('string-escape').strip('"')
        self.sendMessage(msg)

    def sendMessage(self, message):
        """This method sends message to mq"""
        print "sending message:" + str(message)
        self.sender.sendMessage(message)

def make_app():
    """Make app with page"""
    return tornado.web.Application([(r"/", MainHandler)])

def generate_ssl_context(server_certificate, server_key, ca_cert):
    """This function generates an ssl context for Tornado handler"""
    mySSLContex = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    mySSLContex.load_cert_chain(server_certificate, server_key)
    mySSLContex.load_verify_locations(ca_cert)
    mySSLContex.verify_mode = ssl.CERT_REQUIRED
    return mySSLContex

def main(argv):
    '''Main method'''
    define("host", default='localhost', help="tornado host", type=str)
    define("port", default=1027, help="tornado port", type=int)

    define("server_cert", default="../testCerts/server.crt", help="server certificate", type=str)
    define("server_key", default="../testCerts/server.key", help="server key", type=str)
    define("ca_cert", default="../testCerts/CAcert.pem", help="CA certificate", type=str)

    define("mq_host", default="127.0.0.1", help="MQ server host", type=str)
    define("mq_port", default=61613, help="MQ server port", type=int)
    define("mq_queue", default="/queue/test", help="MQ queue name", type=str)
    define("mq_user", default='guest', help="MQ username", type=str)
    define("mq_password", default='guest', help="MQ password", type=str)

    define("dn_filename", default='Test_DN.json', help="path to file with valid DNs", type=str)

    define("config", type=str, help="path to config file",
           callback=lambda path: options.parse_config_file(path, final=False))
    options.parse_command_line()

    files_to_check = [options.server_cert, options.server_key, options.ca_cert, options.dn_filename]
    network = {'Tornado':(options.host, options.port), 'MQ':(options.mq_host, options.mq_port)}
    are_params_valid(files_to_check, options.server_cert, options.ca_cert, network)

    print "options loaded:%s" % str(options.as_dict())
    print "STARTING TORNADO SERVER! Host:%s, Port:%i"%(options.host, options.port)

    app = make_app()
    ssl_ctx = generate_ssl_context(options.server_cert, options.server_key, options.ca_cert)
    http_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print '\nConnection is closed'

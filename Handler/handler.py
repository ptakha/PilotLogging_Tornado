"""This module describes Tornado handler,
   which receives a message from certified sender,'
   checks certificate and certficate_DN
   and if all is ok send message to message queue,
   configuration is described in handler_config.json"""

import ssl
from OpenSSL import SSL
from OpenSSL import crypto
import json
import sys
import requests
import tornado.web
import tornado.httpserver
import tornado.ioloop
from tornado.options import options, define
from stompSender import StompSender

def transformDNComponentsToStr(dnList):
# [('DC', 'ch'), ('DC', 'cern'), ('OU', 'computers'), ('CN', 'lhcbci-cernvm03.cern.ch')#]
# to /DC=ch/DC=cern/OU=computers/CN=lhcbci-cernvm03.cern.ch
  transformed = ['/'+el[0]+'='+el[1] for el in dnList]
  return ''.join(transformed)

def extract_DN(cert):
  x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
  dn = x509.get_subject().get_components()
  return transformDNComponentsToStr(dn)

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
  except IOError:
    pass
  return dn_list

class MainHandler(tornado.web.RequestHandler):

  """Request handler for json messages"""
  def __init__(self, *args, **kwargs):
    super(MainHandler, self).__init__(*args, **kwargs)
    configParams = options.as_dict()
    self.sender = StompSender(generateMQConfig(configParams))


  def initialize(self):
    """Auth by cert"""
    self.validDNs = getValidDNs_from_file(options.as_dict()["dn_filename"])

  def get(self):
    """get function of jsonhandler"""
    self.write("getting some info")

  def post(self):
    """post function of json handler"""
    client_cert = self.request.get_ssl_certificate(True)
    if not valid_cert(client_cert, self.validDNs):
      print "This certificate is not authorized! Bad DN!"
      return
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

  print "options loaded:%s" % str(options.as_dict())
  print "STARTING TORNADO SERVER! Host:%s, Port:%i"%(options.host, options.port)

  app = make_app()
  ssl_ctx = generate_ssl_context(options.server_cert, options.server_key, options.ca_cert)
  http_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
  http_server.listen(options.port)
  tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
  main(sys.argv)

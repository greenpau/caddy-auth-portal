from lxml import etree
from signxml import XMLSigner, XMLVerifier
from pprint import pprint

data_to_sign = "<Test/>"
cert = open("../idp/azure_ad_app_signing_cert.pem").read()
key = open("../idp/azure_ad_app_signing_key.pem").read()
root = etree.fromstring(data_to_sign)
signed_root = XMLSigner().sign(root, key=key, cert=cert)
verified_data = XMLVerifier().verify(signed_root).signed_xml
signed_data = etree.tostring(signed_root, encoding='utf8', method='xml', pretty_print=True)
print("Signed Data:")
print(signed_data.decode('utf-8'))

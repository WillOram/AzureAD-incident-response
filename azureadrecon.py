import csv
import base64
import logging
import argparse
import traceback
import lxml.etree as etree
from io import StringIO
from urllib import request
from cryptography import x509
from urllib.parse import urlparse
from argparse import RawTextHelpFormatter
from cryptography.hazmat.backends import default_backend

parser = argparse.ArgumentParser(description="""
Return Azure AD tenant information, including:
    - All domains configured on the Azure AD tenant
    - The configuration of each domain (managed or federated)
    - One of two token-signing certificates configured in Azure AD for any federated domains
    - The token-signing certificates configured in ADFS for any federated domains that use ADFS
""", formatter_class=RawTextHelpFormatter)

args = parser.parse_args()
domain = args.domain
csv_filename = args.outfile

logger = logging.getLogger('Azure AD Recon')

logger.setLevel(logging.DEBUG)

logger.info("Enumerating domain %s" % domain)


def get_azuread_tenant_domains(domain):
    # Return all domains from the associated Azure AD tenant

    autodiscover_post_body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <soap:Header>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
    </soap:Header>
    <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>"""+ domain +"""</Domain>
            </Request>
        </GetFederationInformationRequestMessage>
    </soap:Body>
</soap:Envelope>"""

    autodiscover_post_headers = {
        "Content-Type" : "text/xml; charset=utf-8",
        "SOAPAction" :   '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        "User-Agent" :   "AutodiscoverClient"
    }

    autodiscover_post_url = 'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc'

    autodiscover_request = request.Request(autodiscover_post_url,
                                           autodiscover_post_body.encode('utf-8'),
                                           autodiscover_post_headers)
    response_raw = request.urlopen(autodiscover_request)
    response_xml = etree.fromstring(response_raw.read())

    return response_xml.xpath("//*[local-name() = 'Domain']//text()")


def get_domain_login_information(domain):
    # Get login information for domain

    user_realm_url = "https://login.microsoftonline.com/getuserrealm.srf?login=" + domain + "&xml=1"
    response_raw = request.urlopen(user_realm_url).read()
    # print(response_raw)
    return etree.fromstring(response_raw)


def decode_cert(base64_cert):
    # Decode certificate

    return x509.load_der_x509_certificate(base64.b64decode(base64_cert),
                                          default_backend())


def get_certs_from_adfs_server(domain):
    # Get the token-signing certificates configured on the ADFS server

    adfs_metadata_url = domain + "/federationmetadata/2007-06/federationmetadata.xml"
    adfs_metadata_raw = request.urlopen(adfs_metadata_url).read()
    adfs_metadata_xml = etree.fromstring(adfs_metadata_raw)
    token_signing_certs = adfs_metadata_xml.xpath("//*[local-name() = 'KeyDescriptor' and @use='signing']//text()")

    adfs_certs = []

    for base64_cert in set(token_signing_certs):
        adfs_cert = decode_cert(base64_cert)

        adfs_certs.append({
            "serial" : str(cert.serial_number),
            "subject" : str(cert.subject),
            "before" : str(cert.not_valid_before),
            "after" : str(cert.not_valid_after)
        })

    return adfs_certs


with open(csv_filename, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile, delimiter=' ',
                           quotechar='|',
                           quoting=csv.QUOTE_MINIMAL)

    # get domains in the related Azure AD tenant
    for domain in get_azuread_tenant_domains(domain):

        logger.info("Querying domain %s" % domain)

        # look up user realm informtion for each domain
        domain_login_information = get_domain_login_information(domain)

        # is the domain managed or federated?
        domain_type = domain_login_information.xpath("//NameSpaceType//text()")[0]

        if (domain_type == "Federated"):

            # 1 of 2 token signing certificates configured for the domain in Azure AD
            token_signing_certs = domain_login_information.xpath("//Certificate//text()")

            assert len(token_signing_certs) == 1

            cert = decode_cert(base64.b64decode(token_signing_certs[0]))

            federation_metadata_url = domain_login_information.xpath("//MEXURL//text()")[0] \
                if domain_login_information.xpath("//MEXURL//text()") else ''

            federation_auth_url = domain_login_information.xpath("//AuthURL//text()")[0]

            # if the domain is federated with ADFS,
            #    let's go and grab the token-signing certs from ADFS too
            if ("adfs" in federation_auth_url):

                federation_metdata_url_parsed = urlparse(federation_auth_url)

                adfs_server_url = federation_metdata_url_parsed.scheme + "://" + \
                                    federation_metdata_url_parsed.netloc

                try:

                    adfs_certs = get_certs_from_adfs_server(adfs_server_url)

                    assert len(adfs_certs) <= 2

                    if (len(adfs_certs) == 2):

                        csvwriter.writerow([domain,  # Domain
                                           domain_type,  # Domain type
                                           federation_auth_url,  # Auth URL
                                           str(cert.serial_number),  # Azure AD Cert (1/2) Serial number
                                           str(cert.subject), #  Azure AD Cert (1/2) Subject
                                           str(cert.not_valid_before),  # Azure AD Cert (1/2) Valid before
                                           str(cert.not_valid_after),  # Azure AD Cert (1/2) Valid after
                                           "Fetched ADFS URL",  # Status of fetching federation URL
                                           adfs_certs[0]["serial"],  # ADFS Cert 1 Serial number
                                           adfs_certs[0]["subject"],  # ADFS Cert 1 Subject number
                                           adfs_certs[0]["before"],  # ADFS Cert 1 Valid before 
                                           adfs_certs[0]["after"],  # ADFS Cert 1 Valid after 
                                           adfs_certs[1]["serial"],  # ADFS Cert 2 Serial number
                                           adfs_certs[1]["subject"],  # ADFS Cert 2 Subject
                                           adfs_certs[1]["before"],  # ADFS Cert 2 Valid before 
                                           adfs_certs[1]["after"]])  # ADFS Cert 2 Valid after 


                    elif (len(adfs_certs) == 1):

                        csvwriter.writerow([domain,  # Domain
                                           domain_type,  # Domain type
                                           federation_auth_url,  # Auth URL
                                           str(cert.serial_number),  # Azure AD Cert (1/2) Serial number
                                           str(cert.subject), #  Azure AD Cert (1/2) Subject
                                           str(cert.not_valid_before),  # Azure AD Cert (1/2) Valid before
                                           str(cert.not_valid_after),  # Azure AD Cert (1/2) Valid after
                                           "Fetched ADFS URL",  # Status of fetching federation URL
                                           adfs_certs[0]["serial"],  # ADFS Cert 1 Serial number
                                           adfs_certs[0]["subject"],  # ADFS Cert 1 Subject number
                                           adfs_certs[0]["before"],  # ADFS Cert 1 Valid before 
                                           adfs_certs[0]["after"],  # ADFS Cert 1 Valid after 
                                           '',  # ADFS Cert 2 Serial number
                                           '',  # ADFS Cert 2 Subject
                                           '',  # ADFS Cert 2 Valid before 
                                           ''])  # ADFS Cert 2 Valid after 

                    else:

                        csvwriter.writerow([domain,  # Domain
                                           domain_type,  # Domain type
                                           federation_auth_url,  # Auth URL
                                           str(cert.serial_number),  # Azure AD Cert (1/2) Serial number
                                           str(cert.subject), #  Azure AD Cert (1/2) Subject
                                           str(cert.not_valid_before),  # Azure AD Cert (1/2) Valid before
                                           str(cert.not_valid_after),  # Azure AD Cert (1/2) Valid after
                                           "Fetched ADFS URL",  # Status of fetching federation URL
                                           '',  # ADFS Cert 1 Serial number
                                           '',  # ADFS Cert 1 Subject number
                                           '',  # ADFS Cert 1 Valid before 
                                           '',  # ADFS Cert 1 Valid after 
                                           '',  # ADFS Cert 2 Serial number
                                           '',  # ADFS Cert 2 Subject
                                           '',  # ADFS Cert 2 Valid before 
                                           ''])  # ADFS Cert 2 Valid after 


                except:

                    traceback.print_exc()

                    print("failed to fetch adfs url %s " % adfs_server_url)

                    csvwriter.writerow([domain,  # Domain
                                        domain_type,  # Domain type
                                        federation_auth_url,  # Auth URL
                                        str(cert.serial_number),  # Azure AD Cert (1/2) Serial number
                                        str(cert.subject), #  Azure AD Cert (1/2) Subject
                                        str(cert.not_valid_before),  # Azure AD Cert (1/2) Valid before
                                        str(cert.not_valid_after),  # Azure AD Cert (1/2) Valid after
                                        "Failed to fetch ADFS URL",  # Status of fetching federation URL
                                        '',  # ADFS Cert 1 Serial number
                                        '',  # ADFS Cert 1 Subject number
                                        '',  # ADFS Cert 1 Valid before 
                                        '',  # ADFS Cert 1 Valid after 
                                        '',  # ADFS Cert 2 Serial number
                                        '',  # ADFS Cert 2 Subject
                                        '',  # ADFS Cert 2 Valid before 
                                        ''])  # ADFS Cert 2 Valid after 

            else:

                csvwriter.writerow([domain,  # Domain
                                    domain_type,  # Domain type
                                    federation_auth_url,  # Auth URL
                                    str(cert.serial_number),  # Azure AD Cert (1/2) Serial number
                                    str(cert.subject), #  Azure AD Cert (1/2) Subject
                                    str(cert.not_valid_before),  # Azure AD Cert (1/2) Valid before
                                    str(cert.not_valid_after),  # Azure AD Cert (1/2) Valid after
                                    "No parser for auth URL",  # Status of fetching federation URL
                                    '',  # ADFS Cert 1 Serial number
                                    '',  # ADFS Cert 1 Subject number
                                    '',  # ADFS Cert 1 Valid before 
                                    '',  # ADFS Cert 1 Valid after 
                                    '',  # ADFS Cert 2 Serial number
                                    '',  # ADFS Cert 2 Subject
                                    '',  # ADFS Cert 2 Valid before 
                                    ''])  # ADFS Cert 2 Valid after 

        else:

            csvwriter.writerow([domain,  # Domain
                                domain_type,  # Domain type
                                '',  # Auth URL
                                '',  # Azure AD Cert (1/2) Serial number
                                '',  # Azure AD Cert (1/2)  Subject
                                '',  # Azure AD Cert (1/2) Valid before
                                '',  # Azure AD Cert (1/2) Valid after
                                '',  # Status of fetching federation URL
                                '',  # ADFS Cert 1 Serial number
                                '',  # ADFS Cert 1 Subject number
                                '',  # ADFS Cert 1 Valid before 
                                '',  # ADFS Cert 1 Valid after 
                                '',  # ADFS Cert 2 Serial number
                                '',  # ADFS Cert 2 Subject
                                '',  # ADFS Cert 2 Valid before 
                                ''])   # ADFS Cert 2 Valid after 

        csvfile.flush()

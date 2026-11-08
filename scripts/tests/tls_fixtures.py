"""Disposable public-project test PKI; never production provisioning."""
import datetime,hashlib,ipaddress,os
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec

def certificates(folder):
    now=datetime.datetime.now(datetime.timezone.utc);root=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'OpenProof fixture CA')])
    base=lambda pub,subject:x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(pub).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
    ca=base(root.public_key(),name).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(root,hashes.SHA256());(folder/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM));result={}
    for role in ['server','client','unlisted']:
        key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,role)]);builder=base(key.public_key(),subject).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False)
        if role=='server':builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
        cert=builder.sign(root,hashes.SHA256());(folder/(role+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM));path=folder/(role+'.key');fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as f:f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        result[role]=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return result

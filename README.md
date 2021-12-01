public static X509Certificate GenCert(CertInfo info)
        {
            RsaKeyPairGenerator _rsa = new RsaKeyPairGenerator();
            SecureRandom _random = new SecureRandom();

            _rsa.Init(new KeyGenerationParameters(_random, info.rsa_strength));
            AsymmetricCipherKeyPair _pair = _rsa.GenerateKeyPair();

            X509Name _cert_name = new X509Name("CN=" + info.name);
            BigInteger _serialnumber = BigInteger.ProbablePrime(120, new Random());

            X509V3CertificateGenerator _cert = new X509V3CertificateGenerator();
            _cert.SetSerialNumber(_serialnumber);
            _cert.SetSubjectDN(_cert_name);
            _cert.SetIssuerDN(_cert_name);
            _cert.SetNotBefore(info.begin_date);
            _cert.SetNotAfter(info.expire_date);
            _cert.SetSignatureAlgorithm("SHA1withRSA");
            _cert.SetPublicKey(_pair.Public);

            _cert.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_pair.Public),
                    new GeneralNames(new GeneralName(_cert_name)), _serialnumber));
            _cert.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
                new ExtendedKeyUsage(new[] { KeyPurposeID.IdKPServerAuth }));

            return _cert.Generate(_pair.Private);
        }



/// <summary>
        /// Generate a cert/key pair
        /// </summary>
        private void GenerateCertKeyPair()
        {
            // Generate RSA key pair
            RsaKeyPairGenerator r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            keyPair = r.GenerateKeyPair();

            // Generate the X509 certificate
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            X509Name dnName = new X509Name("CN=NVIDIA GameStream Client");

            certGen.SetSerialNumber(BigInteger.ValueOf(DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond));
            certGen.SetSubjectDN(dnName);
            certGen.SetIssuerDN(dnName); // use the same
            // Expires in 20 years
            certGen.SetNotBefore(DateTime.Now);
            certGen.SetNotAfter(DateTime.Now.AddYears(20));
            certGen.SetPublicKey(keyPair.Public);
            certGen.SetSignatureAlgorithm("SHA1withRSA");

            try
            {
                cert = certGen.Generate(keyPair.Private);

            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.StackTrace);
            }

            Task.Run(async () => await SaveCertKeyPair()).Wait(); 
        }










public static X509Certificate2 GenerateCertificate(X509Certificate2 caCert, string certSubjectName)
{
    // Generate Certificate

    var cerKp = kpgen.GenerateKeyPair();

    var certName = new X509Name(true,certSubjectName); // subjectName = user
    var serialNo = BigInteger.ProbablePrime(120, new Random());

    X509V3CertificateGenerator gen2 = new X509V3CertificateGenerator();
    gen2.SetSerialNumber(serialNo);
    gen2.SetSubjectDN(certName);
    gen2.SetIssuerDN(new X509Name(true,caCert.Subject));
    gen2.SetNotAfter(DateTime.Now.AddDays(100));
    gen2.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
    gen2.SetSignatureAlgorithm("SHA1WithRSA");
    gen2.SetPublicKey(cerKp.Public);


    AsymmetricCipherKeyPair akp = DotNetUtilities.GetKeyPair(caCert.PrivateKey);
    Org.BouncyCastle.X509.X509Certificate newCert = gen2.Generate(caKp.Private);

    // used for getting a private key
    X509Certificate2 userCert = ConvertToWindows(newCert,cerKp);

    if (caCert22.Verify()) // works well for CA 
    {
        if (userCert.Verify()) // fails for client certificate 
        {
            return userCert;
        }
    }
    return null;

}

private static X509Certificate2 ConvertToWindows(Org.BouncyCastle.X509.X509Certificate newCert, AsymmetricCipherKeyPair kp)
{
    string tempStorePwd = "abcd1234";
    var tempStoreFile = new FileInfo(Path.GetTempFileName());

    try
    {
        // store key 
        {
            var newStore = new Pkcs12Store();

            var certEntry = new X509CertificateEntry(newCert);

            newStore.SetCertificateEntry(
                newCert.SubjectDN.ToString(),
                certEntry
                );

            newStore.SetKeyEntry(
                newCert.SubjectDN.ToString(),
                new AsymmetricKeyEntry(kp.Private),
                new[] { certEntry }
                );
            using (var s = tempStoreFile.Create())
            {
                newStore.Save(
                    s,
                    tempStorePwd.ToCharArray(),
                    new SecureRandom(new CryptoApiRandomGenerator())
                    );
            }
        }

        // reload key 
        return new X509Certificate2(tempStoreFile.FullName, tempStorePwd);
    }
    finally
    {
        tempStoreFile.Delete();
    }
}

域名：^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$
ip4: ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
# test

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

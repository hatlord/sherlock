class SSLScrape

  attr_reader :scanner

  def initialize(scanner, buildchecks)
    @scanner     = scanner
    @buildchecks = buildchecks
  end

  def get_sslscan_results
    @results = []
    @results << ["IP Address", "CertIssuer", "CertHostname", "Signature", "RSA Key Length", "Port" ]
    scanner.buildchecks.each do |issue|
      if issue["command"] == "sslscan"
        sslscan = issue["out"].split("\n")
        issuer     = sslscan.select { |i| i[/Issuer: \/CN=/]}[0].split(" ")[1]
        subject    = sslscan.select { |i| i[/Subject:/]}[1].split(" ")[1]
        signature  = sslscan.select { |i| i[/Signature Algorithm:/]}[0].strip
        key_length = sslscan.select { |i| i[/RSA Key Strength:/]}[0]

        @results << [issue["ip"], issuer, subject, signature, key_length, issue["port"]]
      end
    end
    @results
  end

  def output
    puts "\nSSL Certificate Information Table".light_cyan.bold
    puts @results.to_table(:first_row_is_head => true)
  end

end



  # def get_sslscan_results
  #   #grabs results of sslscan from scanner.buildchecks
  #   scanner.buildchecks.each do |issue|
  #     if issue["command"] == "sslscan"
  #       sslscan = issue["out"].each_line.map(&:chomp &&:strip)
  #       #need to change the below to look at the string instead
  #       issuer     = sslscan.select { |i| i[/Issuer: \/CN=/]}
  #       subject    = sslscan.select { |i| i[/Subject:/]}
  #       signature  = sslscan.select { |i| i[/Signature Algorithm:/]}
  #       key_length = sslscan.select { |i| i[/RSA Key Strength:/]}
  #       hostname   = subject.map { |s| s.split(" ")[1]}
  #       hostname.each do |name|
  #         signature.each do |sig|
  #           puts "#{ip}\t#{issuer.split("=")[1]}#{name}\t#{sig}\t#{key_length}\t#{port}"
  #         end
  #       end
  #     end
  #   end
  # end


  #"name"=>"SSL TLS Versions Supported",
  # "pluginid"=>"56984",
  # "command"=>"sslscan",
  # "arguments"=>"--show-certificate --no-colour _ip_:_port_",
  # "timeout"=>45,
  # "ip"=>"10.129.121.75",
  # "port"=>"3389",
  # "finalargs"=>"--show-certificate --no-colour 10.129.121.75:3389",
  # "out"=>
  #  "sslscan --show-certificate --no-colour 10.129.121.75:3389\n" +
  #  "Version: 1.11.11-static\n" +
  #  "OpenSSL 1.0.2-chacha (1.0.2g-dev)\n" +
  #  "\n" +
  #  "Connected to 10.129.121.75\n" +
  #  "\n" +
  #  "Testing SSL server 10.129.121.75 on port 3389 using SNI name 10.129.121.75\n" +
  #  "\n" +
  #  "  TLS Fallback SCSV:\n" +
  #  "Server does not support TLS Fallback SCSV\n" +
  #  "\n" +
  #  "  TLS renegotiation:\n" +
  #  "Session renegotiation not supported\n" +
  #  "\n" +
  #  "  TLS Compression:\n" +
  #  "Compression disabled\n" +
  #  "\n" +
  #  "  Heartbleed:\n" +
  #  "TLS 1.2 not vulnerable to heartbleed\n" +
  #  "TLS 1.1 not vulnerable to heartbleed\n" +
  #  "TLS 1.0 not vulnerable to heartbleed\n" +
  #  "\n" +
  #  "  Supported Server Cipher(s):\n" +
  #  "Preferred TLSv1.0  128 bits  AES128-SHA                   \n" +
  #  "Accepted  TLSv1.0  256 bits  AES256-SHA                   \n" +
  #  "Accepted  TLSv1.0  128 bits  RC4-SHA                      \n" +
  #  "Accepted  TLSv1.0  112 bits  DES-CBC3-SHA                 \n" +
  #  "Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256\n" +
  #  "Accepted  TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256\n" +
  #  "Accepted  TLSv1.0  128 bits  RC4-MD5                      \n" +
  #  "\n" +
  #  "  SSL Certificate:\n" +
  #  "    Certificate blob:\n" +
  #  "-----BEGIN CERTIFICATE-----\n" +
  #  "MIIC0jCCAbqgAwIBAgIQGdv3z0Cn0ZJMkbXBF/pqKTANBgkqhkiG9w0BAQUFADAS\n" +
  #  "MRAwDgYDVQQDEwd3Mms4d2ViMB4XDTE5MDIwNjExMTI1MVoXDTE5MDgwODExMTI1\n" +
  #  "MVowEjEQMA4GA1UEAxMHdzJrOHdlYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
  #  "AQoCggEBAKdNhWtRY2AKDIw5taY14myTsL8bZ2mXQaK9tydF9UwV3ArOSKID5bmf\n" +
  #  "IJDjBSzqCq2uHpQaizxKxjkjNbWhTGW13LwCZPGlBjiRqO2iEWNSBP9PzF9xZjco\n" +
  #  "p7bALmhI25KUeuh2w4FY5Kbo1zR0Ry0d+oPeB688HdgsMIZN3DIErpR4+yfWhgmo\n" +
  #  "cRTABZhotKyUW4SyHtxWGtSvHq4shZ45X+24mquPzEIowh7ETBa/mSAi6TxQJWaM\n" +
  #  "weWv7nfIYOs2cN8D4OV56meuxAny/78qsm8mqBo8VRDsy/+WWq3GztmyHMeUvMeV\n" +
  #  "4HgEX38aRVxvW8HgrQV+4FqHf2+7X08CAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYB\n" +
  #  "BQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IBAQB6UF02y2aKow+C\n" +
  #  "az8JP4j4Zen8x2a4Jjc/wNZxum8I28Cuw9KqzxDh6ksAbHki5on0YXNvY16Dq2tv\n" +
  #  "NFeMTTP9AxCsYRrPuTXqxFZzJtkIefcX1wW5hTSvK+jNDB2WEXjfuLEmk/GlMPit\n" +
  #  "qXcHp7aXg8IseVk6MDxCncLhS2dEyZGxP82+sFGo2b7XtRPhmmmd+7Oo9kYfsDp4\n" +
  #  "Mtb18sI7/1H52FFwhXi4pEyRaC/tRQUnJF7KMt1D4Yd4P0SHEDU8Hzu28irwXDe3\n" +
  #  "WUIzDGiXdECFiZ6K2oPX3LzfehUlTrEZwtKOGB05hXUH78j+m34MLx4+l6X+NiC1\n" +
  #  "S0Nf3CKR\n" +
  #  "-----END CERTIFICATE-----\n" +
  #  "    Version: 2\n" +
  #  "    Serial Number: 19:db:f7:cf:40:a7:d1:92:4c:91:b5:c1:17:fa:6a:29\n" +
  #  "    Signature Algorithm: sha1WithRSAEncryption\n" +
  #  "    Issuer: /CN=w2k8web\n" +
  #  "    Not valid before: Feb  6 11:12:51 2019 GMT\n" +
  #  "    Not valid after: Aug  8 11:12:51 2019 GMT\n" +
  #  "    Subject: /CN=w2k8web\n" +
  #  "    Public Key Algorithm: rsaEncryption\n" +
  #  "    RSA Public Key: (2048 bit)\n" +
  #  "      Public-Key: (2048 bit)\n" +
  #  "      Modulus:\n" +
  #  "          00:a7:4d:85:6b:51:63:60:0a:0c:8c:39:b5:a6:35:\n" +
  #  "          e2:6c:93:b0:bf:1b:67:69:97:41:a2:bd:b7:27:45:\n" +
  #  "          f5:4c:15:dc:0a:ce:48:a2:03:e5:b9:9f:20:90:e3:\n" +
  #  "          05:2c:ea:0a:ad:ae:1e:94:1a:8b:3c:4a:c6:39:23:\n" +
  #  "          35:b5:a1:4c:65:b5:dc:bc:02:64:f1:a5:06:38:91:\n" +
  #  "          a8:ed:a2:11:63:52:04:ff:4f:cc:5f:71:66:37:28:\n" +
  #  "          a7:b6:c0:2e:68:48:db:92:94:7a:e8:76:c3:81:58:\n" +
  #  "          e4:a6:e8:d7:34:74:47:2d:1d:fa:83:de:07:af:3c:\n" +
  #  "          1d:d8:2c:30:86:4d:dc:32:04:ae:94:78:fb:27:d6:\n" +
  #  "          86:09:a8:71:14:c0:05:98:68:b4:ac:94:5b:84:b2:\n" +
  #  "          1e:dc:56:1a:d4:af:1e:ae:2c:85:9e:39:5f:ed:b8:\n" +
  #  "          9a:ab:8f:cc:42:28:c2:1e:c4:4c:16:bf:99:20:22:\n" +
  #  "          e9:3c:50:25:66:8c:c1:e5:af:ee:77:c8:60:eb:36:\n" +
  #  "          70:df:03:e0:e5:79:ea:67:ae:c4:09:f2:ff:bf:2a:\n" +
  #  "          b2:6f:26:a8:1a:3c:55:10:ec:cb:ff:96:5a:ad:c6:\n" +
  #  "          ce:d9:b2:1c:c7:94:bc:c7:95:e0:78:04:5f:7f:1a:\n" +
  #  "          45:5c:6f:5b:c1:e0:ad:05:7e:e0:5a:87:7f:6f:bb:\n" +
  #  "          5f:4f\n" +
  #  "      Exponent: 65537 (0x10001)\n" +
  #  "    X509v3 Extensions:\n" +
  #  "      X509v3 Extended Key Usage: \n" +
  #  "        TLS Web Server Authentication\n" +
  #  "      X509v3 Key Usage: \n" +
  #  "        Key Encipherment, Data Encipherment\n" +
  #  "  Verify Certificate:\n" +
  #  "    unable to get local issuer certificate\n" +
  #  "\n" +
  #  "  SSL Certificate:\n" +
  #  "Signature Algorithm: sha1WithRSAEncryption\n" +
  #  "RSA Key Strength:    2048\n" +
  #  "\n" +
  #  "Subject:  w2k8web\n" +
  #  "Issuer:   w2k8web\n" +
  #  "\n" +
  #  "Not valid before: Feb  6 11:12:51 2019 GMT\n" +
  #  "Not valid after:  Aug  8 11:12:51 2019 GMT\n"

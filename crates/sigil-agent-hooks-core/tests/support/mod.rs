use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    server::TlsStream,
};

pub const TEST_CERT_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUQQBSBZ0NCezjOlR+QO9L3Zbd+y0wDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNU2lnaWwgVGVzdCBDQTAeFw0yNjA4MjEwMzM2MDBaFw0z
NjA4MTgwMzM2MDBaMBgxFjAUBgNVBAMMDVNpZ2lsIFRlc3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCV1WW+A7TITS8W3goIkIsuuQoXqSLDXRLj
1KCPZlBSsc5jkqRaS1vV06yTuLDYMJVHuIVmwaaBHaNWkANM6k3WpmjXP3znjI4Z
mBSmTAPFFJh03GVmRCFLBkc4ma2pbUIq4XIIit/czj4RM2IWjaz4wvILGBsChay1
LieCFpgL2hwcwXQ8JoqD7VlLuYaJKz3mneloSwl3ueHEC7Z5mcsl79ehDgCB/rRZ
RJsdx+trO+N9NxP7QbjcSbVkGQOv64bxEftAp7y98WWbyywdy4HGCatb2VoPmkOI
09mWxPDQ2T57/OwfgjeQdiryD2ZcrFEDaxyJSJO52XYjcq4Ya6OpAgMBAAGjYzBh
MB0GA1UdDgQWBBTI2DSJWTyCmwfOKWx30YgLWmrsAjAfBgNVHSMEGDAWgBTI2DSJ
WTyCmwfOKWx30YgLWmrsAjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjANBgkqhkiG9w0BAQsFAAOCAQEAPCY6fCQX/dKF2dDVmJ15sWIFY8+zkrmKUEcO
UfxN2f/awDUlQ9/fPSQtTrwSUJF71M4T8dduUkMSju3cYrwCUCQzvUWXxZshpKWV
7UlmBG4Lzr93Vxhsv0opv/g8YHTOgp5wb0/KvvjP7k9KVTOS1PKmBIGXfLzxkuVC
+u+Z0h6osCiFxFw98MA+rBVgAQsi9lfef0NY6W/tUvrsijoBipYExOwLmjc/PyH9
KFjCb30S7wLmfbVHggq5fhOd4yc6iFX/kt79SAZBZjGuOCy2s60M6dM4gGuatZfz
iz7/wdYBDxT5R84ES0gbsVGhhdo3DzsSkpOSru/7RwQ/AGlKIw==
-----END CERTIFICATE-----
"#;

const TEST_LEAF_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUOgJPkfXUl5awJjCsfA82nTCsvUYwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNU2lnaWwgVGVzdCBDQTAeFw0yNjA4MjEwMzM2MDBaFw0z
NjA4MTgwMzM2MDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALjG6gP/FSV2R5oCtP9DtQX0zZ5sHfh5ifgeYxzp
QoMjWmTNnLIR1789PEHuItztyvd9c+evm1bsBqame3DFgxmAXq0VnaWYfP5HXBEy
5IEIaKWKmAwAZT53O03IlJZCU+Xyz8re3bWkpGiTBAiDF5zpK1eiD/fbICCuagbR
QBwpLFGxPwwrynIOtsN2mpiRRfWCNi97QB2jGgLhYS+TkiAuyiP30MDjstvuSuM8
+14LmsLjKhvrOsxVNnKAM0yxOzctU1un2WeRCBxbG7KXOtjqBai98YW1Oif8j3Fi
4s3ic/me5zm/hO7TdGhTEYXZqG/SfR0bwuobhUZfLN+ZuMMCAwEAAaOBjDCBiTAU
BgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC
BaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFLsdfkRpVEODVATxa899
AvRjMha3MB8GA1UdIwQYMBaAFMjYNIlZPIKbB84pbHfRiAtaauwCMA0GCSqGSIb3
DQEBCwUAA4IBAQCDHq261SUPBxYIJFPewG5j0FTBQLrxBPMj5X94zoqxQJuoiCDw
Gna2Dckz9oYgJySEAkNOmcok9shyzKZZ1+bZdmwO5A9G6P7UzsfcLHxnbzV7rOfx
yJ2QnawZdB7cnaO3t7VJ8gx1TulOMnBpvI8ktoaaktpd5hUvR2cfptamsw4JCC3O
btKuRdZVKOTUWInGi2fcTk9z7vBis7q5BHhatVmTs1LCz9yy5Ut6gdUYYSqhdCSN
DW3RnEh1gfySlUOAEQg42WOy8zVDWsNsfJSOudANZ/v0whLKWSSNaxv/kVJmK3mk
2K14rpFAEWn5Ji2xgOaCuv/R578TwEppKdal
-----END CERTIFICATE-----
"#;

const TEST_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4xuoD/xUldkea
ArT/Q7UF9M2ebB34eYn4HmMc6UKDI1pkzZyyEde/PTxB7iLc7cr3fXPnr5tW7Aam
pntwxYMZgF6tFZ2lmHz+R1wRMuSBCGilipgMAGU+dztNyJSWQlPl8s/K3t21pKRo
kwQIgxec6StXog/32yAgrmoG0UAcKSxRsT8MK8pyDrbDdpqYkUX1gjYve0AdoxoC
4WEvk5IgLsoj99DA47Lb7krjPPteC5rC4yob6zrMVTZygDNMsTs3LVNbp9lnkQgc
WxuylzrY6gWovfGFtTon/I9xYuLN4nP5nuc5v4Tu03RoUxGF2ahv0n0dG8LqG4VG
XyzfmbjDAgMBAAECggEAAmh3onxMdCcIKtrDLU2rSi8VD1RjlZpPF0024UJG+O3y
hSLK2n7Ybw6z8aLSKhftQu/YtvNdoZkRqYVWhLM5dxEdt43zEBy38EzRlD9m2MM/
yq+1aJHVJlnBpTNds5GcuOZcf+cLDUCrWQ0lcQKOwbkMm0FEI2iww/94ThHXDvOs
Vs2ZjSsbBP4SfE7uZx0gGYqdJOzdLWREwhB7bGtu4/mTIJziGvVeMFUe47/pvl81
upS03co7g+tewWrqQDjRJXh++LmCQUTw5L+yProYJMnnj5uXPskrui4Ulhe4KDFP
Ppfh1RlFdKXpfnk/od1Yzeb0130BlxL/Io+xOHZxSQKBgQDktWj1oqYyniz5hXfu
p7B1ldgd7m5SReziHYOc1gEPokoweDHscJf+A4QH1lpO3byPRatWSvrSC4ZBzIKx
nzfUZv+a8IPySO7ucpHaeuJm0/ilrXpfnuLMSDUrOon4UCs2BMSIR3ml5Exa6HtD
uyVT6/uwp3V2xQQxTPUyTLVeywKBgQDO03sqKOmtQk4ZNJQGLSVEtYh/zKH0VIGC
wkF53cQ7ZKqDA9xWFDUutztoSSkVJEaAmMCzRDdDkiy4C+hTNVJi3EZn0JMy7Zk1
medKJIMFkeRKsmnzFNNqFRGVvOKcxG6qhKA3JdsAPtclIhq7YmeEuhoijw1pSNpc
K2aglAMW6QKBgGxCavKLETy4nvVl9kVj3yVpzqksadBMBTtrWRduPYZW/eM/ofIX
wfqdU2waTRkz4MO46MeqKlwu1FhlJCBMC7NhJfEDlJGlcGQym1PeAzlFcVeLbHfC
z/x+2Zwi05hU6n9hdl5D5xNdo78MePywo5S8CaGvQuz7iWaE1TQAF4JNAoGBAKY7
b6ipDXfF7QNxMO/t5SBeT4F4NUstiJJSE1IhnhCmji2TMsq0nzIW71aYRr7JUykU
nPz4fPqASBT87RPDrZ3rsWLLTyQFt7hPJIiA5BXb9oLa9zD6shl3KZUSJYkekFvZ
EPSCJo0B9OXRjW7CXrVc5piUJZFTjr253Fh/3iPRAoGAB/RPArVaS92OK6AKsLB3
mcvUerocT6e2ppKeZvQwJvrsxX1VdiZWEAiudhc3hnubZK9MCHgWqo/bcly0fHFS
31AWTEtEHNXOFMua98Fwb2RgkXlPuAaUagVNo66aBdpKJakozdxFO92rKlfNJTzs
V27vi/PU9PxMpUr7k1vzfXE=
-----END PRIVATE KEY-----
"#;

fn decode_pem(pem: &[u8]) -> Vec<u8> {
    let encoded = std::str::from_utf8(pem)
        .expect("ASCII PEM")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    STANDARD.decode(encoded).expect("valid test PEM")
}

pub struct TestTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

const TLS_ACCEPT_ATTEMPTS: usize = 3;

impl TestTlsListener {
    pub fn new(listener: TcpListener) -> Self {
        let leaf = CertificateDer::from(decode_pem(TEST_LEAF_PEM));
        let ca = CertificateDer::from(decode_pem(TEST_CERT_PEM));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode_pem(TEST_KEY_PEM)));
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![leaf, ca], key)
        .expect("test TLS config");
        Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    pub async fn accept(&mut self) -> io::Result<(TlsStream<TcpStream>, SocketAddr)> {
        for attempt in 1..=TLS_ACCEPT_ATTEMPTS {
            let (stream, addr) = self.listener.accept().await?;
            match self.acceptor.accept(stream).await {
                Ok(stream) => return Ok((stream, addr)),
                Err(error) if attempt == TLS_ACCEPT_ATTEMPTS => return Err(error),
                Err(_) => {}
            }
        }
        unreachable!("TLS accept attempts are nonzero")
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

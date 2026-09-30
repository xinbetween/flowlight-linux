//! The certificate authority interception presents.
//!
//! Created on this machine the first time interception is turned on, and never leaves it. The authority's key
//! signs a short-lived certificate for each host that is terminated; one key is shared by all of them, because
//! the leaves exist for minutes and generating a key per host would be the slowest thing in the connection.
//!
//! # What is on disk, in two places, and why
//!
//! The keys go beside the database, in a directory nobody else may enter: mode 600 in a directory of 700,
//! created that way rather than created and then restricted. Anybody who can read the authority's key can
//! impersonate every site on the internet to anything that trusts it, which is a sentence worth writing down
//! next to the code that makes one.
//!
//! The certificate and the bundle go somewhere else entirely, readable by everybody, because that is what they
//! are for. An agent runs as a person and has to be able to read the certificate it is being asked to trust —
//! and the database's directory is root's alone, so a certificate published inside it would be a certificate
//! nothing could use.
//!
//! # Why the certificate says what it says
//!
//! Its common name names Flowlight and the machine it was made on. A certificate somebody finds in a trust
//! store two years from now should say what put it there without anybody having to guess.

use anyhow::{Context as _, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How long a leaf certificate is valid.
///
/// Days rather than years. A leaf is made on demand and cached in memory for the life of the daemon, so a
/// short life costs nothing and a long one is a certificate somebody could find and misuse.
const LEAF_DAYS: i64 = 14;

/// How long the authority is valid.
const AUTHORITY_DAYS: i64 = 365;

/// The files, and the keys held in memory.
pub struct Authority {
    /// Where the certificate and the bundle are, which is where anything that has to trust them looks.
    published: PathBuf,
    /// The authority, ready to sign.
    signing: rcgen::Issuer<'static, KeyPair>,
    /// The certificate as it goes on the wire, and as it is written into a trust store.
    certificate: CertificateDer<'static>,
    /// The key every leaf shares.
    leaf_key: KeyPair,
    /// Leaves already made, by host. A connection to a host reached twice does not pay twice.
    leaves: Mutex<HashMap<String, Signed>>,
}

/// One host's certificate and the key it goes with.
///
/// The key is kept as DER bytes rather than as a parsed key because a parsed one cannot be cloned, and this is
/// handed out once per connection.
#[derive(Clone)]
pub struct Signed {
    /// The chain: the leaf, then the authority, so that something which trusts the authority by file rather
    /// than by store still builds a path.
    pub chain: Vec<CertificateDer<'static>>,
    /// The key every leaf shares, as PKCS#8 DER.
    key: Vec<u8>,
}

impl Signed {
    /// The key, as rustls wants it.
    pub fn key(&self) -> Result<PrivateKeyDer<'static>> {
        PrivateKeyDer::try_from(self.key.clone())
            .map_err(|err| anyhow::anyhow!("reading the leaf key: {err}"))
    }
}

impl Authority {
    /// Where the keys live, given where the database is.
    ///
    /// Beside the database, in the directory only root may enter. The keys and the history have the same
    /// audience, which is nobody.
    pub fn keys_for(database: &Path) -> PathBuf {
        database
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("intercept")
    }

    /// The certificate anything that must trust this reads.
    pub fn certificate_path(published: &Path) -> PathBuf {
        published.join("flowlight-ca.pem")
    }

    /// System roots plus this authority, for anything that reads one PEM bundle: curl, Python, Git, Node.
    pub fn bundle_path(published: &Path) -> PathBuf {
        published.join("ca-bundle.pem")
    }

    /// Whether an authority has been created.
    ///
    /// Judged by the key, not by the certificate: a certificate without its key is not an authority, and the
    /// certificate is the one of the two that somebody might reasonably delete.
    pub fn exists(keys: &Path, published: &Path) -> bool {
        keys.join("flowlight-ca.key").exists() && Self::certificate_path(published).exists()
    }

    /// Loads the authority, creating it if there is not one yet.
    pub fn open(keys: &Path, published: &Path, machine: &str) -> Result<Self> {
        if Self::exists(keys, published) {
            // Checked on every open rather than only on create: a directory somebody widened later is the
            // same problem as one that was never narrowed.
            restricted_directory(keys)?;
        } else {
            create(keys, published, machine)?;
        }
        let certificate_pem = std::fs::read_to_string(Self::certificate_path(published))
            .with_context(|| format!("reading {}", Self::certificate_path(published).display()))?;
        let key_pem = std::fs::read_to_string(keys.join("flowlight-ca.key"))
            .context("reading the authority's key")?;
        let leaf_pem = std::fs::read_to_string(keys.join("leaf.key"))
            .context("reading the shared leaf key")?;

        let certificate = first_certificate(&certificate_pem)?;
        let key = KeyPair::from_pem(&key_pem).context("reading the authority's key")?;
        let leaf_key = KeyPair::from_pem(&leaf_pem).context("reading the shared leaf key")?;
        // Read back out of the certificate rather than rebuilt from what created it. The issuer's name and
        // its key identifier are in there; recreating them from a format string would drift the first time
        // the machine was renamed, and the symptom would be leaves nothing can build a path to.
        let signing = rcgen::Issuer::from_ca_cert_pem(&certificate_pem, key)
            .map_err(|err| anyhow::anyhow!("reading the authority's certificate: {err}"))?;

        Ok(Self {
            published: published.to_path_buf(),
            signing,
            certificate,
            leaf_key,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The authority's certificate, for a trust store.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// Where its certificate is on disk.
    pub fn path(&self) -> PathBuf {
        Self::certificate_path(&self.published)
    }

    /// Where the bundle is.
    pub fn bundle(&self) -> PathBuf {
        Self::bundle_path(&self.published)
    }

    /// A certificate for one host, made if it has not been made already.
    pub fn signed_for(&self, host: &str) -> Result<Signed> {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if let Ok(leaves) = self.leaves.lock()
            && let Some(ready) = leaves.get(&host)
        {
            return Ok(ready.clone());
        }
        let signed = self.sign(&host)?;
        if let Ok(mut leaves) = self.leaves.lock() {
            leaves.insert(host, signed.clone());
        }
        Ok(signed)
    }

    /// Makes one.
    fn sign(&self, host: &str) -> Result<Signed> {
        if host.is_empty() {
            bail!("a certificate cannot be made for a host with no name");
        }
        let mut parameters =
            CertificateParams::new(Vec::new()).context("preparing a certificate for a host")?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        parameters.distinguished_name = name;
        // The name has to be in a subject alternative name to be checked at all: the common name has not been
        // consulted by anything current for a decade. An address goes in as an address, not as a DNS name,
        // for the same reason.
        parameters.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(address) => SanType::IpAddress(address),
            Err(_) => SanType::DnsName(
                host.to_owned()
                    .try_into()
                    .with_context(|| format!("{host} cannot be written into a certificate"))?,
            ),
        }];
        parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
        let (year, month, day) = civil(today() + LEAF_DAYS);
        parameters.not_after = rcgen::date_time_ymd(year as i32, month as u8, day as u8);
        parameters.use_authority_key_identifier_extension = true;

        let certificate = parameters
            .signed_by(&self.leaf_key, &self.signing)
            .with_context(|| format!("signing a certificate for {host}"))?;
        Ok(Signed {
            chain: vec![certificate.der().clone(), self.certificate.clone()],
            key: self.leaf_key.serialize_der(),
        })
    }
}

/// Creates the authority, its key and the shared leaf key.
fn create(keys: &Path, published: &Path, machine: &str) -> Result<()> {
    restricted_directory(keys)?;
    readable_directory(published)?;
    let key = KeyPair::generate().context("generating the authority's key")?;
    let leaf_key = KeyPair::generate().context("generating the shared leaf key")?;

    let mut parameters =
        CertificateParams::new(Vec::new()).context("preparing the authority's certificate")?;
    let mut name = DistinguishedName::new();
    // Says what it is and where it came from. A certificate somebody finds in a trust store two years from
    // now should not need anybody to guess.
    name.push(
        DnType::CommonName,
        format!("Flowlight Interception ({machine})"),
    );
    name.push(DnType::OrganizationName, "Flowlight");
    parameters.distinguished_name = name;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
    let (year, month, day) = civil(today() + AUTHORITY_DAYS);
    parameters.not_after = rcgen::date_time_ymd(year as i32, month as u8, day as u8);
    let certificate = parameters
        .self_signed(&key)
        .context("signing the authority's certificate")?;

    write_restricted(
        &Authority::certificate_path(published),
        certificate.pem().as_bytes(),
        // The certificate is public by definition: anything that must trust it has to be able to read it.
        0o644,
    )?;
    write_restricted(
        &keys.join("flowlight-ca.key"),
        key.serialize_pem().as_bytes(),
        // And this one is not. Anybody who can read it can impersonate every site on the internet to
        // anything that trusts the certificate above.
        0o600,
    )?;
    write_restricted(
        &keys.join("leaf.key"),
        leaf_key.serialize_pem().as_bytes(),
        0o600,
    )?;
    write_bundle(published, &certificate.pem())?;
    Ok(())
}

/// Writes the machine's own roots plus this authority into one file.
///
/// For everything that reads a PEM bundle and ignores the system trust store: `curl --cacert`,
/// `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`. Built by copying whichever bundle this
/// distribution already keeps, because the alternative — a bundle holding only Flowlight's authority — would
/// break every host that is *not* being intercepted the moment anybody pointed a tool at it.
fn write_bundle(published: &Path, authority: &str) -> Result<()> {
    let mut text = String::new();
    if let Some(existing) = system_bundle() {
        text.push_str(&std::fs::read_to_string(&existing).with_context(|| {
            format!(
                "reading this machine's certificate bundle at {}",
                existing.display()
            )
        })?);
        if !text.ends_with('\n') {
            text.push('\n');
        }
    }
    text.push_str(authority);
    write_restricted(&Authority::bundle_path(published), text.as_bytes(), 0o644)
}

/// Where this distribution keeps its bundle of roots, if it keeps one anywhere usual.
///
/// Written out rather than discovered, because the list is short and each entry is a distribution somebody
/// runs. A machine with none of them gets a bundle holding only Flowlight's authority, and `trust` says so.
pub fn system_bundle() -> Option<PathBuf> {
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

/// The first certificate in a PEM file.
fn first_certificate(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let found = rustls_pemfile::certs(&mut reader)
        .next()
        .context("the authority's certificate file has no certificate in it")?
        .context("reading the authority's certificate")?;
    Ok(found)
}

/// Today, in whole days since the epoch.
fn today() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
        .div_euclid(86_400)
}

/// Days since the epoch as a date, by Howard Hinnant's algorithm.
fn civil(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Creates a directory nobody else may enter, created that way rather than created and then restricted.
///
/// A directory that already exists is narrowed anyway. One left behind at 755 by an earlier version, or by
/// somebody's `mkdir -p`, is a directory the authority's key would sit in readable by every user on the
/// machine — and nothing would ever say so, because it would work perfectly.
fn restricted_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        if directory.exists() {
            return std::fs::set_permissions(
                directory,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .with_context(|| format!("restricting {}", directory.display()));
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .with_context(|| format!("creating {}", directory.display()))
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))
}

/// Creates a directory everybody may read, because what goes in it is a certificate.
fn readable_directory(directory: &Path) -> Result<()> {
    if directory.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(directory)
            .with_context(|| format!("creating {}", directory.display()))
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))
}

/// Writes a file with a mode, created with it rather than given it afterwards.
fn write_restricted(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?
    };
    #[cfg(not(unix))]
    let mut file = {
        let _ = mode;
        std::fs::File::create(path).with_context(|| format!("writing {}", path.display()))?
    };
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))
}

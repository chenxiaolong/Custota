/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

mod protobuf;

use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use memchr::memmem;
use quick_protobuf::{BytesReader, MessageRead};
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{
        der::{referenced::OwnedToRef, DecodePem},
        DecodePrivateKey,
    },
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{
    digest::{generic_array::GenericArray, OutputSizeUser},
    Digest, Sha256,
};
use x509_cert::{
    der::{asn1::OctetStringRef, Any, Decode, Encode, Tag},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};
use zip::ZipArchive;

use crate::protobuf::build::tools::releasetools::mod_OtaMetadata::OtaType;
use crate::protobuf::build::tools::releasetools::OtaMetadata;

static EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
static METADATA_PATH: &str = "META-INF/com/android/metadata.pb";
static OTACERT_PATH: &str = "META-INF/com/android/otacert";
static CSIG_EXT: &str = ".csig";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PropertyFile {
    name: String,
    offset: u64,
    size: u64,
    digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CsigInfo {
    version: u8,
    files: Vec<PropertyFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LocationInfo {
    location_ota: String,
    location_csig: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UpdateInfo {
    version: u8,
    full: Option<LocationInfo>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    incremental: HashMap<String, LocationInfo>,
}

#[derive(Clone, Debug)]
struct WebUrlOrRelativePath(String);

impl FromStr for WebUrlOrRelativePath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(':') {
            if Path::new(s).is_absolute() {
                bail!("Not a relative path: {s:?}");
            }
        } else if !s.starts_with("http://") && !s.starts_with("https://") {
            bail!("Only http:// and https:// URLs are supported: {s:?}");
        }

        Ok(Self(s.to_owned()))
    }
}

/// Generate a csig file for an OTA zip.
///
/// The csig file contains the signature for the metadata portions of the OTA zip. This allows
/// Custota to read metadata from the OTA in a secure way without downloading the entire zip.
#[derive(Debug, Parser)]
struct GenerateCsig {
    /// Input path for OTA zip file.
    #[arg(short, long, value_parser)]
    input: PathBuf,

    /// Output path for csig file.
    ///
    /// Defaults to <OTA zip>.csig.
    #[arg(short, long, value_parser)]
    output: Option<PathBuf>,

    /// Path to private key for signing csig.
    #[arg(short, long, value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_file: Option<PathBuf>,

    /// Path to certificate for signing csig.
    #[arg(short, long)]
    cert: PathBuf,

    /// Path to certificate for verifying OTA.
    ///
    /// This is used to verify the signature of the OTA zip file. If this option is omitted, it
    /// defaults to the value of -c/--cert.
    #[arg(short = 'C', long)]
    cert_verify: Option<PathBuf>,
}

/// Generate or update an update info file.
///
/// The update info file contains the relative path or full URL to the OTA zip and the csig file.
/// This command only updates the required fields in the file and leaves other fields untouched.
#[derive(Debug, Parser)]
struct GenerateUpdateInfo {
    /// Relative path or URL to the OTA zip.
    ///
    /// Custota will take the URL of the update info file and use this field to compute the full URL
    /// to the OTA zip. This can be set to a relative path if the OTA is stored in the same
    /// directory tree as the update info file. Otherwise, it can be set to an actual URL, allowing
    /// the OTA zip to be hosted on a different domain.
    #[arg(short, long)]
    location: WebUrlOrRelativePath,

    /// Relative path or URL to the csig file.
    ///
    /// Defaults to <location>.csig.
    #[arg(short, long)]
    csig_location: Option<WebUrlOrRelativePath>,

    /// Path to update info file.
    #[arg(short, long, value_parser)]
    file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenCsig(GenerateCsig),
    GenUpdateInfo(GenerateUpdateInfo),
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

enum PassphraseSource {
    Prompt(String),
    EnvVar(OsString),
    File(PathBuf),
}

impl PassphraseSource {
    fn acquire(&self) -> Result<String> {
        let passphrase = match self {
            Self::Prompt(p) => rpassword::prompt_password(p)?,
            Self::EnvVar(v) => env::var(v)?,
            Self::File(p) => fs::read_to_string(p)?
                .trim_end_matches(&['\r', '\n'])
                .to_owned(),
        };

        Ok(passphrase)
    }
}

/// x509_cert/pem follow rfc7468 strictly instead of implementing a lenient parser. The PEM decoder
/// rejects lines in the base64 section that are longer than 64 characters, excluding whitespace.
/// We'll reformat the data to deal with this because there are certificates that do not follow the
/// spec, like the signing cert for the Pixel 7 Pro official OTAs.
fn reformat_pem(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = vec![];
    let mut base64 = vec![];
    let mut inside_base64 = false;

    for mut line in data.split(|&c| c == b'\n') {
        while !line.is_empty() && line[line.len() - 1].is_ascii_whitespace() {
            line = &line[..line.len() - 1];
        }

        if line.is_empty() {
            continue;
        } else if line.starts_with(b"-----BEGIN CERTIFICATE-----") {
            inside_base64 = true;
        } else if line.starts_with(b"-----END CERTIFICATE-----") {
            inside_base64 = false;

            for chunk in base64.chunks(64) {
                result.extend_from_slice(chunk);
                result.push(b'\n');
            }

            base64.clear();
        } else if inside_base64 {
            base64.extend_from_slice(line);
            continue;
        }

        result.extend_from_slice(line);
        result.push(b'\n');
    }

    if inside_base64 {
        bail!("PEM certificate has start tag, but no end tag");
    }

    Ok(result)
}

/// Read PEM-encoded certificate from a file.
fn read_pem_cert(path: &Path) -> Result<Certificate> {
    let data = fs::read(path)?;
    let data = reformat_pem(&data)?;
    let certificate = Certificate::from_pem(data)?;

    Ok(certificate)
}

/// Read PEM-encoded PKCS8 private key from a file.
fn read_pem_key(path: &Path, source: &PassphraseSource) -> Result<RsaPrivateKey> {
    let data = fs::read_to_string(path)?;

    let certificate = if data.contains("ENCRYPTED") {
        let passphrase = source
            .acquire()
            .with_context(|| format!("Failed to acquire passphrase for {path:?}"))?;

        RsaPrivateKey::from_pkcs8_encrypted_pem(&data, passphrase)
            .with_context(|| format!("Failed to decrypt private key: {path:?}"))?
    } else {
        RsaPrivateKey::from_pkcs8_pem(&data)?
    };

    Ok(certificate)
}

/// Read entry from a zip file into memory.
fn get_zip_entry_data(reader: impl Read + Seek, name: &str) -> Result<Vec<u8>> {
    let mut zip = ZipArchive::new(reader)?;
    let mut entry = zip.by_name(name)?;
    let mut buf = vec![0u8; entry.size() as usize];

    entry.read_exact(&mut buf)?;

    Ok(buf)
}

/// Parse the CMS signature from the file. Returns the decoded CMS [`SignedData`] structure and the
/// length of the file (from the beginning) that's covered by the signature.
fn parse_ota_sig(mut reader: impl Read + Seek) -> Result<(SignedData, u64)> {
    let file_size = reader.seek(SeekFrom::End(0))?;

    reader.seek(SeekFrom::Current(-6))?;
    let mut footer = [0u8; 6];
    reader.read_exact(&mut footer)?;

    let abs_eoc_offset = u16::from_le_bytes(footer[0..2].try_into().unwrap());
    let sig_magic = u16::from_le_bytes(footer[2..4].try_into().unwrap());
    let comment_size = u16::from_le_bytes(footer[4..6].try_into().unwrap());

    if sig_magic != 0xffff {
        bail!("Cannot find OTA signature footer magic");
    }

    // RecoverySystem.verifyPackage() always assumes a non-zip64 EOCD, so we'll do the same.
    let eocd_size = u64::from(22 + comment_size);
    if file_size < eocd_size {
        bail!("Zip is too small to contain EOCD");
    } else if u64::from(abs_eoc_offset) > eocd_size {
        bail!("Signature offset exceeds archive comment size");
    }

    reader.seek(SeekFrom::Start(file_size - eocd_size))?;
    let mut eocd = vec![0u8; eocd_size as usize];
    reader.read_exact(&mut eocd)?;

    let mut eocd_magic_iter = memmem::find_iter(&eocd, EOCD_MAGIC);
    if eocd_magic_iter.next() != Some(0) {
        bail!("Cannot find EOCD magic");
    }
    if eocd_magic_iter.next().is_some() {
        bail!("EOCD magic found in archive comment");
    }

    let sig_offset = eocd_size as usize - usize::from(abs_eoc_offset);
    let sd = parse_cms(&eocd[sig_offset..eocd_size as usize - 6])?;
    // The signature covers everything aside from the archive comment and its length field.
    let hashed_size = file_size - 2 - u64::from(comment_size);

    Ok((sd, hashed_size))
}

/// Parse a CMS [`SignedData`] structure from raw DER-encoded data.
fn parse_cms(data: &[u8]) -> Result<SignedData> {
    let ci = ContentInfo::from_der(data)?;
    let sd = ci.content.decode_as::<SignedData>()?;

    Ok(sd)
}

/// Get a list of all standard X509 certificates contained within a [`SignedData`] structure.
fn get_cms_certs(sd: &SignedData) -> Vec<Certificate> {
    sd.certificates.as_ref().map_or_else(Vec::new, |certs| {
        certs
            .0
            .iter()
            .filter_map(|cc| {
                if let CertificateChoices::Certificate(c) = cc {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect()
    })
}

/// Get and parse the PEM-encoded otacert entry from an OTA zip.
fn get_zip_otacert(reader: impl Read + Seek) -> Result<Certificate> {
    let data = get_zip_entry_data(reader, OTACERT_PATH)?;
    let data = reformat_pem(&data)?;
    let certificate = Certificate::from_pem(data)?;

    Ok(certificate)
}

/// Verify an OTA zip against its embedded certificates. This function makes no assertion about
/// whether the certificate is actually trusted. Returns the embedded certificate.
fn verify_ota(mut reader: impl Read + Seek) -> Result<Certificate> {
    let (sd, hashed_size) = parse_ota_sig(&mut reader)?;

    // Make sure the certificate in the CMS structure matches the otacert zip entry.
    let certs = get_cms_certs(&sd);
    if certs.len() != 1 {
        bail!("Expected exactly one Certificate instance");
    }

    let cert = &certs[0];
    let public_key =
        RsaPublicKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref())?;

    let cert_ota = get_zip_otacert(&mut reader)?;
    if cert != &cert_ota {
        bail!("CMS embedded certificate does not match {OTACERT_PATH}");
    }

    // Make sure this is a signature scheme we can handle. There's currently no Rust library to
    // verify arbitrary CMS signatures for large files without fully reading them into memory.
    if sd.signer_infos.0.len() != 1 {
        bail!("Expected exactly one SignerInfo instance");
    }

    use const_oid::db::rfc5912;

    let signer = sd.signer_infos.0.get(0).unwrap();
    if signer.digest_alg.oid != rfc5912::ID_SHA_256 {
        bail!("Unsupported digest algorithm: {}", signer.digest_alg.oid);
    } else if signer.signature_algorithm.oid != rfc5912::RSA_ENCRYPTION
        && signer.signature_algorithm.oid != rfc5912::SHA_256_WITH_RSA_ENCRYPTION
    {
        bail!(
            "Unsupported signature algorithm: {}",
            signer.signature_algorithm.oid,
        );
    }

    // Manually hash the parts of the file covered by the signature.
    reader.seek(SeekFrom::Start(0))?;

    let digest = {
        let mut hasher = Sha256::new();
        let n = io::copy(&mut reader.take(hashed_size), &mut hasher)?;
        if n != hashed_size {
            bail!("Unexpected EOF while hashing file");
        }

        hasher.finalize()
    };

    // Verify the signature against the public key.
    let scheme = Pkcs1v15Sign::new::<Sha256>();
    public_key.verify(scheme, &digest, signer.signature.as_bytes())?;

    Ok(cert_ota)
}

/// Parse OTA metadata property file list (list of zip entry names, offsets, and sizes).
fn parse_prop_files(data: &str) -> Result<Vec<PropertyFile>> {
    let mut result = vec![];

    for entry in data.trim_end().split(',') {
        let mut pieces = entry.split(':');

        let name = pieces
            .next()
            .ok_or_else(|| anyhow!("Missing property file name"))?
            .to_owned();
        let offset = pieces
            .next()
            .ok_or_else(|| anyhow!("Missing property file offset"))?
            .parse::<u64>()?;
        let size = pieces
            .next()
            .ok_or_else(|| anyhow!("Missing property file size"))?
            .parse::<u64>()?;

        if let Some(piece) = pieces.next() {
            bail!("Unexpected property file entry piece: {piece:?}");
        }

        result.push(PropertyFile {
            name,
            offset,
            size,
            digest: None,
        });
    }

    Ok(result)
}

/// Parse protobuf OTA metadata from zip.
fn get_ota_metadata(reader: impl Read + Seek) -> Result<OtaMetadata> {
    let data = get_zip_entry_data(reader, METADATA_PATH)?;
    let metadata = OtaMetadata::from_reader(&mut BytesReader::from_bytes(&data), &data)?;

    Ok(metadata)
}

/// Compute the SHA256 digest of a section of a file.
fn hash_section(
    mut reader: impl Read + Seek,
    offset: u64,
    size: u64,
) -> Result<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>> {
    let mut hasher = Sha256::new();

    reader.seek(SeekFrom::Start(offset))?;

    let n = io::copy(&mut reader.take(size), &mut hasher)?;
    if n != size {
        bail!("Unexpected EOF while reading {size} bytes at offset {offset}");
    }

    Ok(hasher.finalize())
}

/// Create a CMS signature with the specified encapsulated content.
fn sign_cms_inline(key: &RsaPrivateKey, cert: &Certificate, data: &[u8]) -> Result<ContentInfo> {
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(
            Tag::OctetString,
            OctetStringRef::new(data)?.as_bytes(),
        )?),
    };

    let signer = SigningKey::<Sha256>::new(key.clone());
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let si_builder = SignerInfoBuilder::new(
        &signer,
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_algorithm.clone(),
        &content,
        None,
    )
    .map_err(|e| anyhow!("Failed to create SignerInfoBuilder: {e}"))?;

    let sd = SignedDataBuilder::new(&content)
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| anyhow!("Failed to add digest algorithm: {e}"))?
        .add_certificate(CertificateChoices::Certificate(cert.clone()))
        .map_err(|e| anyhow!("Failed to add certificate: {e}"))?
        .add_signer_info(si_builder)
        .map_err(|e| anyhow!("Failed to add signer info: {e}"))?
        .build()
        .map_err(|e| anyhow!("Failed to build SignedData: {e}"))?;

    Ok(sd)
}

fn subcommand_gen_csig(args: &GenerateCsig) -> Result<()> {
    let passphrase_source = if let Some(v) = &args.passphrase_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &args.passphrase_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", args.key))
    };

    let signing_private_key = read_pem_key(&args.key, &passphrase_source)?;
    let signing_cert = read_pem_cert(&args.cert)?;
    let signing_public_key = RsaPublicKey::try_from(
        signing_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
    )?;

    if signing_private_key.to_public_key() != signing_public_key {
        bail!(
            "Private key {:?} does not match certificate {:?}",
            args.key,
            args.cert,
        );
    }

    let (verify_cert_path, verify_cert) = match &args.cert_verify {
        Some(c) => (c, Cow::Owned(read_pem_cert(c)?)),
        None => (&args.cert, Cow::Borrowed(&signing_cert)),
    };

    let file = File::open(&args.input)?;
    let mut reader = BufReader::new(file);

    println!("Verifying OTA signature...");
    let embedded_cert = verify_ota(&mut reader)?;
    if embedded_cert != *verify_cert {
        bail!("OTA has a valid signature, but was not signed with: {verify_cert_path:?}");
    }

    println!("Reading OTA metadata...");
    let metadata = get_ota_metadata(&mut reader)?;

    if metadata.type_pb != OtaType::AB {
        bail!("Not an A/B OTA");
    } else if metadata.wipe {
        bail!("OTA unconditionally wipes userdata partition");
    } else if metadata.downgrade || metadata.spl_downgrade {
        bail!("Downgrades are not supported");
    }

    let device_name = metadata
        .precondition
        .as_ref()
        .map(|s| &s.device)
        .and_then(|d| d.first())
        .ok_or_else(|| anyhow!("Preconditions do not list a device name"))?;
    if Path::new(device_name).file_name() != Some(OsStr::new(&device_name)) {
        bail!("Invalid device name: {device_name:?}");
    }

    let postcondition = metadata
        .postcondition
        .as_ref()
        .ok_or_else(|| anyhow!("Postconditions are missing"))?;
    let fingerprint = postcondition
        .build
        .first()
        .ok_or_else(|| anyhow!("Postconditions do not list a fingerprint"))?;

    println!("Device name: {device_name}");
    println!("Fingerprint: {fingerprint}");
    println!("Security patch: {}", postcondition.security_patch_level);

    let pfs_raw = metadata
        .property_files
        .get("ota-property-files")
        .ok_or_else(|| anyhow!("Postconditions do not list property files"))?;
    let pfs = parse_prop_files(pfs_raw)?;
    let file_size = reader.seek(SeekFrom::End(0))?;

    let invalid_pfs = pfs
        .iter()
        .filter(|p| p.offset + p.size > file_size)
        .collect::<Vec<_>>();

    if !invalid_pfs.is_empty() {
        bail!("Property file ranges not in bounds: {:?}", invalid_pfs);
    }

    let digested_pfs = pfs
        .iter()
        .map(|pf| {
            hash_section(&mut reader, pf.offset, pf.size).map(|d| PropertyFile {
                digest: Some(format!("{d:x}")),
                ..pf.clone()
            })
        })
        .collect::<Result<_>>()?;

    let csig_info = CsigInfo {
        version: 1,
        files: digested_pfs,
    };
    let csig_info_raw = serde_json::to_string(&csig_info)?;

    let csig_signature = sign_cms_inline(
        &signing_private_key,
        &signing_cert,
        csig_info_raw.as_bytes(),
    )?;
    let csig_signature_der = csig_signature.to_der()?;

    let output = args.output.as_ref().map_or_else(
        || {
            let mut s = args.input.clone().into_os_string();
            s.push(CSIG_EXT);
            Cow::Owned(PathBuf::from(s))
        },
        Cow::Borrowed,
    );

    fs::write(output.as_ref(), csig_signature_der)
        .with_context(|| anyhow!("Failed to create file: {output:?}"))?;

    println!("Wrote: {output:?}");

    Ok(())
}

fn subcommand_gen_update_info(args: &GenerateUpdateInfo) -> Result<()> {
    let csig_location = args.csig_location.as_ref().map_or_else(
        || Cow::Owned(format!("{}{CSIG_EXT}", args.location.0)),
        |l| Cow::Borrowed(&l.0),
    );

    let mut options = OpenOptions::new();
    options.read(true).write(true);

    let (mut file, mut update_info, created) = match options.open(&args.file) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            let update_info: UpdateInfo = serde_json::from_reader(&mut reader)
                .with_context(|| anyhow!("Failed to parse JSON: {:?}", args.file))?;

            (reader.into_inner(), update_info, false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let f = options
                .clone()
                .create(true)
                .open(&args.file)
                .with_context(|| anyhow!("Failed to create: {:?}", args.file))?;

            (f, UpdateInfo::default(), true)
        }
        Err(e) => {
            return Err(e).with_context(|| anyhow!("Failed to open: {:?}", args.file))?;
        }
    };

    update_info.version = 2;
    update_info.full = Some(LocationInfo {
        location_ota: args.location.0.clone(),
        location_csig: csig_location.into_owned(),
    });

    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &update_info)?;

    if created {
        println!("Created: {:?}", args.file);
    } else {
        println!("Updated: {:?}", args.file);
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Command::GenCsig(args) => subcommand_gen_csig(&args),
        Command::GenUpdateInfo(args) => subcommand_gen_update_info(&args),
    }
}

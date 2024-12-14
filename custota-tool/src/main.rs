/*
 * SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fmt::{self, Write as _},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    cli::args::LogFormat,
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::{ota, payload::PayloadHeader},
    protobuf::build::tools::releasetools::ota_metadata::OtaType,
    stream::{self, HashingReader, PSeekFile},
};
use cap_std::ambient_authority;
use cap_tempfile::TempDir;
use clap::{Parser, Subcommand, ValueEnum};
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use const_oid::ObjectIdentifier;
use hex::FromHexError;
use ring::digest::Digest;
use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    signature::Verifier,
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Sha256, Sha512};
use tracing::{info, warn, Level};
use x509_cert::{
    der::{asn1::OctetStringRef, Any, Decode, Encode, Tag},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};
use zip::{write::FileOptions, ZipWriter};

const CSIG_EXT: &str = ".csig";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PropertyFile {
    name: String,
    offset: u64,
    size: u64,
    digest: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct VbmetaDigest(#[serde(with = "hex")] [u8; 32]);

impl fmt::Debug for VbmetaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VbmetaDigest")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for VbmetaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for VbmetaDigest {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Self([0u8; 32]);
        hex::decode_to_slice(s, &mut result.0)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CsigInfo {
    version: CsigVersion,
    files: Vec<PropertyFile>,
    // Version 2 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    vbmeta_digest: Option<VbmetaDigest>,
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

#[derive(Clone, Copy, Debug, ValueEnum, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
enum CsigVersion {
    #[value(name = "1")]
    Version1 = 1,
    #[value(name = "2")]
    Version2 = 2,
}

/// View the contents of a csig file.
#[derive(Debug, Parser)]
struct ShowCsig {
    /// Input path for csig file.
    #[arg(short, long, value_parser)]
    input: PathBuf,

    /// Path to certificate for verifying csig.
    #[arg(short, long, value_parser)]
    cert: Option<PathBuf>,

    /// Show the raw JSON contents of csig data.
    ///
    /// This is useful when programmatically parsing the output.
    #[arg(short, long)]
    raw: bool,
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
    #[arg(short, long, value_parser)]
    cert: PathBuf,

    /// Path to certificate for verifying OTA.
    ///
    /// This is used to verify the signature of the OTA zip file. If this option is omitted, it
    /// defaults to the value of -c/--cert.
    #[arg(short = 'C', long)]
    cert_verify: Option<PathBuf>,

    /// csig file format version.
    ///
    /// csig version 1 is supported by all versions of Custota. Version 2 is
    /// supported since version 5.0 of Custota and adds support for storing the
    /// vbmeta digest to allow detecting updates when the OS version does not
    /// change.
    #[arg(long, value_enum, default_value_t = CsigVersion::Version2)]
    csig_version: CsigVersion,
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

    /// Source vbmeta digest for an incremental OTA.
    #[arg(short, long, value_name = "SHA256", value_parser)]
    inc_vbmeta_digest: Option<VbmetaDigest>,
}

/// Generate a module for system CA certificates.
///
/// The module will install a set of certificates into the system CA trust store.
#[derive(Debug, Parser)]
struct GenerateCertModule {
    /// Output path for module zip.
    #[arg(short, long, value_parser)]
    output: PathBuf,

    /// Path to certificate.
    #[arg(value_parser, num_args = 1)]
    cert: Vec<PathBuf>,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Subcommand)]
enum Command {
    ShowCsig(ShowCsig),
    GenCsig(GenerateCsig),
    GenUpdateInfo(GenerateUpdateInfo),
    GenCertModule(GenerateCertModule),
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Lowest log message severity to output.
    #[arg(long, global = true, value_name = "LEVEL", default_value_t = Level::INFO)]
    log_level: Level,

    /// Output format for log messages.
    #[arg(long, global = true, value_name = "FORMAT", default_value_t)]
    log_format: LogFormat,
}

/// Compute the SHA256 digest of a section of a file.
fn hash_section(
    mut reader: impl Read + Seek,
    offset: u64,
    size: u64,
    cancel_signal: &AtomicBool,
) -> Result<Digest> {
    reader.seek(SeekFrom::Start(offset))?;

    let mut hashing_reader =
        HashingReader::new(reader, ring::digest::Context::new(&ring::digest::SHA256));

    stream::copy_n(&mut hashing_reader, io::sink(), size, cancel_signal)?;

    let (_, context) = hashing_reader.finish();

    Ok(context.finish())
}

/// Verify the CMS signature against the specified data. Only SHA256 and SHA512
/// are supported for both the signed attributes digest and the content digest.
fn verify_cms_signature(
    signed_data: &SignedData,
    econtent_type: ObjectIdentifier,
    econtent_data: &[u8],
    cert: &Certificate,
) -> Result<()> {
    let public_key = crypto::get_public_key(cert)?;

    for signer_info in signed_data.signer_infos.0.iter() {
        let signature = Signature::try_from(signer_info.signature.as_bytes())?;
        let Some(signed_attrs) = &signer_info.signed_attrs else {
            continue;
        };
        let signed_attrs_der = signed_attrs.to_der()?;

        let (ring_algo, result) = match signer_info.digest_alg.oid {
            const_oid::db::rfc5912::ID_SHA_256 => (
                &ring::digest::SHA256,
                VerifyingKey::<Sha256>::new(public_key.clone())
                    .verify(&signed_attrs_der, &signature),
            ),
            const_oid::db::rfc5912::ID_SHA_512 => (
                &ring::digest::SHA512,
                VerifyingKey::<Sha512>::new(public_key.clone())
                    .verify(&signed_attrs_der, &signature),
            ),
            _ => continue,
        };

        if result.is_err() {
            continue;
        }

        // At this point, the signature of the signed attributes is verified and
        // we know we're looking at the correct signer info. All further issues
        // are treated as errors.

        let econtent_type_attr = signed_attrs
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_CONTENT_TYPE)
            .ok_or_else(|| {
                anyhow!(
                    "Signed attribute not found: {}",
                    const_oid::db::rfc5911::ID_CONTENT_TYPE,
                )
            })?;

        if econtent_type_attr.values.len() != 1 {
            bail!("Expected exactly one signed attribute value: {econtent_type_attr:?}");
        }

        let econtent_type_expected = econtent_type_attr
            .values
            .get(0)
            .unwrap()
            .decode_as::<ObjectIdentifier>()?;

        if econtent_type != econtent_type_expected {
            bail!("Content type does not match signed attribute: {econtent_type} != {econtent_type_expected}");
        }

        let econtent_digest_attr = signed_attrs
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .ok_or_else(|| {
                anyhow!(
                    "Signed attribute not found: {}",
                    const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
                )
            })?;

        if econtent_digest_attr.values.len() != 1 {
            bail!("Expected exactly one signed attribute value: {econtent_digest_attr:?}");
        }

        let econtent_digest_expected = econtent_digest_attr
            .values
            .get(0)
            .unwrap()
            .decode_as::<OctetStringRef>()?;

        let econtent_digest = ring::digest::digest(ring_algo, econtent_data);

        if econtent_digest.as_ref() != econtent_digest_expected.as_bytes() {
            bail!(
                "Content digest does not match signed attribute: {} != {}",
                hex::encode(econtent_digest),
                hex::encode(econtent_digest_expected),
            );
        }

        return Ok(());
    }

    bail!("None of the CMS signatures match the specified certificate");
}

/// Return the encapsulated content in a CMS signature, optionally verifying the
/// signature first.
fn get_cms_inline(ci: &ContentInfo, cert: Option<&Certificate>) -> Result<Vec<u8>> {
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        bail!(
            "Invalid content type: {} != {}",
            ci.content_type,
            const_oid::db::rfc5911::ID_SIGNED_DATA,
        );
    }

    let signed_data = ci.content.decode_as::<SignedData>()?;

    let econtent_type = signed_data.encap_content_info.econtent_type;
    if econtent_type != const_oid::db::rfc5911::ID_DATA {
        bail!(
            "Invalid encapsulated content type: {econtent_type} != {}",
            const_oid::db::rfc5911::ID_DATA,
        );
    }

    let Some(econtent) = &signed_data.encap_content_info.econtent else {
        bail!("CMS signature has no encapsulated content");
    };
    let econtent_data = econtent.decode_as::<OctetStringRef>()?;

    if let Some(cert) = cert {
        verify_cms_signature(&signed_data, econtent_type, econtent_data.as_bytes(), cert)?;
    } else {
        warn!("Skipping signature verification");
    }

    Ok(econtent_data.as_bytes().to_vec())
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

fn compute_vbmeta_digest(
    raw_reader: PSeekFile,
    offset: u64,
    size: u64,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<[u8; 32]> {
    info!("Computing vbmeta digest...");

    let authority = ambient_authority();
    let temp_dir = TempDir::new(authority).context("Failed to create temporary directory")?;
    let unique_images = header
        .manifest
        .partitions
        .iter()
        .map(|p| &p.partition_name)
        .cloned()
        .collect::<BTreeSet<_>>();

    avbroot::cli::ota::extract_payload(
        &raw_reader,
        &temp_dir,
        offset,
        size,
        header,
        &unique_images,
        cancel_signal,
    )?;

    avbroot::cli::avb::compute_digest(&temp_dir, "vbmeta", cancel_signal)
}

fn subcommand_show_csig(args: &ShowCsig) -> Result<()> {
    let signing_cert = args
        .cert
        .as_ref()
        .map(|p| {
            crypto::read_pem_cert_file(p)
                .with_context(|| anyhow!("Failed to load certificate: {p:?}"))
        })
        .transpose()?;

    let csig_raw =
        fs::read(&args.input).with_context(|| format!("Failed to read file: {:?}", args.input))?;
    let csig_ci = ContentInfo::from_der(&csig_raw)
        .with_context(|| format!("Failed to parse CMS data: {:?}", args.input))?;

    let csig_json = get_cms_inline(&csig_ci, signing_cert.as_ref())?;

    if args.raw {
        io::stdout().write_all(&csig_json)?;
    } else {
        let csig: CsigInfo = serde_json::from_slice(&csig_json)?;
        println!("{csig:#?}");
    }

    Ok(())
}

fn subcommand_gen_csig(args: &GenerateCsig, cancel_signal: &AtomicBool) -> Result<()> {
    let passphrase_source = if let Some(v) = &args.passphrase_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &args.passphrase_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", args.key))
    };

    let signing_private_key = crypto::read_pem_key_file(&args.key, &passphrase_source)
        .with_context(|| anyhow!("Failed to load key: {:?}", args.key))?;
    let signing_cert = crypto::read_pem_cert_file(&args.cert)
        .with_context(|| anyhow!("Failed to load certificate: {:?}", args.cert))?;

    if !crypto::cert_matches_key(
        &signing_cert,
        &RsaSigningKey::Internal(signing_private_key.clone()),
    )? {
        bail!(
            "Private key {:?} does not match certificate {:?}",
            args.key,
            args.cert,
        );
    }

    let (verify_cert_path, verify_cert) = match &args.cert_verify {
        Some(c) => {
            let cert = crypto::read_pem_cert_file(c)
                .with_context(|| anyhow!("Failed to load certificate: {c:?}"))?;
            (c, Cow::Owned(cert))
        }
        None => (&args.cert, Cow::Borrowed(&signing_cert)),
    };

    let file = File::open(&args.input)
        .map(PSeekFile::new)
        .with_context(|| anyhow!("Failed to open for reading: {:?}", args.input))?;
    let mut reader = BufReader::new(file);

    info!("Verifying OTA signature...");
    let embedded_cert = ota::verify_ota(&mut reader, cancel_signal)?;

    let (metadata, ota_cert, header, _) = ota::parse_zip_ota_info(&mut reader)
        .with_context(|| anyhow!("Failed to parse OTA info from zip"))?;
    if embedded_cert != ota_cert {
        bail!(
            "CMS embedded certificate does not match {}",
            ota::PATH_OTACERT,
        );
    } else if embedded_cert != *verify_cert {
        bail!("OTA has a valid signature, but was not signed with: {verify_cert_path:?}");
    }

    ota::verify_metadata(&mut reader, &metadata, header.blob_offset)
        .with_context(|| anyhow!("Failed to verify OTA metadata offsets"))?;

    if metadata.r#type() != OtaType::Ab {
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

    info!("Device name: {device_name}");
    info!("Fingerprint: {fingerprint}");
    info!("Security patch: {}", postcondition.security_patch_level);

    let pfs_raw = metadata
        .property_files
        .get(ota::PF_NAME)
        .ok_or_else(|| anyhow!("Missing property files: {}", ota::PF_NAME))?;
    let pfs = ota::parse_property_files(pfs_raw)
        .with_context(|| anyhow!("Failed to parse property files: {}", ota::PF_NAME))?;
    let file_size = reader.seek(SeekFrom::End(0))?;

    let (pf_payload_offset, pf_payload_size) = pfs
        .iter()
        .find(|pf| pf.name == ota::PATH_PAYLOAD)
        .ok_or_else(|| anyhow!("Missing property files entry: {}", ota::PATH_PAYLOAD))
        .map(|pf| (pf.offset, pf.size))?;

    let invalid_pfs = pfs
        .iter()
        .filter(|p| p.offset + p.size > file_size)
        .collect::<Vec<_>>();

    if !invalid_pfs.is_empty() {
        bail!("Property file ranges not in bounds: {:?}", invalid_pfs);
    }

    let digested_pfs = pfs
        .into_iter()
        .map(|pf| {
            hash_section(&mut reader, pf.offset, pf.size, cancel_signal).map(|d| PropertyFile {
                name: pf.name,
                offset: pf.offset,
                size: pf.size,
                digest: Some(hex::encode(d)),
            })
        })
        .collect::<Result<_>>()?;

    let raw_reader = reader.into_inner();
    let vbmeta_digest = match args.csig_version {
        CsigVersion::Version1 => None,
        CsigVersion::Version2 => {
            if header.is_full_ota() {
                let digest = compute_vbmeta_digest(
                    raw_reader,
                    pf_payload_offset,
                    pf_payload_size,
                    &header,
                    cancel_signal,
                )?;

                info!("vbmeta digest: {}", hex::encode(digest));

                Some(VbmetaDigest(digest))
            } else {
                info!("Skipping vbmeta digest for incremental OTA");

                None
            }
        }
    };

    let csig_info = CsigInfo {
        version: args.csig_version,
        files: digested_pfs,
        vbmeta_digest,
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

    info!("Wrote: {output:?}");

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
            return Err(e).with_context(|| anyhow!("Failed to open: {:?}", args.file));
        }
    };

    update_info.version = 2;

    let location_info = LocationInfo {
        location_ota: args.location.0.clone(),
        location_csig: csig_location.into_owned(),
    };

    if let Some(vbmeta_digest) = &args.inc_vbmeta_digest {
        update_info
            .incremental
            .insert(vbmeta_digest.to_string(), location_info);
    } else {
        update_info.full = Some(location_info);
    }

    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &update_info)?;

    if created {
        info!("Created: {:?}", args.file);
    } else {
        info!("Updated: {:?}", args.file);
    }

    Ok(())
}

fn subcommand_gen_cert_module(args: &GenerateCertModule) -> Result<()> {
    if args.cert.is_empty() {
        bail!("No certificates specified");
    }

    let mut certs = vec![];
    let mut seen = HashSet::new();

    for path in &args.cert {
        let cert = crypto::read_pem_cert_file(path)
            .with_context(|| format!("Failed to load cert: {path:?}"))?;

        let mut subject_der = vec![];
        cert.tbs_certificate
            .subject
            .encode_to_vec(&mut subject_der)?;

        // Android uses openssl's X509_NAME_hash_old per:
        // https://android.googlesource.com/platform/system/ca-certificates/+/refs/tags/android-14.0.0_r29/README.cacerts
        let subject_md5 = md5::compute(subject_der);
        let subject_hash = u32::from_le_bytes(subject_md5.0[0..4].try_into().unwrap());

        if !seen.insert(subject_hash) {
            warn!("Skipping duplicate cert: {path:?}");
            continue;
        }

        certs.push((subject_hash, cert));
    }

    let raw_writer = File::create(&args.output)
        .with_context(|| format!("Failed to open for writing: {:?}", args.output))?;
    let buf_writer = BufWriter::new(raw_writer);
    let mut zip_writer = ZipWriter::new(buf_writer);
    let options = FileOptions::default();

    let mut description = "Certs: ".to_owned();
    for (i, (hash, _)) in certs.iter().enumerate() {
        if i > 0 {
            write!(&mut description, ", ")?;
        }
        write!(&mut description, "{hash:08x}")?;
    }
    description.push('\n');

    zip_writer.start_file("module.prop", options)?;
    zip_writer.write_all(include_bytes!("../system-ca-certs/module.prop"))?;
    zip_writer.write_all(description.as_bytes())?;

    zip_writer.start_file("post-fs-data.sh", options)?;
    zip_writer.write_all(include_bytes!("../system-ca-certs/post-fs-data.sh"))?;

    for dir in [
        "META-INF",
        "META-INF/com",
        "META-INF/com/google",
        "META-INF/com/google/android",
    ] {
        zip_writer.add_directory(dir, options)?;
    }

    zip_writer.start_file("META-INF/com/google/android/update-binary", options)?;
    zip_writer.write_all(include_bytes!("../system-ca-certs/update-binary"))?;

    zip_writer.start_file("META-INF/com/google/android/updater-script", options)?;
    zip_writer.write_all(include_bytes!("../system-ca-certs/updater-script"))?;

    zip_writer.add_directory("cacerts", options)?;

    for (hash, cert) in certs {
        let name = format!("cacerts/{hash:08x}.0");
        zip_writer.start_file(name, options)?;
        crypto::write_pem_cert(&mut zip_writer, &cert)?;
    }

    zip_writer.finish()?.flush()?;

    Ok(())
}

fn main() -> Result<()> {
    // Set up a cancel signal so we can properly clean up any temporary files.
    let cancel_signal = Arc::new(AtomicBool::new(false));
    {
        let signal = cancel_signal.clone();

        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set signal handler");
    }

    let args = Cli::parse();

    avbroot::cli::args::init_logging(args.log_level, args.log_format);

    match args.command {
        Command::ShowCsig(args) => subcommand_show_csig(&args),
        Command::GenCsig(args) => subcommand_gen_csig(&args, &cancel_signal),
        Command::GenUpdateInfo(args) => subcommand_gen_update_info(&args),
        Command::GenCertModule(args) => subcommand_gen_cert_module(&args),
    }
}

/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    crypto::{self, PassphraseSource},
    format::ota,
    protobuf::build::tools::releasetools::ota_metadata::OtaType,
    stream::{self, HashingReader},
};
use clap::{Parser, Subcommand};
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use ring::digest::Digest;
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x509_cert::{
    der::{asn1::OctetStringRef, Any, Encode, Tag},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};

const CSIG_EXT: &str = ".csig";

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
    #[arg(short, long, value_parser)]
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

/// Compute the SHA256 digest of a section of a file.
fn hash_section(mut reader: impl Read + Seek, offset: u64, size: u64) -> Result<Digest> {
    reader.seek(SeekFrom::Start(offset))?;

    let mut hashing_reader =
        HashingReader::new(reader, ring::digest::Context::new(&ring::digest::SHA256));

    stream::copy_n(
        &mut hashing_reader,
        io::sink(),
        size,
        &Arc::new(AtomicBool::new(false)),
    )?;

    let (_, context) = hashing_reader.finish();

    Ok(context.finish())
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

    let signing_private_key = crypto::read_pem_key_file(&args.key, &passphrase_source)
        .with_context(|| anyhow!("Failed to load key: {:?}", args.key))?;
    let signing_cert = crypto::read_pem_cert_file(&args.cert)
        .with_context(|| anyhow!("Failed to load certificate: {:?}", args.cert))?;

    if !crypto::cert_matches_key(&signing_cert, &signing_private_key)? {
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
        .with_context(|| anyhow!("Failed to open for reading: {:?}", args.input))?;
    let mut reader = BufReader::new(file);

    println!("Verifying OTA signature...");
    let embedded_cert = ota::verify_ota(
        &mut reader,
        // We don't use a signal handler.
        &Arc::new(AtomicBool::new(false)),
    )?;

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

    println!("Device name: {device_name}");
    println!("Fingerprint: {fingerprint}");
    println!("Security patch: {}", postcondition.security_patch_level);

    let pfs_raw = metadata
        .property_files
        .get(ota::PF_NAME)
        .ok_or_else(|| anyhow!("Missing property files: {}", ota::PF_NAME))?;
    let pfs = ota::parse_property_files(pfs_raw)
        .with_context(|| anyhow!("Failed to parse property files: {}", ota::PF_NAME))?;
    let file_size = reader.seek(SeekFrom::End(0))?;

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
            hash_section(&mut reader, pf.offset, pf.size).map(|d| PropertyFile {
                name: pf.name,
                offset: pf.offset,
                size: pf.size,
                digest: Some(hex::encode(d)),
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
            return Err(e).with_context(|| anyhow!("Failed to open: {:?}", args.file));
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

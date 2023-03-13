//! Units of execution.

#![allow(clippy::field_reassign_with_default)]

use std::{
    cell::RefCell,
    fmt::{self, Debug, Display, Formatter},
    rc::Rc,
};

use hex_buffer_serde::{Hex, HexForm};
use hex_fmt::HexFmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use casper_hashing::Digest;
use casper_types::{
    bytesrepr::{self, Bytes, FromBytes, ToBytes, U8_SERIALIZED_LENGTH},
    contracts::{ContractVersion, NamedKeys, DEFAULT_ENTRY_POINT_NAME},
    system::mint::ARG_AMOUNT,
    CLValue, ContractHash, ContractPackage, ContractPackageHash, ContractVersionKey, Key, Phase,
    ProtocolVersion, RuntimeArgs, StoredValue, U512,
};

//use super::error;
/*use crate::{
    core::{
        engine_state::{Error, ExecError, MAX_PAYMENT_AMOUNT},
        execution,
        tracking_copy::{TrackingCopy, TrackingCopyExt},
    },
    shared::newtypes::CorrelationId,
    storage::global_state::StateReader,
};*/

const TAG_LENGTH: usize = U8_SERIALIZED_LENGTH;
const MODULE_BYTES_TAG: u8 = 0;
const STORED_CONTRACT_BY_HASH_TAG: u8 = 1;
const STORED_CONTRACT_BY_NAME_TAG: u8 = 2;
const STORED_VERSIONED_CONTRACT_BY_HASH_TAG: u8 = 3;
const STORED_VERSIONED_CONTRACT_BY_NAME_TAG: u8 = 4;
const TRANSFER_TAG: u8 = 5;

/// Possible ways to identify the `ExecutableDeployItem`.
#[derive(
Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ExecutableDeployItemIdentifier {
    /// The deploy item is of the type [`ExecutableDeployItem::ModuleBytes`]
    Module,
    /// The deploy item is a variation of a stored contract.
    Contract(ContractIdentifier),
    /// The deploy item is a variation of a stored contract package.
    Package(ContractPackageIdentifier),
    /// The deploy item is a native transfer.
    Transfer,
}

/// Possible ways to identify the contract object within an `ExecutableDeployItem`.
#[derive(
Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ContractIdentifier {
    /// The contract object within the deploy item is identified by name.
    Name(String),
    /// The contract object within the deploy item is identified by its hash.
    Hash(ContractHash),
}

/// Possible ways to identify the contract package object within an `ExecutableDeployItem`.
#[derive(
Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ContractPackageIdentifier {
    /// The stored contract package within the deploy item is identified by name.
    Name {
        /// Name of the contract package.
        name: String,
        /// The version specified in the deploy item.
        version: Option<ContractVersion>,
    },
    /// The stored contract package within the deploy item is identified by hash.
    Hash {
        /// Hash of the contract package.
        contract_package_hash: ContractPackageHash,
        /// The version specified in the deploy item.
        version: Option<ContractVersion>,
    },
}

impl ContractPackageIdentifier {
    /// Returns the version of the contract package specified in the deploy item.
    pub fn version(&self) -> Option<ContractVersion> {
        match self {
            ContractPackageIdentifier::Name { version, .. } => *version,
            ContractPackageIdentifier::Hash { version, .. } => *version,
        }
    }
}

/// Represents possible variants of an executable deploy.
#[derive(
Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub enum ExecutableDeployItem {
    /// Executable specified as raw bytes that represent WASM code and an instance of
    /// [`RuntimeArgs`].
    ModuleBytes {
        /// Raw WASM module bytes with assumed "call" export as an entrypoint.
        #[serde(with = "HexForm")]
        module_bytes: Bytes,
        /// Runtime arguments.
        args: RuntimeArgs,
    },
    /// Stored contract referenced by its [`ContractHash`], entry point and an instance of
    /// [`RuntimeArgs`].
    StoredContractByHash {
        /// Contract hash.
        #[serde(with = "contract_hash_as_digest")]
        hash: ContractHash,
        /// Name of an entry point.
        entry_point: String,
        /// Runtime arguments.
        args: RuntimeArgs,
    },
    /// Stored contract referenced by a named key existing in the signer's account context, entry
    /// point and an instance of [`RuntimeArgs`].
    StoredContractByName {
        /// Named key.
        name: String,
        /// Name of an entry point.
        entry_point: String,
        /// Runtime arguments.
        args: RuntimeArgs,
    },
    /// Stored versioned contract referenced by its [`ContractPackageHash`], entry point and an
    /// instance of [`RuntimeArgs`].
    StoredVersionedContractByHash {
        /// Contract package hash
        #[serde(with = "contract_package_hash_as_digest")]
        hash: ContractPackageHash,
        /// An optional version of the contract to call. It will default to the highest enabled
        /// version if no value is specified.
        version: Option<ContractVersion>,
        /// Entry point name.
        entry_point: String,
        /// Runtime arguments.
        args: RuntimeArgs,
    },
    /// Stored versioned contract referenced by a named key existing in the signer's account
    /// context, entry point and an instance of [`RuntimeArgs`].
    StoredVersionedContractByName {
        /// Named key.
        name: String,
        /// An optional version of the contract to call. It will default to the highest enabled
        /// version if no value is specified.
        version: Option<ContractVersion>,
        /// Entry point name.
        entry_point: String,
        /// Runtime arguments.
        args: RuntimeArgs,
    },
    /// A native transfer which does not contain or reference a WASM code.
    Transfer {
        /// Runtime arguments.
        args: RuntimeArgs,
    },
}

mod contract_hash_as_digest {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        contract_hash: &ContractHash,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Digest::from(contract_hash.value()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContractHash, D::Error> {
        let digest = Digest::deserialize(deserializer)?;
        Ok(ContractHash::new(digest.value()))
    }
}

mod contract_package_hash_as_digest {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        contract_package_hash: &ContractPackageHash,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Digest::from(contract_package_hash.value()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContractPackageHash, D::Error> {
        let digest = Digest::deserialize(deserializer)?;
        Ok(ContractPackageHash::new(digest.value()))
    }
}

impl ToBytes for ExecutableDeployItem {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        match self {
            ExecutableDeployItem::ModuleBytes { module_bytes, args } => {
                buffer.insert(0, MODULE_BYTES_TAG);
                buffer.extend(module_bytes.to_bytes()?);
                buffer.extend(args.to_bytes()?);
            }
            ExecutableDeployItem::StoredContractByHash {
                hash,
                entry_point,
                args,
            } => {
                buffer.insert(0, STORED_CONTRACT_BY_HASH_TAG);
                buffer.extend(hash.to_bytes()?);
                buffer.extend(entry_point.to_bytes()?);
                buffer.extend(args.to_bytes()?)
            }
            ExecutableDeployItem::StoredContractByName {
                name,
                entry_point,
                args,
            } => {
                buffer.insert(0, STORED_CONTRACT_BY_NAME_TAG);
                buffer.extend(name.to_bytes()?);
                buffer.extend(entry_point.to_bytes()?);
                buffer.extend(args.to_bytes()?)
            }
            ExecutableDeployItem::StoredVersionedContractByHash {
                hash,
                version,
                entry_point,
                args,
            } => {
                buffer.insert(0, STORED_VERSIONED_CONTRACT_BY_HASH_TAG);
                buffer.extend(hash.to_bytes()?);
                buffer.extend(version.to_bytes()?);
                buffer.extend(entry_point.to_bytes()?);
                buffer.extend(args.to_bytes()?)
            }
            ExecutableDeployItem::StoredVersionedContractByName {
                name,
                version,
                entry_point,
                args,
            } => {
                buffer.insert(0, STORED_VERSIONED_CONTRACT_BY_NAME_TAG);
                buffer.extend(name.to_bytes()?);
                buffer.extend(version.to_bytes()?);
                buffer.extend(entry_point.to_bytes()?);
                buffer.extend(args.to_bytes()?)
            }
            ExecutableDeployItem::Transfer { args } => {
                buffer.insert(0, TRANSFER_TAG);
                buffer.extend(args.to_bytes()?)
            }
        }
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        TAG_LENGTH
            + match self {
            ExecutableDeployItem::ModuleBytes { module_bytes, args } => {
                module_bytes.serialized_length() + args.serialized_length()
            }
            ExecutableDeployItem::StoredContractByHash {
                hash,
                entry_point,
                args,
            } => {
                hash.serialized_length()
                    + entry_point.serialized_length()
                    + args.serialized_length()
            }
            ExecutableDeployItem::StoredContractByName {
                name,
                entry_point,
                args,
            } => {
                name.serialized_length()
                    + entry_point.serialized_length()
                    + args.serialized_length()
            }
            ExecutableDeployItem::StoredVersionedContractByHash {
                hash,
                version,
                entry_point,
                args,
            } => {
                hash.serialized_length()
                    + version.serialized_length()
                    + entry_point.serialized_length()
                    + args.serialized_length()
            }
            ExecutableDeployItem::StoredVersionedContractByName {
                name,
                version,
                entry_point,
                args,
            } => {
                name.serialized_length()
                    + version.serialized_length()
                    + entry_point.serialized_length()
                    + args.serialized_length()
            }
            ExecutableDeployItem::Transfer { args } => args.serialized_length(),
        }
    }
}

impl FromBytes for ExecutableDeployItem {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder) = u8::from_bytes(bytes)?;
        match tag {
            MODULE_BYTES_TAG => {
                let (module_bytes, remainder) = FromBytes::from_bytes(remainder)?;
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((
                    ExecutableDeployItem::ModuleBytes { module_bytes, args },
                    remainder,
                ))
            }
            STORED_CONTRACT_BY_HASH_TAG => {
                let (hash, remainder) = FromBytes::from_bytes(remainder)?;
                let (entry_point, remainder) = String::from_bytes(remainder)?;
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((
                    ExecutableDeployItem::StoredContractByHash {
                        hash,
                        entry_point,
                        args,
                    },
                    remainder,
                ))
            }
            STORED_CONTRACT_BY_NAME_TAG => {
                let (name, remainder) = String::from_bytes(remainder)?;
                let (entry_point, remainder) = String::from_bytes(remainder)?;
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((
                    ExecutableDeployItem::StoredContractByName {
                        name,
                        entry_point,
                        args,
                    },
                    remainder,
                ))
            }
            STORED_VERSIONED_CONTRACT_BY_HASH_TAG => {
                let (hash, remainder) = FromBytes::from_bytes(remainder)?;
                let (version, remainder) = Option::<ContractVersion>::from_bytes(remainder)?;
                let (entry_point, remainder) = String::from_bytes(remainder)?;
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((
                    ExecutableDeployItem::StoredVersionedContractByHash {
                        hash,
                        version,
                        entry_point,
                        args,
                    },
                    remainder,
                ))
            }
            STORED_VERSIONED_CONTRACT_BY_NAME_TAG => {
                let (name, remainder) = String::from_bytes(remainder)?;
                let (version, remainder) = Option::<ContractVersion>::from_bytes(remainder)?;
                let (entry_point, remainder) = String::from_bytes(remainder)?;
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((
                    ExecutableDeployItem::StoredVersionedContractByName {
                        name,
                        version,
                        entry_point,
                        args,
                    },
                    remainder,
                ))
            }
            TRANSFER_TAG => {
                let (args, remainder) = FromBytes::from_bytes(remainder)?;
                Ok((ExecutableDeployItem::Transfer { args }, remainder))
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}
impl Display for ExecutableDeployItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ExecutableDeployItem::ModuleBytes { module_bytes, .. } => {
                write!(f, "module-bytes [{} bytes]", module_bytes.len())
            }
            ExecutableDeployItem::StoredContractByHash {
                hash, entry_point, ..
            } => write!(
                f,
                "stored-contract-by-hash: {:10}, entry-point: {}",
                HexFmt(hash),
                entry_point,
            ),
            ExecutableDeployItem::StoredContractByName {
                name, entry_point, ..
            } => write!(
                f,
                "stored-contract-by-name: {}, entry-point: {}",
                name, entry_point,
            ),
            ExecutableDeployItem::StoredVersionedContractByHash {
                hash,
                version: Some(ver),
                entry_point,
                ..
            } => write!(
                f,
                "stored-versioned-contract-by-hash: {:10}, version: {}, entry-point: {}",
                HexFmt(hash),
                ver,
                entry_point,
            ),
            ExecutableDeployItem::StoredVersionedContractByHash {
                hash, entry_point, ..
            } => write!(
                f,
                "stored-versioned-contract-by-hash: {:10}, version: latest, entry-point: {}",
                HexFmt(hash),
                entry_point,
            ),
            ExecutableDeployItem::StoredVersionedContractByName {
                name,
                version: Some(ver),
                entry_point,
                ..
            } => write!(
                f,
                "stored-versioned-contract: {}, version: {}, entry-point: {}",
                name, ver, entry_point,
            ),
            ExecutableDeployItem::StoredVersionedContractByName {
                name, entry_point, ..
            } => write!(
                f,
                "stored-versioned-contract: {}, version: latest, entry-point: {}",
                name, entry_point,
            ),
            ExecutableDeployItem::Transfer { .. } => write!(f, "transfer"),
        }
    }
}

impl Debug for ExecutableDeployItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ExecutableDeployItem::ModuleBytes { module_bytes, args } => f
                .debug_struct("ModuleBytes")
                .field("module_bytes", &format!("[{} bytes]", module_bytes.len()))
                .field("args", args)
                .finish(),
            ExecutableDeployItem::StoredContractByHash {
                hash,
                entry_point,
                args,
            } => f
                .debug_struct("StoredContractByHash")
                .field("hash", &base16::encode_lower(hash))
                .field("entry_point", &entry_point)
                .field("args", args)
                .finish(),
            ExecutableDeployItem::StoredContractByName {
                name,
                entry_point,
                args,
            } => f
                .debug_struct("StoredContractByName")
                .field("name", &name)
                .field("entry_point", &entry_point)
                .field("args", args)
                .finish(),
            ExecutableDeployItem::StoredVersionedContractByHash {
                hash,
                version,
                entry_point,
                args,
            } => f
                .debug_struct("StoredVersionedContractByHash")
                .field("hash", &base16::encode_lower(hash))
                .field("version", version)
                .field("entry_point", &entry_point)
                .field("args", args)
                .finish(),
            ExecutableDeployItem::StoredVersionedContractByName {
                name,
                version,
                entry_point,
                args,
            } => f
                .debug_struct("StoredVersionedContractByName")
                .field("name", &name)
                .field("version", version)
                .field("entry_point", &entry_point)
                .field("args", args)
                .finish(),
            ExecutableDeployItem::Transfer { args } => {
                f.debug_struct("Transfer").field("args", args).finish()
            }
        }
    }
}
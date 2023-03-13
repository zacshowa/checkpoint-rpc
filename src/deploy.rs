use std::collections::BTreeSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeError};
use ed25519_dalek::ExpandedSecretKey;
use thiserror::Error;
use derive_more::{Add, AddAssign, From, Shl, Shr, Sub, SubAssign};
use k256::ecdsa::Signature as Secp256k1Signature;
use itertools::Itertools;
use humantime::{DurationError, TimestampError};
use casper_types::{bytesrepr, bytesrepr::{Bytes, ToBytes, FromBytes},crypto, PublicKey, SecretKey, Signature, U512};
use casper_hashing::Digest;
use k256::ecdsa::signature::Signer;
use crate::executable_deploy_item::ExecutableDeployItem;


// A deploy; an item containing a smart contract along with the requester's signature(s).
#[derive(
Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug,
)]
pub struct Deploy {
    hash: DeployHash,
    header: DeployHeader,
    payment: ExecutableDeployItem,
    session: ExecutableDeployItem,
    approvals: BTreeSet<Approval>,
    #[serde(skip)]
    is_valid: Option<Result<(), DeployConfigurationFailure>>,
}

impl Deploy {
    /// Constructs a new signed `Deploy`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: Timestamp,
        ttl: TimeDiff,
        gas_price: u64,
        dependencies: Vec<DeployHash>,
        chain_name: String,
        payment: ExecutableDeployItem,
        session: ExecutableDeployItem,
        secret_key: &SecretKey,
        account: Option<PublicKey>,
    ) -> Deploy {

        let serialized_body = serialize_body(&payment, &session);
        let body_hash = Digest::hash(&serialized_body);

        let account = account.unwrap_or_else(|| PublicKey::from(secret_key));

        // Remove duplicates.
        let dependencies = dependencies.into_iter().unique().collect();
        let header = DeployHeader {
            account,
            timestamp,
            ttl,
            gas_price,
            body_hash,
            dependencies,
            chain_name,
        };
        let serialized_header = serialize_header(&header);
        let hash = DeployHash::new(Digest::hash(&serialized_header));

        let mut deploy = Deploy {
            hash,
            header,
            payment,
            session,
            approvals: BTreeSet::new(),
            is_valid: None,
        };

        deploy.sign(secret_key);
        deploy
    }

    /// Adds a signature of this deploy's hash to its approvals.
    pub fn sign(&mut self, secret_key: &SecretKey) {
        let approval = Approval::create(&self.hash, secret_key);
        self.approvals.insert(approval);
    }
}

/// The header portion of a [`Deploy`](struct.Deploy.html).
#[derive(
Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug,
)]
pub struct DeployHeader {
    account: PublicKey,
    timestamp: Timestamp,
    ttl: TimeDiff,
    gas_price: u64,
    body_hash: Digest,
    dependencies: Vec<DeployHash>,
    chain_name: String,
}

impl ToBytes for DeployHeader {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.account.to_bytes()?);
        buffer.extend(self.timestamp.to_bytes()?);
        buffer.extend(self.ttl.to_bytes()?);
        buffer.extend(self.gas_price.to_bytes()?);
        buffer.extend(self.body_hash.to_bytes()?);
        buffer.extend(self.dependencies.to_bytes()?);
        buffer.extend(self.chain_name.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.account.serialized_length()
            + self.timestamp.serialized_length()
            + self.ttl.serialized_length()
            + self.gas_price.serialized_length()
            + self.body_hash.serialized_length()
            + self.dependencies.serialized_length()
            + self.chain_name.serialized_length()
    }
}

/// A timestamp type, representing a concrete moment in time.
#[derive(
Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Shr, Shl,
)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The maximum value a timestamp can have.
    pub const MAX: Timestamp = Timestamp(u64::MAX);

    /// Returns the timestamp of the current moment.
    pub fn now() -> Self {
        let millis = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis() as u64;
        Timestamp(millis)
    }

    /// Returns the timestamp as the number of milliseconds since the Unix epoch
    pub fn millis(&self) -> u64 {
        self.0
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(self.0)) {
            Some(system_time) => write!(f, "{}", humantime::format_rfc3339_millis(system_time))
                .or_else(|e| write!(f, "Invalid timestamp: {}: {}", e, self.0)),
            None => write!(f, "invalid Timestamp: {} ms after the Unix epoch", self.0),
        }
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let system_time = humantime::parse_rfc3339_weak(value)?;
        let inner = system_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TimestampError::OutOfRange)?
            .as_millis() as u64;
        Ok(Timestamp(inner))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let value_as_string = String::deserialize(deserializer)?;
            Timestamp::from_str(&value_as_string).map_err(SerdeError::custom)
        } else {
            let inner = u64::deserialize(deserializer)?;
            Ok(Timestamp(inner))
        }
    }
}

impl ToBytes for Timestamp {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

impl FromBytes for Timestamp {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        u64::from_bytes(bytes).map(|(inner, remainder)| (Timestamp(inner), remainder))
    }
}

impl From<u64> for Timestamp {
    fn from(milliseconds_since_epoch: u64) -> Timestamp {
        Timestamp(milliseconds_since_epoch)
    }
}
/// A time difference between two timestamps.
#[derive(
Debug,
Default,
Clone,
Copy,
PartialEq,
Eq,
PartialOrd,
Ord,
Hash,
From,
)]
pub struct TimeDiff(u64);

impl From<TimeDiff> for Duration {
    fn from(diff: TimeDiff) -> Duration {
        Duration::from_millis(diff.0)
    }
}

impl Display for TimeDiff {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", humantime::format_duration(Duration::from(*self)))
    }
}

impl FromStr for TimeDiff {
    type Err = DurationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let inner = humantime::parse_duration(value)?.as_millis() as u64;
        Ok(TimeDiff(inner))
    }
}


impl TimeDiff {
    /// Returns the time difference as the number of milliseconds since the Unix epoch
    pub fn millis(&self) -> u64 {
        self.0
    }

    /// Creates a new time difference from seconds.
    pub const fn from_seconds(seconds: u32) -> Self {
        TimeDiff(seconds as u64 * 1_000)
    }

    /// Returns the product, or `TimeDiff(u64::MAX)` if it would overflow.
    pub fn saturating_mul(self, rhs: u64) -> Self {
        TimeDiff(self.0.saturating_mul(rhs))
    }
}

impl Serialize for TimeDiff {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for TimeDiff {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let value_as_string = String::deserialize(deserializer)?;
            TimeDiff::from_str(&value_as_string).map_err(SerdeError::custom)
        } else {
            let inner = u64::deserialize(deserializer)?;
            Ok(TimeDiff(inner))
        }
    }
}

impl ToBytes for TimeDiff {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

impl FromBytes for TimeDiff {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        u64::from_bytes(bytes).map(|(inner, remainder)| (TimeDiff(inner), remainder))
    }
}

/// A struct containing a signature and the public key of the signer.
#[derive(
Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug,
)]
pub struct Approval {
    signer: PublicKey,
    signature: Signature,
}

impl Approval {
    /// Creates an approval for the given deploy hash using the given secret key.
    pub fn create(hash: &DeployHash, secret_key: &SecretKey) -> Self {
        let signer = PublicKey::from(secret_key);
        let signature = sign(hash, secret_key, &signer);
        Self { signer, signature }
    }

    /// Returns the public key of the approval's signer.
    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }

    /// Returns the approval signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// The cryptographic hash of a [`Deploy`](struct.Deploy.html).
#[derive(
Copy,
Clone,
Ord,
PartialOrd,
Eq,
PartialEq,
Hash,
Serialize,
Deserialize,
Debug,
Default,
)]

pub struct DeployHash( Digest);

impl DeployHash {
    /// Constructs a new `DeployHash`.
    pub fn new(hash: Digest) -> Self {
        DeployHash(hash)
    }

    /// Returns the wrapped inner hash.
    pub fn inner(&self) -> &Digest {
        &self.0
    }

    /// Creates a random deploy hash.
    #[cfg(test)]
    pub fn random(rng: &mut TestRng) -> Self {
        let hash = rng.gen::<[u8; Digest::LENGTH]>().into();
        DeployHash(hash)
    }
}

impl From<DeployHash> for casper_types::DeployHash {
    fn from(deploy_hash: DeployHash) -> casper_types::DeployHash {
        casper_types::DeployHash::new(deploy_hash.inner().value())
    }
}

impl ToBytes for DeployHash {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

impl AsRef<[u8]> for DeployHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn serialize_body(payment: &ExecutableDeployItem, session: &ExecutableDeployItem) -> Vec<u8> {
    let mut buffer = payment
        .to_bytes()
        .unwrap_or_else(|error| panic!("should serialize payment code: {}", error));
    buffer.extend(
        session
            .to_bytes()
            .unwrap_or_else(|error| panic!("should serialize session code: {}", error)),
    );
    buffer
}

fn serialize_header(header: &DeployHeader) -> Vec<u8> {
    header
        .to_bytes()
        .unwrap_or_else(|error| panic!("should serialize deploy header: {}", error))
}

pub fn sign<T: AsRef<[u8]>>(
    message: T,
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Signature {
    match (secret_key, public_key) {
        (SecretKey::System, PublicKey::System) => {
            panic!("cannot create signature with system keys",)
        }
        (SecretKey::Ed25519(secret_key), PublicKey::Ed25519(public_key)) => {
            let expanded_secret_key = ExpandedSecretKey::from(secret_key);
            let signature = expanded_secret_key.sign(message.as_ref(), public_key);
            Signature::Ed25519(signature)
        }
        (SecretKey::Secp256k1(secret_key), PublicKey::Secp256k1(_public_key)) => {
            let signer = secret_key;
            let signature: Secp256k1Signature = signer
                .try_sign(message.as_ref())
                .expect("should create signature");
            Signature::Secp256k1(signature)
        }
        _ => panic!("secret and public key types must match"),
    }
}

/// A representation of the way in which a deploy failed validation checks.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Serialize)]
pub enum DeployConfigurationFailure {
    /// Invalid chain name.
    #[error("invalid chain name: expected {expected}, got {got}")]
    InvalidChainName {
        /// The expected chain name.
        expected: String,
        /// The received chain name.
        got: String,
    },

    /// Too many dependencies.
    #[error("{got} dependencies exceeds limit of {max_dependencies}")]
    ExcessiveDependencies {
        /// The dependencies limit.
        max_dependencies: u8,
        /// The actual number of dependencies provided.
        got: usize,
    },

    /// Deploy is too large.
    #[error("deploy size too large: {0}")]
    ExcessiveSize(#[from] ExcessiveSizeError),

    /// Excessive time-to-live.
    #[error("time-to-live of {got} exceeds limit of {max_ttl}")]
    ExcessiveTimeToLive {
        /// The time-to-live limit.
        max_ttl: TimeDiff,
        /// The received time-to-live.
        got: TimeDiff,
    },

    /// The provided body hash does not match the actual hash of the body.
    #[error("the provided body hash does not match the actual hash of the body")]
    InvalidBodyHash,

    /// The provided deploy hash does not match the actual hash of the deploy.
    #[error("the provided hash does not match the actual hash of the deploy")]
    InvalidDeployHash,

    /// The deploy has no approvals.
    #[error("the deploy has no approvals")]
    EmptyApprovals,

    /// Invalid approval.
    #[error("the approval at index {index} is invalid: {error_msg}")]
    InvalidApproval {
        /// The index of the approval at fault.
        index: usize,
        /// The approval validation error.
        error_msg: String,
    },

    /// Excessive length of deploy's session args.
    #[error("serialized session code runtime args of {got} exceeds limit of {max_length}")]
    ExcessiveSessionArgsLength {
        /// The byte size limit of session arguments.
        max_length: usize,
        /// The received length of session arguments.
        got: usize,
    },

    /// Excessive length of deploy's payment args.
    #[error("serialized payment code runtime args of {got} exceeds limit of {max_length}")]
    ExcessivePaymentArgsLength {
        /// The byte size limit of payment arguments.
        max_length: usize,
        /// The received length of payment arguments.
        got: usize,
    },

    /// Missing payment "amount" runtime argument.
    #[error("missing payment 'amount' runtime argument ")]
    MissingPaymentAmount,

    /// Failed to parse payment "amount" runtime argument.
    #[error("failed to parse payment 'amount' as U512")]
    FailedToParsePaymentAmount,

    /// The payment amount associated with the deploy exceeds the block gas limit.
    #[error("payment amount of {got} exceeds the block gas limit of {block_gas_limit}")]
    ExceededBlockGasLimit {
        /// Configured block gas limit.
        block_gas_limit: u64,
        /// The payment amount received.
        got: U512,
    },

    /// Missing payment "amount" runtime argument
    #[error("missing transfer 'amount' runtime argument")]
    MissingTransferAmount,

    /// Failed to parse transfer "amount" runtime argument.
    #[error("failed to parse transfer 'amount' as U512")]
    FailedToParseTransferAmount,

    /// Insufficient transfer amount.
    #[error("insufficient transfer amount; minimum: {minimum} attempted: {attempted}")]
    InsufficientTransferAmount {
        /// The minimum transfer amount.
        minimum: U512,
        /// The attempted transfer amount.
        attempted: U512,
    },

    /// The amount of approvals on the deploy exceeds the max_associated_keys limit.
    #[error("number of associated keys {got} exceeds the maximum {max_associated_keys}")]
    ExcessiveApprovals {
        /// Number of approvals on the deploy.
        got: u32,
        /// The chainspec limit for max_associated_keys.
        max_associated_keys: u32,
    },
}
/// Error returned when a Deploy is too large.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Serialize)]
#[error("deploy size of {actual_deploy_size} bytes exceeds limit of {max_deploy_size}")]
pub struct ExcessiveSizeError {
    /// The maximum permitted serialized deploy size, in bytes.
    pub max_deploy_size: u32,
    /// The serialized size of the deploy provided, in bytes.
    pub actual_deploy_size: usize,
}


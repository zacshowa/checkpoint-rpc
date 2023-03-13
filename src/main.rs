mod deploy;
mod executable_deploy_item;

use anyhow;
use jsonrpc_lite::JsonRpc;
use reqwest::{Client, Response};
use serde_json::Value::Object;
use serde_json::{json, Map, Value};
use std::fmt;
use std::fmt::Formatter;
use std::fs;
use pem::Pem;
use std::path::Path;
use casper_types::bytesrepr::Bytes;
use casper_types::{RuntimeArgs, U512, PublicKey, SecretKey, AsymmetricType, runtime_args};
use serde::Deserialize;
use thiserror::Error;
use crate::deploy::{Deploy, DeployHash, TimeDiff, Timestamp};
use crate::executable_deploy_item::ExecutableDeployItem;


const TEST_FILE_PATH: &str = "public_key_hex.txt";
const TEST_SECRET_KEY_PATH: &str = "secret_key.pem";
const FILE_PATH: &str =
    "/home/vimnovice/casper/casper-node/utils/nctl/assets/net1/users/user1/public_key_hex";
const SECRET_KEY_PATH: &str = "/home/vimnovice/casper/casper-node/utils/nctl/assets/net-1/users/user-1/secret_key.pem";
const CONTRACT_NAME: &str = "data_processor_contract";
const CONTRACT_LOCATION: &str = "contract.wasm";
const STANDARD_PAYMENT_ARG_AMOUNT: &str = "amount";

#[derive(Error, Debug)]
enum Error {
    FailedToParseResponse {
        rpc_id: u64,
        rpc_method: &'static str,
        error: anyhow::Error,
    },
    FailedToLoadPublicKey {
        path: String,
        error: std::io::Error,
    },
    FailedToParseSecretKey,
    CasperTypesErrorWrapper{
        error: casper_types::Error
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "doesn't matter for now")
    }
}

fn make_put_deploy_params<A: Into<U512>>(amount: A, account_hex: &str, chain_name: String) -> Result<Value, anyhow::Error>{
    let timestamp: Timestamp = Timestamp::now();
    let ttl: TimeDiff = TimeDiff::from_seconds(180);
    let gas_price: u64 = 1;
    let dependencies:Vec<DeployHash> = vec![];
    println!("before payment");
    let payment: ExecutableDeployItem = ExecutableDeployItem::ModuleBytes {
        module_bytes: Bytes::new(),
        args: runtime_args! {
            STANDARD_PAYMENT_ARG_AMOUNT => amount.into()
        },
    };
    println!("test");
    let pub_key: PublicKey = match PublicKey::from_hex(account_hex){
        Ok(key) => {key}
        Err(error) => {return Err(anyhow::Error::from(Error::CasperTypesErrorWrapper{error}));}
    };
    println!("after pub key");
    let bytes = match obtain_module_bytes(){
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Error obtaining module bytes");
            return Err(error)
        },
    };
    println!("after byutes");
    let session: ExecutableDeployItem = ExecutableDeployItem::ModuleBytes {
        module_bytes: bytes,
        args: runtime_args! {},
    };
    let secret_key = SecretKey::from_file(SECRET_KEY_PATH)?;
    println!("after key");
    let deploy = Deploy::new(timestamp, ttl, gas_price, dependencies, chain_name, payment, session, &secret_key, Some(pub_key));
 Ok(json!({
     "name": "deploy",
     "value": deploy
 }))
}

async fn put_deploy() -> Result<bool, anyhow::Error>{
    let unwrapped_vec: Vec<u8> = if let Ok(vec) = read_public_key_file() {
        vec
    } else {
        println!("Parsing the public key file failed, retrying.");
        //warn here that something is wrong, retry
        Vec::new()
    };
    let test: &[u8] = &unwrapped_vec;
    let test_str: &str = if let Ok(string) = std::str::from_utf8(test) {
        string
    } else {
        //warn here that something is wrong, retry
        ""
    };
    println!("what?>");
    let params = make_put_deploy_params(5000000000000_u64, test_str, "casper-net-1".to_string())?;
    println!("params");
    let rpc_req_json = JsonRpc::request_with_params(1, "account_put_deploy", params);

    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;
    println!("res: {:?}", res);
    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "put_deploy",
            error: error.into(),
        })?;
    println!("rpc_response: {:?}", rpc_response);
    if let Some(value) = rpc_response.get_result().clone() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(_map) => {return Ok(true);},
        }
    } else if let JsonRpc::Error(err) = rpc_response {
        println!("An error occurred in the rpc request: {:?}", err);
        return Ok(false);
    }
    Ok(false)
}



fn make_query_global_state_params(account: &str, state_identifier: &str) -> Map<String, Value> {
    let test_json = json!({ "StateRootHash": state_identifier });
    let mut map: Map<String, Value> = Map::new();
    let mut array: Vec<Value> = Vec::new();
    array.push(Value::String(CONTRACT_NAME.to_string()));
    map.insert("key".to_string(), Value::String(account.to_string()));
    map.insert("state_identifier".to_string(), test_json);
    map.insert("path".to_string(), Value::Array(array));
    map
}

async fn query_global_state_for_contract_named_key() -> Result<bool, anyhow::Error> {
    let state_root_hash = if let Ok(root_hash) = get_state_root_hash().await {
        root_hash
    } else {
        "".to_string()
    };
    let account = if let Ok(account_hash) = get_account_info().await {
        account_hash
    } else {
        "".to_string()
    };
    let params = make_query_global_state_params(&account, &state_root_hash);

    let rpc_req_json = JsonRpc::request_with_params(1, "query_global_state", params);

    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;

    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "query",
            error: error.into(),
        })?;

    if let Some(value) = rpc_response.get_result().clone() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(_map) => {return Ok(true);},
        }
    } else if let JsonRpc::Error(err) = rpc_response {
        println!("An error occurred in the rpc request: {:?}", err);
        return Ok(false);
    }

    Ok(false)
}

fn read_public_key_file() -> Result<Vec<u8>, anyhow::Error> {
    let data = fs::read(TEST_FILE_PATH)?;
    Ok(data)
}

fn make_get_account_params(account: &str) -> Map<String, Value> {
    let mut map: Map<String, Value> = Map::new();
    map.insert("public_key".to_string(), Value::String(account.to_string()));
    map
}

async fn get_account_info() -> Result<String, anyhow::Error> {
    let unwrapped_vec: Vec<u8> = if let Ok(vec) = read_public_key_file() {
        vec
    } else {
        println!("Parsing the public key file failed, retrying.");
        //warn here that something is wrong, retry
        Vec::new()
    };
    let test: &[u8] = &unwrapped_vec;
    let test_str: &str = if let Ok(string) = std::str::from_utf8(test) {
        string
    } else {
        //warn here that something is wrong, retry
        ""
    };

    let params = make_get_account_params(test_str);
    let rpc_req_json = JsonRpc::request_with_params(1, "state_get_account_info", params);
    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;
    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "state_get_account_info",
            error: error.into(),
        })?;
    if let Some(value) = rpc_response.get_result().clone() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(map) => {
                if let Some(value) = map.get("account") {
                    if let Value::Object(map) = value {
                        if let Some(Value::String(account_hash)) = map.get("account_hash") {
                            return Ok(account_hash.clone());
                        };
                    }
                }
            }
        }
    }

    Ok("".to_string())
}

async fn get_account_info_main_purse() -> Result<String, anyhow::Error> {
    let unwrapped_vec: Vec<u8> = if let Ok(vec) = read_public_key_file() {
        vec
    } else {
        println!("Parsing the public key file failed, retrying.");
        //warn here that something is wrong, retry
        Vec::new()
    };
    if let Err(e) = read_public_key_file() {
        println!("Error: {:?}", e);
    }
    let test: &[u8] = &unwrapped_vec;
    let test_str: &str = if let Ok(string) = std::str::from_utf8(test) {
        string
    } else {
        //warn here that something is wrong, retry
        ""
    };

    let params = make_get_account_params(test_str);
    let rpc_req_json = JsonRpc::request_with_params(1, "state_get_account_info", params);
    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;
    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "state_get_account_info",
            error: error.into(),
        })?;
    if let Some(value) = rpc_response.get_result().clone() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(map) => {
                if let Some(value) = map.get("account") {
                    if let Value::Object(map) = value {
                        if let Some(Value::String(val)) = map.get("main_purse") {
                            return Ok(val.clone());
                        };
                    }
                }
            }
        }
    }

    Ok("".to_string())
}

async fn get_state_root_hash() -> Result<String, anyhow::Error> {
    let rpc_req_json = JsonRpc::request(1, "chain_get_state_root_hash");
    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;
    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "state_get_balance",
            error: error.into(),
        })?;

    if let Some(value) = rpc_response.get_result().clone() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(map) => {
                if let Some(Value::String(value)) = map.get("state_root_hash") {
                    return Ok(value.clone());
                }
            }
        }
    }

    Ok("".to_string())
}

fn make_get_balance_params(state_root_hash: &str, purse_uref: &str) -> Map<String, Value> {
    let mut map: Map<String, Value> = Map::new();
    map.insert(
        "state_root_hash".to_string(),
        Value::String(state_root_hash.to_string()),
    );
    map.insert(
        "purse_uref".to_string(),
        Value::String(purse_uref.to_string()),
    );
    map
}

async fn get_balance_value() -> Result<String, anyhow::Error> {
    let state_root_hash = if let Ok(root_hash) = get_state_root_hash().await {
        root_hash
    } else {
        println!("Warn: Failed to get state root hash");
        "".to_string()
    };
    let main_purse_uref = if let Ok(uref) = get_account_info_main_purse().await {
        uref
    } else {
        println!("Warn: Failed to get state root hash");
        "".to_string()
    };
    let params = make_get_balance_params(&state_root_hash, &main_purse_uref);
    let rpc_req_json = JsonRpc::request_with_params(1, "state_get_balance", params);
    let client = Client::new();
    let res = client
        .post("http://localhost:11101/rpc")
        .json(&rpc_req_json)
        .send()
        .await?;
    let rpc_response: JsonRpc = res
        .json()
        .await
        .map_err(|error| Error::FailedToParseResponse {
            rpc_id: 1,
            rpc_method: "state_get_balance",
            error: error.into(),
        })?;

    if let Some(value) = rpc_response.get_result() {
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(_) => {}
            Value::String(_) => {}
            Value::Array(_) => {}
            Value::Object(map) => {
                if let Some(Value::String(number)) = map.get("balance_value") {
                    return Ok(number.clone());
                }
            }
        }
    }

    Ok("".to_string())
}

fn obtain_module_bytes() -> Result<Bytes, anyhow::Error> {
    let bytes = std::fs::read(CONTRACT_LOCATION)?;
    Ok(bytes.into())
}

#[tokio::main]
async fn main() {
   // let res4 = query_global_state_for_contract_named_key().await;
    //let res1 = get_balance_value().await;
   // let res2 = get_state_root_hash().await;
    println!("test");
    if let Ok(res3) = get_account_info_main_purse().await {
        println!("{}", res3);
    };
    if let Ok(res4) =  query_global_state_for_contract_named_key().await{
        println!("{}", res4);
    }
    if let Ok(res5) =  put_deploy().await{
        println!("{}", res5);
    }
    if let Err(err) = put_deploy().await{

    }
    //println!("Res3: {:?}", res3);
}
